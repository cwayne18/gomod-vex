// Package analyze orchestrates the gomod-vex pipeline: extract an image, find
// its Go binaries, resolve vulnerable packages from OSV, and decide for each
// requested CVE whether the vulnerable code is present / reachable, optionally
// consulting an LLM for the genuinely-linked survivors.
package analyze

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/cwayne18/gomod-vex/internal/binscan"
	"github.com/cwayne18/gomod-vex/internal/image"
	"github.com/cwayne18/gomod-vex/internal/llm"
	"github.com/cwayne18/gomod-vex/internal/osv"
)

// Status classifies a (binary, CVE) pair.
type Status string

const (
	StatusNotPresent   Status = "not_present"         // vulnerable package absent from pclntab
	StatusNotInPath    Status = "not_in_execute_path" // linked but govulncheck says unreachable
	StatusLinked       Status = "linked"              // vulnerable package genuinely linked
	StatusUndetermined Status = "undetermined"        // could not resolve OSV mapping
)

// Finding is the per-binary, per-CVE result.
type Finding struct {
	Binary        string       `json:"binary"`
	Module        string       `json:"module"`
	Version       string       `json:"version"`
	CVE           string       `json:"cve"`
	GoID          string       `json:"go_id,omitempty"`
	Packages      []string     `json:"packages,omitempty"`
	Granularity   string       `json:"granularity,omitempty"` // package | module
	Stripped      bool         `json:"stripped"`
	Status        Status       `json:"status"`
	Method        string       `json:"method,omitempty"`
	Justification string       `json:"justification,omitempty"`
	Reason        string       `json:"reason,omitempty"` // for undetermined
	LLM           *llm.Verdict `json:"llm,omitempty"`
}

// Options configure a run.
type Options struct {
	Image   string
	Module  string
	CVEs    []string // optional filter; empty means "all advisories for module@version"
	Version string   // optional override of the detected module version
	OS      string
	Arch    string

	UseLLM   bool
	LLMModel string
	Token    string

	// Logf receives progress messages (may be nil).
	Logf func(format string, args ...any)
}

// Result is the full analysis output.
type Result struct {
	Image    string    `json:"image"`
	Module   string    `json:"module"`
	Findings []Finding `json:"findings"`
}

// Run executes the full pipeline.
func Run(ctx context.Context, opts Options) (*Result, error) {
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if opts.OS == "" {
		opts.OS = "linux"
	}
	if opts.Arch == "" {
		opts.Arch = "amd64"
	}

	dest, err := os.MkdirTemp("", "gomod-vex-fs-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dest)

	logf("Extracting %s (%s/%s)...", opts.Image, opts.OS, opts.Arch)
	ex := image.NewExtractor()
	ex.OS, ex.Arch = opts.OS, opts.Arch
	if err := ex.Extract(ctx, opts.Image, dest); err != nil {
		return nil, fmt.Errorf("extract image: %w", err)
	}

	logf("Scanning for Go binaries...")
	bins := binscan.FindGoBinaries(dest)
	logf("Found %d Go binaries.", len(bins))

	osvClient := osv.NewClient()
	osvCache := map[string]map[string]*osv.Advisory{} // version -> advisory map

	var llmClient *llm.Client
	if opts.UseLLM {
		llmClient, err = llm.NewClient(opts.LLMModel, opts.Token)
		if err != nil {
			return nil, fmt.Errorf("llm client: %w", err)
		}
	}

	result := &Result{Image: opts.Image, Module: opts.Module}

	for _, bin := range bins {
		version := opts.Version
		if version == "" {
			version = bin.ModuleVersion(opts.Module)
		}
		if version == "" {
			continue // module not linked into this binary and no override given
		}
		rel := relPath(dest, bin.Path)

		advMap, ok := osvCache[version]
		if !ok {
			advMap, err = osvClient.Query(ctx, opts.Module, version)
			if err != nil {
				logf("  ! OSV query failed for %s@%s: %v", opts.Module, version, err)
				advMap = map[string]*osv.Advisory{}
			}
			osvCache[version] = advMap
		}

		syms, err := binscan.LoadSymbols(bin.Path)
		if err != nil {
			logf("  ! cannot read %s: %v", rel, err)
			continue
		}
		stripped := binscan.IsStripped(bin.Path)

		// govulncheck is computed lazily (only for non-stripped binaries with a
		// linked package candidate).
		var gvIDs map[string]struct{}
		gvDone := false
		govuln := func() map[string]struct{} {
			if !gvDone {
				gvIDs = binscan.GovulncheckNotAffected(ctx, bin.Path)
				gvDone = true
			}
			return gvIDs
		}

		for _, req := range resolveRequests(opts.CVEs, advMap) {
			f := evaluate(ctx, evalCtx{
				binaryRel: rel,
				module:    opts.Module,
				version:   version,
				stripped:  stripped,
				syms:      syms,
				govuln:    govuln,
				llmClient: llmClient,
				logf:      logf,
			}, req.id, req.adv)
			result.Findings = append(result.Findings, f)
		}
	}

	sort.Slice(result.Findings, func(i, j int) bool {
		a, b := result.Findings[i], result.Findings[j]
		if a.Binary != b.Binary {
			return a.Binary < b.Binary
		}
		return a.CVE < b.CVE
	})
	return result, nil
}

type request struct {
	id  string
	adv *osv.Advisory
}

// resolveRequests turns the CVE filter (or "all") into concrete advisory
// lookups. In filter mode every requested id is returned, with a nil advisory
// when OSV has no mapping (recorded as undetermined). In "all" mode every
// distinct advisory is returned keyed by its canonical GO id.
func resolveRequests(cves []string, advMap map[string]*osv.Advisory) []request {
	if len(cves) > 0 {
		out := make([]request, 0, len(cves))
		for _, id := range cves {
			out = append(out, request{id: id, adv: advMap[id]})
		}
		return out
	}
	seen := map[string]bool{}
	var out []request
	for _, adv := range advMap {
		if seen[adv.GoID] {
			continue
		}
		seen[adv.GoID] = true
		out = append(out, request{id: adv.GoID, adv: adv})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

type evalCtx struct {
	binaryRel string
	module    string
	version   string
	stripped  bool
	syms      *binscan.Symbols
	govuln    func() map[string]struct{}
	llmClient *llm.Client
	logf      func(string, ...any)
}

func evaluate(ctx context.Context, ec evalCtx, id string, adv *osv.Advisory) Finding {
	f := Finding{
		Binary:   ec.binaryRel,
		Module:   ec.module,
		Version:  ec.version,
		CVE:      id,
		Stripped: ec.stripped,
	}
	if adv == nil {
		f.Status = StatusUndetermined
		f.Reason = "no_osv_package_mapping"
		return f
	}
	f.GoID = adv.GoID

	var pkgs []string
	var linked bool
	if len(adv.Pkgs) > 0 {
		pkgs = append(pkgs, adv.Pkgs...)
		sort.Strings(pkgs)
		f.Granularity = "package"
		for _, p := range pkgs {
			if ec.syms.PackagePresent(p) {
				linked = true
				break
			}
		}
	} else {
		pkgs = []string{ec.module}
		f.Granularity = "module"
		linked = ec.syms.ModulePresent(ec.module)
	}
	f.Packages = pkgs

	switch {
	case !linked:
		f.Status = StatusNotPresent
		f.Justification = "vulnerable_code_not_present"
		if f.Granularity == "module" {
			f.Method = "pclntab-module"
		} else {
			f.Method = "pclntab"
		}
	case f.Granularity == "package" && !ec.stripped && inNotAffected(ec.govuln(), id, adv.GoID):
		f.Status = StatusNotInPath
		f.Justification = "vulnerable_code_not_in_execute_path"
		f.Method = "govulncheck"
	default:
		f.Status = StatusLinked
		if ec.llmClient != nil {
			v, err := ec.llmClient.Assess(ctx, llm.Request{
				CVE:       id,
				Module:    ec.module,
				Version:   ec.version,
				Packages:  pkgs,
				Binary:    ec.binaryRel,
				Reachable: reachability(ec.stripped),
			})
			if err != nil {
				ec.logf("  ! LLM assess failed for %s: %v", id, err)
			} else {
				f.LLM = v
			}
		}
	}
	return f
}

func reachability(stripped bool) string {
	if stripped {
		return "linked"
	}
	return "linked (symbols retained; reachability not asserted)"
}

func inNotAffected(set map[string]struct{}, ids ...string) bool {
	for _, id := range ids {
		if _, ok := set[id]; ok {
			return true
		}
	}
	return false
}

func relPath(root, p string) string {
	if len(p) > len(root) && p[:len(root)] == root {
		trimmed := p[len(root):]
		if len(trimmed) > 0 && trimmed[0] == '/' {
			return trimmed
		}
		return "/" + trimmed
	}
	return p
}
