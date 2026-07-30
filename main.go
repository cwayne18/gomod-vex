// Command gomod-vex checks whether specific CVEs in a Go module are actually
// present in the binaries shipped inside a container image, using pclntab
// presence tests and govulncheck, with an optional LLM exploitability check.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cwayne18/gomod-vex/internal/analyze"
	"github.com/cwayne18/gomod-vex/internal/archive"
	flagutil "github.com/cwayne18/gomod-vex/internal/flag"
	"github.com/cwayne18/gomod-vex/internal/gist"
)

func main() {
	var (
		image      = flag.String("image", "", "container image reference to inspect (mutually exclusive with --repo and --image-file)")
		repo       = flag.String("repo", "", "git source repo to analyze via govulncheck source mode, e.g. github.com/rancher/rancher (mutually exclusive with --image and --image-file)")
		imageFile  = flag.String("image-file", "", "the local or remote path to an images.txt file e.g. ./imagelist.txt, https://github.com/rancher/rke2/releases/download/v1.36.2%2Brke2r1/rke2-images.linux-amd64.txt (mutually exclusive with --image and --repo)")
		ref        = flag.String("ref", "", "branch, tag, or commit to check out for --repo (default: repo default branch)")
		repoPath   = flag.String("repo-path", ".", "module subdirectory within --repo to scan")
		module     = flag.String("module", "", "Go module import path to evaluate, or 'stdlib' for the standard library (required)")
		cvesFlag   = flag.String("cves", "", "comma-separated CVE/GHSA/GO ids to check; empty checks every advisory found for the module version")
		cvesFile   = flag.String("cves-file", "", "path to a file with one CVE/GHSA/GO id per line (merged with --cves)")
		version    = flag.String("version", "", "override the module version (image mode only; default: read from each binary's build info)")
		goVersion  = flag.String("go-version", "", "pin the Go toolchain for --repo analysis, e.g. 1.24.0 (useful with --module stdlib)")
		goos       = flag.String("os", "linux", "image OS variant to pull (image mode)")
		arch       = flag.String("arch", "amd64", "image architecture variant to pull (image mode)")
		useLLM     = flag.Bool("llm", false, "consult a GitHub Models LLM on genuinely-affected CVEs for exploitability")
		llmModel   = flag.String("llm-model", "openai/gpt-4o", "GitHub Models model id for --llm")
		format     = flag.String("format", "text", "output format: text or json")
		out        = flag.String("out", "", "write output to this file instead of stdout")
		gistFlag   = flag.Bool("gist", false, "also upload the output to a public GitHub gist and print its URL (needs GITHUB_TOKEN/GH_TOKEN with gist scope)")
		gistSecret = flag.Bool("gist-secret", false, "with --gist, create a secret (unlisted) gist instead of a public one")
		quiet      = flag.Bool("quiet", false, "suppress progress logging on stderr")
	)
	flag.Usage = usage
	flag.Parse()

	if *module == "" {
		fmt.Fprintln(os.Stderr, "error: --module is required")
		flag.Usage()
		os.Exit(2)
	}
	if !flagutil.OneOf(*image, *repo, *imageFile) {
		fmt.Fprintln(os.Stderr, "error: set exactly one of --image, --repo or --image-file")
		flag.Usage()
		os.Exit(2)
	}

	cves := parseCVEs(*cvesFlag, *cvesFile)

	logf := func(format string, args ...any) {
		if !*quiet {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// if repo isn't set, get the list of images to analyze either from --image xor
	// from --image-file
	var images []string
	if *repo == "" {
		var err error
		images, err = imageList(ctx, *image, *imageFile, logf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
	}

	res, err := analyze.Run(ctx, analyze.Options{
		Images:    images,
		Repo:      *repo,
		Ref:       *ref,
		Path:      *repoPath,
		Module:    *module,
		CVEs:      cves,
		Version:   *version,
		OS:        *goos,
		Arch:      *arch,
		GoVersion: *goVersion,
		UseLLM:    *useLLM,
		LLMModel:  *llmModel,
		Logf:      logf,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var rendered string
	switch *format {
	case "json":
		b, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		rendered = string(b) + "\n"
	case "text":
		rendered = renderText(res)
	default:
		fmt.Fprintf(os.Stderr, "error: unknown --format %q\n", *format)
		os.Exit(2)
	}

	if *out != "" {
		if err := os.WriteFile(*out, []byte(rendered), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		logf("Wrote %s", *out)
	} else {
		fmt.Print(rendered)
	}

	if *gistFlag {
		url, err := uploadGist(ctx, res, rendered, *format, !*gistSecret)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: gist upload failed: %v\n", err)
			os.Exit(1)
		}
		logf("Uploaded report to gist")
		fmt.Println(url)
	}
}

// uploadGist pushes the rendered report to a GitHub gist and returns its URL.
func uploadGist(ctx context.Context, results analyze.Results, rendered, format string, public bool) (string, error) {
	client, err := gist.NewClient("")
	if err != nil {
		return "", err
	}
	filename := "gomod-vex-report.txt"
	if format == "json" {
		filename = "gomod-vex-report.json"
	}

	var (
		mode, module string
		target       []string
	)
	for i, res := range results {
		// use the first result's mode and module for the gist description because they are the same
		// for all results, but accumulate all targets
		if i == 0 {
			mode = res.Mode
			module = res.Module
		}
		target = append(target, res.Target)
	}
	desc := fmt.Sprintf("gomod-vex %s report for %s (module %s)", mode, strings.Join(target, ","), module)
	return client.Create(ctx, filename, desc, rendered, public)
}

func parseCVEs(flagVal, file string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, part := range strings.Split(flagVal, ",") {
		add(part)
	}
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: read --cves-file: %v\n", err)
			os.Exit(2)
		}
		for _, line := range strings.Split(string(data), "\n") {
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = line[:i]
			}
			add(line)
		}
	}
	return out
}

func renderText(results analyze.Results) string {
	var b strings.Builder
	for _, res := range results {
		fmt.Fprintf(&b, "gomod-vex report (%s) for %s\n", res.Mode, res.Target)
		fmt.Fprintf(&b, "module: %s\n\n", res.Module)

		if len(res.Findings) == 0 {
			b.WriteString("No findings: the module was not linked into any Go binary in this image,\n")
			b.WriteString("or no matching advisories were found.\n")
			b.WriteString("\n")
			continue
		}

		// Group by status for a readable summary.
		counts := map[analyze.Status]int{}
		for _, f := range res.Findings {
			counts[f.Status]++
		}
		fmt.Fprintf(&b, "summary: %d not_present, %d not_in_execute_path, %d linked, %d reachable, %d undetermined\n\n",
			counts[analyze.StatusNotPresent], counts[analyze.StatusNotInPath],
			counts[analyze.StatusLinked], counts[analyze.StatusReachable],
			counts[analyze.StatusUndetermined])

		for _, f := range res.Findings {
			id := f.CVE
			if f.GoID != "" && f.GoID != f.CVE {
				id = fmt.Sprintf("%s (%s)", f.CVE, f.GoID)
			}
			fmt.Fprintf(&b, "%-22s %s@%s\n", statusLabel(f.Status), f.Module, f.Version)
			fmt.Fprintf(&b, "  cve:      %s\n", id)
			if f.Binary != "" {
				fmt.Fprintf(&b, "  binary:   %s%s\n", f.Binary, strippedNote(f.Stripped))
			}
			if len(f.Packages) > 0 {
				fmt.Fprintf(&b, "  packages: %s (%s)\n", strings.Join(f.Packages, ", "), f.Granularity)
			}
			if f.Justification != "" {
				fmt.Fprintf(&b, "  vex:      %s [%s]\n", f.Justification, f.Method)
			} else if f.Method != "" && f.Status == analyze.StatusReachable {
				fmt.Fprintf(&b, "  method:   %s\n", f.Method)
			}
			if f.Reason != "" {
				fmt.Fprintf(&b, "  reason:   %s\n", f.Reason)
			}
			if f.LLM != nil {
				fmt.Fprintf(&b, "  llm:      exploitable=%s confidence=%s\n", f.LLM.Exploitable, f.LLM.Confidence)
				if f.LLM.Rationale != "" {
					fmt.Fprintf(&b, "            %s\n", f.LLM.Rationale)
				}
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func statusLabel(s analyze.Status) string {
	switch s {
	case analyze.StatusNotPresent:
		return "[NOT PRESENT]"
	case analyze.StatusNotInPath:
		return "[NOT REACHABLE]"
	case analyze.StatusLinked:
		return "[LINKED]"
	case analyze.StatusReachable:
		return "[REACHABLE]"
	default:
		return "[UNDETERMINED]"
	}
}

func strippedNote(stripped bool) string {
	if stripped {
		return " (stripped)"
	}
	return ""
}

func usage() {
	fmt.Fprint(os.Stderr, `gomod-vex - check whether Go-module CVEs are actually present in an image or source repo

Usage:
  gomod-vex --image REF   --module PATH [--cves LIST] [flags]
  gomod-vex --repo  REPO  --module PATH [--cves LIST] [flags]

Examples:
  # Container image (pclntab + govulncheck binary mode)
  gomod-vex --image rancher/hardened-kubernetes:v1.30.1 --module golang.org/x/net \
    --cves CVE-2023-39325,CVE-2023-44487

  # Source repo (govulncheck source-mode reachability)
  gomod-vex --repo github.com/rancher/rancher --module golang.org/x/net \
    --cves CVE-2023-39325

  # Standard library CVEs (module "stdlib")
  gomod-vex --image myorg/app:latest --module stdlib --cves CVE-2025-22870
  gomod-vex --repo github.com/rancher/rancher --module stdlib --go-version 1.24.0

  # Share the report as a public gist (needs GITHUB_TOKEN/GH_TOKEN with gist scope)
  gomod-vex --image rancher/hardened-kubernetes:v1.30.1 --module golang.org/x/net \
    --cves CVE-2023-39325 --gist

Flags:
`)
	flag.PrintDefaults()
}

// imageList returns a list of images to analyze, either from the --image flag or
// --image-file (local or remote) file containing one image per line. --image takes
// precedence over --image-file. Lines starting with '#' are treated as comments
// and ignored. Empty lines are also ignored.
func imageList(ctx context.Context, image string, imageFile string, logf func(string, ...any)) ([]string, error) {
	if image != "" {
		return []string{image}, nil
	}

	normalize := func(buf *bytes.Buffer) ([]string, error) {
		var imageList []string
		decompressed, err := archive.EnsureDecompressed(buf)
		if err != nil {
			return nil, err
		}

		d, err := io.ReadAll(decompressed)
		if err != nil {
			return nil, err
		}

		for _, image := range strings.Split(string(d), "\n") {
			trimmed := strings.TrimSpace(image)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue // skip empty lines and comments
			}
			imageList = append(imageList, trimmed)
		}

		if len(imageList) == 0 {
			return nil, fmt.Errorf("no images found in %s", imageFile)
		}
		return imageList, nil
	}

	logf("Fetching image list from %s", imageFile)
	if flagutil.IsHTTPURL(imageFile) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, imageFile, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create http request for %s: %w", imageFile, err)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed http get %s: %w", imageFile, err)
		}
		//nolint:errcheck
		defer resp.Body.Close()

		// any non-200 response is treated as error because the body won't have the image list.
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed http get %s: %s", imageFile, resp.Status)
		}

		buf := &bytes.Buffer{}
		if _, err := buf.ReadFrom(resp.Body); err != nil {
			return nil, fmt.Errorf("failed reading from http response body: %w", err)
		}
		return normalize(buf)
	}

	content, err := os.ReadFile(imageFile)
	if err != nil {
		return nil, fmt.Errorf("read file %s: %w", imageFile, err)
	}
	buf := bytes.NewBuffer(content)
	return normalize(buf)
}
