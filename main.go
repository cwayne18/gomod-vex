// Command gomod-vex checks whether specific CVEs in a Go module are actually
// present in the binaries shipped inside a container image, using pclntab
// presence tests and govulncheck, with an optional LLM exploitability check.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cwayne18/gomod-vex/internal/analyze"
)

func main() {
	var (
		image    = flag.String("image", "", "container image reference to inspect (required)")
		module   = flag.String("module", "", "Go module import path to evaluate (required)")
		cvesFlag = flag.String("cves", "", "comma-separated CVE/GHSA/GO ids to check; empty checks every advisory OSV knows for the module version")
		cvesFile = flag.String("cves-file", "", "path to a file with one CVE/GHSA/GO id per line (merged with --cves)")
		version  = flag.String("version", "", "override the module version (default: read from each binary's build info)")
		goos     = flag.String("os", "linux", "image OS variant to pull")
		arch     = flag.String("arch", "amd64", "image architecture variant to pull")
		useLLM   = flag.Bool("llm", false, "consult a GitHub Models LLM on genuinely-linked CVEs for exploitability")
		llmModel = flag.String("llm-model", "openai/gpt-4o", "GitHub Models model id for --llm")
		format   = flag.String("format", "text", "output format: text or json")
		out      = flag.String("out", "", "write output to this file instead of stdout")
		quiet    = flag.Bool("quiet", false, "suppress progress logging on stderr")
	)
	flag.Usage = usage
	flag.Parse()

	if *image == "" || *module == "" {
		fmt.Fprintln(os.Stderr, "error: --image and --module are required")
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

	res, err := analyze.Run(ctx, analyze.Options{
		Image:    *image,
		Module:   *module,
		CVEs:     cves,
		Version:  *version,
		OS:       *goos,
		Arch:     *arch,
		UseLLM:   *useLLM,
		LLMModel: *llmModel,
		Logf:     logf,
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

func renderText(res *analyze.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "gomod-vex report for %s\n", res.Image)
	fmt.Fprintf(&b, "module: %s\n\n", res.Module)

	if len(res.Findings) == 0 {
		b.WriteString("No findings: the module was not linked into any Go binary in this image,\n")
		b.WriteString("or no matching advisories were found.\n")
		return b.String()
	}

	// Group by status for a readable summary.
	counts := map[analyze.Status]int{}
	for _, f := range res.Findings {
		counts[f.Status]++
	}
	fmt.Fprintf(&b, "summary: %d not_present, %d not_in_execute_path, %d linked, %d undetermined\n\n",
		counts[analyze.StatusNotPresent], counts[analyze.StatusNotInPath],
		counts[analyze.StatusLinked], counts[analyze.StatusUndetermined])

	for _, f := range res.Findings {
		id := f.CVE
		if f.GoID != "" && f.GoID != f.CVE {
			id = fmt.Sprintf("%s (%s)", f.CVE, f.GoID)
		}
		fmt.Fprintf(&b, "%-22s %s@%s\n", statusLabel(f.Status), f.Module, f.Version)
		fmt.Fprintf(&b, "  cve:      %s\n", id)
		fmt.Fprintf(&b, "  binary:   %s%s\n", f.Binary, strippedNote(f.Stripped))
		if len(f.Packages) > 0 {
			fmt.Fprintf(&b, "  packages: %s (%s)\n", strings.Join(f.Packages, ", "), f.Granularity)
		}
		if f.Justification != "" {
			fmt.Fprintf(&b, "  vex:      %s [%s]\n", f.Justification, f.Method)
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
	fmt.Fprint(os.Stderr, `gomod-vex - check whether Go-module CVEs are actually present in an image's binaries

Usage:
  gomod-vex --image REF --module PATH [--cves LIST] [flags]

Examples:
  gomod-vex --image rancher/hardened-kubernetes:v1.30.1 --module golang.org/x/net \
    --cves CVE-2023-39325,CVE-2023-44487

  gomod-vex --image myimg:latest --module golang.org/x/crypto --llm --format json

Flags:
`)
	flag.PrintDefaults()
}
