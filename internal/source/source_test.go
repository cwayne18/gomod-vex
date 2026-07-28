package source

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNormalizeRepo(t *testing.T) {
	cases := map[string]string{
		"github.com/rancher/rancher":         "https://github.com/rancher/rancher.git",
		"https://github.com/rancher/rancher": "https://github.com/rancher/rancher.git",
		"http://github.com/x/y/":             "https://github.com/x/y.git",
		"rancher/rancher":                    "https://github.com/rancher/rancher.git",
		"gitlab.com/foo/bar":                 "https://gitlab.com/foo/bar.git",
		"git@github.com:foo/bar.git":         "git@github.com:foo/bar.git",
	}
	for in, want := range cases {
		if got := normalizeRepo(in); got != want {
			t.Errorf("normalizeRepo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParsePurl(t *testing.T) {
	products := []product{
		{Subcomponents: []struct {
			ID string `json:"@id"`
		}{
			{ID: "pkg:golang/golang.org%2Fx%2Fnet@v0.7.0"},
		}},
	}
	mod, ver := parsePurl(products)
	if mod != "golang.org/x/net" {
		t.Errorf("module = %q, want golang.org/x/net", mod)
	}
	if ver != "v0.7.0" {
		t.Errorf("version = %q, want v0.7.0", ver)
	}
}

func TestParsePurlStdlib(t *testing.T) {
	products := []product{
		{Subcomponents: []struct {
			ID string `json:"@id"`
		}{
			{ID: "pkg:golang/stdlib@go1.21.5"},
		}},
	}
	mod, ver := parsePurl(products)
	if mod != "stdlib" || ver != "go1.21.5" {
		t.Errorf("got %q@%q, want stdlib@go1.21.5", mod, ver)
	}
}

func TestDiagnoseNoOutputOOM(t *testing.T) {
	stderr := "go: downloading golang.org/x/vuln v1.6.0\nsignal: killed"
	err := diagnoseNoOutput(context.Background(), nil, stderr)
	if err == nil {
		t.Fatal("expected error")
	}
	got := err.Error()
	if !strings.Contains(got, "out of memory") || !strings.Contains(got, "--repo-path") {
		t.Fatalf("unhelpful OOM error: %q", got)
	}
}

func TestDiagnoseNoOutputTimeout(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	err := diagnoseNoOutput(ctx, ctx.Err(), "")
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func TestDiagnoseNoOutputGeneric(t *testing.T) {
	err := diagnoseNoOutput(context.Background(), nil, "some other failure")
	if err == nil || !strings.Contains(err.Error(), "some other failure") {
		t.Fatalf("expected passthrough error, got %v", err)
	}
}

func TestNormalizeGoVersion(t *testing.T) {
	cases := map[string]string{
		"1.24.0":   "1.24.0",
		"go1.24.0": "1.24.0",
		"v1.24.0":  "1.24.0",
		" go1.25 ": "1.25",
	}
	for in, want := range cases {
		if got := normalizeGoVersion(in); got != want {
			t.Errorf("normalizeGoVersion(%q) = %q, want %q", in, got, want)
		}
	}
}
