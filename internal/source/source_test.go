package source

import "testing"

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
