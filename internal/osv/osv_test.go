package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

const sampleResponse = `{
  "vulns": [
    {
      "id": "GO-2023-1988",
      "aliases": ["CVE-2023-39325", "GHSA-4374-p667-p6c8"],
      "affected": [
        {
          "package": {"name": "golang.org/x/net"},
          "ecosystem_specific": {"imports": [{"path": "golang.org/x/net/http2"}]}
        }
      ]
    },
    {
      "id": "GHSA-only-record",
      "aliases": ["CVE-2023-39325"],
      "affected": [
        {
          "package": {"name": "golang.org/x/net"},
          "ecosystem_specific": {"imports": []}
        }
      ]
    }
  ]
}`

func TestQueryAliasMappingAndPreference(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sampleResponse))
	}))
	defer srv.Close()

	c := NewClient()
	c.URL = srv.URL

	m, err := c.Query(context.Background(), "golang.org/x/net", "v0.7.0")
	if err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{"GO-2023-1988", "CVE-2023-39325", "GHSA-4374-p667-p6c8"} {
		adv, ok := m[key]
		if !ok {
			t.Fatalf("expected key %q in map", key)
		}
		if len(adv.Pkgs) != 1 || adv.Pkgs[0] != "golang.org/x/net/http2" {
			t.Errorf("key %q: expected http2 import path, got %v", key, adv.Pkgs)
		}
	}

	// CVE-2023-39325 is aliased by both records; the one carrying import paths
	// must win over the empty GHSA-only record.
	if got := m["CVE-2023-39325"].GoID; got != "GO-2023-1988" {
		t.Errorf("expected import-carrying record to win, got GoID %q", got)
	}
}

func TestQueryNormalizesStdlibVersion(t *testing.T) {
	var gotVersion, gotName string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req queryRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		gotVersion = req.Version
		gotName = req.Package.Name
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vulns":[]}`))
	}))
	defer srv.Close()

	c := NewClient()
	c.URL = srv.URL
	if _, err := c.Query(context.Background(), "stdlib", "go1.24.0"); err != nil {
		t.Fatal(err)
	}
	if gotVersion != "1.24.0" {
		t.Errorf("version sent to OSV = %q, want 1.24.0", gotVersion)
	}
	if gotName != "stdlib" {
		t.Errorf("name sent to OSV = %q, want stdlib", gotName)
	}
}
