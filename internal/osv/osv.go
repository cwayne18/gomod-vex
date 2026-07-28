// Package osv resolves the vulnerable package import paths for a Go module
// version from the OSV Go vulnerability database (https://osv.dev).
//
// This mirrors the resolution logic in the rke2-toolbox vex_candidates.py
// script: an advisory is keyed by every identifier it is known by (its own OSV
// GO- id plus all aliases such as CVE- and GHSA-), and the record that actually
// carries import paths wins when the same key is contributed by more than one
// source record.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const queryURL = "https://api.osv.dev/v1/query"

// Advisory is the resolved information for a single vulnerability id.
type Advisory struct {
	// GoID is the canonical OSV identifier (e.g. GO-2024-1234).
	GoID string
	// Pkgs is the set of vulnerable import paths declared for the module.
	// Empty when OSV publishes no package-level import paths (e.g. GitHub-only
	// GHSA records), in which case callers should fall back to module
	// granularity.
	Pkgs []string
	// Aliases are all identifiers this advisory is known by.
	Aliases []string
}

// Client queries the OSV API.
type Client struct {
	HTTP *http.Client
	URL  string
}

// NewClient returns a Client with sane defaults.
func NewClient() *Client {
	return &Client{
		HTTP: &http.Client{Timeout: 30 * time.Second},
		URL:  queryURL,
	}
}

type queryRequest struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Version string `json:"version"`
}

type queryResponse struct {
	Vulns []struct {
		ID       string   `json:"id"`
		Aliases  []string `json:"aliases"`
		Affected []struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
			EcosystemSpecific struct {
				Imports []struct {
					Path string `json:"path"`
				} `json:"imports"`
			} `json:"ecosystem_specific"`
		} `json:"affected"`
	} `json:"vulns"`
}

// Query returns the map of advisory-id -> Advisory for module@version. Every
// alias identifier is a key in the returned map so a caller may look up a CVE,
// GHSA or GO id interchangeably.
func (c *Client) Query(ctx context.Context, module, version string) (map[string]*Advisory, error) {
	version = strings.TrimPrefix(version, "v")

	var req queryRequest
	req.Package.Ecosystem = "Go"
	req.Package.Name = module
	req.Version = version

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	var resp queryResponse
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
		lastErr = c.do(ctx, body, &resp)
		if lastErr == nil {
			break
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}

	out := map[string]*Advisory{}
	for _, v := range resp.Vulns {
		pkgs := map[string]struct{}{}
		for _, aff := range v.Affected {
			if aff.Package.Name != module {
				continue
			}
			for _, imp := range aff.EcosystemSpecific.Imports {
				if imp.Path != "" {
					pkgs[imp.Path] = struct{}{}
				}
			}
		}
		pkgList := make([]string, 0, len(pkgs))
		for p := range pkgs {
			pkgList = append(pkgList, p)
		}

		adv := &Advisory{GoID: v.ID, Pkgs: pkgList, Aliases: v.Aliases}
		keys := append([]string{v.ID}, v.Aliases...)
		for _, key := range keys {
			if key == "" {
				continue
			}
			// Prefer whichever record carries import paths so an import-less
			// GHSA record never clobbers a richer GO record's package list.
			if existing, ok := out[key]; !ok || (len(existing.Pkgs) == 0 && len(pkgList) > 0) {
				out[key] = adv
			}
		}
	}
	return out, nil
}

func (c *Client) do(ctx context.Context, body []byte, out *queryResponse) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	res, err := c.HTTP.Do(httpReq)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("osv: unexpected status %d", res.StatusCode)
	}
	return json.NewDecoder(res.Body).Decode(out)
}
