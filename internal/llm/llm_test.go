package llm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func testClient(endpoint string) *Client {
	return &Client{
		HTTP:     &http.Client{Timeout: 5 * time.Second},
		Endpoint: endpoint,
		Model:    "test",
		Token:    "test",
	}
}

func TestParseVerdict(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"plain", `{"exploitable":"likely","confidence":"high","rationale":"reachable parser"}`, "likely"},
		{"fenced", "```json\n{\"exploitable\":\"unlikely\",\"confidence\":\"medium\",\"rationale\":\"x\"}\n```", "unlikely"},
		{"prose_wrapped", "Here is my answer:\n{\"exploitable\":\"unknown\",\"confidence\":\"low\",\"rationale\":\"y\"}\nThanks", "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := parseVerdict(tc.content)
			if err != nil {
				t.Fatal(err)
			}
			if v.Exploitable != tc.want {
				t.Errorf("got %q, want %q", v.Exploitable, tc.want)
			}
		})
	}
}

func TestParseVerdictNonJSON(t *testing.T) {
	v, err := parseVerdict("I cannot determine this.")
	if err != nil {
		t.Fatal(err)
	}
	if v.Exploitable != "unknown" {
		t.Errorf("expected unknown fallback, got %q", v.Exploitable)
	}
}

// TestAssessNonJSONError verifies a non-JSON error body (the case behind
// "invalid character 'T'...") surfaces as a legible status-based error rather
// than an opaque JSON parse failure.
func TestAssessNonJSONError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("The request was malformed."))
	}))
	defer srv.Close()

	_, err := testClient(srv.URL).Assess(context.Background(), Request{CVE: "CVE-x"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got == "" ||
		!containsAll(got, "github models", "400", "malformed") {
		t.Fatalf("unhelpful error: %q", got)
	}
}

// TestAssessRetryThenSuccess verifies transient 429s are retried and a later
// 200 succeeds.
func TestAssessRetryThenSuccess(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("Too Many Requests"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"exploitable\":\"likely\",\"confidence\":\"high\",\"rationale\":\"ok\"}"}}]}`))
	}))
	defer srv.Close()

	v, err := testClient(srv.URL).Assess(context.Background(), Request{CVE: "CVE-x"})
	if err != nil {
		t.Fatal(err)
	}
	if v.Exploitable != "likely" {
		t.Errorf("got %q, want likely", v.Exploitable)
	}
	if calls < 2 {
		t.Errorf("expected a retry, saw %d call(s)", calls)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
