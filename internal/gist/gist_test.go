package gist

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testClient(endpoint string) *Client {
	return &Client{
		HTTP:     &http.Client{Timeout: 5 * time.Second},
		Endpoint: endpoint,
		Token:    "test",
	}
}

func TestCreateSuccess(t *testing.T) {
	var gotPublic bool
	var gotFiles map[string]gistFile
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test" {
			t.Errorf("missing auth header: %q", r.Header.Get("Authorization"))
		}
		body, _ := io.ReadAll(r.Body)
		var req createRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("bad request body: %v", err)
		}
		gotPublic = req.Public
		gotFiles = req.Files
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"html_url":"https://gist.github.com/abc123"}`))
	}))
	defer srv.Close()

	url, err := testClient(srv.URL).Create(context.Background(), "r.txt", "desc", "hello", true)
	if err != nil {
		t.Fatal(err)
	}
	if url != "https://gist.github.com/abc123" {
		t.Errorf("got url %q", url)
	}
	if !gotPublic {
		t.Error("expected public=true")
	}
	if f, ok := gotFiles["r.txt"]; !ok || f.Content != "hello" {
		t.Errorf("unexpected files: %+v", gotFiles)
	}
}

func TestCreateForbiddenGivesScopeHint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Resource not accessible by personal access token"}`))
	}))
	defer srv.Close()

	_, err := testClient(srv.URL).Create(context.Background(), "r.txt", "d", "x", true)
	if err == nil {
		t.Fatal("expected error")
	}
	if got := err.Error(); !contains(got, "gist scope") || !contains(got, "403") {
		t.Fatalf("unhelpful error: %q", got)
	}
}

func TestCreateNonJSONError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("The service is unavailable."))
	}))
	defer srv.Close()

	_, err := testClient(srv.URL).Create(context.Background(), "r.txt", "d", "x", true)
	if err == nil {
		t.Fatal("expected error")
	}
	if got := err.Error(); !contains(got, "502") || !contains(got, "unavailable") {
		t.Fatalf("unhelpful error: %q", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
