package binscan

import (
	"debug/buildinfo"
	"testing"
)

func TestPackagePresent(t *testing.T) {
	blob := []byte("prefixgolang.org/x/net/http2.(*Framer).ReadFrame\x00other golang.org/x/net/idna.ToASCII junk")
	s := &Symbols{blob: blob}

	if !s.PackagePresent("golang.org/x/net/http2") {
		t.Errorf("expected http2 package to be present")
	}
	if !s.PackagePresent("golang.org/x/net/idna") {
		t.Errorf("expected idna package to be present")
	}
	// A sibling that is not linked must not leak from a parent match.
	if s.PackagePresent("golang.org/x/net/websocket") {
		t.Errorf("websocket should not be present")
	}
	// Parent path without a trailing symbol must not match a child's symbol.
	if s.PackagePresent("golang.org/x/net/http2/hpack") {
		t.Errorf("hpack subpackage should not be present")
	}
}

func TestModulePresent(t *testing.T) {
	blob := []byte("... google.golang.org/grpc/internal/transport.newHTTP2Server ...")
	s := &Symbols{blob: blob}

	if !s.ModulePresent("google.golang.org/grpc") {
		t.Errorf("expected grpc module to be present")
	}
	// The [./] guard must keep a prefix from matching an unrelated module.
	if s.ModulePresent("google.golang.org/grpcfoo") {
		t.Errorf("grpcfoo must not match")
	}
	if s.ModulePresent("golang.org/x/net") {
		t.Errorf("x/net must not be present")
	}
}

func TestNormalizeGoVersion(t *testing.T) {
	cases := map[string]string{
		"go1.24.0":                "1.24.0",
		"go1.21.5":                "1.21.5",
		"go1.24.0 X:boringcrypto": "1.24.0",
		"devel go1.26-abc":        "",
		"":                        "",
	}
	for in, want := range cases {
		if got := NormalizeGoVersion(in); got != want {
			t.Errorf("NormalizeGoVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestModuleVersionStdlib(t *testing.T) {
	b := Binary{Info: &buildinfo.BuildInfo{GoVersion: "go1.24.0"}}
	if got := b.ModuleVersion("stdlib"); got != "1.24.0" {
		t.Errorf("stdlib version = %q, want 1.24.0", got)
	}
	if got := b.ModuleVersion("std"); got != "1.24.0" {
		t.Errorf("std alias version = %q, want 1.24.0", got)
	}
	if got := b.ModuleVersion("golang.org/x/net"); got != "" {
		t.Errorf("non-dep module = %q, want empty", got)
	}
}
