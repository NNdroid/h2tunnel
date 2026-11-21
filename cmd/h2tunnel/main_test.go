package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	h2tunnel "github.com/NNdroid/h2tunnel"
	"github.com/NNdroid/h2tunnel/internal/share"
)

// The CLI's default dialer is the SSRF boundary for a local_only=false server:
// link-local addresses host the cloud-metadata endpoint, so they are refused
// regardless of localOnly. Literal IPs need no DNS round trip, which keeps the
// test deterministic.
func TestDirectTargetDialerRefusesLinkLocal(t *testing.T) {
	dialer := directTargetDialer(false)
	for _, target := range []string{"169.254.169.254:80", "[fe80::1]:80"} {
		if _, err := dialer(context.Background(), h2tunnel.DialRequest{Network: h2tunnel.NetworkTCP, Target: target}); !errors.Is(err, h2tunnel.ErrForbidden) {
			t.Fatalf("link-local target %q: err = %v, want ErrForbidden", target, err)
		}
	}
}

// Loopback targets keep working under local_only, and the resolved IP is what
// gets dialed (the checked address is the dialed address).
func TestDirectTargetDialerAllowsLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dialer := directTargetDialer(true)
	conn, err := dialer(context.Background(), h2tunnel.DialRequest{Network: h2tunnel.NetworkTCP, Target: ln.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

// gen-uri defaults to a verified URI; an explicit -insecure must be visible in
// the output (the parameter travels in the plaintext direct URI).
func TestGenURIDefaultsToVerifiedTLS(t *testing.T) {
	out := captureStdout(t, func() {
		if err := runGenURI([]string{"-host", "h.example", "-port", "8443"}); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(out, "insecure=1") {
		t.Fatalf("gen-uri default emitted an insecure URI:\n%s", out)
	}
	out = captureStdout(t, func() {
		if err := runGenURI([]string{"-host", "h.example", "-port", "8443", "-insecure", "true"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "insecure=1") || !strings.Contains(out, "skip TLS verification") {
		t.Fatalf("explicit -insecure must carry the warning; got:\n%s", out)
	}
}

// The generated PIN carries the brute-force gate for a captured stun:// URI;
// the Go generators (root package and internal/share) must agree on its
// entropy floor.
func TestGeneratedPINLength(t *testing.T) {
	_, pin, _, err := share.Generate("h2", "h.example", "8443", "", "", "", "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(pin) != 9 {
		t.Fatalf("generated PIN %q has length %d, want 9 digits", pin, len(pin))
	}
	for _, r := range pin {
		if r < '0' || r > '9' {
			t.Fatalf("generated PIN %q is not numeric", pin)
		}
	}
}
