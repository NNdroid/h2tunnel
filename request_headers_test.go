package h2tunnel

// =========================================
// Outbound request header consistency: the camouflage User-Agent +
// anti-buffering headers must appear on every tunnel request.
// Go's HTTP/2 Transport auto-injects "Go-http-client/2.0" when a request
// lacks a User-Agent, which directly contradicts the utls browser TLS
// fingerprint (the handshake says Chrome, the headers say Go) — this test
// locks it down at the source so no future helper removal or new request-
// building path can miss it.
// =========================================

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func assertTunnelRequestHeaders(t *testing.T, h http.Header, where string) {
	t.Helper()
	if got := h.Get("User-Agent"); got != clientUserAgent {
		t.Errorf("%s: User-Agent = %q, want the camouflage string", where, got)
	}
	if got := h.Get("Accept-Encoding"); got != "identity" {
		t.Errorf("%s: Accept-Encoding = %q, want identity", where, got)
	}
	if got := h.Get("Cache-Control"); !strings.Contains(got, "no-store") || !strings.Contains(got, "no-transform") {
		t.Errorf("%s: Cache-Control = %q, want no-store + no-transform", where, got)
	}
}

func TestTunnelRequestHeadersCarryCamouflagedUA(t *testing.T) {
	cfg := clientConfig{
		ServerUrl:     "https://cdn.example.com",
		Path:          "/tunnel",
		TargetAddr:    "db.internal:5432",
		Token:         "sekret",
		Network:       "tcp",
		SessionWindow: 256,
	}
	reqURL := cfg.ServerUrl + cfg.Path

	// TCP resume (the backup-line buildResumeRequestChecked shares this path).
	tcpReq := buildResumeRequest(context.Background(), strings.NewReader(""), "sess-tcp", new(uint64), newResumeClientRingBuf(256), reqURL, cfg)
	assertTunnelRequestHeaders(t, tcpReq.Header, "tcp resume")

	// UDP resume.
	udpReq := buildResumeUDPRequest(context.Background(), strings.NewReader(""), "sess-udp", reqURL, cfg)
	assertTunnelRequestHeaders(t, udpReq.Header, "udp resume")

	// WebTransport CONNECT session headers.
	mgr, err := newWTManagerForTunnelContext(context.Background(), cfg, reqURL, "sess-wt")
	if err != nil {
		t.Fatal(err)
	}
	assertTunnelRequestHeaders(t, mgr.headers, "wt connect")
}
