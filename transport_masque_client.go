package h2tunnel

// =========================================
// MASQUE client carrier selection (MasqueALPN)
//
// transport=masque describes the protocol shape (CONNECT +
// .well-known/masque/... URI + the resume/2 data plane); the carrier can be
// chosen explicitly or auto-detected:
//
//   h3 ── quic-go http3.Transport (UDP/QUIC, ALPN "h3")
//   h2 ── x/net http2.Transport (TCP/TLS, ALPN "h2"), with CONNECT carried via
//          RFC 8441 extended CONNECT (the :protocol pseudo-header)
//
// The two carriers read the upgrade token from different places, which is why
// every masque request sets both:
//   - h2 reads the rewritten ":protocol" pseudo-header (masqueExtendedConnectTransport
//     below converts the plain Protocol header into it).
//   - quic-go's h3 client reads **req.Proto** as the :protocol value (CONNECT with a
//     non-empty, non-HTTP/1.1 Proto counts as extended CONNECT) and validates it as a
//     token. It must therefore be the real upgrade token ("connect-tcp" /
//     "connect-udp"); a placeholder like "HTTP/3" is not a token and makes the h3 leg
//     stall until the auto-mode grace expires instead of failing fast.
//
// Why a parameter rather than pure auto: on a UDP-blocked path, the first h3
// dial must burn the whole QUIC handshake timeout before falling back, adding
// 1–2s to the first connection; explicit h2 skips that cost and makes behavior
// reproducible and debuggable. The default is still auto (h3 first + pin-to-h2
// on failure), but operators can pin one carrier.
//
// Prerequisite for the server to accept the h2 carrier: x/net gates extended
// CONNECT on the process-wide GODEBUG=http2xconnect=1 (it must be set at process
// start; //go:debug does not accept this non-stdlib key, and os.Setenv after init
// is too late). The CLI logs a WARN when MASQUE is enabled but the flag is
// absent; without it, the peer advertises no SETTINGS_ENABLE_CONNECT_PROTOCOL
// and this side fails clearly with "extended connect not supported by peer".
//
// Go 1.27 constraint: as of Go 1.27 the http2 source of truth moved into
// net/http, and x/net ships a "wrapping implementation" that delegates
// RoundTrip to a stdlib http.Transport — whose front-door validateHeaders
// rejects the ":protocol" pseudo-header outright (it has no RFC 8441
// exemption), killing every masque-over-h2 dial with
// "net/http: invalid header field name \":protocol\"". The original
// implementation (which does accept :protocol) is selected by the
// //go:build !(go1.27 && !http2legacy) tag on x/net's side, which is gated by
// the MAIN MODULE's language version. This module therefore pins `go 1.26` in
// go.mod (see the comment there). When a consumer's own main module declares
// go >= 1.27, the wrapping implementation is compiled instead and masque-over-h2
// breaks — consumers must keep their go directive at 1.26 or build with
// -tags http2legacy until net/http grows a client-side extended-CONNECT API.
// =========================================

import (
	"context"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// masqueALPN values ("" = auto).
const (
	alpnH2 = "h2"
	alpnH3 = "h3"
	// masqueH3ProbeGrace is the maximum wait for the first h3 dial in auto mode:
	// a timeout means UDP is unavailable, so pin h2. Overridden by RedialBudget if set.
	masqueH3ProbeGrace = 5 * time.Second
)

// masqueExtendedConnectTransport rewrites the regular Protocol header into the
// h2 extended-CONNECT :protocol pseudo-header (the x/net client enters its
// extended state machine on it). The request Clone copies only the header view;
// Body stays the same io.Pipe — this wrapper only runs before the first
// RoundTrip of an attempt and never consumes or replays the body.
type masqueExtendedConnectTransport struct {
	base http.RoundTripper
}

func (t *masqueExtendedConnectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if protocol := req.Header.Get("Protocol"); protocol != "" && req.Header.Get(":protocol") == "" {
		req = req.Clone(req.Context())
		req.Header.Set(":protocol", protocol)
	}
	return t.base.RoundTrip(req)
}

// masqueAutoTransport prefers h3: if the first dial fails within grace, it pins
// h2 (never tries UDP again). The current error is returned as-is: the CONNECT
// body is a streaming pipe that may have been consumed, so replaying would tear
// the frame stream — the next lane rebuild / resume attempt uses the pinned h2 leg.
// grace matters because on a UDP blackhole the QUIC handshake can hang 10s+; without
// a cap, the lane-reconnect loop would spend its whole timeout budget on h3 retries.
type masqueAutoTransport struct {
	h3     http.RoundTripper
	h2     http.RoundTripper
	pinned *atomic.Bool
	grace  time.Duration
}

func (t *masqueAutoTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.pinned.Load() {
		return t.h2.RoundTrip(req)
	}
	// grace only bounds stream *establishment*: once the CONNECT stream is up, its
	// lifetime must stay bound to the caller's ctx (the response body is a
	// bidirectional pipe). So do NOT cancel() when RoundTrip returns — that would
	// immediately kill the just-established stream; instead hand the cancel to Body.Close.
	ctx, cancel := context.WithCancel(req.Context())
	timer := time.AfterFunc(t.grace, cancel)
	resp, err := t.h3.RoundTrip(req.WithContext(ctx))
	if err != nil {
		timer.Stop()
		cancel()
		if req.Context().Err() == nil {
			t.pinned.Store(true) // UDP unreachable → pin h2
		}
		return nil, err
	}
	timer.Stop() // establishment succeeded; cancel is now driven by Body.Close
	resp.Body = &graceCanceller{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

// graceCanceller releases the RoundTrip-derived ctx cancel when the stream ends, avoiding a leak.
type graceCanceller struct {
	io.ReadCloser
	once   sync.Once
	cancel context.CancelFunc
}

func (g *graceCanceller) Close() error {
	err := g.ReadCloser.Close()
	g.once.Do(g.cancel)
	return err
}
