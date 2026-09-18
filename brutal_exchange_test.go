package h2tunnel

// TCP Brutal bandwidth exchange: the routing short-circuit, the server's no-dial
// handler, and the end-to-end round trip through the public API.

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestBrutalSentinelIsMatchedBeforeDefaultSubstitution(t *testing.T) {
	mk := func(target string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/tunnel", nil)
		req.Proto, req.ProtoMajor = "HTTP/2.0", 2
		req.TLS = &tls.ConnectionState{}
		req.Header.Set("X-Tunnel-Proto", resumeFrameTypeResume)
		if target != "" {
			req.Header.Set("X-Target", target)
		}
		return req
	}

	// The serverConfig here deliberately has no TargetDialer, so
	// getRequestDestination takes the getXDst fallback and would substitute a
	// real address for an unrecognized target.
	cfg := serverConfig{}

	tr := classifyTunnelRequest(mk(brutalBwExchangeTarget), cfg, false)
	if tr.kind != kindBrutalExchange {
		t.Fatalf("sentinel classified as %d, want kindBrutalExchange", tr.kind)
	}
	if tr.target != brutalBwExchangeTarget {
		t.Fatalf("sentinel target = %q, want it passed through untouched", tr.target)
	}
	if tr.network != networkTCP {
		t.Fatalf("sentinel network = %q, want tcp", tr.network)
	}
	if tr.transport != Transport(transportH2) {
		t.Fatalf("sentinel transport = %q, want the resume carrier label", tr.transport)
	}

	// A missing target takes the legacy fallback path and must NOT be treated as
	// a bandwidth exchange: only the exact sentinel string qualifies.
	tr = classifyTunnelRequest(mk(""), cfg, false)
	if tr.kind == kindBrutalExchange {
		t.Fatalf("a request without a target must not become a bandwidth exchange: %+v", tr)
	}
	if tr.target != "127.0.0.1:22" {
		t.Fatalf("fallback target = %q, want 127.0.0.1:22", tr.target)
	}

	// Near misses must not qualify either. Surrounding whitespace is trimmed
	// deliberately, so "_BrutalBwExchange " does qualify — matching a header
	// value with a stray space is the friendlier failure mode.
	for _, near := range []string{"brutalBwExchange", "_brutalbwexchange", "_BrutalBwExchange/x", "_BrutalBwExchange2"} {
		tr = classifyTunnelRequest(mk(near), cfg, false)
		if tr.kind == kindBrutalExchange {
			t.Fatalf("near miss %q was classified as a bandwidth exchange", near)
		}
	}
}

// startBrutalExchangeServer runs an h2 server whose target dialer fails loudly
// if it is ever called — the whole point of the sentinel is that the exchange
// never dials — and returns its URL plus a dial counter for that assertion.
func startBrutalExchangeServer(t *testing.T, serverBrutal BrutalTuning) (string, *atomic.Int64) {
	t.Helper()

	dials := &atomic.Int64{}
	dialer := TargetDialer(func(ctx context.Context, req DialRequest) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("h2tunnel: the bandwidth exchange must not dial a target")
	})
	tlsConfig, err := SelfSignedTLSConfig("localhost")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerOptions{
		Path:          "/tunnel",
		Transports:    []Transport{TransportH2},
		Networks:      []Network{NetworkTCP},
		TLSConfig:     tlsConfig,
		Authenticator: tokenAuth(brutalExchangeToken),
		Dialer:        dialer,
		Tuning:        ServerTuning{Brutal: serverBrutal},
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(Listeners{TCP: ln}) }()
	t.Cleanup(func() { _ = server.Close() })
	return "https://" + ln.Addr().String(), dials
}

const brutalExchangeToken = "brutal-exchange-token"

func newBrutalExchangeClient(t *testing.T, endpoint string, tuning ClientTuning) *Client {
	t.Helper()
	credentials, err := NewTokenCredentials(brutalExchangeToken)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ClientOptions{
		Endpoint:    endpoint,
		Path:        "/tunnel",
		TLSConfig:   &tls.Config{InsecureSkipVerify: true},
		Credentials: credentials,
		Tuning:      tuning,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestBrutalBandwidthExchangeEndToEnd(t *testing.T) {
	endpoint, dials := startBrutalExchangeServer(t, BrutalTuning{
		Enabled:   true,
		RateBytes: 200_000_000,
		CwndGain:  20,
		Negotiate: true,
	})
	client := newBrutalExchangeClient(t, endpoint, ClientTuning{
		Brutal: BrutalTuning{
			Enabled:   true,
			RateBytes: 100_000_000,
			CwndGain:  25,
			Negotiate: true,
		},
	})
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatalf("client start: %v", err)
	}

	got, err := client.NegotiateBrutal(ctx)
	if err != nil {
		t.Fatalf("NegotiateBrutal: %v (dials=%d)", err, dials.Load())
	}

	// min(server, client) on both axes.
	if got.RateBytes != 100_000_000 {
		t.Errorf("rate = %d, want min(200M, 100M) = 100000000", got.RateBytes)
	}
	if got.CwndGain != 20 {
		t.Errorf("cwnd gain = %d, want min(20, 25) = 20", got.CwndGain)
	}
	if got.GroupID == 0 || got.GroupID&1 == 0 {
		t.Errorf("group id %d is not a real (non-zero, forced-bit) group", got.GroupID)
	}
	if !got.Enabled || !got.Negotiate {
		t.Errorf("returned tuning = %+v, want Enabled and Negotiate set", got)
	}
	if n := dials.Load(); n != 0 {
		t.Fatalf("the bandwidth exchange dialed a target %d times", n)
	}
}

// The negotiated value feeds the next dial, not the socket carrying the reply,
// so a second exchange must come back at the already-negotiated rate.
func TestBrutalBandwidthExchangeIsMonotone(t *testing.T) {
	endpoint, dials := startBrutalExchangeServer(t, BrutalTuning{
		Enabled:   true,
		RateBytes: 200_000_000,
		CwndGain:  20,
		Negotiate: true,
	})
	client := newBrutalExchangeClient(t, endpoint, ClientTuning{
		Brutal: BrutalTuning{
			Enabled:   true,
			RateBytes: 100_000_000,
			CwndGain:  25,
			Negotiate: true,
		},
	})
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatalf("client start: %v", err)
	}
	first, err := client.NegotiateBrutal(ctx)
	if err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	second, err := client.NegotiateBrutal(ctx)
	if err != nil {
		t.Fatalf("second exchange: %v", err)
	}
	if second.RateBytes > first.RateBytes {
		t.Errorf("rate crept upward: %d -> %d", first.RateBytes, second.RateBytes)
	}
	if first.GroupID != second.GroupID {
		t.Errorf("group id must be stable for one client: %d -> %d", first.GroupID, second.GroupID)
	}
	if n := dials.Load(); n != 0 {
		t.Fatalf("the bandwidth exchange dialed a target %d times", n)
	}
}

func TestNegotiateBrutalRequiresTheFeatureOnTheClient(t *testing.T) {
	endpoint, dials := startBrutalExchangeServer(t, BrutalTuning{
		Enabled: true, RateBytes: 1, CwndGain: 15, Negotiate: true,
	})
	client := newBrutalExchangeClient(t, endpoint, ClientTuning{})
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := client.NegotiateBrutal(ctx); !errors.Is(err, ErrBrutalUnavailable) {
		t.Fatalf("err = %v, want ErrBrutalUnavailable", err)
	}
	if n := dials.Load(); n != 0 {
		t.Fatalf("a disabled client must not touch the server: %d dials", n)
	}
}

// A server with brutal disabled answers the sentinel with 503, so the client
// reports a negotiation failure rather than a silent success.
func TestBrutalBandwidthExchangeIsRejectedWhenTheServerIsDisabled(t *testing.T) {
	endpoint, dials := startBrutalExchangeServer(t, BrutalTuning{})
	client := newBrutalExchangeClient(t, endpoint, ClientTuning{
		Brutal: BrutalTuning{Enabled: true, RateBytes: 1, CwndGain: 15, Negotiate: true},
	})
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatalf("client start: %v", err)
	}
	if _, err := client.NegotiateBrutal(ctx); err == nil {
		t.Fatal("a server without brutal must not complete the exchange")
	}
	if n := dials.Load(); n != 0 {
		t.Fatalf("the rejected exchange dialed a target %d times", n)
	}
}

// The exchange answer must not leak to an unauthenticated request: group ids are
// derived from the presented token, so answering before authentication would let
// an attacker probe the derivation with arbitrary tokens.
func TestBrutalReplyIsNotSentBeforeAuthentication(t *testing.T) {
	endpoint, _ := startBrutalExchangeServer(t, BrutalTuning{
		Enabled: true, RateBytes: 1, CwndGain: 15, Negotiate: true,
	})
	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	exchangeRequest := func(token string) *http.Request {
		req, err := http.NewRequest(http.MethodPost, endpoint+"/tunnel", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Tunnel-Proto", resumeFrameTypeResume)
		req.Header.Set("X-Target", "_BrutalBwExchange")
		req.Header.Set("X-Brutal-Offer", "rate=100,gain=15,nonce=n1")
		req.Header.Set("X-Client-Group", "victim")
		if token != "" {
			req.Header.Set("X-Auth-Token", token)
		}
		return req
	}

	resp, err := httpClient.Do(exchangeRequest(""))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Brutal-Params"); got != "" {
		t.Fatalf("an unauthenticated request learned a group id: %q", got)
	}

	// Same request with the token attached: the server answers now.
	resp, err = httpClient.Do(exchangeRequest(brutalExchangeToken))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated exchange: status = %d, want 200", resp.StatusCode)
	}
	reply := resp.Header.Get("X-Brutal-Params")
	if reply == "" {
		t.Fatal("an authenticated exchange got no reply")
	}
	if _, echoed := parseBrutalReply(reply); echoed != "n1" {
		t.Fatalf("the nonce was not echoed: %q", reply)
	}
	if d, _ := parseBrutalReply(reply); d.groupID == 0 {
		t.Fatalf("the reply carries no group id: %q", reply)
	}
}

// The server applies the per-client group to the accepted socket, which needs the
// socket handle to survive from ConnContext through the whole production handler
// chain into routeTunnelRequest. This pins that down end to end: if the value
// stops reaching the tunnel path, the server silently reverts to never
// configuring its socket and only this test notices.
func TestAcceptedSocketReachesTheTunnelPath(t *testing.T) {
	var caught atomic.Pointer[net.Conn]
	tlsConfig, err := SelfSignedTLSConfig("localhost")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerOptions{
		Path:       "/tunnel",
		Transports: []Transport{TransportH2},
		Networks:   []Network{NetworkTCP},
		TLSConfig:  tlsConfig,
		Authenticator: func(_ context.Context, r *http.Request) (Principal, error) {
			if c := brutalConnFromRequest(r); c != nil {
				caught.Store(&c)
			}
			return Principal{ID: "authenticated"}, nil
		},
		Dialer: TargetDialer(func(context.Context, DialRequest) (net.Conn, error) {
			return nil, errors.New("h2tunnel: no upstream in this test")
		}),
		Tuning: ServerTuning{Brutal: BrutalTuning{Enabled: true, RateBytes: 1, CwndGain: 15, Negotiate: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(Listeners{TCP: ln}) }()
	t.Cleanup(func() { _ = server.Close() })

	client := newBrutalExchangeClient(t, "https://"+ln.Addr().String(), ClientTuning{
		Brutal: BrutalTuning{Enabled: true, RateBytes: 1, CwndGain: 15, Negotiate: true},
	})
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatalf("client start: %v", err)
	}
	if _, err := client.NegotiateBrutal(ctx); err != nil {
		t.Fatalf("NegotiateBrutal: %v", err)
	}
	if caught.Load() == nil {
		t.Fatal("the accepted socket never reached the tunnel handler, so the per-client group is not applied")
	}
}
