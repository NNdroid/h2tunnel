package h2tunnel

// Bounds and information-disclosure checks for the security review round:
// every untrusted input that becomes a key, a buffer size or a framing decision
// must be bounded server-side, and every rejection must stop short of telling
// the peer what it does not know.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// anyTargetDialer is the permissive dialer the policy tests need: the point of
// those tests is that a rejected request never reaches the target at all.
func anyTargetDialer() TargetDialer {
	return TargetDialer(func(ctx context.Context, req DialRequest) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, string(req.Network), req.Target)
	})
}

func TestValidateSessionIDBounds(t *testing.T) {
	for _, test := range []struct {
		id  string
		err error
	}{
		{id: "", err: errSessionIDRequired},
		{id: "   ", err: errSessionIDRequired},
		{id: strings.Repeat("s", sessionIDMaxBytes-1)},
		{id: strings.Repeat("s", sessionIDMaxBytes)},
		{id: strings.Repeat("s", sessionIDMaxBytes+1), err: errSessionIDTooLong},
		{id: strings.Repeat("s", 1<<20), err: errSessionIDTooLong},
	} {
		if err := validateSessionID(test.id); !errors.Is(err, test.err) {
			t.Errorf("validateSessionID(%d bytes) error = %v, want %v", len(test.id), err, test.err)
		}
	}
}

// The gate has to hold where the key is actually created, not only at the HTTP
// edge: a library caller that skips the handler would otherwise get an
// unbounded map key.
func TestSessionTableRejectsAnOversizedIDBeforeDialing(t *testing.T) {
	table := &sessionTable{sessions: make(map[string]*tunnelSession)}
	dialed := false
	_, _, err := table.getOrCreate(strings.Repeat("s", sessionIDMaxBytes+1), func() (net.Conn, error) {
		dialed = true
		return nil, nil
	}, 1, false, nil, nil)
	if !errors.Is(err, errSessionIDTooLong) {
		t.Fatalf("error = %v, want errSessionIDTooLong", err)
	}
	if dialed {
		t.Fatal("an oversized session id dialed a target")
	}
	if len(table.sessions) != 0 {
		t.Fatalf("sessions = %d, want 0", len(table.sessions))
	}
}

func TestGunzipDataRejectsACompressionBomb(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(bytes.Repeat([]byte{0}, shareGzipMaxBytes+4096)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := gunzipData(buf.Bytes()); err == nil {
		t.Fatalf("a %d-byte decompression was accepted, the limit is %d", shareGzipMaxBytes+4096, shareGzipMaxBytes)
	}

	// A normal profile still round-trips.
	var small bytes.Buffer
	sg := gzip.NewWriter(&small)
	if _, err := sg.Write([]byte(`{"name":"node"}`)); err != nil {
		t.Fatal(err)
	}
	if err := sg.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := gunzipData(small.Bytes())
	if err != nil || string(out) != `{"name":"node"}` {
		t.Fatalf("small payload = %q, %v", out, err)
	}
}

// Channel binding is the point of TLSUnique: dropping it makes every
// VerifyConnection callback that checks tls-unique see nil and accept.
func TestAdaptVerifyConnectionCarriesChannelBinding(t *testing.T) {
	var seen tls.ConnectionState
	adapted := adaptVerifyConnection(func(cs tls.ConnectionState) error {
		seen = cs
		return nil
	})
	if adapted == nil {
		t.Fatal("adaptVerifyConnection returned nil for a non-nil callback")
	}
	adapted(utls.ConnectionState{
		Version:            tls.VersionTLS12,
		ServerName:         "server.example",
		NegotiatedProtocol: "h2",
		TLSUnique:          []byte{0xde, 0xad, 0xbe, 0xef},
		ECHAccepted:        true,
	})
	if !bytes.Equal(seen.TLSUnique, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("TLSUnique = %x, want the utls value copied through", seen.TLSUnique)
	}
	if !seen.ECHAccepted {
		t.Fatal("ECHAccepted was dropped")
	}
	if seen.ServerName != "server.example" || seen.NegotiatedProtocol != "h2" || seen.Version != tls.VersionTLS12 {
		t.Fatalf("the rest of the state was not carried: %+v", seen)
	}

	if got := adaptVerifyConnection(nil); got != nil {
		t.Fatal("adaptVerifyConnection(nil) returned a callback, want nil")
	}
}

// A CONNECT-TCP stream is byte-oriented. The client gets to send X-Network and
// X-Target, and the session table decides datagram framing from X-Network, so a
// peer could otherwise create a UDP-framed session over a TCP dial and lose
// packet boundaries on both sides. The handler must pin both to the
// classification.
func TestMasqueTCPDoesNotTakeTheNetworkFromTheClient(t *testing.T) {
	serverSide, peerSide := net.Pipe()
	defer func() {
		_ = peerSide.Close()
		_ = serverSide.Close()
	}()

	table := &sessionTable{sessions: make(map[string]*tunnelSession), idleTimeout: sessionIdleTimeout}
	cfg := serverConfig{
		TargetDialer: TargetDialer(func(context.Context, DialRequest) (net.Conn, error) {
			return serverSide, nil
		}),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	req := httptest.NewRequest(http.MethodConnect, ln.Addr().String()+"/tunnel/tcp/127.0.0.1:1", nil)
	req.Header.Set("Protocol", protocolConnectTCP)
	req.Header.Set("X-Network", networkUDP) // the client's lie
	req.Header.Set("X-Target", "127.0.0.1:1")
	req.Header.Set("X-Tunnel-Proto", resumeFrameTypeResume)
	req.Header.Set("X-Resume-Version", "2")
	req.Header.Set("X-Resume-Params", "window_kb=1")
	req.Header.Set("X-Session-ID", "masque-tcp-1")

	tr := classifyTunnelRequest(req, cfg, false)
	if tr.kind != kindMasqueTCP || tr.network != networkTCP {
		t.Fatalf("classification = kind=%d network=%q, want kindMasqueTCP/tcp", tr.kind, tr.network)
	}

	var rw httptest.ResponseRecorder
	handleMasqueTCPServer(&rw, req, "log-id", tr, cfg, table)
	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", rw.Code, rw.Body.String())
	}

	if got := len(table.sessions); got != 1 {
		t.Fatalf("sessions = %d, want 1", got)
	}
	sess := table.sessions["masque-tcp-1"]
	if sess == nil {
		t.Fatal("the classified session was not created")
	}
	if sess.datagram {
		t.Fatal("a client X-Network header created a datagram-framed MASQUE-TCP session")
	}
	if sess.binding.network != networkTCP {
		t.Fatalf("session network = %q, want %q", sess.binding.network, networkTCP)
	}
	if sess.binding.target != tr.target {
		t.Fatalf("session target = %q, want the classified %q", sess.binding.target, tr.target)
	}
	if got := rw.Header().Get("X-Resume-Params"); got == "" {
		t.Fatal("the resume handshake did not run, so the test is not exercising the data plane")
	}
}

// The detailed policy error names the configured allow-list, which is an
// enumeration oracle. The detail belongs in the server log; the peer gets a
// generic 403.
func TestTransportPolicyRejectionDoesNotEchoTheAllowList(t *testing.T) {
	// Detail is retained for the log and the policy check itself.
	req := httptest.NewRequest(http.MethodPost, "/tunnel", nil)
	req.Proto, req.ProtoMajor = "HTTP/2.0", 2
	req.TLS = &tls.ConnectionState{}
	req.Header.Set("Content-Type", "application/grpc")
	if err := checkStrictTransportPolicy(req, compileRoutingPolicy(transportH2, networkAll), transportH2, Transport(transportGRPC)); err == nil || !strings.Contains(err.Error(), "allowed=") {
		t.Fatalf("internal policy error lost its detail: %v", err)
	}

	tlsConfig, err := SelfSignedTLSConfig("localhost")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerOptions{
		Path:          "/tunnel",
		Transports:    []Transport{TransportH2},
		Networks:      []Network{NetworkTCP},
		TLSConfig:     tlsConfig,
		Authenticator: tokenAuth("policy-token"),
		Dialer:        anyTargetDialer(),
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

	// http2.Transport always hands DialTLSContext a non-nil ALPN-h2 config, so
	// the dialer does the TLS handshake itself.
	transport := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialTLSContext: func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			tconn := tls.Client(conn, cfg)
			if err := tconn.HandshakeContext(ctx); err != nil {
				_ = tconn.Close()
				return nil, err
			}
			return tconn, nil
		},
	}
	client := &http.Client{Transport: transport}
	t.Cleanup(transport.CloseIdleConnections)

	request, err := http.NewRequest(http.MethodPost, "https://"+ln.Addr().String()+"/tunnel", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/grpc")
	request.Header.Set("X-Tunnel-Proto", resumeFrameTypeResume)
	request.Header.Set("X-Session-ID", "policy-1")
	request.Header.Set("X-Target", "127.0.0.1:1")
	request.Header.Set("X-Auth-Token", "policy-token")
	resp, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, body = %q", resp.StatusCode, respBody)
	}
	for _, leaked := range []string{"allowed=", transportH2, "Content-Type"} {
		if strings.Contains(string(respBody), leaked) {
			t.Fatalf("the 403 body leaks %q to the peer: %q", leaked, respBody)
		}
	}
}

// A tunnel whose peer went away first must leave the active set on its own, or
// Shutdown's activeWG.Wait() hangs until its caller gives up. finishWith only
// records the error and signals Done(); the removal is the separate step.
func TestNaturallyDeadTunnelIsRemovedFromTheActiveSet(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = target.Close() }()
	// The target half-closes only after it has seen the client's bytes. That
	// ordering matters: downlinkPump sends the END frame only to a stream that
	// is already attached, so closing before the handshake completes would leave
	// the client waiting on a stream that never ends. It is also the real shape
	// of "the peer went away after the tunnel was in use". A full Close would
	// reset the client's read and send it into the redial loop instead, which
	// intentionally keeps the tunnel registered.
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			tcp, ok := conn.(*net.TCPConn)
			if !ok {
				t.Errorf("target conn is %T, want *net.TCPConn", conn)
				return
			}
			_ = tcp.SetReadDeadline(time.Now().Add(10 * time.Second))
			if _, err := tcp.Read(make([]byte, 16)); err != nil {
				return
			}
			_ = tcp.CloseWrite()
		}
	}()

	tlsConfig, err := SelfSignedTLSConfig("localhost")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerOptions{
		Path:          "/tunnel",
		Transports:    []Transport{TransportH2},
		Networks:      []Network{NetworkTCP},
		TLSConfig:     tlsConfig,
		Authenticator: tokenAuth("dead-tunnel-token"),
		Dialer:        anyTargetDialer(),
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

	creds, err := NewTokenCredentials("dead-tunnel-token")
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ClientOptions{
		Endpoint:    "https://" + ln.Addr().String(),
		Path:        "/tunnel",
		TLSConfig:   &tls.Config{InsecureSkipVerify: true},
		Credentials: creds,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	conn, err := client.DialContext(context.Background(), "tcp", target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	// Put a byte through first so the target's half-close happens after the
	// stream is attached (see the target handler above).
	if _, err := conn.Write([]byte("probe")); err != nil {
		t.Fatalf("Write error = %v", err)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("Read error = %v, want io.EOF (the target closed first)", err)
	}
	managed, ok := conn.(*managedConn)
	if !ok {
		t.Fatal("DialContext did not return a managed conn")
	}
	select {
	case <-managed.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the peer ended the tunnel but Done() never closed")
	}
	// A peer-driven normal end is a clean end, not a failure, so the terminal
	// error is nil. Done() closing is the death signal.
	if err := managed.Err(); err != nil {
		t.Fatalf("a peer-driven normal end reported a terminal error: %v", err)
	}

	// The application deliberately never closes the conn: that is the shape of
	// the leak.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown after a naturally dead tunnel: %v", err)
	}
}
