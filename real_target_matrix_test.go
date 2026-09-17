package h2tunnel_test

// =========================================
// Real-target protocol matrix:
//   - TCP targets use a real HTTP server (net/http), running 10 HTTP
//     request/response round-trips on the same tunnel connection (keep-alive reuse),
//     and assert the target side accepted only one connection;
//   - UDP targets use a real DNS server (standard DNS wire format), sending 10
//     independent A queries on the same PacketConn and verifying ID/RCODE/answer records per packet;
//   - every transport (h2/h2c/grpc/h3/wt/masque) covers both TCP and UDP.
//
// Compared with the echo matrix (connmanager_test.go), real-semantic targets expose
// "sticky/half packets, reuse and reconnection under real application protocols".
// =========================================

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/NNdroid/h2tunnel"
)

const (
	protocolMatrixToken = "real-target-token"
	protocolIterations  = 10 // round-trips on the same connection
)

// countedListener counts the connections accepted on the target side (verifies tunnel keep-alive reuse).
type countedListener struct {
	net.Listener
	conns atomic.Int32
}

func (l *countedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.conns.Add(1)
	}
	return c, err
}

// protocolEnv is one shared test environment: real HTTP target + real DNS target +
// TCP/UDP echo targets for throughput benchmarks + two tunnel servers, TLS / h2c
// (h2c cannot share a listener with TLS, so they must be separate).
type protocolEnv struct {
	httpListener *countedListener
	dnsConn      net.PacketConn

	tlsURL string // https://127.0.0.1:port
	h2cURL string // http://127.0.0.1:port
}

// isBindForbidden reports whether a Windows excluded-port-range bind refusal occurred
// (WSAEACCES 10013): Hyper-V/WSL reserve ranges inside the dynamic port space, and a
// udp :0 random bind that hits one reports
// "bind: An attempt was made to access a socket in a way forbidden by
// its access permissions". Linux errno tops out at 133, so it never collides with 10013.
func isBindForbidden(err error) bool {
	var errno syscall.Errno
	return errors.As(err, &errno) && errno == 10013
}

// bindUDPRetry binds a UDP port, retrying on another port when it lands in a Windows excluded range.
func bindUDPRetry(t testing.TB, addr string) net.PacketConn {
	t.Helper()
	for attempt := 1; ; attempt++ {
		conn, err := net.ListenPacket("udp", addr)
		if err == nil {
			return conn
		}
		if !isBindForbidden(err) || attempt >= 10 {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func newProtocolEnv(t testing.TB) *protocolEnv {
	return newProtocolEnvWithPadding(t, h2tunnel.PaddingTuning{})
}

func newProtocolEnvWithPadding(t testing.TB, padding h2tunnel.PaddingTuning) *protocolEnv {
	t.Helper()
	env := &protocolEnv{}

	// —— real HTTP target: /iter-N returns hello-iter-N ——
	rawHTTP, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	env.httpListener = &countedListener{Listener: rawHTTP}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %s", strings.TrimPrefix(r.URL.Path, "/"))
	})
	httpTarget := &http.Server{Handler: mux}
	go func() { _ = httpTarget.Serve(env.httpListener) }()
	t.Cleanup(func() { _ = httpTarget.Close() })

	// —— real DNS target (UDP, a minimal A-record responder in standard wire format) ——
	env.dnsConn = bindUDPRetry(t, "127.0.0.1:0")
	go serveFakeDNS(env.dnsConn)
	t.Cleanup(func() { _ = env.dnsConn.Close() })

	// —— echo targets for throughput benchmarks (TCP + UDP on the same address) ——
	benchEcho, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go serveEcho(benchEcho)
	t.Cleanup(func() { _ = benchEcho.Close() })
	udpEcho := bindUDPRetry(t, "127.0.0.1:0")
	go serveUDPEcho(udpEcho)
	t.Cleanup(func() { _ = udpEcho.Close() })

	// —— tunnel servers ——
	authenticator, err := h2tunnel.NewTokenAuthenticator(protocolMatrixToken)
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := h2tunnel.NewStaticServiceDialer(map[string]h2tunnel.Service{
		"http":      {Network: h2tunnel.NetworkTCP, Address: rawHTTP.Addr().String()},
		"dns":       {Network: h2tunnel.NetworkUDP, Address: env.dnsConn.LocalAddr().String()},
		"bench-tcp": {Network: h2tunnel.NetworkTCP, Address: benchEcho.Addr().String()},
		"bench-udp": {Network: h2tunnel.NetworkUDP, Address: udpEcho.LocalAddr().String()},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// TLS side: carries h2/h3/wt/masque/grpc.
	tlsConfig, err := h2tunnel.SelfSignedTLSConfig("localhost")
	if err != nil {
		t.Fatal(err)
	}
	tlsServer, err := h2tunnel.NewServer(h2tunnel.ServerOptions{
		Transports:    []h2tunnel.Transport{h2tunnel.TransportH2, h2tunnel.TransportH3, h2tunnel.TransportWebTransport, h2tunnel.TransportMASQUE, h2tunnel.TransportGRPC},
		Networks:      []h2tunnel.Network{h2tunnel.NetworkTCP, h2tunnel.NetworkUDP},
		TLSConfig:     tlsConfig,
		Authenticator: authenticator,
		Dialer:        dialer,
		Tuning:        h2tunnel.ServerTuning{Padding: padding},
	})
	if err != nil {
		t.Fatal(err)
	}
	// TCP+UDP bound as a pair on the same port: if the UDP side hits an excluded range, redo the whole pair (the TCP port must match).
	var tlsTCP net.Listener
	var tlsQUIC net.PacketConn
	for attempt := 1; ; attempt++ {
		tlsTCP, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		tlsQUIC, err = net.ListenPacket("udp", tlsTCP.Addr().String())
		if err == nil {
			break
		}
		if !isBindForbidden(err) || attempt >= 10 {
			t.Fatal(err)
		}
		_ = tlsTCP.Close()
		time.Sleep(50 * time.Millisecond)
	}
	tlsEnv := make(chan error, 1)
	go func() { tlsEnv <- tlsServer.Serve(h2tunnel.Listeners{TCP: tlsTCP, QUIC: tlsQUIC}) }()
	t.Cleanup(func() {
		_ = tlsServer.Close()
		if err := <-tlsEnv; err != nil {
			t.Errorf("TLS Serve returned %v", err)
		}
	})
	env.tlsURL = "https://" + tlsTCP.Addr().String()

	// h2c side: plaintext; h2c cannot share a listener with TLS.
	h2cServer, err := h2tunnel.NewServer(h2tunnel.ServerOptions{
		Transports:    []h2tunnel.Transport{h2tunnel.TransportH2C},
		Networks:      []h2tunnel.Network{h2tunnel.NetworkTCP, h2tunnel.NetworkUDP},
		Authenticator: authenticator,
		Dialer:        dialer,
		Tuning:        h2tunnel.ServerTuning{Padding: padding},
	})
	if err != nil {
		t.Fatal(err)
	}
	h2cListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h2cEnv := make(chan error, 1)
	go func() { h2cEnv <- h2cServer.Serve(h2tunnel.Listeners{TCP: h2cListener}) }()
	t.Cleanup(func() {
		_ = h2cServer.Close()
		if err := <-h2cEnv; err != nil {
			t.Errorf("h2c Serve returned %v", err)
		}
	})
	env.h2cURL = "http://" + h2cListener.Addr().String()

	return env
}

// serveFakeDNS is a minimal DNS responder: it echoes the question section, sets QR/RA,
// and appends one A record (127.0.0.1) pointing at the question name. It answers A for
// any QTYPE — the test client only sends A queries, which is sufficient and deterministic.
func serveFakeDNS(pc net.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		resp := buildFakeDNSResponse(buf[:n])
		if resp == nil {
			continue
		}
		if _, err := pc.WriteTo(resp, addr); err != nil {
			return
		}
	}
}

// buildFakeDNSResponse parses the query message (header + question section) and assembles a standard response.
func buildFakeDNSResponse(q []byte) []byte {
	if len(q) < 12+1+4 {
		return nil
	}
	i := 12
	for i < len(q) && q[i] != 0 {
		i += int(q[i]) + 1
	}
	if i >= len(q) {
		return nil
	}
	i++           // root label 0x00
	qEnd := i + 4 // QTYPE + QCLASS
	if qEnd > len(q) {
		return nil
	}
	resp := make([]byte, qEnd+16)
	copy(resp, q[:qEnd])
	resp[2] = q[2] | 0x80 // QR=1
	resp[3] = q[3] | 0x80 // RA=1
	binary.BigEndian.PutUint16(resp[6:8], 1)
	ans := resp[qEnd:]
	binary.BigEndian.PutUint16(ans[0:2], 0xC00C) // name compression pointer → question section
	binary.BigEndian.PutUint16(ans[2:4], 1)      // TYPE A
	binary.BigEndian.PutUint16(ans[4:6], 1)      // CLASS IN
	binary.BigEndian.PutUint32(ans[6:10], 300)   // TTL
	binary.BigEndian.PutUint16(ans[10:12], 4)    // RDLENGTH
	ans[12], ans[13], ans[14], ans[15] = 127, 0, 0, 1
	return resp
}

// dnsQuery builds an A query (RD=1).
func dnsQuery(id uint16, name string) []byte {
	var out []byte
	out = binary.BigEndian.AppendUint16(out, id)
	out = binary.BigEndian.AppendUint16(out, 0x0100) // RD
	out = binary.BigEndian.AppendUint16(out, 1)      // QDCOUNT
	out = binary.BigEndian.AppendUint16(out, 0)
	out = binary.BigEndian.AppendUint16(out, 0)
	out = binary.BigEndian.AppendUint16(out, 0)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	out = binary.BigEndian.AppendUint16(out, 1) // QTYPE A
	out = binary.BigEndian.AppendUint16(out, 1) // QCLASS IN
	return out
}

// newProtocolClient creates and starts a client per transport type.
func newProtocolClient(t testing.TB, env *protocolEnv, transport h2tunnel.Transport) *h2tunnel.Client {
	return newProtocolClientWithPadding(t, env, transport, h2tunnel.PaddingTuning{})
}

func newProtocolClientWithPadding(t testing.TB, env *protocolEnv, transport h2tunnel.Transport, padding h2tunnel.PaddingTuning) *h2tunnel.Client {
	return newProtocolClientWithPaddingALPN(t, env, transport, padding, "")
}

// newProtocolClientWithPaddingALPN is like newProtocolClientWithPadding but lets
// callers pin the MASQUE carrier (""=auto, "h2", "h3") so benchmarks can measure
// each MASQUE leg (over-h2 extended CONNECT vs over-h3 QUIC) independently
// instead of only whatever the auto selector lands on for the environment.
func newProtocolClientWithPaddingALPN(t testing.TB, env *protocolEnv, transport h2tunnel.Transport, padding h2tunnel.PaddingTuning, masqueALPN string) *h2tunnel.Client {
	t.Helper()
	var credentials h2tunnel.CredentialProvider
	credentials, err := h2tunnel.NewTokenCredentials(protocolMatrixToken)
	if err != nil {
		t.Fatal(err)
	}
	var tlsConfig *tls.Config
	endpoint := env.tlsURL
	if transport == h2tunnel.TransportH2C {
		endpoint = env.h2cURL
	} else {
		tlsConfig = &tls.Config{InsecureSkipVerify: true} // self-signed dev certificate
	}
	client, err := h2tunnel.NewClient(h2tunnel.ClientOptions{
		Endpoint:    endpoint,
		Transport:   transport,
		TLSConfig:   tlsConfig,
		Credentials: credentials,
		Tuning:      h2tunnel.ClientTuning{Padding: padding, MasqueALPN: masqueALPN},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := client.Start(ctx); err != nil {
		// A pinned MASQUE carrier (h2/h3) may be unavailable in a given environment
		// (e.g. extended CONNECT unsupported despite GODEBUG=http2xconnect=1, or
		// UDP blocked for the h3 leg). Skip rather than fail so the rest of the
		// matrix still runs — this mirrors the guarded-skip pattern in
		// masque_h2_test.go (extendedConnectEnabled).
		if masqueALPN != "" {
			t.Skipf("masque carrier %q unavailable in this environment: %v", masqueALPN, err)
		}
		t.Fatalf("start %s client: %v", transport, err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// TestProtocolRealTargetMatrix runs every transport × real target (HTTP / DNS),
// with 10 round-trips on the same connection.
func TestProtocolRealTargetMatrix(t *testing.T) {
	env := newProtocolEnv(t)

	tcpCases := []h2tunnel.Transport{
		h2tunnel.TransportH2, h2tunnel.TransportH2C, h2tunnel.TransportGRPC,
		h2tunnel.TransportH3, h2tunnel.TransportWebTransport, h2tunnel.TransportMASQUE,
	}
	udpCases := []h2tunnel.Transport{
		h2tunnel.TransportH2, h2tunnel.TransportH2C, h2tunnel.TransportGRPC,
		h2tunnel.TransportH3, h2tunnel.TransportMASQUE, h2tunnel.TransportWebTransport,
	}

	for _, transport := range tcpCases {
		transport := transport
		t.Run(string(transport)+"_TCP_HTTP_10x", func(t *testing.T) {
			client := newProtocolClient(t, env, transport)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			conn, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "http")
			if err != nil {
				t.Fatalf("dial http target: %v", err)
			}
			defer conn.Close()

			// Connections the target had already accepted before this subtest started (the counter is shared across subtests).
			connsBefore := env.httpListener.conns.Load()

			// All requests reuse the same tunnel connection (keep-alive).
			httpClient := &http.Client{
				Transport: &http.Transport{
					DialContext: func(context.Context, string, string) (net.Conn, error) {
						return conn, nil
					},
				},
			}
			for i := 1; i <= protocolIterations; i++ {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet,
					fmt.Sprintf("http://target/iter-%d", i), nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := httpClient.Do(req)
				if err != nil {
					t.Fatalf("request %d: %v", i, err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					t.Fatalf("read body %d: %v", i, err)
				}
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("request %d: status %d", i, resp.StatusCode)
				}
				if want := fmt.Sprintf("hello iter-%d", i); string(body) != want {
					t.Fatalf("request %d: body = %q, want %q", i, body, want)
				}
			}
			// The 10 HTTP round-trips must all reuse the target connection established at dial time:
			// zero new accepts on the target side (it already exists once DialContext returns).
			if got := env.httpListener.conns.Load(); got != connsBefore {
				t.Fatalf("http target accepted %d extra connections, want 0 (all 10 requests must reuse the tunnel's single target connection)", got-connsBefore)
			}
		})
	}

	for _, transport := range udpCases {
		transport := transport
		t.Run(string(transport)+"_UDP_DNS_10x", func(t *testing.T) {
			client := newProtocolClient(t, env, transport)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			packetConn, err := client.DialPacketContext(ctx, h2tunnel.NetworkUDP, "dns")
			if err != nil {
				t.Fatalf("dial dns target: %v", err)
			}
			defer packetConn.Close()

			expectedIP := []byte{127, 0, 0, 1}
			for i := 1; i <= protocolIterations; i++ {
				name := fmt.Sprintf("iter-%d.h2tunnel.test", i)
				query := dnsQuery(uint16(0x4000+i), name)
				_ = packetConn.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err := packetConn.Write(query); err != nil {
					t.Fatalf("query %d write: %v", i, err)
				}
				resp := make([]byte, 512)
				n, err := packetConn.Read(resp)
				if err != nil {
					t.Fatalf("query %d read: %v", i, err)
				}
				if n < len(query)+16 {
					t.Fatalf("query %d: response too short (%d bytes)", i, n)
				}
				if gotID := binary.BigEndian.Uint16(resp[0:2]); gotID != uint16(0x4000+i) {
					t.Fatalf("query %d: response ID = %d", i, gotID)
				}
				if rcode := resp[3] & 0x0F; rcode != 0 {
					t.Fatalf("query %d: rcode = %d", i, rcode)
				}
				if ancount := binary.BigEndian.Uint16(resp[6:8]); ancount != 1 {
					t.Fatalf("query %d: ancount = %d", i, ancount)
				}
				// The answer RDATA follows right after the echoed question section: +12 (name pointer/type/class/TTL/RDLENGTH), the first 4 bytes are the A record.
				rdata := resp[len(query)+12 : len(query)+16]
				if string(rdata) != string(expectedIP) {
					t.Fatalf("query %d: answer = %v, want 127.0.0.1", i, rdata)
				}
			}
		})
	}
}

// TestMASQUEPathDerived verifies the MASQUE path is nested under the tunnel path:
// path=/abc/stone → CONNECT /abc/stone/.well-known/masque/tcp/...;
// a client on the default path (/tunnel) cannot match the route.
func TestMASQUEPathDerived(t *testing.T) {
	env := newProtocolEnv(t)
	authenticator, err := h2tunnel.NewTokenAuthenticator(protocolMatrixToken)
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := h2tunnel.NewStaticServiceDialer(map[string]h2tunnel.Service{
		"http": {Network: h2tunnel.NetworkTCP, Address: env.httpListener.Addr().String()},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig, err := h2tunnel.SelfSignedTLSConfig("localhost")
	if err != nil {
		t.Fatal(err)
	}
	server, err := h2tunnel.NewServer(h2tunnel.ServerOptions{
		Transports:    []h2tunnel.Transport{h2tunnel.TransportMASQUE},
		Networks:      []h2tunnel.Network{h2tunnel.NetworkTCP},
		TLSConfig:     tlsConfig,
		Authenticator: authenticator,
		Dialer:        dialer,
		Path:          "/abc/stone",
	})
	if err != nil {
		t.Fatal(err)
	}
	// a masque-only server opens no TCP listener (requiredListeners returns QUIC only),
	// and there is no need to pre-create a TCP listener to hold the port — use the QUIC listen address directly.
	quicConn := bindUDPRetry(t, "127.0.0.1:0")
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(h2tunnel.Listeners{QUIC: quicConn}) }()
	defer func() {
		_ = server.Close()
		if err := <-serveErr; err != nil {
			t.Errorf("Serve returned %v", err)
		}
	}()

	newClient := func(path string) *h2tunnel.Client {
		t.Helper()
		credentials, err := h2tunnel.NewTokenCredentials(protocolMatrixToken)
		if err != nil {
			t.Fatal(err)
		}
		client, err := h2tunnel.NewClient(h2tunnel.ClientOptions{
			Endpoint:    "https://" + quicConn.LocalAddr().String(),
			Transport:   h2tunnel.TransportMASQUE,
			TLSConfig:   &tls.Config{InsecureSkipVerify: true},
			Credentials: credentials,
			Path:        path,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		return client
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Custom path: the masque CONNECT hits /abc/stone/.well-known/masque/tcp/....
	client := newClient("/abc/stone")
	conn, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "http")
	if err != nil {
		t.Fatalf("dial with custom path: %v", err)
	}
	defer conn.Close()
	resp, err := (&http.Client{
		Transport: &http.Transport{
			DialContext: func(context.Context, string, string) (net.Conn, error) { return conn, nil },
		},
	}).Get("http://target/masque-prefix")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if want := "hello masque-prefix"; string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}

	// The default path (/tunnel) cannot match the /abc/stone/... route; the server returns 404.
	plain := newClient("")
	if _, err := plain.DialContext(ctx, h2tunnel.NetworkTCP, "http"); err == nil {
		t.Fatal("dial without prefix should fail (server routes only /ccc/...)")
	}
}
