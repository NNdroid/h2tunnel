package h2tunnel_test

// =========================================
// Weak-network benchmarks: one-way delay, packet loss, jitter, reordering and a
// byte-rate cap applied to the tunnel leg between the client and the server.
//
// The link is simulated in userspace -- a two-hop proxy with a packet pipeline
// in the middle -- rather than with a kernel qdisc, on purpose. A kernel
// `tc netem` cannot inject loss into a TCP leg at all: the kernel retransmitter
// hides packet loss from a byte stream, so a qdisc measures only the cost of
// retransmission, not how h2tunnel behaves under loss. Userspace injection
// reaches the QUIC/UDP legs at datagram granularity and stays honest about the
// TCP legs, where the visible effect is added latency rather than drops. The
// kernel view is kept in CI by the weaknet-kernel job.
//
// Reordering is injectable only on the datagram legs. A byte-stream link sits
// between two net.Conn endpoints, and a reordered write into a TCP connection
// corrupts the stream -- the reordering a qdisc would do is undone by TCP's
// reassembly, which lives below this layer. So reorder is a UDP-only knob
// here, and the reorder profile runs only on the QUIC legs.
//
// Two properties keep these profiles CI-safe:
//
//   - Correctness is asserted, throughput is only reported. Every profile's
//     assertion is "the echoed bytes came back intact", so a slow profile
//     cannot go red; it goes red only if bytes arrive corrupted, reordered or
//     duplicated. Absolute numbers are judged from local multi-round runs, the
//     same as the other benchmarks in this package.
//
//   - They are excluded from `-bench .`. Every profile is gated on
//     H2TUNNEL_WEAKNET_BENCH so the profile and 32-bit jobs -- both of which
//     run `-bench .` -- never pick them up: lossy QUIC under qemu-user takes
//     minutes per subtest.
//
// TestWeakNetDelayIsObserved is deliberately NOT gated: it is the proof that
// the simulator injects delay at all, and a silently no-op simulator would
// otherwise let every benchmark below report clean-loopback numbers and still
// look green.
//
// Pipe goroutines block on a channel once their subtest is done and are not
// joined; each one is small and the count is bounded by the number of
// subtests, so the leak is inert for the lifetime of the test binary.
// =========================================

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/NNdroid/h2tunnel"
)

// weakNetBenchEnv opts a `go test -bench` run into the weak-network profiles.
const weakNetBenchEnv = "H2TUNNEL_WEAKNET_BENCH"

// weakNetBenchmarkSeconds is the wall-clock stretch each benchmark measures.
const weakNetBenchmarkSeconds = 2

// weakNetDialTimeout caps the time a transport may take to establish through the
// simulated link. It exists to bound a wedged leg, not to time a healthy one.
const weakNetDialTimeout = 20 * time.Second

// weakNetRoundCushion is the headroom after the measured stretch.
const weakNetRoundCushion = 30 * time.Second

// weakNetToken authenticates the weak-network tunnel pairs.
const weakNetToken = "weaknet-token"

// weakProfile is one simulated link. loss is the per-packet drop probability
// for one direction, jitter adds on top of the base one-way delay, and rateBps
// caps the byte rate (0 = uncapped).
type weakProfile struct {
	name    string
	rtt     time.Duration // the round-trip the link should present
	loss    float64
	jitter  time.Duration
	reorder int
	rateBps int64
}

// weakNetProfiles is the matrix. Loss and reorder are observable only on the
// QUIC legs, so the TCP legs run the clean and capped profiles. The cap sits
// below the RTT-limited rate at its delay, otherwise the cap would never bind
// and the profile would report the same number as Clean.
var weakNetProfiles = []weakProfile{
	{name: "Clean_40ms", rtt: 40 * time.Millisecond},
	{name: "Capped32KiBps_10ms", rtt: 10 * time.Millisecond, rateBps: 32 * 1024},
	{name: "Loss5_80ms", rtt: 80 * time.Millisecond, loss: 0.05},
	{name: "Loss10_160ms_Jitter25ms", rtt: 160 * time.Millisecond, loss: 0.10, jitter: 25 * time.Millisecond},
	{name: "Loss5_240ms_Reorder8", rtt: 240 * time.Millisecond, loss: 0.05, reorder: 8},
}

func requireWeakNetBench(b testing.TB) {
	b.Helper()
	if os.Getenv(weakNetBenchEnv) == "" {
		b.Skipf("set %s=1 to run the weak-network profiles", weakNetBenchEnv)
	}
}

// weakNetPipe is one direction of a simulated link: packets in, the same
// packets out in order, with loss, a byte-rate cap and a one-way delay applied
// along the way. reorder holds packets so a newer one overtakes an older one
// and is meaningful only for datagrams -- see the file header.
type weakNetPipe struct {
	delay   time.Duration
	loss    float64
	jitter  time.Duration
	reorder int
	rateBps int64

	in   chan []byte
	out  chan []byte
	stop chan struct{}
	once sync.Once

	rateMu sync.Mutex
	rateAt time.Time
	tokens int64
}

func newWeakNetPipe(p weakProfile) *weakNetPipe {
	pipe := &weakNetPipe{
		delay:   p.rtt / 2,
		loss:    p.loss,
		jitter:  p.jitter,
		reorder: p.reorder,
		rateBps: p.rateBps,
		in:      make(chan []byte, 512),
		out:     make(chan []byte, 512),
		stop:    make(chan struct{}),
	}
	go pipe.run()
	return pipe
}

// stagedPacket is a packet carrying the order it entered the link, so a
// parallel delay stage can hand them back in the order they arrived.
type stagedPacket struct {
	seq uint64
	pkt []byte
}

// run is the pipeline: drop, then rate-limit and delay in parallel, then
// reorder or restore order. One dispatcher owns the read side so the sequence
// number is stamped in the order packets entered the link; the delay itself is
// parallel so a burst does not queue behind itself.
func (p *weakNetPipe) run() {
	delayed := make(chan stagedPacket, 512)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		var (
			wg  sync.WaitGroup
			seq uint64
		)
		defer wg.Wait()
		for {
			var (
				pkt []byte
				ok  bool
			)
			select {
			case pkt, ok = <-p.in:
				if !ok {
					return
				}
			case <-p.stop:
				return
			}
			if p.loss > 0 && mrand.Float64() < p.loss {
				continue
			}
			wg.Add(1)
			go func(s stagedPacket) {
				defer wg.Done()
				p.pace(int64(len(s.pkt)))
				time.Sleep(p.delay + time.Duration(mrand.Int64N(int64(p.jitter)+1)))
				delayed <- s
			}(stagedPacket{seq: seq, pkt: pkt})
			seq++
		}
	}()
	go func() {
		<-finished
		close(delayed)
	}()

	if p.reorder == 0 && p.loss == 0 {
		p.restoreOrder(delayed)
		return
	}

	held := make([][]byte, 0, p.reorder)
	for s := range delayed {
		if p.reorder > 0 {
			held = append(held, s.pkt)
			if len(held) > p.reorder {
				// Let the newest packet pass first, then release the one it
				// overtook: pkt N+reorder reaches the receiver before pkt N.
				p.out <- s.pkt
				old := held[0]
				held = held[1:]
				p.out <- old
			}
			continue
		}
		p.out <- s.pkt
	}
	// Flush whatever is still held so the tail of the flow is not lost.
	for len(held) > 0 {
		p.out <- held[0]
		held = held[1:]
	}
	close(p.out)
}

// restoreOrder hands packets back in the order they entered the link. A
// parallel delay stage delivers bursts out of order, which is harmless on a
// datagram leg but corrupts a byte stream -- reordered writes into a TCP
// connection surface as tls: bad record MAC. Only loss-free, reorder-free links
// reach this path, and those are the byte-stream ones; loss would leave a gap
// in the sequence and make the wait below hang, which is exactly why a lossy
// link is never modelled as a byte stream here.
func (p *weakNetPipe) restoreOrder(delayed <-chan stagedPacket) {
	var next uint64
	pending := make(map[uint64][]byte)
	for s := range delayed {
		pending[s.seq] = s.pkt
		for {
			pkt, ok := pending[next]
			if !ok {
				break
			}
			delete(pending, next)
			p.out <- pkt
			next++
		}
	}
	close(p.out)
}

// send queues one packet and reports whether it was accepted. It never blocks
// forever: once finish has been called the sender bails instead of queueing
// into a pipeline that is draining. `in` is never closed, so the send cannot
// panic against a closed channel.
func (p *weakNetPipe) send(pkt []byte) bool {
	select {
	case p.in <- pkt:
		return true
	case <-p.stop:
		return false
	}
}

// recv returns the next packet to hand to the receiver, or io.EOF once the
// pipeline has drained.
func (p *weakNetPipe) recv() ([]byte, error) {
	pkt, ok := <-p.out
	if !ok {
		return nil, io.EOF
	}
	return pkt, nil
}

// finish ends the pipe in this direction; the receiver then sees io.EOF after
// the pipeline drains. The reader and the writer can both observe a failure
// concurrently, so it is idempotent.
func (p *weakNetPipe) finish() {
	p.once.Do(func() { close(p.stop) })
}

// pace enforces the link's byte rate. Both directions of a link get their own
// pipe and therefore their own bucket, so the cap applies per direction. The
// burst is deliberately small: a large burst would let a whole flow get through
// before pacing ever engages, which is the opposite of what a rate cap should
// do to a bursty benchmark.
func (p *weakNetPipe) pace(want int64) {
	if p.rateBps <= 0 || want <= 0 {
		return
	}
	p.rateMu.Lock()
	now := time.Now()
	if p.rateAt.IsZero() {
		p.rateAt = now
	}
	available := now.Sub(p.rateAt).Nanoseconds() * p.rateBps / int64(time.Second)
	if available < 0 {
		available = 0
	}
	p.tokens += available
	burst := int64(4 * 1024)
	if r := p.rateBps / 100; r > burst {
		burst = r
	}
	if p.tokens > burst {
		p.tokens = burst
	}
	var wait time.Duration
	if want > p.tokens {
		wait = time.Duration((want - p.tokens) * int64(time.Second) / p.rateBps)
	}
	p.tokens -= want
	p.rateAt = now.Add(wait)
	p.rateMu.Unlock()
	if wait > 0 {
		time.Sleep(wait)
	}
}

// pump copies src -> pipe -> dst and reports when it stops.
func pump(pipe *weakNetPipe, src, dst net.Conn) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 32*1024)
		go func() {
			for {
				n, err := src.Read(buf)
				if n > 0 {
					pkt := make([]byte, n)
					copy(pkt, buf[:n])
					if !pipe.send(pkt) {
						return
					}
				}
				if err != nil {
					pipe.finish()
					return
				}
			}
		}()
		for {
			pkt, err := pipe.recv()
			if err != nil {
				return
			}
			if _, err := dst.Write(pkt); err != nil {
				pipe.finish()
				return
			}
		}
	}()
	return done
}

// linkPair wires two connections through one pipe per direction.
func linkPair(profile weakProfile, a, b net.Conn) {
	go func() { <-pump(newWeakNetPipe(profile), a, b); a.Close(); b.Close() }()
	go func() { <-pump(newWeakNetPipe(profile), b, a); a.Close(); b.Close() }()
}

// weakNetProxy is the three-hop chain that hides the server from the client
// and puts the simulated link in between: client -> proxy -> link -> proxy ->
// server.
type weakNetProxy struct {
	clientAddr string
	close      func()
}

// tcpProxy fronts a TCP listener; each accepted connection dials the server.
func tcpProxy(t testing.TB, profile weakProfile, serverAddr string) *weakNetProxy {
	t.Helper()
	serverSide, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("weaknet: proxy server-side listen: %v", err)
	}
	clientSide, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		serverSide.Close()
		t.Fatalf("weaknet: proxy client-side listen: %v", err)
	}
	go func() {
		for {
			outer, err := clientSide.Accept()
			if err != nil {
				return
			}
			inner, err := net.Dial("tcp", serverAddr)
			if err != nil {
				outer.Close()
				continue
			}
			linkPair(profile, outer, inner)
		}
	}()
	return &weakNetProxy{
		clientAddr: clientSide.Addr().String(),
		close: func() {
			serverSide.Close()
			clientSide.Close()
		},
	}
}

// udpProxy fronts a UDP socket the same way. The client's address is learned
// from its first datagram and used for the reply path.
func udpProxy(t testing.TB, profile weakProfile, serverAddr net.Addr) *weakNetProxy {
	t.Helper()
	serverSide := listenUDP(t, "127.0.0.1:0")
	clientSide := listenUDP(t, "127.0.0.1:0")

	up := newWeakNetPipe(profile)   // client -> server
	down := newWeakNetPipe(profile) // server -> client

	var (
		mu      sync.Mutex
		replyTo net.Addr
	)

	// client -> server
	go func() {
		buf := make([]byte, 65536)
		for {
			n, addr, err := clientSide.ReadFrom(buf)
			if err != nil {
				up.finish()
				return
			}
			if addr != nil {
				mu.Lock()
				replyTo = addr
				mu.Unlock()
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			up.send(pkt)
		}
	}()
	go func() {
		for {
			pkt, err := up.recv()
			if err != nil {
				return
			}
			if _, err := serverSide.WriteTo(pkt, serverAddr); err != nil {
				up.finish()
				return
			}
		}
	}()

	// server -> client
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := serverSide.ReadFrom(buf)
			if err != nil {
				down.finish()
				return
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			down.send(pkt)
		}
	}()
	go func() {
		for {
			pkt, err := down.recv()
			if err != nil {
				return
			}
			mu.Lock()
			addr := replyTo
			mu.Unlock()
			if addr == nil {
				continue
			}
			if _, err := clientSide.WriteTo(pkt, addr); err != nil {
				down.finish()
				return
			}
		}
	}()

	return &weakNetProxy{
		clientAddr: clientSide.LocalAddr().String(),
		close: func() {
			serverSide.Close()
			clientSide.Close()
		},
	}
}

func listenUDP(t testing.TB, addr string) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("weaknet: udp listen %s: %v", addr, err)
	}
	return pc
}

// weakNetEnv is one tunnel server. The server reaches its echo target over
// plain loopback, so only the client leg is degraded and a clean run and a
// degraded run are directly comparable.
type weakNetEnv struct {
	serverTCP string   // the server's own TCP listen address
	serverUDP net.Addr // the server's own UDP listen address
}

// endpoint returns a proxied address for one client. The proxy is created per
// client rather than shared across a profile's legs, because the UDP reply path
// is learned from whichever datagram arrives first and the pipe goroutines of an
// earlier subtest are deliberately not joined: a lingering sender from the
// previous leg would latch replyTo and every reply of this client would be sent
// to a socket nobody reads. That is what made MASQUE over a lossy link look
// intermittently ten times slower than H3 on the very same link, and then fail
// to complete a round at all -- until it was measured in isolation, where it
// came in level with H3. tcpProxy would not show the symptom (it builds a fresh
// link pair per accepted connection) and was made per-client too, so the two
// namespaces behave the same way.
func (e *weakNetEnv) endpoint(t testing.TB, profile weakProfile, udp bool) string {
	t.Helper()
	var p *weakNetProxy
	if udp {
		p = udpProxy(t, profile, e.serverUDP)
	} else {
		p = tcpProxy(t, profile, e.serverTCP)
	}
	t.Cleanup(p.close)
	return p.clientAddr
}

func newWeakNetEnv(t testing.TB) *weakNetEnv {
	t.Helper()
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("weaknet: echo target: %v", err)
	}
	go serveEcho(echoLn)
	udpEcho := bindUDPRetry(t, "127.0.0.1:0")
	go serveUDPEcho(udpEcho)

	tlsCfg, err := h2tunnel.SelfSignedTLSConfig("localhost")
	if err != nil {
		t.Fatalf("weaknet: tls: %v", err)
	}
	auth, err := h2tunnel.NewTokenAuthenticator(weakNetToken)
	if err != nil {
		t.Fatalf("weaknet: auth: %v", err)
	}
	dialer, err := h2tunnel.NewStaticServiceDialer(map[string]h2tunnel.Service{
		"weaknet-tcp": {Network: h2tunnel.NetworkTCP, Address: echoLn.Addr().String()},
		"weaknet-udp": {Network: h2tunnel.NetworkUDP, Address: udpEcho.LocalAddr().String()},
	}, nil)
	if err != nil {
		t.Fatalf("weaknet: dialer: %v", err)
	}
	srv, err := h2tunnel.NewServer(h2tunnel.ServerOptions{
		Transports:    []h2tunnel.Transport{h2tunnel.TransportH2, h2tunnel.TransportH3, h2tunnel.TransportWebTransport, h2tunnel.TransportMASQUE, h2tunnel.TransportGRPC},
		Networks:      []h2tunnel.Network{h2tunnel.NetworkTCP, h2tunnel.NetworkUDP},
		TLSConfig:     tlsCfg,
		Authenticator: auth,
		Dialer:        dialer,
	})
	if err != nil {
		t.Fatalf("weaknet: server: %v", err)
	}

	tcpLn, udpLn, err := listenTCPUDPPair(net.Listen, net.ListenPacket)
	if err != nil {
		t.Fatalf("weaknet: server listen: %v", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(h2tunnel.Listeners{TCP: tcpLn, QUIC: udpLn}) }()
	t.Cleanup(func() {
		_ = srv.Close()
		if err := <-serveErr; err != nil {
			t.Errorf("weaknet: server Serve returned %v", err)
		}
		_ = tcpLn.Close()
		_ = udpLn.Close()
		_ = echoLn.Close()
		_ = udpEcho.Close()
	})

	return &weakNetEnv{serverTCP: tcpLn.Addr().String(), serverUDP: udpLn.LocalAddr()}
}

func newWeakNetClient(t testing.TB, env *weakNetEnv, profile weakProfile, transport h2tunnel.Transport, udp bool) *h2tunnel.Client {
	t.Helper()
	endpoint := env.endpoint(t, profile, udp)
	creds, err := h2tunnel.NewTokenCredentials(weakNetToken)
	if err != nil {
		t.Fatalf("weaknet: creds: %v", err)
	}
	client, err := h2tunnel.NewClient(h2tunnel.ClientOptions{
		Endpoint:    "https://" + endpoint,
		Transport:   transport,
		TLSConfig:   &tls.Config{InsecureSkipVerify: true},
		Credentials: creds,
	})
	if err != nil {
		t.Fatalf("weaknet: client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// TestWeakNetDelayIsObserved proves the simulator injects delay and the tunnel
// adds nothing pathological on top of it. One delay per transport is enough:
// `observed >= rtt` is the injection proof, and the upper bound catches a
// broken link path that would otherwise report clean-loopback numbers.
func TestWeakNetDelayIsObserved(t *testing.T) {
	for _, tc := range []struct {
		name      string
		transport h2tunnel.Transport
		udp       bool
	}{
		{"H2_TCP", h2tunnel.TransportH2, false},
		{"H3_UDP", h2tunnel.TransportH3, true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			const rtt = 150 * time.Millisecond
			link := weakProfile{name: tc.name, rtt: rtt}
			env := newWeakNetEnv(t)
			observed, err := measureEchoRTT(t, newWeakNetClient(t, env, link, tc.transport, tc.udp), 5)
			if err != nil {
				t.Fatalf("echo through the %s leg: %v", tc.name, err)
			}
			if observed < rtt {
				t.Fatalf("echo RTT %s is below the injected %s: the link is not injecting delay", observed, rtt)
			}
			// QUIC starts from the RFC 9002 1s RTT estimate and warms up over the
			// first packets, so the first measurements of a fresh connection run
			// well above the injected delay. The median of five skips the outliers
			// on both ends; the bound is generous enough for that but tight enough
			// to still catch a link that is not in the path.
			if observed > 3*rtt+time.Second {
				t.Fatalf("echo RTT %s far exceeds the injected %s", observed, rtt)
			}
			t.Logf("injected %s round-trip: median echo RTT %s", rtt, observed)
		})
	}
}

// TestWeakNetRateCapSlowsTheLeg asserts the byte-rate cap bites: at the same
// delay the capped leg must move well under half the bytes the uncapped one
// does. Relative, so it survives a noisy runner.
//
// The delay is short on purpose. A cap only binds when the RTT-limited rate is
// above it, and an h2 tunnel over a 40 ms link tops out near 80 KiB/s -- below
// the 64 KiB/s cap, so the cap would sit idle and the assertion could not
// distinguish "the cap works" from "the cap is ignored".
func TestWeakNetRateCapSlowsTheLeg(t *testing.T) {
	requireWeakNetBench(t)
	payload := make([]byte, 4*1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	const delay = 20 * time.Millisecond
	const capBps = int64(16 * 1024)
	type measured struct {
		name string
		rate float64
	}
	results := make([]measured, 2)
	for i, cap := range []struct {
		name    string
		rateBps int64
	}{
		{name: "Uncapped", rateBps: 0},
		{name: "Capped", rateBps: capBps},
	} {
		link := weakProfile{
			name: cap.name, rtt: delay, rateBps: cap.rateBps,
		}
		env := newWeakNetEnv(t)
		conn, err := newWeakNetClient(t, env, link, h2tunnel.TransportH2, false).
			DialContext(context.WithoutCancel(context.Background()), h2tunnel.NetworkTCP, "weaknet-tcp")
		if err != nil {
			t.Skipf("h2 unavailable through the proxy: %v", err)
		}
		defer conn.Close()
		results[i] = measured{cap.name, measureEchoRate(t, conn, payload)}
	}
	if results[1].rate >= results[0].rate*0.5 {
		t.Fatalf("capped leg %v/s is not under half the uncapped leg %v/s", results[1].rate, results[0].rate)
	}
	t.Logf("uncapped %v/s, capped %v/s", results[0].rate, results[1].rate)
}

// BenchmarkWeakNetEchoIntegrity is the weak-network throughput matrix. Every
// profile asserts byte integrity on each echoed chunk and reports the
// throughput that resulted -- slowness is a result, not a failure, so a
// transport that cannot sustain a lossy link shows up as a low number instead
// of a red build.
//
// The rows are hand-picked rather than a full cross product: each weak link
// costs a server, a proxy and a warm-up, and the point of the matrix is to
// cover every link shape once and every transport on the links it survives.
// The lossy and reorder rows carry the transports that actually reach them.
func BenchmarkWeakNetEchoIntegrity(b *testing.B) {
	requireWeakNetBench(b)
	payload := make([]byte, 4*1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	for _, row := range []struct {
		link weakProfile
		legs []struct {
			name      string
			transport h2tunnel.Transport
			udp       bool
		}
	}{
		{weakNetProfiles[0], []struct {
			name      string
			transport h2tunnel.Transport
			udp       bool
		}{
			{"H2_TCP", h2tunnel.TransportH2, false},
			{"gRPC_TCP", h2tunnel.TransportGRPC, false},
			{"H3_UDP", h2tunnel.TransportH3, true},
			{"WT_UDP", h2tunnel.TransportWebTransport, true},
			{"MASQUE_H3_UDP", h2tunnel.TransportMASQUE, true},
		}},
		{weakNetProfiles[1], []struct {
			name      string
			transport h2tunnel.Transport
			udp       bool
		}{
			{"H2_TCP", h2tunnel.TransportH2, false},
			{"gRPC_TCP", h2tunnel.TransportGRPC, false},
		}},
		{weakNetProfiles[2], []struct {
			name      string
			transport h2tunnel.Transport
			udp       bool
		}{
			{"H3_UDP", h2tunnel.TransportH3, true},
			{"WT_UDP", h2tunnel.TransportWebTransport, true},
			{"MASQUE_H3_UDP", h2tunnel.TransportMASQUE, true},
		}},
		{weakNetProfiles[3], []struct {
			name      string
			transport h2tunnel.Transport
			udp       bool
		}{
			{"H3_UDP", h2tunnel.TransportH3, true},
			{"WT_UDP", h2tunnel.TransportWebTransport, true},
		}},
		{weakNetProfiles[4], []struct {
			name      string
			transport h2tunnel.Transport
			udp       bool
		}{
			{"H3_UDP", h2tunnel.TransportH3, true},
			{"WT_UDP", h2tunnel.TransportWebTransport, true},
		}},
	} {
		b.Run(row.link.name, func(b *testing.B) {
			env := newWeakNetEnv(b)
			for _, leg := range row.legs {
				leg := leg
				b.Run(leg.name, func(b *testing.B) {
					benchmarkWeakNetEcho(b, newWeakNetClient(b, env, row.link, leg.transport, leg.udp), payload)
				})
			}
		})
	}
}

// benchmarkWeakNetEcho measures a fixed wall-clock stretch instead of b.N
// iterations, so the result does not depend on how slow the link is -- a slow
// profile would otherwise need very few iterations to fit the benchmark budget
// and report a nonsense rate. b.N is forced to 1 afterwards so bytes/sec comes
// out as the total bytes moved over the stretch.
//
// Only byte integrity fails the subtest. A write or read error -- including a
// deadline, which means this transport cannot carry a round at all on that
// link -- skips instead, so a transport that cannot establish through a harsh
// link is reported as unavailable rather than turning the job red.
func benchmarkWeakNetEcho(b *testing.B, client *h2tunnel.Client, payload []byte) {
	b.Helper()
	// These bounds are generous relative to the link, not the other way round:
	// the slowest profile injects 120ms one-way plus 25ms jitter, so a handshake
	// and a round both complete in well under a second, and the slowest
	// subtest measured so far has taken 10s. What the bounds must cap is a
	// genuinely wedged leg -- an unbounded dial once cost ~90s per skipped
	// subtest, turning a 65s matrix into a 4-minute one.
	ctx, cancel := context.WithTimeout(context.Background(), weakNetDialTimeout)
	defer cancel()
	conn, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "weaknet-tcp")
	if err != nil {
		b.Skipf("transport unavailable through the proxy: %v", err)
	}
	defer conn.Close()

	got := make([]byte, len(payload))
	stretch := time.Duration(weakNetBenchmarkSeconds) * time.Second
	// One round must be able to finish at all, or the whole budget is wasted.
	// The cushion covers a transport that paces its first writes against the
	// RFC 9002 1s RTT estimate before it learns the real one.
	if err := conn.SetDeadline(time.Now().Add(stretch + weakNetRoundCushion)); err != nil {
		b.Fatalf("set deadline: %v", err)
	}

	// Warm up before starting the clock: a QUIC/WT connection does its handshake
	// on the first write, and charging that to the measured window would make a
	// slow first round look like a stalled link.
	if _, err := conn.Write(payload); err != nil {
		b.Skipf("transport could not write through this link: %v", err)
	}
	if _, err := io.ReadFull(conn, got); err != nil {
		b.Skipf("echo did not come back through this link: %v", err)
	}
	if !slices.Equal(got, payload) {
		b.Fatal("warmed-up echo chunk differs")
	}

	rounds := 0
	total := int64(0)
	b.ReportAllocs()
	b.ResetTimer()
	start := time.Now()
	for time.Since(start) < stretch {
		if _, err := conn.Write(payload); err != nil {
			b.Skipf("transport stalled on this link after %d rounds: %v", rounds, err)
		}
		if _, err := io.ReadFull(conn, got); err != nil {
			b.Skipf("echo stalled on this link after %d rounds: %v", rounds, err)
		}
		if !slices.Equal(got, payload) {
			b.Fatalf("echoed chunk differs after %d rounds through the weak link", rounds+1)
		}
		rounds++
		total += int64(len(payload)) * 2
	}
	if rounds == 0 {
		b.Skipf("no round completed in %s", stretch)
	}
	b.SetBytes(total)
	b.N = 1
	b.ReportMetric(float64(rounds), "rounds")
	if rounds < 4 {
		b.Logf("only %d rounds in %s: this link cannot sustain the transport", rounds, stretch)
	}
}

// measureEchoRate moves a fixed wall-clock stretch of echoed chunks and
// returns the resulting bytes per second.
func measureEchoRate(t testing.TB, conn net.Conn, payload []byte) float64 {
	t.Helper()
	got := make([]byte, len(payload))
	rounds := 0
	total := int64(0)
	const stretch = 2 * time.Second
	start := time.Now()
	for time.Since(start) < stretch {
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("read: %v", err)
		}
		if !slices.Equal(got, payload) {
			t.Fatal("echoed chunk differs")
		}
		rounds++
		total += int64(len(payload)) * 2
	}
	elapsed := time.Since(start)
	t.Logf("echoed %d chunks of %d bytes in %s", rounds, len(payload), elapsed.Round(time.Millisecond))
	return float64(total) / elapsed.Seconds()
}

// measureEchoRTT measures one-byte round-trips through the tunnel leg and
// returns their median. The median rather than a mean keeps a single GC pause
// or a slow first packet from skewing the comparison against the injected delay.
func measureEchoRTT(t testing.TB, client *h2tunnel.Client, n int) (time.Duration, error) {
	t.Helper()
	if n < 3 {
		t.Fatalf("measureEchoRTT: need at least 3 samples for a median, got %d", n)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "weaknet-tcp")
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	buf := make([]byte, 1)
	samples := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		if _, err := conn.Write([]byte{0x41}); err != nil {
			return 0, err
		}
		if _, err := io.ReadFull(conn, buf); err != nil {
			return 0, err
		}
		if buf[0] != 0x41 {
			return 0, fmt.Errorf("echo mismatch: got 0x%02x", buf[0])
		}
		samples = append(samples, time.Since(start))
	}
	slices.Sort(samples)
	return samples[len(samples)/2], nil
}
