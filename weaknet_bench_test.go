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
//   - On the datagram legs the absolute number is bounded by the OS, not the
//     link. The pipe's own channels are sized well past the bandwidth-delay
//     product, but the proxy's sockets are not: the client->server write blocks
//     once the server's UDP receive buffer is full, and restoreOrder blocks once
//     the 512-packet out queue is. So a clean 40ms QUIC leg reports whatever the
//     runner's socket buffers allow -- tens of MB/s on an idle machine, a couple
//     on a loaded one -- while the TCP legs sit at a stable ~100 MB/s because a
//     byte-stream proxy is drained by the kernel as a stream. Read the datagram
//     rows as relative to each other and against their own cap and loss rows,
//     not as a machine-wide constant, and never as a comparison with the TCP
//     rows. Raising SO_RCVBUF would move the ceiling, but only via platform
//     socket-option code, which is disproportionate for a benchmark that reports
//     rather than asserts.
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
	"container/heap"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"os"
	"slices"
	"sync"
	"sync/atomic"
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

// weakNetDrainTail bounds how long a back-pressured writer may sit blocked after
// the measured stretch. The writer stops on its own once the stretch ends, so
// this only ever bites when the transport cannot absorb what it is given.
const weakNetDrainTail = 10 * time.Second

// weakNetWarmupRounds caps how many echo rounds a benchmark spends settling a
// connection before the clock starts. A QUIC or WebTransport connection does its
// handshake on the first write, and quic-go opens from the RFC 9002 1s RTT
// estimate, so on a 40ms link the first round trips pace themselves to a second
// of RTT -- well below line rate. Starting the clock inside that transient makes
// a healthy leg look stalled. TCP legs converge on the second round and pay no
// more than two.
const weakNetWarmupRounds = 6

// weakNetWarmupConvergeRatio is how close the last two warm-up round trips must
// be for the connection to count as settled. It is generous on purpose: it must
// absorb measurement noise on a loaded runner, but the cold-start gap from 1s
// down to the injected RTT is far wider than it.
const weakNetWarmupConvergeRatio = 3

// weakNetFlapWindow is how long TestWeakNetFlapSurvives holds the link
// black-holed. It must sit well under the QUIC idle timeout (30s), so the
// connection under test is expected to outlast the partition rather than
// rebuild itself: the assertion is survival, not reconnection.
const weakNetFlapWindow = 3 * time.Second

// weakNetFlapRecoverTimeout bounds how long the tunnel may take to carry
// traffic again after the link comes back. Recovery is paced by QUIC's
// retransmission backoff, which outlives the partition itself, so this needs
// headroom on a loaded runner.
const weakNetFlapRecoverTimeout = 30 * time.Second

// weakNetFlapBudget bounds the test as a whole, so a permanently wedged write
// becomes a failed test instead of a hung one.
const weakNetFlapBudget = 60 * time.Second

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

	// lossNow, when set, decides per packet whether to drop instead of the
	// constant `loss` fraction. A fixed fraction can only model a link that is
	// steady; this is how a test drives the same link from healthy to
	// black-holed and back while traffic is in flight. Profiles are values, so
	// the knob carries a closure rather than a second copy of the pipe.
	lossNow func() bool
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
	lossNow func() bool
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
		lossNow: p.lossNow,
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

// weakNetDelayBuffer sizes the hand-off from the delay stage to the reorder or
// restore stage. It must be large: when it is full the scheduler blocks, which
// back-pressures the in queue and then the client, so an undersized value turns
// the link into a fixed worker pool again and the datagram legs collapse toward
// the 0.08MB/s the old 256-worker design reported. A pipelined leg keeps well
// under this many packets in flight, so it never binds on its own -- the real
// ceilings are the out queue and, on the datagram legs, the OS socket buffers.
const weakNetDelayBuffer = 1 << 20

// stagedPacket is a packet carrying the order it entered the link and the time
// it is due for delivery, so a reordered delay stage can hand them back in the
// order they arrived.
type stagedPacket struct {
	seq uint64
	at  time.Time
	pkt []byte
}

// delayHeap is a min-heap of packets waiting for their scheduled delivery time.
//
// A clock-driven heap replaced two earlier designs, each of which corrupted the
// measurement rather than the product. One goroutine per packet leaked: a
// pipelined leg emits tens of thousands of packets, and a goroutine that is
// still sleeping when its subtest's reader is gone blocks on a full
// `delayed` forever, starving the legs that run behind it. A fixed worker pool
// did not leak, but the pool size then became the in-flight budget: 256 workers
// at a 20ms one-way delay admit about 15MB/s, well below the bandwidth-delay
// product a QUIC leg wants, so the UDP legs reported 0.08MB/s where they
// delivered 77MB/s. A heap has no such budget: it grows to whatever the in and
// out queues admit, so depth follows back-pressure instead of a constant, which
// is what a real link does.
type delayHeap []stagedPacket

func (h delayHeap) Len() int           { return len(h) }
func (h delayHeap) Less(i, j int) bool { return h[i].at.Before(h[j].at) }
func (h delayHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *delayHeap) Push(x any)        { *h = append(*h, x.(stagedPacket)) }
func (h *delayHeap) Pop() any {
	old := *h
	n := len(old) - 1
	x := old[n]
	old[n] = stagedPacket{}
	*h = old[:n]
	return x
}

// run is the pipeline: drop, then rate-limit and delay, then reorder or
// restore order. The scheduler owns the sequence number, so it is stamped in
// the order packets entered the link.
func (p *weakNetPipe) run() {
	delayed := make(chan stagedPacket, weakNetDelayBuffer)
	go p.schedule(delayed)

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

// schedule is the rate limit and the delay: one goroutine owns both the heap
// and the clock. A packet admitted now is delivered when its scheduled time
// arrives, so the delay is exact instead of spread across whatever a pool of
// sleepers happened to be doing. Pacing happens at admission rather than
// delivery because the token bucket caps the rate the link admits; a bursty
// delivery pattern is invisible to a throughput measurement, and this keeps the
// goroutine count at one.
func (p *weakNetPipe) schedule(out chan<- stagedPacket) {
	var (
		h   delayHeap
		seq uint64
	)
	timer := time.NewTimer(0)
	timer.Stop()

	for {
		for h.Len() > 0 && !h[0].at.After(time.Now()) {
			out <- heap.Pop(&h).(stagedPacket)
		}

		var due <-chan time.Time
		if h.Len() > 0 {
			until := time.Until(h[0].at)
			if until > 0 {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(until)
				due = timer.C
			}
		}

		select {
		case pkt, ok := <-p.in:
			if !ok {
				p.drainStage(&h, out)
				return
			}
			if p.drops() {
				continue
			}
			// Stamp before incrementing: restoreOrder looks for sequence 0
			// first, so the first packet admitted must carry 0.
			p.pace(int64(len(pkt)))
			at := time.Now().Add(p.delay + time.Duration(mrand.Int64N(int64(p.jitter)+1)))
			heap.Push(&h, stagedPacket{seq: seq, at: at, pkt: pkt})
			seq++
		case <-p.stop:
			p.drainStage(&h, out)
			return
		case <-due:
		}
	}
}

// drainStage releases whatever is still scheduled, so the tail of a flow is not
// lost, then closes the channel the reorder stage ranges over.
func (p *weakNetPipe) drainStage(h *delayHeap, out chan<- stagedPacket) {
	for h.Len() > 0 {
		out <- heap.Pop(h).(stagedPacket)
	}
	close(out)
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

// drops decides whether this packet is lost. The live knob wins over the static
// fraction, which is what lets a test hold a link black-holed for a bounded
// window and then let it recover under existing traffic.
func (p *weakNetPipe) drops() bool {
	if f := p.lossNow; f != nil {
		return f()
	}
	return p.loss > 0 && mrand.Float64() < p.loss
}

// pace enforces the link's byte rate. Both directions of a link get their own
// pipe and therefore their own bucket, so the cap applies per direction.
func (p *weakNetPipe) pace(want int64) {
	if p.rateBps <= 0 || want <= 0 {
		return
	}
	p.rateMu.Lock()
	now := time.Now()
	if p.rateAt.IsZero() {
		// Start the bucket full so a flow may open with a burst instead of
		// the first packet being charged for the whole burst.
		p.rateAt = now
		p.tokens = p.burst()
	}
	available := now.Sub(p.rateAt).Nanoseconds() * p.rateBps / int64(time.Second)
	if available < 0 {
		available = 0
	}
	p.tokens += available
	if b := p.burst(); p.tokens > b {
		p.tokens = b
	}
	var wait time.Duration
	if want > p.tokens {
		// Pay the deficit from the future: it becomes sleep, the bucket is
		// emptied, and the refill clock is anchored past it. Tokens must
		// never go negative -- the old accounting subtracted `want` either
		// way, so each deficit stacked on the last and the waits grew
		// without bound, letting a 32KiB/s cap pass a megabyte a second.
		wait = time.Duration((want - p.tokens) * int64(time.Second) / p.rateBps)
		p.tokens = 0
		p.rateAt = now.Add(wait)
	} else {
		p.tokens -= want
		// The elapsed time was just folded into the bucket, so now is the
		// new anchor; keeping the old one would re-credit it.
		p.rateAt = now
	}
	p.rateMu.Unlock()
	if wait > 0 {
		time.Sleep(wait)
	}
}

// burst is how many bytes a single admission may take without waiting: at
// least one 4KiB packet and at least one 10ms window of the configured rate,
// whichever is larger. It is deliberately small -- a large burst would let a
// whole flow through before pacing ever engages, the opposite of what a rate
// cap should do to a bursty benchmark.
func (p *weakNetPipe) burst() int64 {
	burst := int64(4 * 1024)
	if r := p.rateBps / 100; r > burst {
		burst = r
	}
	return burst
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
// well above it, otherwise the cap sits idle and the assertion cannot tell
// "the cap works" from "the cap is ignored". A serial 4 KiB echo over a 20 ms
// link moves 200 KiB/s -- ten times the 16 KiB/s cap here.
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

// TestWeakNetFlapSurvives black-holes a live tunnel for a few seconds and
// asserts it carries traffic again once the link comes back, with the same
// bytes intact.
//
// Every matrix profile holds its loss fixed for the whole run, so it can only
// model a link that is steady. The link that reaches a user goes bad and then
// recovers, and nothing else in this file covers that shape: a transport that
// wedges on a partition would show up here and never in a constant profile.
// Both directions share one knob, so the tunnel sees a symmetric partition
// rather than a one-way stall.
func TestWeakNetFlapSurvives(t *testing.T) {
	requireWeakNetBench(t)

	var blackHoled atomic.Bool
	link := weakProfile{
		name:    "Flap_160ms",
		rtt:     160 * time.Millisecond,
		lossNow: blackHoled.Load,
	}
	env := newWeakNetEnv(t)
	client := newWeakNetClient(t, env, link, h2tunnel.TransportH2, false)

	payload := make([]byte, 4*1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	got := make([]byte, len(payload))
	ctx, cancel := context.WithTimeout(context.Background(), weakNetDialTimeout)
	defer cancel()
	conn, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "weaknet-tcp")
	if err != nil {
		t.Skipf("h2 unavailable through the proxy: %v", err)
	}
	defer conn.Close()

	// echoOnce is one round trip on its own clock, so a wedged tunnel fails this
	// call instead of hanging the test. The deadline is cleared on the way out,
	// so the writer in flight below keeps its own generous budget.
	echoOnce := func(timeout time.Duration) error {
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		defer conn.SetDeadline(time.Time{})
		if _, err := conn.Write(payload); err != nil {
			return fmt.Errorf("write: %w", err)
		}
		if _, err := io.ReadFull(conn, got); err != nil {
			return fmt.Errorf("read: %w", err)
		}
		if !slices.Equal(got, payload) {
			return fmt.Errorf("echoed chunk differs")
		}
		return nil
	}

	if err := echoOnce(20 * time.Second); err != nil {
		t.Fatalf("baseline echo: %v", err)
	}
	t.Log("leg healthy; partitioning the link")

	// An echo round trip started inside the partition cannot complete until the
	// link returns: the reply has nowhere to come from. That is what makes the
	// next check non-trivial, so a silently no-op partition knob cannot pass it.
	partitioned := time.Now()
	blackHoled.Store(true)
	inflight := make(chan struct{})
	go func() {
		defer close(inflight)
		if err := echoOnce(weakNetFlapBudget); err != nil {
			t.Logf("echo across the partition: %v", err)
		}
	}()
	time.Sleep(weakNetFlapWindow)
	blackHoled.Store(false)
	t.Log("link restored")

	select {
	case <-inflight:
	case <-time.After(weakNetFlapRecoverTimeout):
		t.Fatal("a round trip started inside the partition never completed after the link recovered")
	}
	if settled := time.Since(partitioned); settled < weakNetFlapWindow {
		t.Fatalf("a round trip across the partition settled in %s, before the link was restored: the black hole never took effect", settled)
	}

	if err := echoOnce(weakNetFlapRecoverTimeout); err != nil {
		t.Fatalf("echo after the partition: %v", err)
	}
	t.Logf("tunnel survived a %s black hole and resumed", weakNetFlapWindow)
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
	benchmarkWeakNetMatrix(b, weakNetEchoPayload(), benchmarkWeakNetEcho)
}

// BenchmarkWeakNetPipelinedThroughput measures the same matrix with writes
// outstanding while the echo is still being read.
//
// BenchmarkWeakNetEchoIntegrity is serial: one 4KiB write, then a blocking read
// of the echo, then the next write. At most one chunk is ever in flight, so it
// reports payload/RTT -- a latency ceiling -- and a pipelining, write-coalescing
// or flow-control change produces a byte-identical number there. Nothing in the
// suite could have caught such a change, because this benchmark is the only one
// that combines a degraded link with bytes in flight. The writer and the reader
// run concurrently here: the writer pushes until the stretch ends while the
// reader verifies, so bytes sit outstanding inside the transport and the number
// tracks throughput rather than RTT.
func BenchmarkWeakNetPipelinedThroughput(b *testing.B) {
	requireWeakNetBench(b)
	benchmarkWeakNetMatrix(b, weakNetEchoPayload(), benchmarkWeakNetPipelined)
}

func weakNetEchoPayload() []byte {
	payload := make([]byte, 4*1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	return payload
}

// weakNetLeg is one transport over the simulated link. udp selects the proxied
// UDP namespace; the TCP legs and the QUIC legs cannot share one profile
// address because they are independent namespaces.
type weakNetLeg struct {
	name      string
	transport h2tunnel.Transport
	udp       bool
}

// weakNetRow is one link profile with the transports that reach it.
type weakNetRow struct {
	link weakProfile
	legs []weakNetLeg
}

// weakNetMatrix is the (link, legs) pairs every weak-network benchmark runs:
// Clean covers all five transports, the rate cap the two TCP legs, and the lossy
// and reorder links only the QUIC legs that actually reach them.
func weakNetMatrix() []weakNetRow {
	return []weakNetRow{
		{weakNetProfiles[0], []weakNetLeg{
			{"H2_TCP", h2tunnel.TransportH2, false},
			{"gRPC_TCP", h2tunnel.TransportGRPC, false},
			{"H3_UDP", h2tunnel.TransportH3, true},
			{"WT_UDP", h2tunnel.TransportWebTransport, true},
			{"MASQUE_H3_UDP", h2tunnel.TransportMASQUE, true},
		}},
		{weakNetProfiles[1], []weakNetLeg{
			{"H2_TCP", h2tunnel.TransportH2, false},
			{"gRPC_TCP", h2tunnel.TransportGRPC, false},
		}},
		{weakNetProfiles[2], []weakNetLeg{
			{"H3_UDP", h2tunnel.TransportH3, true},
			{"WT_UDP", h2tunnel.TransportWebTransport, true},
			{"MASQUE_H3_UDP", h2tunnel.TransportMASQUE, true},
		}},
		{weakNetProfiles[3], []weakNetLeg{
			{"H3_UDP", h2tunnel.TransportH3, true},
			{"WT_UDP", h2tunnel.TransportWebTransport, true},
		}},
		{weakNetProfiles[4], []weakNetLeg{
			{"H3_UDP", h2tunnel.TransportH3, true},
			{"WT_UDP", h2tunnel.TransportWebTransport, true},
		}},
	}
}

// benchmarkWeakNetMatrix runs one runner per (profile, leg) pair against a fresh
// environment per profile. Each profile stands up one server and shares it across
// the legs that dial it, so a 25-row matrix costs 5 environments.
func benchmarkWeakNetMatrix(b *testing.B, payload []byte, run func(*testing.B, *h2tunnel.Client, []byte)) {
	b.Helper()
	for _, row := range weakNetMatrix() {
		row := row
		b.Run(row.link.name, func(b *testing.B) {
			env := newWeakNetEnv(b)
			for _, leg := range row.legs {
				leg := leg
				b.Run(leg.name, func(b *testing.B) {
					run(b, newWeakNetClient(b, env, row.link, leg.transport, leg.udp), payload)
				})
			}
		})
	}
}

// warmUpEcho drives a fresh connection to steady state before the measured
// stretch starts, then returns the last round trip it observed.
//
// Two costs must land outside the measured window, and a single warm-up round
// guarantees neither. A QUIC or WebTransport connection does its handshake on
// the first write. And quic-go opens from the RFC 9002 1s RTT estimate, so on a
// 40ms link the first round trips run at a fraction of line rate. Echo until the
// round trip stops falling within the convergence ratio; a TCP leg converges on
// the second round and pays no more than two.
//
// A round that fails skips the subtest, matching the runners: a transport that
// cannot carry a round through this link is unavailable, not broken.
func warmUpEcho(b testing.TB, conn net.Conn, payload, got []byte) time.Duration {
	b.Helper()
	var prev time.Duration
	for i := 0; i < weakNetWarmupRounds; i++ {
		start := time.Now()
		if _, err := conn.Write(payload); err != nil {
			b.Skipf("transport could not write through this link: %v", err)
		}
		if _, err := io.ReadFull(conn, got); err != nil {
			b.Skipf("echo did not come back through this link: %v", err)
		}
		if !slices.Equal(got, payload) {
			b.Fatal("warmed-up echo chunk differs")
		}
		rtt := time.Since(start)
		if prev > 0 && rtt >= prev/weakNetWarmupConvergeRatio && rtt <= prev*weakNetWarmupConvergeRatio {
			break
		}
		prev = rtt
	}
	return prev
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

	// Warm up before starting the clock. The deadline is set afterwards: it
	// bounds the measured rounds, not the settling rounds above, so a slow cold
	// start cannot eat into the cushion a wedged round is meant to burn.
	warmUpEcho(b, conn, payload, got)

	// One round must be able to finish at all, or the whole budget is wasted.
	if err := conn.SetDeadline(time.Now().Add(stretch + weakNetRoundCushion)); err != nil {
		b.Fatalf("set deadline: %v", err)
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
		// Only the client->server leg is charged: the echo returns over the
		// server's own clean loopback path to the echo target, so counting it
		// would double a byte that never crossed the simulated link.
		total += int64(len(payload))
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

// benchmarkWeakNetPipelined keeps a writer and a reader running at once over one
// connection, so chunks are outstanding inside the transport instead of one
// being in flight at a time. The same fixed-stretch reporting applies: bytes
// verified over the stretch, b.N forced to 1.
//
// Only byte integrity fails the subtest. A broken stream skips, matching the
// serial variant, so a transport that cannot carry pipelined traffic through a
// harsh link is reported as unavailable rather than turning the job red.
func benchmarkWeakNetPipelined(b *testing.B, client *h2tunnel.Client, payload []byte) {
	b.Helper()
	stretch := time.Duration(weakNetBenchmarkSeconds) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), weakNetDialTimeout)
	defer cancel()
	conn, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "weaknet-tcp")
	if err != nil {
		b.Skipf("transport unavailable through the proxy: %v", err)
	}
	defer conn.Close()

	got := make([]byte, len(payload))

	// Warm up before the clock. The deadline is set afterwards: it bounds the
	// writer after the measured stretch, not the settling rounds above, so a slow
	// cold start cannot eat into the cushion a wedged writer is meant to burn.
	warmUpEcho(b, conn, payload, got)

	// The deadline bounds the writer after the stretch, so a back-pressured
	// writer cannot hold the subtest hostage waiting for a write that never
	// drains. It does not bound the reader: the reader stops on the stretch.
	if err := conn.SetDeadline(time.Now().Add(stretch + weakNetDrainTail)); err != nil {
		b.Fatalf("set deadline: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	start := time.Now()

	type writerResult struct {
		wrote int64
		err   error
	}
	done := make(chan writerResult, 1)
	go func() {
		var wrote int64
		for time.Since(start) < stretch {
			if _, err := conn.Write(payload); err != nil {
				done <- writerResult{wrote, fmt.Errorf("writer: %w", err)}
				return
			}
			wrote += int64(len(payload))
		}
		done <- writerResult{wrote, nil}
	}()

	// The reader stops on the stretch, so the measured window is the stretch
	// regardless of how long the last in-flight bytes take to land. Verified
	// bytes are what the link actually delivered, which is the number that
	// tracks throughput: a back-pressured writer sends less, and that shows up
	// here rather than being hidden inside the transport.
	var verified int64
	for time.Since(start) < stretch {
		_, err := io.ReadFull(conn, got)
		if err != nil {
			// A hard error before the stretch ends means the stream broke, which
			// is what the serial variant skips on too.
			if !isTimeoutErr(err) {
				b.Skipf("pipelined echo stopped after %d verified bytes: %v", verified, err)
			}
			break
		}
		if !slices.Equal(got, payload) {
			b.Fatalf("pipelined echo chunk differs after %d verified bytes", verified)
		}
		verified += int64(len(payload))
	}

	// The measured window is over; let the writer unwind unmeasured.
	b.StopTimer()
	res := <-done // the writer sends before returning, so wrote is settled here
	if res.err != nil {
		b.Logf("pipelined writer could not keep up: %v", res.err)
	}
	if verified == 0 {
		b.Skipf("no pipelined byte completed in %s", stretch)
	}
	b.SetBytes(verified)
	b.N = 1
	b.ReportMetric(float64(res.wrote), "sent")
}

// isTimeoutErr reports an i/o timeout without importing errors: the conn
// deadline is the intended end of a measured stretch, not a failure.
func isTimeoutErr(err error) bool {
	ne, ok := err.(interface{ Timeout() bool })
	return ok && ne.Timeout()
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
		total += int64(len(payload))
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
