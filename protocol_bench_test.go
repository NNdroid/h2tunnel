package h2tunnel_test

// =========================================
// Throughput benchmarks for every protocol × TCP/UDP.
//
// One real tunnel per (transport × network) combination:
//   - TCP: a 72KB payload written through the tunnel → echo → read back (round-trip on the same conn);
//   - UDP: a 16KB datagram (UDP-safe size limit, matching the old benchmarks)
//     written via PacketConn → echo → read back.
//
// The target is a loopback echo, so this measures the tunnel stack's own
// overhead (frame codec + HTTP/2/3 multiplexing + session engine); for CDN /
// high-RTT scenarios, scale the absolute values by the window and RTT.
// All protocols cover TCP and UDP (WT-UDP uses the datagram plane over the WT stream).
// =========================================

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/NNdroid/h2tunnel"
)

// serveUDPEcho is the UDP echo target (symmetric to the TCP echo).
func serveUDPEcho(pc net.PacketConn) {
	buf := make([]byte, 65536)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if _, err := pc.WriteTo(buf[:n], addr); err != nil {
			return
		}
	}
}

const (
	benchTCPChunk = 72 * 1024
	benchUDPChunk = 16 * 1024
)

func BenchmarkProtocolThroughput(b *testing.B) {
	benchmarkProtocolThroughput(b, h2tunnel.PaddingTuning{})
}

func BenchmarkProtocolThroughputPadding600To1200(b *testing.B) {
	benchmarkProtocolThroughput(b, h2tunnel.PaddingTuning{MinRecordBytes: 600, MaxRecordBytes: 1200})
}

func benchmarkProtocolThroughput(b *testing.B, padding h2tunnel.PaddingTuning) {
	// The matrix has 16 legs, and on a healthy host every leg establishes and
	// finishes in a couple of seconds, so generous bounds are fine for the
	// always-on jobs (which never set the weak-net env). Under the weak-network
	// profiles the same generous bounds are what made the kernel-netem job
	// unable to terminate: a single stuck leg could burn a minute of dial
	// budget, hold its stream open for a 10-minute read deadline, or (on the
	// datagram leg, which has no deadline at all) block forever on one echo
	// datagram that the 2% netem loss dropped. The short bounds below only cap
	// how long a genuinely stuck leg can stall before the suite fails visibly
	// instead of hanging to the job timeout; they never change what a healthy
	// host measures.
	dialTimeout, connDeadline := time.Minute, 10*time.Minute
	readWait := time.Minute // unused unless lossy
	lossy := os.Getenv(weakNetBenchEnv) != ""
	if lossy {
		dialTimeout, connDeadline = 15*time.Second, 10*time.Second
		readWait = time.Second
	}

	env := newProtocolEnvWithPadding(b, padding)
	cases := []struct {
		name      string
		transport h2tunnel.Transport
		udp       bool
		alpn      string // MASQUE carrier pin: ""=auto (h3-first, pin h2 on failure), "h2", "h3"
	}{
		{"H2_TCP", h2tunnel.TransportH2, false, ""},
		{"H2_UDP", h2tunnel.TransportH2, true, ""},
		{"H2C_TCP", h2tunnel.TransportH2C, false, ""},
		{"H2C_UDP", h2tunnel.TransportH2C, true, ""},
		{"gRPC_TCP", h2tunnel.TransportGRPC, false, ""},
		{"gRPC_UDP", h2tunnel.TransportGRPC, true, ""},
		{"H3_TCP", h2tunnel.TransportH3, false, ""},
		{"H3_UDP", h2tunnel.TransportH3, true, ""},
		{"WT_TCP", h2tunnel.TransportWebTransport, false, ""},
		{"WT_UDP", h2tunnel.TransportWebTransport, true, ""},
		// MASQUE: keep the auto case (backward-compat with historical numbers
		// and the profile job) plus explicit per-carrier legs so each is
		// measured deterministically instead of only whichever carrier the auto
		// selector lands on for the CI runner's UDP reachability.
		{"MASQUE_TCP", h2tunnel.TransportMASQUE, false, ""},
		{"MASQUE_UDP", h2tunnel.TransportMASQUE, true, ""},
		{"MASQUE_H2_TCP", h2tunnel.TransportMASQUE, false, "h2"},
		{"MASQUE_H2_UDP", h2tunnel.TransportMASQUE, true, "h2"},
		{"MASQUE_H3_TCP", h2tunnel.TransportMASQUE, false, "h3"},
		{"MASQUE_H3_UDP", h2tunnel.TransportMASQUE, true, "h3"},
	}

	for _, c := range cases {
		c := c
		b.Run(c.name, func(b *testing.B) {
			client := newProtocolClientWithPaddingALPN(b, env, c.transport, padding, c.alpn)
			ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
			defer cancel()

			if !c.udp {
				conn, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "bench-tcp")
				if err != nil {
					// Pinned MASQUE carrier (h2/h3) may be unavailable in a given
					// environment (e.g. UDP-blocked CI for h3); skip rather than
					// fail so the rest of the matrix still runs.
					if c.alpn != "" {
						b.Skipf("masque carrier %q unavailable in this environment: %v", c.alpn, err)
					}
					b.Fatal(err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(connDeadline))

				payload := make([]byte, benchTCPChunk)
				for i := range payload {
					payload[i] = byte(i)
				}
				got := make([]byte, len(payload))
				b.SetBytes(int64(len(payload)))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := conn.Write(payload); err != nil {
						b.Fatal(err)
					}
					if _, err := io.ReadFull(conn, got); err != nil {
						b.Fatal(err)
					}
				}
				return
			}

			packetConn, err := client.DialPacketContext(ctx, h2tunnel.NetworkUDP, "bench-udp")
			if err != nil {
				if c.alpn != "" {
					b.Skipf("masque carrier %q unavailable in this environment: %v", c.alpn, err)
				}
				b.Fatal(err)
			}
			defer packetConn.Close()

			payload := make([]byte, benchUDPChunk)
			for i := range payload {
				payload[i] = byte(i)
			}
			got := make([]byte, len(payload))
			b.ReportAllocs()

			if lossy {
				// The datagram path has no app-level retransmission, so one echo
				// dropped by the qdisc is gone for good -- with no deadline the
				// read parks it until the job is killed, which is exactly what
				// run 71 showed: a healthy host, probe under a second, and the
				// benchmark still unable to finish in 25 minutes. Drops are the
				// impairment here, not a regression, so measure what actually
				// completes against a wall-clock budget and let the harness derive
				// the rate, the same fixed-stretch pattern the weak-network suite
				// uses. Per-read waits are short because a lost datagram is known
				// to be lost; the budget is not, since a fully wedged leg has to
				// be able to report 0 instead of running forever.
				b.ResetTimer()
				budget := time.Now().Add(3 * time.Second)
				var completed int64
				for time.Now().Before(budget) {
					if _, err := packetConn.Write(payload); err != nil {
						b.Fatal(err)
					}
					_ = packetConn.SetReadDeadline(time.Now().Add(readWait))
					n, err := packetConn.Read(got)
					if err != nil {
						var netErr net.Error
						if errors.As(err, &netErr) && netErr.Timeout() {
							continue
						}
						b.Fatalf("read echo: err=%v", err)
					}
					if n != len(payload) {
						b.Fatalf("read echo: n=%d want %d", n, len(payload))
					}
					completed++
				}
				b.StopTimer()
				b.N = 1
				b.SetBytes(completed * int64(len(payload)))
				return
			}

			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := packetConn.Write(payload); err != nil {
					b.Fatal(err)
				}
				if n, err := packetConn.Read(got); err != nil || n != len(payload) {
					b.Fatalf("read echo: n=%d err=%v", n, err)
				}
			}
		})
	}
}
