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
	"io"
	"net"
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
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
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
				_ = conn.SetDeadline(time.Now().Add(10 * time.Minute))

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
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
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
