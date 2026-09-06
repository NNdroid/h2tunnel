package h2tunnel_test

// =========================================
// 全协议 × TCP/UDP 吞吐基准。
//
// 每个（传输 × 网络）组合一条真实隧道：
//   - TCP：72KB payload 经隧道写→echo→读回（同一条连接内往复）；
//   - UDP：16KB 数据报（UDP 安全边界，与旧基准一致）经
//     PacketConn 写→echo→读回。
//
// 目标是环回 echo，测的是隧道栈自身开销（帧编解码 + HTTP/2/3 复用 +
// 会话引擎）；CDN / 高 RTT 场景的绝对值请按窗口与 RTT 折算。
// 全部协议都含 TCP 与 UDP（WT-UDP 走 WT 流上的 datagram 面）。
// =========================================

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/NNdroid/h2tunnel"
)

// serveUDPEcho UDP 回显目标（与 TCP echo 对称）。
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
	env := newProtocolEnv(b)
	cases := []struct {
		name      string
		transport h2tunnel.Transport
		udp       bool
	}{
		{"H2_TCP", h2tunnel.TransportH2, false},
		{"H2_UDP", h2tunnel.TransportH2, true},
		{"H2C_TCP", h2tunnel.TransportH2C, false},
		{"H2C_UDP", h2tunnel.TransportH2C, true},
		{"gRPC_TCP", h2tunnel.TransportGRPC, false},
		{"gRPC_UDP", h2tunnel.TransportGRPC, true},
		{"H3_TCP", h2tunnel.TransportH3, false},
		{"H3_UDP", h2tunnel.TransportH3, true},
		{"WT_TCP", h2tunnel.TransportWebTransport, false},
		{"WT_UDP", h2tunnel.TransportWebTransport, true},
		{"MASQUE_TCP", h2tunnel.TransportMASQUE, false},
		{"MASQUE_UDP", h2tunnel.TransportMASQUE, true},
	}

	for _, c := range cases {
		c := c
		b.Run(c.name, func(b *testing.B) {
			client := newProtocolClient(b, env, c.transport)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			if !c.udp {
				conn, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "bench-tcp")
				if err != nil {
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
