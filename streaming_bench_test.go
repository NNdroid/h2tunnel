package h2tunnel_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/NNdroid/h2tunnel"
)

// A real TCP target: mode + byte count followed by a continuous transfer.
// Completion ACK prevents counting bytes merely accepted by a local buffer.
func serveTransferTarget(listener net.Listener) {
	for {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Minute))
			var header [9]byte
			if _, err := io.ReadFull(c, header[:]); err != nil {
				return
			}
			n := int64(binary.BigEndian.Uint64(header[1:]))
			if n < 0 {
				return
			}
			mode := header[0] & 0x7f
			verify := header[0]&0x80 != 0
			if mode > 2 {
				return
			}
			output := make(chan error, 1)
			if mode != 0 {
				go func() { _, err := io.CopyN(c, patternReader{}, n); output <- err }()
			}
			if mode != 1 {
				sink := io.Writer(io.Discard)
				if verify {
					sink = &patternVerifier{}
				}
				if _, err := io.CopyN(sink, c, n); err != nil {
					return
				}
			}
			if mode != 0 {
				if err := <-output; err != nil {
					return
				}
			}
			c.Write([]byte{0xAC})
		}()
	}
}

type patternReader struct{}

type patternVerifier struct{ offset int64 }

func (v *patternVerifier) Write(p []byte) (int, error) {
	for i, b := range p {
		if b != byte(v.offset+int64(i)) {
			return i, fmt.Errorf("uplink corrupted at %d", v.offset+int64(i))
		}
	}
	v.offset += int64(len(p))
	return len(p), nil
}

func (patternReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(i)
	}
	return len(p), nil
}

// Each operation represents one 32KiB chunk per session. Upload/download count
// one direction; duplex counts both directions. All chunks run continuously,
// without waiting for an echo after each write. Uses real TCP target sockets.
func BenchmarkProtocolStreaming(b *testing.B) {
	for _, padded := range []bool{false, true} {
		padding := h2tunnel.PaddingTuning{}
		if padded {
			padding = h2tunnel.PaddingTuning{MinRecordBytes: 600, MaxRecordBytes: 1200}
		}
		b.Run(fmt.Sprintf("Padding=%v", padded), func(b *testing.B) {
			env := newProtocolEnvWithPadding(b, padding)
			for _, tr := range []struct {
				name      string
				transport h2tunnel.Transport
				alpn      string
			}{
				{"H2", h2tunnel.TransportH2, ""}, {"H2C", h2tunnel.TransportH2C, ""},
				{"gRPC", h2tunnel.TransportGRPC, ""}, {"H3", h2tunnel.TransportH3, ""},
				{"WT", h2tunnel.TransportWebTransport, ""},
				{"MASQUE_H2", h2tunnel.TransportMASQUE, "h2"}, {"MASQUE_H3", h2tunnel.TransportMASQUE, "h3"},
			} {
				b.Run(tr.name, func(b *testing.B) {
					client := newProtocolClientWithPaddingALPN(b, env, tr.transport, padding, tr.alpn)
					for mode, name := range []string{"Upload", "Download", "Duplex"} {
						b.Run(name, func(b *testing.B) {
							for _, streams := range []int{1, 8} {
								b.Run(fmt.Sprintf("Streams=%d", streams), func(b *testing.B) { benchmarkContinuousTransfer(b, client, mode, streams) })
							}
						})
					}
				})
			}
		})
	}
}

func benchmarkContinuousTransfer(b *testing.B, client *h2tunnel.Client, mode, streams int) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	conns := make([]net.Conn, streams)
	for i := range conns {
		c, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "bench-transfer")
		if err != nil {
			b.Fatal(err)
		}
		conns[i] = c
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Minute))
	}
	const chunk = 32 * 1024
	multiplier := 1
	if mode == 2 {
		multiplier = 2
	}
	b.SetBytes(int64(chunk * streams * multiplier))
	b.ReportAllocs()
	b.ResetTimer()
	errs := make(chan error, streams)
	var wg sync.WaitGroup
	for _, c := range conns {
		wg.Go(func() { errs <- runContinuousTransfer(c, mode, int64(b.N)*chunk, nil) })
	}
	wg.Wait()
	b.StopTimer()
	close(errs)
	for err := range errs {
		if err != nil {
			b.Fatal(err)
		}
	}
}

func runContinuousTransfer(c net.Conn, mode int, n int64, received io.Writer) error {
	var header [9]byte
	header[0] = byte(mode)
	if received != nil {
		header[0] |= 0x80
	}
	binary.BigEndian.PutUint64(header[1:], uint64(n))
	if _, err := c.Write(header[:]); err != nil {
		return err
	}
	up := make(chan error, 1)
	if mode != 1 {
		go func() { _, err := io.CopyN(c, patternReader{}, n); up <- err }()
	}
	if mode != 0 {
		if received == nil {
			received = io.Discard
		}
		if _, err := io.CopyN(received, c, n); err != nil {
			return err
		}
	}
	if mode != 1 {
		if err := <-up; err != nil {
			return err
		}
	}
	var ack [1]byte
	if _, err := io.ReadFull(c, ack[:]); err != nil {
		return err
	}
	if ack[0] != 0xAC {
		return fmt.Errorf("transfer ACK=%x", ack)
	}
	return nil
}

func TestProtocolContinuousTransfers(t *testing.T) {
	padding := h2tunnel.PaddingTuning{MinRecordBytes: 600, MaxRecordBytes: 1200}
	env := newProtocolEnvWithPadding(t, padding)
	for _, transport := range []h2tunnel.Transport{h2tunnel.TransportH2, h2tunnel.TransportH2C, h2tunnel.TransportGRPC, h2tunnel.TransportH3, h2tunnel.TransportWebTransport, h2tunnel.TransportMASQUE} {
		t.Run(string(transport), func(t *testing.T) {
			client := newProtocolClientWithPadding(t, env, transport, padding)
			for mode := 0; mode < 3; mode++ {
				t.Run(fmt.Sprint(mode), func(t *testing.T) {
					var wg sync.WaitGroup
					for i := 0; i < 4; i++ {
						wg.Go(func() {
							ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
							defer cancel()
							c, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "bench-transfer")
							if err != nil {
								t.Error(err)
								return
							}
							defer c.Close()
							c.SetDeadline(time.Now().Add(30 * time.Second))
							var got bytes.Buffer
							const n = 512 * 1024
							if err := runContinuousTransfer(c, mode, n, &got); err != nil {
								t.Error(err)
								return
							}
							if mode != 0 {
								for i, v := range got.Bytes() {
									if v != byte(i) {
										t.Errorf("downlink corrupted at %d", i)
										return
									}
								}
								if got.Len() != n {
									t.Errorf("received %d bytes", got.Len())
								}
							}
						})
					}
					wg.Wait()
				})
			}
		})
	}
}

func TestLargeUDPDatagramsAllProtocols(t *testing.T) {
	want := bytes.Repeat([]byte("datagram"), 6000)
	// Fail at the kernel boundary with the actual send error rather than
	// timing out six tunnel protocols when the host cannot send this payload.
	probe := bindUDPRetry(t, "127.0.0.1:0")
	defer probe.Close()
	peer, err := net.Dial("udp", probe.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	probe.SetDeadline(time.Now().Add(5 * time.Second))
	peer.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := peer.Write(want); err != nil {
		t.Fatalf("kernel UDP payload preflight (%d bytes): %v; on macOS check net.inet.udp.maxdgram", len(want), err)
	}
	buf := make([]byte, 65536)
	n, addr, err := probe.ReadFrom(buf)
	if err != nil || !bytes.Equal(buf[:n], want) {
		t.Fatalf("kernel UDP receive preflight: bytes=%d err=%v", n, err)
	}
	if _, err := probe.WriteTo(buf[:n], addr); err != nil {
		t.Fatalf("kernel UDP echo preflight: %v", err)
	}
	n, err = peer.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], want) {
		t.Fatalf("kernel UDP echo receive preflight: bytes=%d err=%v", n, err)
	}
	env := newProtocolEnv(t)
	for _, transport := range []h2tunnel.Transport{h2tunnel.TransportH2, h2tunnel.TransportH2C, h2tunnel.TransportGRPC, h2tunnel.TransportH3, h2tunnel.TransportWebTransport, h2tunnel.TransportMASQUE} {
		t.Run(string(transport), func(t *testing.T) {
			client := newProtocolClient(t, env, transport)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			c, err := client.DialPacketContext(ctx, h2tunnel.NetworkUDP, "bench-udp")
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			got := make([]byte, 65536)
			for i := 0; i < 3; i++ {
				if _, err := c.Write(want); err != nil {
					t.Fatal(err)
				}
				n, err := c.Read(got)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got[:n], want) {
					t.Fatalf("datagram truncated/corrupted: %d/%d", n, len(want))
				}
			}
		})
	}
}
