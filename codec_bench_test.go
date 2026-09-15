package h2tunnel

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// =========================================
// Data-plane microbenchmarks: frame codec / ring / session downlink.
//
// End-to-end benchmarks (benchmark_test.go, public_api_test.go) measure the
// whole chain, so a hot-path regression cannot be pinned to a layer; here we
// establish ns/op and allocs/op baselines for the frame codec, ringBuffer and
// writeDownlink. See BenchmarkTunnelSessionFullDuplex for full-duplex
// cross-locking (s.mu contention).
// =========================================

const benchChunk = 32 * 1024

// benchFrameBuffer builds a contiguous byte stream of nFrames 32KB DATA frames.
func benchFrameBuffer(b *testing.B, nFrames int) []byte {
	b.Helper()
	// First build one complete frame (with an explicit padLen=0 — otherwise the
	// previous frame's data padding would overwrite later frame headers' padLen
	// with a non-zero value, desynchronizing the reader once io.CopyN consumes
	// the padding bytes), then replicate it nFrames times with an increasing seq.
	frameLen := resumeHeaderLen + benchChunk
	frame := make([]byte, frameLen)
	frame[0] = resumeFrameData
	frame[1] = resumeProtoVersion
	binary.BigEndian.PutUint32(frame[2:6], benchChunk)
	binary.BigEndian.PutUint16(frame[6:8], 0)
	for j := range frame[16:] {
		frame[16+j] = byte(j)
	}
	out := make([]byte, frameLen*nFrames)
	for i := 0; i < nFrames; i++ {
		binary.BigEndian.PutUint64(frame[8:16], uint64(i)*benchChunk)
		copy(out[i*frameLen:], frame)
	}
	return out
}

// BenchmarkWriteFrame32KB covers the pooled whole-frame single-write fast path (writeFrame path A).
func BenchmarkWriteFrame32KB(b *testing.B) {
	data := make([]byte, benchChunk)
	for i := range data {
		data[i] = byte(i)
	}
	sink := io.Discard
	b.SetBytes(int64(resumeHeaderLen + benchChunk))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := writeResumeFrame(sink, uint64(i)*benchChunk, data, 0); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkWriteDataFrames32KBPadding600To1200 isolates the shaping codec from
// HTTP/TLS flush costs. It should stay allocation-free on the steady-state
// path even though one input buffer becomes many independently padded records.
func BenchmarkWriteDataFrames32KBPadding600To1200(b *testing.B) {
	data := make([]byte, benchChunk)
	policy := paddingPolicy{min: 600, max: 1200}
	b.SetBytes(benchChunk)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if n, err := writeResumeDataFrames(io.Discard, uint64(i)*benchChunk, data, policy); err != nil || n != len(data) {
			b.Fatalf("writeResumeDataFrames = %d, %v", n, err)
		}
	}
}

// BenchmarkReadFrame32KB decodes frames sequentially from a contiguous frame stream (server-side uplink / client-side downlink hot path).
func BenchmarkReadFrame32KB(b *testing.B) {
	const frames = 512
	stream := benchFrameBuffer(b, frames)
	payload := make([]byte, benchChunk)
	b.SetBytes(int64((resumeHeaderLen + benchChunk) * frames))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(stream)
		for {
			if _, _, _, err := readFrame(r, payload); err != nil {
				if err == io.EOF {
					break
				}
				b.Fatal(err)
			}
		}
	}
}

// BenchmarkRingAppendOverwrite32KB covers overwrite appends at full capacity (high-throughput steady state).
func BenchmarkRingAppendOverwrite32KB(b *testing.B) {
	rb := newRingBuffer(256)
	data := make([]byte, benchChunk)
	b.SetBytes(benchChunk)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rb.Append(data)
	}
}

// BenchmarkRingReadAt32KB reads from random positions inside the window (downlink replay hot path).
func BenchmarkRingReadAt32KB(b *testing.B) {
	rb := newRingBuffer(256)
	data := make([]byte, benchChunk)
	for i := 0; i < 8; i++ {
		rb.Append(data)
	}
	out := make([]byte, benchChunk)
	b.SetBytes(benchChunk)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seq := rb.WindowStartSeq() + uint64(i%4)*benchChunk
		if _, err := rb.ReadAt(seq, out); err != nil {
			b.Fatal(err)
		}
	}
}

// benchNewSession builds a session whose targetConn is a net.Pipe (the peer
// keeps draining) with an active stream attached to the given downlink writer.
func benchNewSession(b *testing.B, downlinkWriter io.Writer) *tunnelSession {
	b.Helper()
	table := &sessionTable{sessions: make(map[string]*tunnelSession)}
	serverConn, peerConn := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, peerConn) }()
	sess, _, err := table.getOrCreate("bench", func() (net.Conn, error) {
		return serverConn, nil
	}, 256, false, nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		sess.close()
		_ = peerConn.Close()
	})
	sess.setActiveWriter(&resumeSessionWriter{w: downlinkWriter})
	return sess
}

// BenchmarkSessionDownlinkWrite covers the one-way session downlink: s.mu + ring append + frame write.
func BenchmarkSessionDownlinkWrite(b *testing.B) {
	sess := benchNewSession(b, io.Discard)
	data := make([]byte, benchChunk)
	b.SetBytes(benchChunk)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := sess.writeDownlink(data); err != nil {
			b.Fatal(err)
		}
	}
}

// slowWriter simulates real network write latency (injecting a fixed delay per
// Write) to widen the downlink lock-held window and measure how much the
// uplink is dragged down by cross-locking.
type slowWriter struct{ d time.Duration }

func (w slowWriter) Write(p []byte) (int, error) {
	time.Sleep(w.d)
	return len(p), nil
}

// BenchmarkTunnelSessionUplinkUnderDownlink is the isolation benchmark under a
// true full-duplex shape: a single downlink pump goroutine keeps calling
// writeDownlink (the writer sleeps 50µs per frame to simulate network writes)
// while the uplink continuously calls acceptUplinkSeq in handler form,
// measuring uplink throughput. Before the lock split, uplink and downlink
// cross-locked (the downlink held s.mu for 50µs per frame, slowing the uplink
// by two orders of magnitude); after the split the uplink only serializes
// with itself and its throughput is independent.
func BenchmarkTunnelSessionUplinkUnderDownlink(b *testing.B) {
	sess := benchNewSession(b, slowWriter{d: 50 * time.Microsecond})
	data := make([]byte, benchChunk)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = sess.writeDownlink(data) // downlink pump form: the sole downlink writer
			}
		}
	}()
	b.Cleanup(func() { close(stop) })
	b.SetBytes(benchChunk)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := sess.acceptUplinkSeq(uint64(i)*benchChunk, data); err != nil {
			b.Fatal(err)
		}
	}
}
