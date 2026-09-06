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
// 数据面微基准：帧编解码 / ring / 会话下行。
//
// 端到端基准（benchmark_test.go、public_api_test.go）测的是整条链路，
// 热路径回归时定位不到层；这里给帧编解码、ringBuffer、writeDownlink
// 建立 ns/op 与 allocs/op 基线。全双工互锁（s.mu 竞争）另见
// BenchmarkTunnelSessionFullDuplex。
// =========================================

const benchChunk = 32 * 1024

// benchFrameBuffer 构造 nFrames 个 32KB DATA 帧的连续字节流。
func benchFrameBuffer(b *testing.B, nFrames int) []byte {
	b.Helper()
	// 先构建单个完整帧（含显式 padLen=0 —— 否则前一帧的数据填充会把
	// 后续帧头的 padLen 覆盖成非零，读端 io.CopyN 消费填充字节后失步），
	// 再按 seq 递增复制 nFrames 份。
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

// BenchmarkWriteFrame32KB 池化整帧单写快路径（writeFrame 路径 A）。
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

// BenchmarkReadFrame32KB 从连续帧流顺序解帧（服务端上行 / 客户端下行热路径）。
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

// BenchmarkRingAppendOverwrite32KB 满载覆盖写（高吞吐稳态）。
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

// BenchmarkRingReadAt32KB 窗口内随机位置读（下行重放热路径）。
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

// benchNewSession 构造一个 targetConn 接 net.Pipe（对端持续排空）的会话，
// 并挂上指定下行 writer 的活跃流。
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

// BenchmarkSessionDownlinkWrite 会话下行单方向：s.mu + ring 追加 + 帧写。
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

// slowWriter 模拟真实网络写的延迟（每 Write 注入固定耗时），
// 用于放大下行持锁窗口，度量上行被互锁拖累的程度。
type slowWriter struct{ d time.Duration }

func (w slowWriter) Write(p []byte) (int, error) {
	time.Sleep(w.d)
	return len(p), nil
}

// BenchmarkTunnelSessionUplinkUnderDownlink 真实全双工形态的隔离度基准：
// 单一下行泵 goroutine 持续 writeDownlink（writer 每帧 50µs 模拟网络写），
// 上行按 handler 形态连续 acceptUplinkSeq，度量上行吞吐。
// 拆锁前上行与下行互锁（下行每帧持 s.mu 50µs，上行被拖慢两个数量级）；
// 拆锁后上行只与自身串行化，吞吐独立。
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
				_, _ = sess.writeDownlink(data) // 下行泵形态：唯一下行写者
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
