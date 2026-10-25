package h2tunnel

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
)

// TestBuildResumeRequestDownlink guards that the generated request's
// X-Resume-Downlink reflects "locally received downlink bytes
// (clientDownlink)", not the uplink ring cursor (ringBuf.WindowEnd()).
// Regression: the h2 path previously misused ringBuf.WindowEnd() (uplink
// coordinates) as the downlink watermark, so after a reconnect the server
// replayed from a wrong offset and the client's first frame seq mismatched
// → errGap → resume failure.
func TestBuildResumeRequestDownlink(t *testing.T) {
	base := clientConfig{
		ServerUrl:     "https://cdn.example.com",
		Path:          "/tunnel",
		TargetAddr:    "db.internal:5432",
		Token:         "sekret",
		Network:       "tcp",
		SessionWindow: 256,
	}

	dl := uint64(1234)
	req := buildResumeRequest(context.Background(), strings.NewReader(""), "sess-1", &dl, newResumeClientRingBuf(256), base.ServerUrl+base.Path, base)
	if got := req.Header.Get("X-Resume-Downlink"); got != "1234" {
		t.Fatalf("X-Resume-Downlink = %q, want 1234 (must reflect clientDownlink, not the uplink ring cursor)", got)
	}

	// Zero value: first stream clientDownlink=0, server replays nothing.
	var zero uint64
	req0 := buildResumeRequest(context.Background(), strings.NewReader(""), "sess-1", &zero, newResumeClientRingBuf(256), base.ServerUrl+base.Path, base)
	if got := req0.Header.Get("X-Resume-Downlink"); got != "0" {
		t.Fatalf("X-Resume-Downlink(zero) = %q, want 0", got)
	}
}

// TestResumeRecvLoopDownlinkWatermark guards that resumeRecvLoop uses
// *clientDownlink as the downlink coordinate origin (first stream=0,
// reconnected stream=bytes already received) and keeps writing delivered
// bytes back into *clientDownlink for the next reconnect report. Covers the
// resume semantics of both h2 (resumeRecvLoop) and WT (resumeRecvLoopWT
// sharing the same expected initialization).
func TestResumeRecvLoopDownlinkWatermark(t *testing.T) {
	const seg = 100

	runCase := func(name string, start uint64, seqs []uint64, wantDelivered uint64, wantErr error) {
		t.Run(name, func(t *testing.T) {
			localConn, testConn := net.Pipe()
			defer localConn.Close()
			defer testConn.Close()
			pr, pw := io.Pipe()

			var clientDownlink uint64 = start
			var recvErr error
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				recvErr = resumeRecvLoop(pr, localConn, &clientDownlink, discardLogger, nil)
			}()

			// Write frames in a separate goroutine to avoid the deadlock caused by net.Pipe's synchronous writes.
			go func() {
				data := bytes.Repeat([]byte("x"), seg)
				for _, s := range seqs {
					_ = writeResumeFrame(pw, s, data, 0)
				}
				_ = pw.Close()
			}()

			if wantErr == nil {
				buf := make([]byte, len(seqs)*seg)
				if _, err := io.ReadFull(testConn, buf); err != nil {
					t.Fatalf("failed to read downlink data: %v", err)
				}
			}
			wg.Wait()

			if wantErr == nil {
				if clientDownlink != wantDelivered {
					t.Fatalf("clientDownlink = %d, want %d", clientDownlink, wantDelivered)
				}
				// In a real client: a stream ending normally with an END frame → err=nil; a
				// stream closed without END → err=io.EOF, and the caller reconnects. Both are
				// "no gap, watermark advances correctly".
				// What must truly be guarded: the first frame of a reconnected stream with
				// seq=clientDownlink must not be judged as errGap.
				if recvErr != nil && !errorsIs(recvErr, io.EOF) {
					t.Fatalf("%s: expected clean end or EOF (reconnect path), got err=%v", name, recvErr)
				}
				t.Logf("✅ %s: resume OK, clientDownlink=%d, err=%v", name, clientDownlink, recvErr)
			} else {
				if !errorsIs(recvErr, wantErr) {
					t.Fatalf("%s: err = %v, want %v", name, recvErr, wantErr)
				}
				if clientDownlink != start {
					t.Fatalf("%s: gap scenario clientDownlink should stay %d, got %d", name, start, clientDownlink)
				}
				t.Logf("✅ %s: gap correctly detected as %v, clientDownlink stays %d", name, wantErr, clientDownlink)
			}
		})
	}

	// First stream: starts at 0, receives 3 segments → 0,100,200, 300 bytes received.
	runCase("first stream starts at 0", 0, []uint64{0, 100, 200}, 300, nil)
	// Reconnected stream: starts at 500, receives 500,600,700, 800 bytes received.
	runCase("reconnected stream starts at clientDownlink", 500, []uint64{500, 600, 700}, 800, nil)
	// Gap: expects 0 but first frame is 500 → errGap, clientDownlink unchanged.
	runCase("gap detected as ErrGap", 0, []uint64{500, 600, 700}, 0, errGap)
}

// TestResumeRecvLoopDeliversEveryByteOnAPartialWrite guards against reporting
// bytes as delivered when the application never received them. A tunnel conn
// whose Write returns a partial count must be drained, because the frame seq
// is already correct and no continuity check can see the hole. The next stream
// would resume from an offset past it and the lost bytes would never be
// replayed.
func TestResumeRecvLoopDeliversEveryByteOnAPartialWrite(t *testing.T) {
	const seg = 64
	const frames = 3
	const limit = 21

	for name, loop := range map[string]func(io.Reader, net.Conn, *uint64, *slog.Logger, *ClientStats) error{
		"h2": resumeRecvLoop,
		"WT": resumeRecvLoopWT,
	} {
		loop := loop
		t.Run(name, func(t *testing.T) {
			conn := &partialWriterConn{limit: limit}
			in := newResumeDataFrameStream(seg, frames)
			var clientDownlink uint64
			recvErr := loop(in, conn, &clientDownlink, discardLogger, nil)
			if recvErr != nil && !errorsIs(recvErr, io.EOF) {
				t.Fatalf("err = %v, want clean end or EOF", recvErr)
			}

			want := seg * frames
			if got := len(conn.written); got != want {
				t.Fatalf("the application received %d bytes, want %d", got, want)
			}
			if clientDownlink != uint64(want) {
				t.Fatalf("clientDownlink = %d, want %d", clientDownlink, want)
			}
			if conn.calls < frames {
				t.Fatalf("only %d Write calls, want at least %d; the partial-write path was not exercised", conn.calls, frames)
			}
		})
	}
}

// partialWriterConn accepts at most limit bytes per Write, so every call from
// resumeRecvLoop returns a partial count.
type partialWriterConn struct {
	net.Conn
	limit   int
	written []byte
	calls   int
}

func (w *partialWriterConn) Write(p []byte) (int, error) {
	n := len(p)
	if n > w.limit {
		n = w.limit
	}
	w.calls++
	w.written = append(w.written, p[:n]...)
	return n, nil
}

func (w *partialWriterConn) Close() error { return nil }

// newResumeDataFrameStream builds a reader of `frames` contiguous resume DATA
// frames of `seg` bytes each, starting at seq 0, followed by EOF. It mirrors
// the wire shape resumeRecvLoop consumes.
func newResumeDataFrameStream(seg, frames int) *bytes.Reader {
	var wire bytes.Buffer
	data := bytes.Repeat([]byte("y"), seg)
	for i := 0; i < frames; i++ {
		if err := writeResumeFrame(&wire, uint64(i*seg), data, 0); err != nil {
			panic(err)
		}
	}
	return bytes.NewReader(wire.Bytes())
}

// errorsIs is a small wrapper to avoid import ambiguity with errors in test files.
func errorsIs(err, target error) bool {
	if err == nil || target == nil {
		return err == target
	}
	return err.Error() == target.Error() || err == target
}
