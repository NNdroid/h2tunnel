package h2tunnel

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fragmentWriter emulates writers that legally accept only part of a buffer.
// Network code normally completes a Write, but the io.Writer contract does not
// promise that behaviour.
type fragmentWriter struct {
	buf   bytes.Buffer
	limit int
	zero  bool
}

type notifyingBuffer struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	written chan struct{}
	once    sync.Once
}

func (w *notifyingBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	n, err := w.buf.Write(p)
	w.mu.Unlock()
	w.once.Do(func() { close(w.written) })
	return n, err
}

func (w *notifyingBuffer) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buf.Bytes()...)
}

func (w *fragmentWriter) Write(p []byte) (int, error) {
	if w.zero {
		return 0, nil
	}
	n := len(p)
	if n > w.limit {
		n = w.limit
	}
	return w.buf.Write(p[:n])
}

func TestFrameWriterHandlesShortWritesAndFullPadding(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 4096)
	w := &fragmentWriter{limit: 31}
	if err := writeResumeFrame(w, 99, payload, 0xffff); err != nil {
		t.Fatalf("writeResumeFrame: %v", err)
	}

	gotPayload := make([]byte, len(payload))
	typ, seq, n, err := readFrame(&w.buf, gotPayload)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if typ != resumeFrameData || seq != 99 || n != len(payload) || !bytes.Equal(gotPayload[:n], payload) {
		t.Fatalf("frame mismatch: type=%#x seq=%d n=%d", typ, seq, n)
	}

	if err := writeResumeFrame(&fragmentWriter{zero: true}, 0, nil, 0); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero-byte write error = %v, want io.ErrShortWrite", err)
	}
}

func TestFrameValidationRejectsMalformedFields(t *testing.T) {
	var wire bytes.Buffer
	if err := writeFrame(&wire, 0xff, 0, nil, 0); err == nil {
		t.Fatal("unknown frame type was accepted")
	}
	if err := writeResumeFrame(&wire, 0, nil, -1); err == nil {
		t.Fatal("negative padding was accepted")
	}
	if err := writeFrame(&wire, resumeFrameEnd, 0, []byte("unexpected"), 0); err == nil {
		t.Fatal("END payload was accepted")
	}
}

func TestCDNStreamingHeadersAndMissingSessionID(t *testing.T) {
	responseHeaders := make(http.Header)
	setTunnelHeaders(responseHeaders)
	for key, want := range map[string]string{
		"Content-Type":      "application/octet-stream",
		"Cache-Control":     "no-store, no-transform",
		"Content-Encoding":  "identity",
		"X-Accel-Buffering": "no",
	} {
		if got := responseHeaders.Get(key); got != want {
			t.Errorf("response header %s = %q, want %q", key, got, want)
		}
	}
	requestHeaders := make(http.Header)
	setTunnelRequestHeaders(requestHeaders)
	if got := requestHeaders.Get("Accept-Encoding"); got != "identity" {
		t.Errorf("request Accept-Encoding = %q, want identity", got)
	}
	if got := requestHeaders.Get("Cache-Control"); got != "no-store, no-transform" {
		t.Errorf("request Cache-Control = %q, want no-store, no-transform", got)
	}

	// An empty ID used to create/reuse the shared map key "", which could make
	// unrelated clients share one target connection. It is now an explicit 400.
	req := httptest.NewRequest(http.MethodPost, "https://cdn.example/tunnel", bytes.NewReader(nil))
	req.Header.Set("X-Tunnel-Proto", resumeFrameTypeResume)
	req.Header.Set("X-Resume-Version", "2")
	req.Header.Set("X-Resume-Caps", "replay")
	req.Header.Set("X-Resume-Params", "window_kb=1")
	req.Header.Set("X-Network", "tcp")
	req.Header.Set("X-Target", "127.0.0.1:1")
	rr := httptest.NewRecorder()
	handleH2StreamResumeServer(rr, req, "missing-id", serverConfig{SessionWindow: 1}, &sessionTable{sessions: make(map[string]*tunnelSession)})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("missing session ID status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	if got := rr.Header().Get("X-Resume-Error"); got != resumeErrInvalidParams.String() {
		t.Errorf("X-Resume-Error = %q, want %q", got, resumeErrInvalidParams.String())
	}
}

func TestLocalOnlyTargetPolicy(t *testing.T) {
	cfg := serverConfig{LocalOnly: true}
	for _, target := range []string{"127.0.0.1:22", "127.0.0.42:22", "[::1]:22", "localhost:22"} {
		if !checkTargetIsAvailable(target, cfg) {
			t.Errorf("local target %q was rejected", target)
		}
	}
	for _, target := range []string{"10.0.0.1:22", "localhost.example:22", "[2001:db8::1]:22"} {
		if checkTargetIsAvailable(target, cfg) {
			t.Errorf("non-local target %q was accepted", target)
		}
	}
}

func TestSessionTableRejectsMissingIDAndUsesConfiguredWindow(t *testing.T) {
	table := &sessionTable{sessions: make(map[string]*tunnelSession)}
	dialed := false
	if _, _, err := table.getOrCreate("  ", func() (net.Conn, error) {
		dialed = true
		return nil, nil
	}, 1, false, nil, nil); !errors.Is(err, errSessionIDRequired) {
		t.Fatalf("missing id error = %v, want errSessionIDRequired", err)
	}
	if dialed {
		t.Fatal("missing session id dialed a target")
	}

	serverConn, peerConn := net.Pipe()
	sess, created, err := table.getOrCreate("window-test", func() (net.Conn, error) {
		return serverConn, nil
	}, 1, false, nil, nil)
	if err != nil || !created {
		t.Fatalf("create session: created=%v err=%v", created, err)
	}
	t.Cleanup(func() {
		sess.close()
		_ = peerConn.Close()
	})
	if got := len(sess.downlinkRing.buf); got != 1024 {
		t.Fatalf("server ring size = %d bytes, want configured 1024", got)
	}
}

func TestSessionTableDialDoesNotSerializeUnrelatedSessions(t *testing.T) {
	table := &sessionTable{sessions: make(map[string]*tunnelSession)}
	release := make(chan struct{})
	entered := make(chan string, 2)
	peers := make(chan net.Conn, 2)
	results := make(chan *tunnelSession, 2)
	errs := make(chan error, 2)

	start := func(id string) {
		go func() {
			sess, _, err := table.getOrCreate(id, func() (net.Conn, error) {
				entered <- id
				<-release
				serverConn, peerConn := net.Pipe()
				peers <- peerConn
				return serverConn, nil
			}, 1, false, nil, nil)
			if err != nil {
				errs <- err
				return
			}
			results <- sess
		}()
	}

	start("first")
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first dial did not start")
	}
	start("second")
	select {
	case <-entered:
		// The second dial entered before the first was released: table locking is
		// not on the slow dial path.
	case <-time.After(300 * time.Millisecond):
		t.Fatal("second session dial was blocked by an unrelated dial")
	}
	close(release)

	for range 2 {
		select {
		case err := <-errs:
			t.Fatalf("create session: %v", err)
		case sess := <-results:
			t.Cleanup(sess.close)
		case <-time.After(time.Second):
			t.Fatal("session creation did not finish")
		}
	}
	for range 2 {
		peer := <-peers
		t.Cleanup(func() { _ = peer.Close() })
	}
}

func TestMainStreamKeepaliveRoundTrip(t *testing.T) {
	// Client sender emits KEEPALIVE while the local application is idle.
	clientConn, appConn := net.Pipe()
	defer clientConn.Close()
	defer appConn.Close()
	upstream := &notifyingBuffer{written: make(chan struct{})}
	done := make(chan struct{})
	sendResult := make(chan error, 1)
	go func() {
		sendResult <- resumeSendLoop(upstream, clientConn, newResumeClientRingBuf(1), 0, done, 20*time.Millisecond)
	}()

	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()
	select {
	case <-upstream.written:
	case <-timeout.C:
		close(done)
		t.Fatal("idle client did not emit a KEEPALIVE frame")
	}
	close(done)
	_ = clientConn.SetReadDeadline(time.Now())
	if err := <-sendResult; err != nil {
		t.Fatalf("keepalive sender stopped with error: %v", err)
	}
	payload := make([]byte, 1)
	typ, _, _, err := readFrame(bytes.NewReader(upstream.Bytes()), payload)
	if err != nil || typ != resumeFrameKeepalive {
		t.Fatalf("upstream frame = %#x, %v; want KEEPALIVE", typ, err)
	}

	// The server acknowledges a main-stream KEEPALIVE rather than treating it
	// as application data.
	var serverInput bytes.Buffer
	if err := writeFrame(&serverInput, resumeFrameKeepalive, 0, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := writeResumeEndFrame(&serverInput); err != nil {
		t.Fatal(err)
	}
	var serverOutput bytes.Buffer
	sess := &tunnelSession{downlinkRing: newRingBuffer(1)}
	serveResumeDataPlane(sess, &serverInput, &resumeSessionWriter{w: &serverOutput}, defaultParams(), 0, "keepalive-test", true, sess.clearActiveWriter)
	typ, _, _, err = readFrame(&serverOutput, payload)
	if err != nil || typ != resumeFrameKeepaliveAck {
		t.Fatalf("server frame = %#x, %v; want KEEPALIVE-ACK", typ, err)
	}

	// The receiver drops the ACK and continues the ordered data stream.
	var downstream bytes.Buffer
	if err := writeFrame(&downstream, resumeFrameKeepaliveAck, 0, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := writeResumeFrame(&downstream, 0, []byte("ok"), 0); err != nil {
		t.Fatal(err)
	}
	if err := writeResumeEndFrame(&downstream); err != nil {
		t.Fatal(err)
	}
	localConn, consumer := net.Pipe()
	defer localConn.Close()
	defer consumer.Close()
	var watermark uint64
	recvResult := make(chan error, 1)
	go func() { recvResult <- resumeRecvLoop(&downstream, localConn, &watermark) }()
	got := make([]byte, 2)
	if _, err := io.ReadFull(consumer, got); err != nil || string(got) != "ok" {
		t.Fatalf("received data = %q, %v", got, err)
	}
	if err := <-recvResult; err != nil {
		t.Fatalf("receiver error: %v", err)
	}
	if watermark != 2 {
		t.Fatalf("downlink watermark = %d, want 2", watermark)
	}
}
