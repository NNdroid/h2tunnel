package h2tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestSessionReservationsAndResumeAtCapacity(t *testing.T) {
	for _, perPrincipal := range []bool{false, true} {
		t.Run(fmt.Sprint(perPrincipal), func(t *testing.T) {
			table := &sessionTable{sessions: make(map[string]*tunnelSession), maxSessions: 1}
			if perPrincipal {
				table.maxSessions = 0
				table.maxPerPrincipal = 1
			}
			defer table.closeAll()
			started, release := make(chan struct{}), make(chan struct{})
			result := make(chan error, 1)
			a, b := net.Pipe()
			defer b.Close()
			go func() {
				_, _, err := table.getOrCreate("first", func() (net.Conn, error) {
					close(started)
					<-release
					return a, nil
				}, 1, false, nil, nil)
				result <- err
			}()
			<-started
			var dials atomic.Int64
			dial := func() (net.Conn, error) { dials.Add(1); return nil, errors.New("unexpected dial") }
			var wg sync.WaitGroup
			for i := 0; i < 32; i++ {
				wg.Go(func() {
					_, _, err := table.getOrCreate(newSessionID(), dial, 1, false, nil, nil)
					if !errors.Is(err, errSessionLimitExceeded) {
						t.Errorf("admission: %v", err)
					}
				})
			}
			wg.Wait()
			close(release)
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			if dials.Load() != 0 {
				t.Fatal("capacity gate dialed a target")
			}
			_, isNew, err := table.getOrCreate("first", dial, 1, false, nil, nil)
			if err != nil || isNew {
				t.Fatalf("resume at capacity: new=%v err=%v", isNew, err)
			}
		})
	}
}

func TestSessionReservationReleasedAndShutdown(t *testing.T) {
	table := &sessionTable{sessions: make(map[string]*tunnelSession), maxSessions: 1}
	_, _, _ = table.getOrCreate("failed", func() (net.Conn, error) { return nil, io.EOF }, 1, false, nil, nil)
	if table.pending != 0 || len(table.pendingPrincipal) != 0 {
		t.Fatal("failed dial retained its reservation")
	}
	started, release := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	a, b := net.Pipe()
	defer b.Close()
	go func() {
		_, _, err := table.getOrCreate("late", func() (net.Conn, error) {
			close(started)
			<-release
			return a, nil
		}, 1, false, nil, nil)
		result <- err
	}()
	<-started
	table.closeAll()
	close(release)
	if err := <-result; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("late admission: %v", err)
	}
	if len(table.sessions) != 0 || table.pending != 0 {
		t.Fatal("late dial survived shutdown")
	}
	if _, err := b.Write([]byte("x")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("losing target connection not closed: %v", err)
	}
}

func TestUDPSessionDoesNotAllocateReplayRing(t *testing.T) {
	table := &sessionTable{sessions: make(map[string]*tunnelSession)}
	defer table.closeAll()
	a, b := net.Pipe()
	defer b.Close()
	s, _, err := table.getOrCreate("udp", func() (net.Conn, error) { return a, nil }, maxWindowKB, true, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.downlinkRing != nil {
		t.Fatal("UDP allocated an unused replay ring")
	}
}

type countingFlushWriter struct {
	bytes.Buffer
	flushes int
}

func (w *countingFlushWriter) Flush() { w.flushes++ }

func TestPaddedChunkFlushPreservesFramesAndControls(t *testing.T) {
	sink := &countingFlushWriter{}
	w := &resumeSessionWriter{w: sink, flusher: sink, padding: paddingPolicy{min: 600, max: 1200}}
	want := bytes.Repeat([]byte("payload"), 5000)
	if n, err := w.writeFrame(123, want); err != nil || n != len(want) {
		t.Fatalf("write: %d %v", n, err)
	}
	if sink.flushes != 1 {
		t.Fatalf("data flushes=%d, want 1", sink.flushes)
	}
	var got []byte
	buf := make([]byte, 65536)
	for len(got) < len(want) {
		typ, seq, n, err := readFrame(&sink.Buffer, buf)
		if err != nil || typ != resumeFrameData || seq != 123+uint64(len(got)) {
			t.Fatalf("frame: %d %d %v", typ, seq, err)
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("batch changed payload")
	}
	if err := w.writeControl(resumeFrameKeepaliveAck, nil); err != nil {
		t.Fatal(err)
	}
	if sink.flushes != 2 {
		t.Fatal("control frame not flushed immediately")
	}
	if _, err := w.writeFrame(uint64(len(want))+123, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if sink.flushes != 3 {
		t.Fatal("interactive write not flushed immediately")
	}
}

func TestDatagramQueueCloseWakesBlockedWriterAndDrains(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q := newDatagramQueue(1)
		p := newVirtualPacketConn("target", func() {})
		p.attachWTTunnel(q, q.done, closeFunc(q.close))
		if _, err := p.Write([]byte("first")); err != nil {
			t.Fatal(err)
		}
		finished := make(chan error, 1)
		go func() { _, err := p.Write([]byte("second")); finished <- err }()
		synctest.Wait()
		p.Close()
		if err := <-finished; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("blocked write: %v", err)
		}
		if len(q.packets) != 0 {
			t.Fatal("close retained queued buffers")
		}
		if _, err := p.Write([]byte("late")); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("write after close: %v", err)
		}
		if len(q.packets) != 0 {
			t.Fatal("enqueue after drain")
		}
	})
}

func TestDatagramPoolSizesAndOwnership(t *testing.T) {
	for _, size := range []int{0, 1, 2048, 2049, 8192, 8193, 32768, 32769, maxTunnelUDPPayload} {
		original := bytes.Repeat([]byte{42}, size)
		p := copyDatagram(original)
		if !bytes.Equal(original, p.Data) {
			t.Fatalf("payload truncated at %d", size)
		}
		clear(original)
		if size > 0 && p.Data[0] != 42 {
			t.Fatal("queue borrowed caller memory")
		}
		releaseDatagram(p)
	}
}

type rejectionTransport struct{ calls atomic.Int64 }

func (r *rejectionTransport) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls.Add(1)
	return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
}

func TestUDPAuthenticationFailureStopsAutoRedial(t *testing.T) {
	rt := &rejectionTransport{}
	s := newUDPSession("denied", clientConfig{AutoRedial: true}, "http://example.com", &http.Client{Transport: rt}, nil, nil)
	s.run()
	if rt.calls.Load() != 1 {
		t.Fatalf("auth retried %d times", rt.calls.Load())
	}
}

func TestRetryDelayBounds(t *testing.T) {
	for _, attempt := range []int{0, 1, 16, 25, 1000000000} {
		base := time.Duration(max(1, min(25, attempt))) * 200 * time.Millisecond
		for i := 0; i < 100; i++ {
			d := resumeRetryDelay(attempt)
			if d < base || d >= 2*base {
				t.Fatalf("retry %d: %v", attempt, d)
			}
		}
	}
}

func TestFatalRejectionClassification(t *testing.T) {
	for _, status := range []int{401, 403, 407, 426} {
		if !isFatalTunnelError(newTunnelHTTPError(status)) {
			t.Fatalf("status %d retried", status)
		}
	}
	for _, status := range []int{429, 500, 502, 503} {
		if isFatalTunnelError(newTunnelHTTPError(status)) {
			t.Fatalf("transient status %d stopped", status)
		}
	}
}

func BenchmarkDatagramPoolCopy(b *testing.B) {
	for _, size := range []int{1200, 16384} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			p := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				d := copyDatagram(p)
				releaseDatagram(d)
			}
		})
	}
}

func BenchmarkPacketConnQueueWrite(b *testing.B) {
	for _, size := range []int{1200, 16384} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			q := newDatagramQueue(1)
			p := newVirtualPacketConn("target", func() {})
			p.attachWTTunnel(q, q.done, closeFunc(q.close))
			defer p.Close()
			payload := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := p.Write(payload); err != nil {
					b.Fatal(err)
				}
				releaseDatagram(<-q.packets)
			}
		})
	}
}

func TestDatagramEnqueueCancelled(t *testing.T) {
	s := newUDPSession("cancelled", clientConfig{}, "", nil, nil, nil)
	defer s.close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Fill the queue so cancellation is the only eligible transfer outcome.
	for i := 0; i < cap(s.upstream.packets); i++ {
		s.enqueue([]byte("x"))
	}
	if err := s.enqueueContext(ctx, []byte("y")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestPauseDetachedTargetReads(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := net.Pipe()
		s := &tunnelSession{targetConn: a, downlinkRing: newRingBuffer(1), pauseDetachedRead: true}
		defer b.Close()
		defer s.close()
		go s.downlinkPump()
		first := make(chan error, 1)
		go func() { _, err := b.Write([]byte("before attach")); first <- err }()
		synctest.Wait()
		select {
		case <-first:
			t.Fatal("detached pump read target")
		default:
		}
		w := &resumeSessionWriter{w: io.Discard}
		if err := s.attachAndReplay(w, 0); err != nil {
			t.Fatal(err)
		}
		if err := <-first; err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		s.clearActiveWriter(w)
		// One previously started read may complete; the next must pause.
		if _, err := b.Write([]byte("in flight")); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		before := s.downlinkRing.WindowEnd()
		second := make(chan error, 1)
		go func() { _, err := b.Write([]byte("paused")); second <- err }()
		synctest.Wait()
		select {
		case <-second:
			t.Fatal("pump kept reading while detached")
		default:
		}
		if s.downlinkRing.WindowEnd() != before {
			t.Fatal("detached read changed replay window")
		}
		if err := s.attachAndReplay(&resumeSessionWriter{w: io.Discard}, 0); err != nil {
			t.Fatal(err)
		}
		if err := <-second; err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		got := make([]byte, s.downlinkRing.WindowEnd())
		s.downlinkRing.ReadAt(0, got)
		if string(got) != "before attachin flightpaused" {
			t.Fatalf("recovery data=%q", got)
		}
	})
}

func TestQUICReceiveWindowValidationAndWiring(t *testing.T) {
	for _, bad := range []QUICReceiveWindowTuning{
		{MaxStreamBytes: 257 << 20}, {MaxStreamBytes: 1},
		{InitialStreamBytes: 9 << 20}, {InitialConnectionBytes: 21 << 20},
		{MaxStreamBytes: 24 << 20}, {InitialStreamBytes: 1 << 20},
	} {
		if err := bad.Validate(); err == nil {
			t.Fatalf("accepted invalid windows: %+v", bad)
		}
	}
	w := QUICReceiveWindowTuning{InitialStreamBytes: 1 << 20, InitialConnectionBytes: 2 << 20, MaxStreamBytes: 16 << 20, MaxConnectionBytes: 32 << 20}
	if err := w.Validate(); err != nil {
		t.Fatal(err)
	}
	c := w.config()
	if c.InitialStreamReceiveWindow != w.InitialStreamBytes || c.InitialConnectionReceiveWindow != w.InitialConnectionBytes || c.MaxStreamReceiveWindow != w.MaxStreamBytes || c.MaxConnectionReceiveWindow != w.MaxConnectionBytes {
		t.Fatal("QUIC tuning lost")
	}
	if d := (QUICReceiveWindowTuning{}).config(); d.MaxStreamReceiveWindow != 8<<20 || d.MaxConnectionReceiveWindow != 20<<20 || d.InitialStreamReceiveWindow != 0 || d.InitialConnectionReceiveWindow != 0 {
		t.Fatal("default windows changed")
	}
	tlsConfig, err := SelfSignedTLSConfig("localhost")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(ServerOptions{TLSConfig: tlsConfig, Transports: []Transport{TransportH3}, Authenticator: tokenAuth("token"), Dialer: anyTargetDialer(), Tuning: ServerTuning{QUICReceiveWindow: w, PauseDetachedRead: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.wtServer.H3.QUICConfig.MaxStreamReceiveWindow != w.MaxStreamBytes || !s.sessions.pauseDetachedRead {
		t.Fatal("server ignored tuning")
	}
	client, err := NewClient(ClientOptions{Endpoint: "https://localhost", Transport: TransportH3, Tuning: ClientTuning{QUICReceiveWindow: w}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.cfg.QUICReceiveWindow != w {
		t.Fatal("client ignored tuning")
	}
}

func TestIncomingDatagramCloseDrainsBlockedDelivery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newVirtualPacketConn("target", func() {})
		for i := 0; i < cap(p.incoming); i++ {
			if err := p.deliver([]byte("x")); err != nil {
				t.Fatal(err)
			}
		}
		done := make(chan error, 1)
		go func() { done <- p.deliver([]byte("blocked")) }()
		synctest.Wait()
		p.Close()
		if err := <-done; !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
		if len(p.incoming) != 0 {
			t.Fatal("close retained inbound buffers")
		}
	})
}

type appendDuringReplayWriter struct {
	bytes.Buffer
	append func()
}

func (w *appendDuringReplayWriter) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	if w.append != nil {
		f := w.append
		w.append = nil
		f()
	}
	return n, err
}

func TestReplayStopsAtSnapshotDuringAppend(t *testing.T) {
	s := &tunnelSession{downlinkRing: newRingBuffer(64), downlinkSent: 10000}
	s.downlinkRing.Append(bytes.Repeat([]byte{1}, 10000))
	sink := &appendDuringReplayWriter{append: func() {
		s.downlinkRing.Append(bytes.Repeat([]byte{2}, 8000))
		s.mu.Lock()
		s.downlinkSent += 8000
		s.mu.Unlock()
	}}
	w := &resumeSessionWriter{w: sink}
	s.downlinkMu.Lock()
	err := s.replayDownlinkLocked(w, 0)
	s.downlinkMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if s.frameSentSeq != 10000 {
		t.Fatalf("replay consumed live tail: %d", s.frameSentSeq)
	}
	buf := make([]byte, 32768)
	total := 0
	for {
		_, seq, n, err := readFrame(&sink.Buffer, buf)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if seq != uint64(total) {
			t.Fatal("replay sequence changed")
		}
		total += n
	}
	if total != 10000 {
		t.Fatalf("replayed %d bytes", total)
	}
}

type partialWriteTarget struct {
	net.Conn
	bytes.Buffer
	fail bool
}

func (c *partialWriteTarget) Read([]byte) (int, error) { return 0, io.EOF }

func (c *partialWriteTarget) Write(p []byte) (int, error) {
	if c.fail {
		c.fail = false
		n, _ := c.Buffer.Write(p[:3])
		return n, io.ErrUnexpectedEOF
	}
	return c.Buffer.Write(p)
}

func TestUplinkWatermarkCommitsOnlyWrittenBytes(t *testing.T) {
	c := &partialWriteTarget{fail: true}
	s := &tunnelSession{targetConn: c}
	payload := []byte("recover without duplicates")
	if err := s.acceptUplinkSeq(0, payload); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	if s.uplinkRecv != 3 {
		t.Fatalf("acknowledged unwritten data: %d", s.uplinkRecv)
	}
	if err := s.acceptUplinkSeq(0, payload); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.Bytes(), payload) || s.uplinkRecv != uint64(len(payload)) {
		t.Fatal("partial write recovery lost or duplicated data")
	}
}
