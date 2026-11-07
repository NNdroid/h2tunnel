package h2tunnel

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// countingTarget records every Write call and its bytes. Read blocks forever
// so nothing else consumes the conn; deadlines are ignored.
type countingTarget struct {
	net.Conn
	mu     sync.Mutex
	buf    bytes.Buffer
	writes int
}

func (c *countingTarget) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	return c.buf.Write(p)
}

func (c *countingTarget) Read([]byte) (int, error) {
	select {}
}

// truncatingTarget accepts only failN bytes of the next oversized Write and
// errors once, modelling a target socket that died mid-write.
type truncatingTarget struct {
	net.Conn
	mu    sync.Mutex
	buf   bytes.Buffer
	failN int
}

func (c *truncatingTarget) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failN > 0 && c.failN < len(p) {
		n := c.failN
		c.failN = 0
		c.buf.Write(p[:n])
		return n, io.ErrUnexpectedEOF
	}
	return c.buf.Write(p)
}

func (c *truncatingTarget) Read([]byte) (int, error) { return 0, io.EOF }

func (c *countingTarget) snapshot() (int, []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes, append([]byte(nil), c.buf.Bytes()...)
}

const benchChunkBytes = 32 << 10

func bulkFrame(t *testing.T, idx byte) []byte {
	t.Helper()
	p := make([]byte, benchChunkBytes)
	for i := range p {
		p[i] = idx
	}
	return p
}

// Four bulk frames must coalesce into one target write at the 128KiB batch
// target, delivered in order, with the watermark advancing only at the flush.
func TestUplinkBatchCoalescesBulkWrites(t *testing.T) {
	c := &countingTarget{}
	s := &tunnelSession{targetConn: c}
	for i := 0; i < 4; i++ {
		if err := s.acceptUplinkSeq(uint64(i)*benchChunkBytes, bulkFrame(t, byte(i))); err != nil {
			t.Fatal(err)
		}
	}
	writes, got := c.snapshot()
	if writes != 1 {
		t.Fatalf("bulk frames produced %d target writes, want 1", writes)
	}
	if len(got) != 4*benchChunkBytes {
		t.Fatalf("target received %d bytes, want %d", len(got), 4*benchChunkBytes)
	}
	for i := range got {
		if want := byte(i / benchChunkBytes); got[i] != want {
			t.Fatalf("byte %d is 0x%02x, want 0x%02x (ordering broken)", i, got[i], want)
		}
	}
	if s.uplinkRecv != 4*benchChunkBytes {
		t.Fatalf("watermark %d, want %d", s.uplinkRecv, 4*benchChunkBytes)
	}
}

// A small (interactive) frame must flush immediately and drain any pending
// bulk ahead of it, in order, in a single coalesced write.
func TestUplinkBatchFlushesOnSmallFrame(t *testing.T) {
	c := &countingTarget{}
	s := &tunnelSession{targetConn: c}
	if err := s.acceptUplinkSeq(0, bulkFrame(t, 1)); err != nil {
		t.Fatal(err)
	}
	if err := s.acceptUplinkSeq(benchChunkBytes, bulkFrame(t, 2)); err != nil {
		t.Fatal(err)
	}
	if writes, _ := c.snapshot(); writes != 0 {
		t.Fatalf("batched frames flushed early: %d writes", writes)
	}
	if s.uplinkRecv != 0 {
		t.Fatalf("unflushed bytes committed: %d", s.uplinkRecv)
	}
	small := []byte("keystroke")
	if err := s.acceptUplinkSeq(2*benchChunkBytes, small); err != nil {
		t.Fatal(err)
	}
	writes, got := c.snapshot()
	if writes != 1 {
		t.Fatalf("small frame produced %d writes, want 1 coalesced write", writes)
	}
	if !bytes.Equal(got[:2*benchChunkBytes], append(bulkFrame(t, 1), bulkFrame(t, 2)...)) {
		t.Fatal("pending bulk bytes corrupted by small frame")
	}
	if !bytes.Equal(got[2*benchChunkBytes:], small) {
		t.Fatal("small frame not delivered last")
	}
	if s.uplinkRecv != uint64(2*benchChunkBytes+len(small)) {
		t.Fatalf("watermark %d after flush", s.uplinkRecv)
	}
}

// A batch older than the latency cap is flushed by the next accepted frame
// even when it is far below the byte target, and the fresh frame batches on.
func TestUplinkBatchLatencyCap(t *testing.T) {
	c := &countingTarget{}
	s := &tunnelSession{targetConn: c}
	if err := s.acceptUplinkSeq(0, bulkFrame(t, 1)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * uplinkFlushDelay)
	if err := s.acceptUplinkSeq(benchChunkBytes, bulkFrame(t, 2)); err != nil {
		t.Fatal(err)
	}
	writes, got := c.snapshot()
	if writes != 1 || len(got) != benchChunkBytes {
		t.Fatalf("expired batch not flushed: %d writes, %d bytes", writes, len(got))
	}
	if s.uplinkRecv != benchChunkBytes {
		t.Fatalf("watermark %d, want the flushed frame only", s.uplinkRecv)
	}
	if len(s.uplinkBuf) != benchChunkBytes {
		t.Fatalf("fresh frame not batched: %d buffered", len(s.uplinkBuf))
	}
}

// A target that dies mid-write commits only the confirmed prefix; the rest of
// the batch is dropped so the client replays it without duplication.
func TestUplinkFlushErrorDropsTail(t *testing.T) {
	c := &truncatingTarget{failN: 16 << 10}
	s := &tunnelSession{targetConn: c}
	if err := s.acceptUplinkSeq(0, bulkFrame(t, 1)); err != nil {
		t.Fatal(err)
	}
	// Force the flush with a small frame (coalesces the pending bulk).
	err := s.acceptUplinkSeq(benchChunkBytes, []byte("x"))
	if err == nil {
		t.Fatal("expected the truncated write to surface an error")
	}
	if s.uplinkRecv != 16<<10 {
		t.Fatalf("watermark %d, want only the confirmed 16KiB", s.uplinkRecv)
	}
	if len(s.uplinkBuf) != 0 {
		t.Fatalf("tail not dropped: %d bytes still buffered", len(s.uplinkBuf))
	}
	if got := c.buf.Bytes(); len(got) != 16<<10 {
		t.Fatalf("target received %d bytes, want 16KiB", len(got))
	}
	// The next stream replays from the watermark: the trimmed remainder is
	// accepted (and batched again, as bulk), and the resume watermark snapshot
	// flushes it — the target ends up with the whole frame exactly once.
	c.mu.Lock()
	c.failN = 0
	c.mu.Unlock()
	if err := s.acceptUplinkSeq(16<<10, bulkFrame(t, 1)[16<<10:]); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.uplinkCommitted(); got != benchChunkBytes {
		t.Fatalf("watermark %d after replay commit, want %d", got, benchChunkBytes)
	}
	if got := c.buf.Bytes(); len(got) != benchChunkBytes || !bytes.Equal(got[:16<<10], bulkFrame(t, 1)[:16<<10]) {
		t.Fatalf("target stream inconsistent after replay: %d bytes", len(got))
	}
}

// The resume watermark snapshot must first drain the batch: a client resuming
// from a watermark that excludes buffered bytes would make the target receive
// them twice (once from the flush, once replayed).
func TestUplinkWatermarkCoversBatchOnResume(t *testing.T) {
	c := &countingTarget{}
	s := &tunnelSession{targetConn: c}
	if err := s.acceptUplinkSeq(0, bulkFrame(t, 1)); err != nil {
		t.Fatal(err)
	}
	if err := s.acceptUplinkSeq(benchChunkBytes, bulkFrame(t, 2)); err != nil {
		t.Fatal(err)
	}
	got, ok := s.uplinkCommitted()
	if !ok {
		t.Fatal("stream session must report a watermark")
	}
	if got != 2*benchChunkBytes {
		t.Fatalf("watermark %d excludes batched bytes", got)
	}
	writes, flushed := c.snapshot()
	if writes != 1 || len(flushed) != 2*benchChunkBytes {
		t.Fatalf("resume drain wrote %d frames / %d bytes", writes, len(flushed))
	}
	if len(s.uplinkBuf) != 0 {
		t.Fatalf("batch not drained: %d bytes", len(s.uplinkBuf))
	}
}

// flushPendingUplink on a dead target drops the batch without committing it,
func TestUplinkFlushPendingOnDeadTarget(t *testing.T) {
	c := &truncatingTarget{}
	s := &tunnelSession{targetConn: c}
	if err := s.acceptUplinkSeq(0, bulkFrame(t, 1)); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.targetConn = nil
	s.mu.Unlock()
	if err := s.flushPendingUplink(); err == nil {
		t.Fatal("expected ErrClosed for a nil target")
	}
	if s.uplinkRecv != 0 {
		t.Fatalf("watermark advanced on a dead target: %d", s.uplinkRecv)
	}
	if len(s.uplinkBuf) != 0 {
		t.Fatalf("batch not dropped: %d bytes", len(s.uplinkBuf))
	}
}

// A request that ENDS mid-batch (request-response traffic: the app writes and
// then waits for a reply) must not wait for another uplink frame to flush the
// tail — none will ever come. The per-batch timer delivers it.
func TestUplinkBatchTailFlushedByTimer(t *testing.T) {
	c := &countingTarget{}
	s := &tunnelSession{targetConn: c}
	for i := 0; i < 3; i++ {
		if err := s.acceptUplinkSeq(uint64(i)*benchChunkBytes, bulkFrame(t, byte(i))); err != nil {
			t.Fatal(err)
		}
	}
	if writes, _ := c.snapshot(); writes != 0 {
		t.Fatalf("sub-target batch flushed early: %d writes", writes)
	}
	// No further frames, no explicit flush: the timer must deliver the tail.
	deadline := time.Now().Add(2*uplinkFlushDelay + 50*time.Millisecond)
	for {
		writes, got := c.snapshot()
		if writes > 0 {
			if len(got) != 3*benchChunkBytes {
				t.Fatalf("timer flushed %d bytes, want the full tail", len(got))
			}
			if s.uplinkRecv != 3*benchChunkBytes {
				t.Fatalf("watermark %d after timer flush", s.uplinkRecv)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("tail bytes never flushed without a follow-up frame")
		}
		time.Sleep(time.Millisecond)
	}
}
