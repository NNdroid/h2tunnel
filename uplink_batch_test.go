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

// uplinkState snapshots the watermark and batch length under s.mu: the batch
// timer goroutine updates both concurrently with any test that feeds frames
// and then waits, and the race detector rightly flags unsynchronized reads.
func (s *tunnelSession) uplinkState() (recv uint64, buffered int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.uplinkRecv, len(s.uplinkBuf)
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

// waitForUplink polls until the target has received at least want bytes. Every
// batching assertion below is phrased as a final state: on a slow machine the
// per-batch flush timer fires between test steps and splits what a fast
// machine coalesces into one write, so write COUNTS are only range-checked —
// bytes, order and the watermark are what the tests hold fixed.
func waitForUplink(t *testing.T, c *countingTarget, want int) (writes int, got []byte) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		writes, got = c.snapshot()
		if len(got) >= want {
			return writes, got
		}
		if time.Now().After(deadline) {
			t.Fatalf("target received %d of %d bytes within the deadline", len(got), want)
		}
		time.Sleep(200 * time.Microsecond)
	}
}

// Four bulk frames must reach the target in order with the watermark matching,
// coalesced when the machine is fast enough to deliver all four inside the
// latency window (1 write locally; the timer may split it into up to 4 under
// CI scheduling without any violation).
func TestUplinkBatchCoalescesBulkWrites(t *testing.T) {
	c := &countingTarget{}
	s := &tunnelSession{targetConn: c}
	for i := 0; i < 4; i++ {
		if err := s.acceptUplinkSeq(uint64(i)*benchChunkBytes, bulkFrame(t, byte(i))); err != nil {
			t.Fatal(err)
		}
	}
	writes, got := waitForUplink(t, c, 4*benchChunkBytes)
	if writes < 1 || writes > 4 {
		t.Fatalf("bulk frames produced %d target writes, want 1..4", writes)
	}
	if len(got) != 4*benchChunkBytes {
		t.Fatalf("target received %d bytes, want %d", len(got), 4*benchChunkBytes)
	}
	for i := range got {
		if want := byte(i / benchChunkBytes); got[i] != want {
			t.Fatalf("byte %d is 0x%02x, want 0x%02x (ordering broken)", i, got[i], want)
		}
	}
	if recv, _ := s.uplinkState(); recv != 4*benchChunkBytes {
		t.Fatalf("watermark %d, want %d", recv, 4*benchChunkBytes)
	}
}

// A small (interactive) frame must flush immediately and drain any pending
// bulk ahead of it: the small frame is the LAST thing the target receives,
// whatever the flush schedule in between.
func TestUplinkBatchFlushesOnSmallFrame(t *testing.T) {
	c := &countingTarget{}
	s := &tunnelSession{targetConn: c}
	if err := s.acceptUplinkSeq(0, bulkFrame(t, 1)); err != nil {
		t.Fatal(err)
	}
	if err := s.acceptUplinkSeq(benchChunkBytes, bulkFrame(t, 2)); err != nil {
		t.Fatal(err)
	}
	small := []byte("keystroke")
	if err := s.acceptUplinkSeq(2*benchChunkBytes, small); err != nil {
		t.Fatal(err)
	}
	writes, got := waitForUplink(t, c, 2*benchChunkBytes+len(small))
	if writes < 1 || writes > 3 {
		t.Fatalf("frames produced %d writes, want 1..3", writes)
	}
	if !bytes.Equal(got[:2*benchChunkBytes], append(bulkFrame(t, 1), bulkFrame(t, 2)...)) {
		t.Fatal("pending bulk bytes corrupted by small frame")
	}
	if !bytes.Equal(got[2*benchChunkBytes:], small) {
		t.Fatal("small frame not delivered last")
	}
	if recv, _ := s.uplinkState(); recv != uint64(2*benchChunkBytes+len(small)) {
		t.Fatalf("watermark %d after flush", recv)
	}
}

// A batch that cannot reach the 128KiB target is still delivered once it
// outlives the latency window: two frames (64KiB) with no explicit flush and
// no 128KiB in sight must reach the target.
func TestUplinkBatchFlushesBeforeReachingTarget(t *testing.T) {
	c := &countingTarget{}
	s := &tunnelSession{targetConn: c}
	if err := s.acceptUplinkSeq(0, bulkFrame(t, 1)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * uplinkFlushDelay)
	if err := s.acceptUplinkSeq(benchChunkBytes, bulkFrame(t, 2)); err != nil {
		t.Fatal(err)
	}
	writes, got := waitForUplink(t, c, 2*benchChunkBytes)
	if writes < 1 || writes > 2 {
		t.Fatalf("frames produced %d writes, want 1..2", writes)
	}
	if !bytes.Equal(got, append(bulkFrame(t, 1), bulkFrame(t, 2)...)) {
		t.Fatal("sub-target batch delivered out of order or corrupted")
	}
	if recv, _ := s.uplinkState(); recv != 2*benchChunkBytes {
		t.Fatalf("watermark %d, want %d", recv, 2*benchChunkBytes)
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
	if recv, buffered := s.uplinkState(); recv != 16<<10 || buffered != 0 {
		t.Fatalf("watermark %d / buffered %d after the failed flush, want 16KiB committed and nothing buffered", recv, buffered)
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
	writes, flushed := waitForUplink(t, c, 2*benchChunkBytes)
	if writes > 2 {
		t.Fatalf("resume drain produced %d writes", writes)
	}
	if len(flushed) != 2*benchChunkBytes {
		t.Fatalf("resume drain delivered %d bytes, want %d", len(flushed), 2*benchChunkBytes)
	}
	if _, buffered := s.uplinkState(); buffered != 0 {
		t.Fatalf("batch not drained: %d bytes", buffered)
	}
}

// flushPendingUplink on a dead target drops the batch without committing it,
// leaving the replay to cover the gap.
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
	if recv, buffered := s.uplinkState(); recv != 0 || buffered != 0 {
		t.Fatalf("watermark %d / buffered %d after a dead-target drop, want 0/0", recv, buffered)
	}
}

// A request that ENDS mid-batch (request-response traffic: the app writes and
// then waits for a reply) must not wait for another uplink frame to flush the
// tail — none will ever come. The per-batch timer delivers it. The three
// frames never reach the 128KiB target, so nothing here can flush by size.
func TestUplinkBatchTailFlushedByTimer(t *testing.T) {
	c := &countingTarget{}
	s := &tunnelSession{targetConn: c}
	for i := 0; i < 3; i++ {
		if err := s.acceptUplinkSeq(uint64(i)*benchChunkBytes, bulkFrame(t, byte(i))); err != nil {
			t.Fatal(err)
		}
	}
	// No further frames, no explicit flush: the timer must deliver the tail.
	// On a slow CI machine the timer may fire mid-feed and split the delivery;
	// whatever the schedule, the last sub-target chunk has no flush path left
	// except the timer.
	writes, got := waitForUplink(t, c, 3*benchChunkBytes)
	if writes < 1 || writes > 3 {
		t.Fatalf("timer tail produced %d writes, want 1..3", writes)
	}
	if len(got) != 3*benchChunkBytes {
		t.Fatalf("timer flushed %d bytes, want the full tail", len(got))
	}
	if recv, _ := s.uplinkState(); recv != 3*benchChunkBytes {
		t.Fatalf("watermark %d after timer flush", recv)
	}
}
