package h2tunnel

import (
	"errors"
	"sync"
)

// =========================================
// ringBuffer — fixed-capacity circular byte buffer
//
// Backs the session-recovery layer's "last N bytes" cache.
//
// Key properties:
//   - Global 64-bit seq coordinate space; window is [windowStartSeq, windowStartSeq+length)
//   - When full, writes overwrite the oldest bytes ring-wise (overwrite rolls the window forward: windowStartSeq++)
//   - Reads are by seq; seq < windowStartSeq returns errGap (the gap is unrecoverable)
//   - Concurrent writes and reads; Append never blocks (ring overwrite always has room)
//
// Motivation: long-lived streaming protocols like SSH must not drop the session on
// disconnect. Each side keeps its last N KB (default 256KB) and replays the gap by
// seq after a reconnect. Overwriting the oldest means losing the oldest window —
// after a long outage, the session table tells the client "data before X is gone"
// and the client can choose to abandon recovery.
// =========================================

var errGap = errors.New("ringBuffer: requested seq is before current window start (gap unrecoverable)")

type ringBuffer struct {
	mu             sync.Mutex
	buf            []byte
	size           int
	head           int    // physical offset of the window start in buf
	length         int    // current number of valid bytes
	windowStartSeq uint64 // global seq corresponding to buf[head]
	notify         *sync.Cond
}

func newRingBuffer(sizeKB int) *ringBuffer {
	sizeKB = resolveSessionWindow(sizeKB)
	rb := &ringBuffer{
		buf:  make([]byte, sizeKB*1024),
		size: sizeKB * 1024,
	}
	rb.notify = sync.NewCond(&rb.mu)
	return rb
}

// Append writes a run of bytes. When full it overwrites the oldest ring-wise and
// rolls the window forward. Simplified implementation: a single write never spans
// the head/tail boundary (write what fits best in one pass; if len(p) > free,
// overwrite in one shot and roll the window).
func (rb *ringBuffer) Append(p []byte) {
	if len(p) == 0 {
		return
	}
	rb.mu.Lock()
	defer rb.mu.Unlock()
	for len(p) > 0 {
		tail := (rb.head + rb.length) % rb.size
		free := rb.size - rb.length
		if free == 0 {
			// When full, overwrite whole segments instead of evicting one byte at a
			// time. The recovery window is often saturated under high throughput;
			// byte-wise rolling would add 32K loop+index ops per 32KB block.
			if len(p) >= rb.size {
				overwriteLen := len(p)
				p = p[len(p)-rb.size:]
				rb.windowStartSeq += uint64(overwriteLen)
				copy(rb.buf, p)
				rb.head = 0
				rb.length = rb.size
				break
			}

			n := len(p)
			first := rb.size - tail
			if n <= first {
				copy(rb.buf[tail:tail+n], p)
			} else {
				copy(rb.buf[tail:rb.size], p[:first])
				copy(rb.buf[:n-first], p[first:n])
			}
			rb.head = (rb.head + n) % rb.size
			rb.windowStartSeq += uint64(n)
			break
		}
		n := len(p)
		if n > free {
			n = free
		}
		first := rb.size - tail
		if n <= first {
			copy(rb.buf[tail:tail+n], p[:n])
		} else {
			copy(rb.buf[tail:rb.size], p[:first])
			copy(rb.buf[:n-first], p[first:n])
		}
		rb.length += n
		p = p[n:]
	}
	rb.notify.Broadcast()
}

// ReadAt reads up to len(p) bytes starting at the global seq, returning the count
// actually read. If seq < windowStartSeq the data is out of window (overwritten)
// and errGap is returned.
func (rb *ringBuffer) ReadAt(seq uint64, p []byte) (int, error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	windowEnd := rb.windowStartSeq + uint64(rb.length)
	if seq < rb.windowStartSeq {
		return 0, errGap
	}
	if seq >= windowEnd {
		return 0, nil
	}
	offset := int(seq - rb.windowStartSeq)
	physStart := (rb.head + offset) % rb.size
	avail := int(windowEnd - seq)
	n := len(p)
	if n > avail {
		n = avail
	}
	first := rb.size - physStart
	if n <= first {
		copy(p[:n], rb.buf[physStart:physStart+n])
	} else {
		copy(p[:first], rb.buf[physStart:rb.size])
		copy(p[first:n], rb.buf[:n-first])
	}
	return n, nil
}

// WindowEnd returns the seq one past the current window end.
func (rb *ringBuffer) WindowEnd() uint64 {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.windowStartSeq + uint64(rb.length)
}

// WaitNewData blocks until the window end passes seq (consumers waiting for new data).
func (rb *ringBuffer) WaitNewData(seq uint64) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	for rb.windowStartSeq+uint64(rb.length) <= seq {
		rb.notify.Wait()
	}
}

// WindowStartSeq returns the current window-start seq.
func (rb *ringBuffer) WindowStartSeq() uint64 {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.windowStartSeq
}
