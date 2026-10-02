package h2tunnel

import "sync"

// Size classes avoid retaining a 64KiB buffer for every small queued packet.
var datagramPools = [...]sync.Pool{
	{New: func() any { b := make([]byte, 2048); return &b }},
	{New: func() any { b := make([]byte, 4096); return &b }},
	{New: func() any { b := make([]byte, 8192); return &b }},
	{New: func() any { b := make([]byte, 16384); return &b }},
	{New: func() any { b := make([]byte, 32768); return &b }},
	{New: func() any { b := make([]byte, 65536); return &b }},
}

func copyDatagram(p []byte) udpData {
	i := 0
	for i < len(datagramPools)-1 && len(p) > [...]int{2048, 4096, 8192, 16384, 32768, 65536}[i] {
		i++
	}
	pool := &datagramPools[i]
	ptr := pool.Get().(*[]byte)
	n := copy(*ptr, p)
	return udpData{BufPtr: ptr, Data: (*ptr)[:n], pool: pool}
}

func releaseDatagram(p udpData) {
	if p.BufPtr != nil {
		pool := p.pool
		if pool == nil {
			pool = &udpBufPool
		}
		pool.Put(p.BufPtr)
	}
}

// Producers hold mu for the duration of their enqueue. close first wakes
// blocked producers, then waits for ownership transfers before draining.
// Consumers own each received buffer until the network write completes.
type datagramQueue struct {
	packets chan udpData
	done    chan struct{}
	mu      sync.RWMutex
	once    sync.Once
}

func newDatagramQueue(size int) *datagramQueue {
	return &datagramQueue{packets: make(chan udpData, size), done: make(chan struct{})}
}

func (q *datagramQueue) close() {
	q.once.Do(func() {
		close(q.done)
		q.mu.Lock()
		defer q.mu.Unlock()
		for {
			select {
			case p := <-q.packets:
				releaseDatagram(p)
			default:
				return
			}
		}
	})
}
