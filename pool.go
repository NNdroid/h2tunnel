package h2tunnel

import "sync"

var (
	// tcpBufPool is a 32KB buffer pool for TCP io.CopyBuffer use.
	tcpBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 32*1024)
			return &buf
		},
	}
	// udpBufPool is a 64KB buffer pool for UDP reads.
	udpBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 65536)
			return &buf
		},
	}
)

// udpData carries a pool-buffer pointer plus its data so the UDP client can
// hand packets to a channel with zero allocation.
type udpData struct {
	BufPtr *[]byte
	Data   []byte
	pool   *sync.Pool
}

// frameBufPool is a 64KiB scratch-buffer pool for resume-frame payload reads:
// the server uplink loop, the client recv loops (TCP + WT), the handshake
// exchanges and the ring replays. These were one make() per stream rebuild
// before; redial-heavy deployments churned megabytes of garbage per outage.
var frameBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 64*1024)
		return &buf
	},
}

// getFrameBuf returns a pooled 64KiB buffer; the caller owns it until
// putFrameBuf. The buffer must be returned with its full length intact, so
// callers pass slices (buf[:n]) to consumers, never re-slice the pointer's
// backing array to a different length permanently.
func getFrameBuf() *[]byte {
	return frameBufPool.Get().(*[]byte)
}

func putFrameBuf(p *[]byte) {
	if p != nil && len(*p) == 64*1024 {
		frameBufPool.Put(p)
	}
}
