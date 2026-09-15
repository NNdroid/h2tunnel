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
}
