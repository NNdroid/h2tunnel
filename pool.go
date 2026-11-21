package h2tunnel

import (
	"bufio"
	"io"
	"sync"
)

// frameReadAheadBytes sizes the read-ahead wrapper around the resume data
// plane's body readers. Small frames (16-byte header + payload) and UDP
// capsules (two-to-three varints each) otherwise cost one pipe hop per
// io.ReadFull; a bufio.Reader merges them into one body read. Bulk reads
// (32KiB+) bypass the buffer, so no extra copy is added on the hot path.
const frameReadAheadBytes = 16 * 1024

// bufioReaderPool pools those wrappers. The wrapped body is exclusively owned
// by the loop for the wrapper's lifetime (serveResumeDataPlane's request body,
// the client recv loops' response body), so buffering ahead is safe.
var bufioReaderPool = sync.Pool{
	New: func() interface{} {
		return bufio.NewReaderSize(nil, frameReadAheadBytes)
	},
}

// getFrameReader returns a pooled read-ahead wrapper around r; the caller owns
// it until putFrameReader.
func getFrameReader(r io.Reader) *bufio.Reader {
	br := bufioReaderPool.Get().(*bufio.Reader)
	br.Reset(r)
	return br
}

// emptyReader feeds nothing: resetting a pooled bufio.Reader onto it releases
// the wrapped body reference without allocating (io.Discard is a Writer).
type emptyReader struct{}

func (emptyReader) Read([]byte) (int, error) { return 0, io.EOF }

var deadReader emptyReader

func putFrameReader(br *bufio.Reader) {
	if br != nil && br.Size() == frameReadAheadBytes {
		br.Reset(deadReader) // drop the body reference before recycle
		bufioReaderPool.Put(br)
	}
}

// udpBufPoolLen sizes the shared UDP pool buffer: the largest single-write
// assembly is an unpadded DATAGRAM capsule for a maxTunnelUDPPayload payload
// (1 type byte + 4 length-varint bytes + 1 context byte + 65532 payload =
// 65538, which is why the single-write path in writeUDPCapsule falls back to
// header+payload writes for the rare over-pool datagram).
const udpBufPoolLen = 64 * 1024

var (
	// tcpBufPool is a 32KB buffer pool for TCP io.CopyBuffer use.
	tcpBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 32*1024)
			return &buf
		},
	}
	// udpBufPool is a 64KB buffer pool for UDP packet assembly (header +
	// payload in one write) and datagram reads.
	udpBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, udpBufPoolLen)
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
