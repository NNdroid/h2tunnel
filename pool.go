package main

import "sync"

var (
	// tcpBufPool 用于 TCP io.CopyBuffer 的 32KB 缓冲池
	tcpBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 32*1024)
			return &buf
		},
	}
	// udpBufPool 用于 UDP 读取的 64KB 缓冲池
	udpBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 65536)
			return &buf
		},
	}
)

// UDPData 用于在 UDP Client 中高效地将携带缓冲池指针的数据投递到 channel
// 以实现真正的 Zero-Allocation
type UDPData struct {
	BufPtr *[]byte
	Data   []byte
}