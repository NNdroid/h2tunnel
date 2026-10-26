//go:build !windows

package h2tunnel_test

import (
	"net"
	"syscall"
)

// setWeakNetUdpBuffers requests the large receive and send buffers a pipelined
// datagram leg needs from the proxy's sockets. Control's callback has no return
// value and RawControl reports no error either, so this is a request the kernel
// may decline or shrink; the benchmark measures what it was actually granted.
func setWeakNetUdpBuffers(pc net.PacketConn) {
	udp, ok := pc.(*net.UDPConn)
	if !ok {
		return
	}
	raw, err := udp.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, weakNetUdpSocketBuffer)
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, weakNetUdpSocketBuffer)
	})
}
