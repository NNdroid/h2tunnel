//go:build windows

package h2tunnel_test

import (
	"net"
	"syscall"
)

// setWeakNetUdpBuffers requests the large receive and send buffers a pipelined
// datagram leg needs from the proxy's sockets. Windows passes the socket handle
// rather than a plain fd, so this file is the only difference from the unix
// variant. Control's callback has no return value and RawControl reports no
// error either, so the request is best-effort; the benchmark measures what the
// socket was actually granted.
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
		h := syscall.Handle(fd)
		_ = syscall.SetsockoptInt(h, syscall.SOL_SOCKET, syscall.SO_RCVBUF, weakNetUdpSocketBuffer)
		_ = syscall.SetsockoptInt(h, syscall.SOL_SOCKET, syscall.SO_SNDBUF, weakNetUdpSocketBuffer)
	})
}
