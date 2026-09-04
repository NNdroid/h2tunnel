package h2tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type tunnelAddr struct {
	network string
	value   string
}

func (a tunnelAddr) Network() string { return a.network }
func (a tunnelAddr) String() string  { return a.value }

type virtualPacketConn struct {
	target string
	local  net.Addr
	remote net.Addr

	ctx      context.Context
	cancel   context.CancelFunc
	session  *udpSession
	incoming chan []byte
	done     chan struct{}

	mu            sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
	readChanged   chan struct{}
	writeChanged  chan struct{}
	terminalErr   error
	closeOnce     sync.Once
	onClose       func()
}

func newVirtualPacketConn(target string, cancel context.CancelFunc) *virtualPacketConn {
	ctx, localCancel := context.WithCancel(context.Background())
	return &virtualPacketConn{
		target:       target,
		local:        tunnelAddr{network: networkUDP, value: "h2tunnel-client"},
		remote:       tunnelAddr{network: networkUDP, value: target},
		ctx:          ctx,
		cancel:       func() { localCancel(); cancel() },
		incoming:     make(chan []byte, 256),
		done:         make(chan struct{}),
		readChanged:  make(chan struct{}),
		writeChanged: make(chan struct{}),
	}
}

func (c *virtualPacketConn) deliver(packet []byte) error {
	copyOfPacket := append([]byte(nil), packet...)
	select {
	case <-c.done:
		return net.ErrClosed
	case c.incoming <- copyOfPacket:
		return nil
	}
}

func (c *virtualPacketConn) Read(p []byte) (int, error) {
	n, _, err := c.ReadFrom(p)
	return n, err
}

func (c *virtualPacketConn) Write(p []byte) (int, error) {
	return c.WriteTo(p, c.remote)
}

func (c *virtualPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		deadline, changed := c.readState()
		timer, timeout := deadlineTimer(deadline)
		select {
		case <-c.done:
			stopTimer(timer)
			return 0, nil, c.endError()
		case packet := <-c.incoming:
			stopTimer(timer)
			n := copy(p, packet)
			return n, c.remote, nil
		case <-changed:
			stopTimer(timer)
			continue
		case <-timeout:
			return 0, nil, &net.OpError{Op: "read", Net: networkUDP, Err: context.DeadlineExceeded}
		}
	}
}

func (c *virtualPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr != nil && addr.String() != c.remote.String() {
		return 0, &net.OpError{Op: "write", Net: networkUDP, Addr: addr, Err: errors.New("packet connection has a fixed remote target")}
	}
	packet := append([]byte(nil), p...)
	for {
		deadline, changed := c.writeState()
		timer, timeout := deadlineTimer(deadline)
		select {
		case c.session.upstream <- packet:
			stopTimer(timer)
			return len(p), nil
		case <-changed:
			stopTimer(timer)
			continue
		case <-c.done:
			stopTimer(timer)
			return 0, c.endError()
		case <-c.session.done:
			stopTimer(timer)
			return 0, net.ErrClosed
		case <-timeout:
			return 0, &net.OpError{Op: "write", Net: networkUDP, Addr: c.remote, Err: context.DeadlineExceeded}
		}
	}
}

func (c *virtualPacketConn) Close() error {
	c.fail(net.ErrClosed)
	return nil
}

func (c *virtualPacketConn) fail(err error) {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.terminalErr = err
		c.mu.Unlock()
		if c.cancel != nil {
			c.cancel()
		}
		if c.session != nil {
			c.session.close()
		}
		close(c.done)
		if c.onClose != nil {
			c.onClose()
		}
	})
}

func (c *virtualPacketConn) LocalAddr() net.Addr  { return c.local }
func (c *virtualPacketConn) RemoteAddr() net.Addr { return c.remote }

func (c *virtualPacketConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.readDeadline = deadline
	c.writeDeadline = deadline
	close(c.readChanged)
	close(c.writeChanged)
	c.readChanged = make(chan struct{})
	c.writeChanged = make(chan struct{})
	c.mu.Unlock()
	return nil
}

func (c *virtualPacketConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.readDeadline = deadline
	close(c.readChanged)
	c.readChanged = make(chan struct{})
	c.mu.Unlock()
	return nil
}

func (c *virtualPacketConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.writeDeadline = deadline
	close(c.writeChanged)
	c.writeChanged = make(chan struct{})
	c.mu.Unlock()
	return nil
}

func (c *virtualPacketConn) readState() (time.Time, <-chan struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readDeadline, c.readChanged
}

func (c *virtualPacketConn) writeState() (time.Time, <-chan struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeDeadline, c.writeChanged
}

func (c *virtualPacketConn) endError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminalErr == nil || errors.Is(c.terminalErr, net.ErrClosed) {
		return net.ErrClosed
	}
	if errors.Is(c.terminalErr, io.EOF) {
		return io.EOF
	}
	return c.terminalErr
}

func deadlineTimer(deadline time.Time) (*time.Timer, <-chan time.Time) {
	if deadline.IsZero() {
		return nil, nil
	}
	delay := time.Until(deadline)
	if delay < 0 {
		delay = 0
	}
	timer := time.NewTimer(delay)
	return timer, timer.C
}

func stopTimer(timer *time.Timer) {
	if timer != nil {
		timer.Stop()
	}
}

var _ PacketConn = (*virtualPacketConn)(nil)
