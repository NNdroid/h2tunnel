package h2tunnel_test

import (
	"errors"
	"net"
	"syscall"
	"testing"
)

func TestTCPUDPPairRetriesOccupiedUDPPort(t *testing.T) {
	occupied := bindUDPRetry(t, "127.0.0.1:0")
	defer occupied.Close()
	first, err := net.Listen("tcp", occupied.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	calls := 0
	tcp, udp, err := listenTCPUDPPair(func(network, address string) (net.Listener, error) {
		calls++
		if calls == 1 {
			return first, nil
		}
		return net.Listen(network, address)
	}, net.ListenPacket)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	defer udp.Close()
	if calls < 2 {
		t.Fatal("occupied UDP port was not retried")
	}
	if tcp.Addr().String() != udp.LocalAddr().String() {
		t.Fatal("listeners do not share a port")
	}
	if _, err := first.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("failed TCP listener not closed: %v", err)
	}
}

func TestTCPUDPPairStopsAndClosesOnPermanentBindError(t *testing.T) {
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	calls := 0
	_, _, err = listenTCPUDPPair(func(string, string) (net.Listener, error) {
		calls++
		return first, nil
	}, func(string, string) (net.PacketConn, error) { return nil, syscall.EINVAL })
	if !errors.Is(err, syscall.EINVAL) || calls != 1 {
		t.Fatalf("permanent error: calls=%d err=%v", calls, err)
	}
	if _, err := first.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("failed TCP listener not closed: %v", err)
	}
}
