//go:build linux

package h2tunnel

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
)

func TestPackBrutalParamsLayout(t *testing.T) {
	d := brutalDecision{rateBytes: 0x1122334455667788, cwndGain: 0x12345678, groupID: 0xAABBCCDDEEFF0011}
	v2 := packBrutalParamsV2(d)
	if binary.LittleEndian.Uint64(v2[0:8]) != 0x1122334455667788 {
		t.Errorf("rate at offset 0 = %016x", binary.LittleEndian.Uint64(v2[0:8]))
	}
	if binary.LittleEndian.Uint32(v2[8:12]) != 0x12345678 {
		t.Errorf("cwnd_gain at offset 8 = %08x", binary.LittleEndian.Uint32(v2[8:12]))
	}
	if binary.LittleEndian.Uint64(v2[12:20]) != 0xAABBCCDDEEFF0011 {
		t.Errorf("group_id at offset 12 = %016x", binary.LittleEndian.Uint64(v2[12:20]))
	}

	v1 := packBrutalParamsV1(d)
	if binary.LittleEndian.Uint64(v1[0:8]) != 0x1122334455667788 || binary.LittleEndian.Uint32(v1[8:12]) != 0x12345678 {
		t.Errorf("v1 layout: %x", v1)
	}
}

func TestSetBrutalOnALiveTCPConnection(t *testing.T) {
	if !brutalAvailable() {
		t.Skip("the kernel has no 'brutal' controller in " + brutalAvailablePath)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	connCh := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		connCh <- conn
	}()
	if _, err := net.Dial(ln.Addr().Network(), ln.Addr().String()); err != nil {
		t.Fatal(err)
	}
	conn, ok := <-connCh
	if !ok {
		t.Fatal("no connection accepted")
	}
	t.Cleanup(func() { _ = conn.Close() })

	if _, isTCP := tcpConnFrom(conn); !isTCP {
		t.Fatalf("tcpConnFrom did not recognize a live TCP connection (%T)", conn)
	}

	// Full decision: switch the algorithm and push the params.
	if err := applyBrutalToConn(conn, brutalDecision{rateBytes: 1_000_000, cwndGain: 15, groupID: 7, setParams: true}); err != nil {
		t.Fatalf("applying a full brutal decision: %v", err)
	}
	// Algorithm only (no rate declared by either side): the module's own
	// defaults stay in force and nothing is pushed.
	if err := applyBrutalToConn(conn, brutalDecision{cwndGain: 15, setParams: false}); err != nil {
		t.Fatalf("switching the algorithm without params: %v", err)
	}
	// Reapplying is idempotent; a busy proxy reapplies on every dial.
	if err := applyBrutalToConn(conn, brutalDecision{rateBytes: 1_000_000, cwndGain: 15, groupID: 7, setParams: true}); err != nil {
		t.Fatalf("reapplying the decision: %v", err)
	}
}

func TestSetBrutalRejectsNonTCPConnections(t *testing.T) {
	// net.Pipe is a net.Conn that is not a TCP connection: it must be reported
	// as unavailable rather than crashing, because a QUIC or WebSocket carrier
	// reaches the same call site.
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	if err := applyBrutalToConn(a, brutalDecision{rateBytes: 1, cwndGain: 15, setParams: true}); !errors.Is(err, ErrBrutalUnavailable) {
		t.Fatalf("err = %v, want ErrBrutalUnavailable for a non-TCP connection", err)
	}
	if err := applyBrutalToConn(nil, brutalDecision{}); !errors.Is(err, ErrBrutalUnavailable) {
		t.Fatalf("err = %v, want ErrBrutalUnavailable for a nil connection", err)
	}
}
