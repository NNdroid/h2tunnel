package h2tunnel

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// The client's HTTP/2 stream receive window is not an http2.Transport field;
// it is fed from a bound net/http Transport's HTTP2Config via
// ConfigureTransports. These tests dial a raw TCP listener with the real
// transport (the h2c path) and parse the client preface's SETTINGS frame, so
// the wire behavior itself is what's verified, not the plumbing.

const h2FrameSettings = 0x04

type capturedSettings struct {
	initialWindow uint32
	maxFrame      uint32
}

func parseClientInitialSettings(t *testing.T, conn net.Conn) (initialWindow, maxFrame uint32) {
	t.Helper()
	preface := make([]byte, 24)
	if _, err := io.ReadFull(conn, preface); err != nil {
		t.Fatalf("read preface: %v", err)
	}
	if string(preface) != "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
		t.Fatalf("unexpected client preface %q", preface)
	}
	hdr := make([]byte, 9)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
	if frameType := hdr[3]; frameType != h2FrameSettings {
		t.Fatalf("first frame type 0x%02x, want SETTINGS", frameType)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatalf("read settings payload: %v", err)
	}
	for i := 0; i+6 <= len(payload); i += 6 {
		switch binary.BigEndian.Uint16(payload[i:]) {
		case 0x04: // SETTINGS_INITIAL_WINDOW_SIZE
			initialWindow = binary.BigEndian.Uint32(payload[i+2:])
		case 0x05: // SETTINGS_MAX_FRAME_SIZE
			maxFrame = binary.BigEndian.Uint32(payload[i+2:])
		}
	}
	return initialWindow, maxFrame
}

func dialClientSettings(t *testing.T, windowBytes int) (initialWindow, maxFrame uint32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	settings := make(chan capturedSettings, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			close(settings)
			return
		}
		defer conn.Close()
		iw, mf := parseClientInitialSettings(t, conn)
		settings <- capturedSettings{initialWindow: iw, maxFrame: mf}
	}()

	client, err := NewClient(ClientOptions{
		Endpoint: "http://" + ln.Addr().String(),
		Tuning:   ClientTuning{H2StreamReceiveWindowBytes: windowBytes},
	})
	if err != nil {
		t.Fatal(err)
	}
	t2 := client.newHTTP2Transport()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://"+ln.Addr().String()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	// The request fails once the listener closes the conn after capture; only
	// the preface matters here.
	_, _ = t2.RoundTrip(req)

	select {
	case parsed, ok := <-settings:
		if !ok {
			t.Fatal("listener failed to accept")
		}
		return parsed.initialWindow, parsed.maxFrame
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the client preface")
	}
	return 0, 0
}

// Zero keeps the x/net stock behavior: 4MiB per-stream window, spec-default
// frame size, and no bound net/http Transport.
func TestH2StreamWindowDefaultUnchanged(t *testing.T) {
	initialWindow, maxFrame := dialClientSettings(t, 0)
	if initialWindow != uint32(h2StreamWindowDefault) {
		t.Fatalf("default initial window %d, want the x/net 4MiB default", initialWindow)
	}
	if maxFrame != 0 && maxFrame != 16384 {
		t.Fatalf("default MAX_FRAME_SIZE %d, want spec default 16384 (or absent)", maxFrame)
	}
}

// An explicit window lands on the wire as SETTINGS_INITIAL_WINDOW_SIZE, with
// the frame-size bump that pairs with it.
func TestH2StreamWindowTunedLandsOnWire(t *testing.T) {
	initialWindow, maxFrame := dialClientSettings(t, 16<<20)
	if initialWindow != 16<<20 {
		t.Fatalf("initial window %d, want 16MiB", initialWindow)
	}
	if maxFrame != 64<<10 {
		t.Fatalf("MAX_FRAME_SIZE %d, want 64KiB", maxFrame)
	}
}

func TestResolveH2StreamReceiveWindow(t *testing.T) {
	cases := []struct {
		in, want int
	}{
		{0, 0},
		{1, h2StreamWindowMin},
		{64 << 10, 64 << 10},
		{4 << 20, 4 << 20},
		{300 << 20, h2StreamWindowMax},
	}
	for _, c := range cases {
		if got := resolveH2StreamReceiveWindow(c.in); got != c.want {
			t.Fatalf("resolveH2StreamReceiveWindow(%d) = %d, want %d", c.in, got, c.want)
		}
	}
	if _, err := NewClient(ClientOptions{
		Endpoint: "http://127.0.0.1:1",
		Tuning:   ClientTuning{H2StreamReceiveWindowBytes: -1},
	}); err == nil {
		t.Fatal("negative H2StreamReceiveWindowBytes must be rejected")
	}
}
