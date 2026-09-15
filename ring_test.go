package h2tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

// TestRingBufferBasic verifies normal reads and writes of the ring buffer
func TestRingBufferBasic(t *testing.T) {
	rb := newRingBuffer(4) // 4KB
	want := []byte("hello-world")
	rb.Append(want)

	got := make([]byte, len(want))
	n, err := rb.ReadAt(0, got)
	if err != nil || n != len(want) || !bytes.Equal(got[:n], want) {
		t.Fatalf("basic read failed: n=%d err=%v got=%q", n, err, got)
	}
	if rb.WindowEnd() != uint64(len(want)) {
		t.Fatalf("WindowEnd=%d, want %d", rb.WindowEnd(), len(want))
	}
}

// TestRingBufferRolling tests window-rolling semantics when the oldest data is overwritten
func TestRingBufferRolling(t *testing.T) {
	rb := newRingBuffer(1) // 1KB
	// write 2KB to trigger window rolling
	rb.Append(make([]byte, 1024))
	rb.Append(make([]byte, 1024))
	// WindowStartSeq should have advanced to 1024
	if rb.WindowStartSeq() != 1024 {
		t.Fatalf("WindowStartSeq=%d, want 1024", rb.WindowStartSeq())
	}
	// seq=512 (overwritten) should return errGap
	if _, err := rb.ReadAt(512, make([]byte, 16)); !errors.Is(err, errGap) {
		t.Fatalf("expected errGap, got %v", err)
	}
	// from seq=1024 we can still read 1024 bytes
	got := make([]byte, 1024)
	n, err := rb.ReadAt(1024, got)
	if err != nil || n != 1024 {
		t.Fatalf("post-roll read failed: n=%d err=%v", n, err)
	}
}

// TestRingBufferLargeAppend guards the full-window fast path. Besides
// preserving the sequence window, this prevents a full ring from degrading to
// one loop iteration per overwritten byte under sustained throughput.
func TestRingBufferLargeAppend(t *testing.T) {
	rb := newRingBuffer(1)
	input := make([]byte, 64*1024)
	for i := range input {
		input[i] = byte(i)
	}
	rb.Append(input)

	if got, want := rb.WindowStartSeq(), uint64(len(input)-1024); got != want {
		t.Fatalf("WindowStartSeq=%d, want %d", got, want)
	}
	got := make([]byte, 1024)
	n, err := rb.ReadAt(rb.WindowStartSeq(), got)
	if err != nil || n != len(got) {
		t.Fatalf("ReadAt: n=%d err=%v", n, err)
	}
	if !bytes.Equal(got, input[len(input)-len(got):]) {
		t.Fatal("large append did not retain the most recent window")
	}
}

// TestResumeFrameRoundTrip verifies read/write of the resume frame format
func TestResumeFrameRoundTrip(t *testing.T) {
	var wire bytes.Buffer
	payload1 := []byte("first-chunk")
	payload2 := []byte("second-chunk")

	if err := writeResumeFrame(&wire, 0, payload1, 64); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	if err := writeResumeFrame(&wire, uint64(len(payload1)), payload2, 128); err != nil {
		t.Fatalf("write 2: %v", err)
	}

	buf := make([]byte, 1024)
	seq, n, err := readResumeFrame(&wire, buf)
	if err != nil || seq != 0 || !bytes.Equal(buf[:n], payload1) {
		t.Fatalf("read 1 failed: seq=%d n=%d err=%v", seq, n, err)
	}
	seq, n, err = readResumeFrame(&wire, buf)
	if err != nil || seq != uint64(len(payload1)) || !bytes.Equal(buf[:n], payload2) {
		t.Fatalf("read 2 failed: seq=%d n=%d err=%v", seq, n, err)
	}
}

// TestResumeEndFrame verifies the END control frame
func TestResumeEndFrame(t *testing.T) {
	var wire bytes.Buffer
	if err := writeResumeEndFrame(&wire, paddingPolicy{}); err != nil {
		t.Fatalf("write end: %v", err)
	}
	_, _, err := readResumeFrame(&wire, make([]byte, 1024))
	if !errors.Is(err, errResumeEndFrame) {
		t.Fatalf("expected errResumeEndFrame, got %v", err)
	}
}

// TestResumeClientRingBufReplay verifies the replay semantics of the client ring
func TestResumeClientRingBufReplay(t *testing.T) {
	b := newResumeClientRingBuf(4)
	b.Append([]byte("0123456789"))
	var got bytes.Buffer
	n, err := b.ReplayFrom(0, &got)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if n != 10 || got.String() != "0123456789" {
		t.Fatalf("replay mismatch: n=%d got=%q", n, got.String())
	}
}

// io.AssignTo: extra sanity once the tests pass — enforces the io interface dependency
var _ io.Reader = (*bytes.Buffer)(nil)

// TestResumeRequestBuilderTransports verifies the resume request builder covers
// the h2 / grpc / masque-tcp transports, each producing the correct method / path / headers.
func TestResumeRequestBuilderTransports(t *testing.T) {
	ring := newResumeClientRingBuf(256)
	base := clientConfig{
		ServerUrl:     "https://cdn.example.com",
		Path:          "/tunnel",
		TargetAddr:    "db.internal:5432",
		CustomHost:    "cdn.example.com",
		Token:         "sekret",
		Network:       "tcp",
		SessionWindow: 256,
	}

	cases := []struct {
		name           string
		mutate         func(*clientConfig)
		wantMethod     string
		wantPathPrefix string
		wantProto      string
		wantCT         string
	}{
		{
			name:           "h2 POST",
			mutate:         func(c *clientConfig) {},
			wantMethod:     "POST",
			wantPathPrefix: "/tunnel",
			wantProto:      "resume/2",
			wantCT:         "",
		},
		{
			name:           "grpc POST",
			mutate:         func(c *clientConfig) { c.Transport = transportGRPC },
			wantMethod:     "POST",
			wantPathPrefix: "/tunnel",
			wantProto:      "resume/2",
			wantCT:         "application/grpc",
		},
		{
			name:           "masque-tcp CONNECT",
			mutate:         func(c *clientConfig) { c.Transport = transportMasque },
			wantMethod:     "CONNECT",
			wantPathPrefix: "/tunnel/.well-known/masque/tcp/",
			wantProto:      "resume/2",
			wantCT:         "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			req := buildResumeRequest(context.Background(), strings.NewReader(""), "sess-1", new(uint64), ring, cfg.ServerUrl+cfg.Path, cfg)

			if req.Method != tc.wantMethod {
				t.Errorf("method = %s, want %s", req.Method, tc.wantMethod)
			}
			if !strings.HasPrefix(req.URL.Path, tc.wantPathPrefix) {
				t.Errorf("path = %s, want prefix %s", req.URL.Path, tc.wantPathPrefix)
			}
			if got := req.Header.Get("X-Tunnel-Proto"); got != tc.wantProto {
				t.Errorf("X-Tunnel-Proto = %q, want %q", got, tc.wantProto)
			}
			if got := req.Header.Get("X-Session-ID"); got != "sess-1" {
				t.Errorf("X-Session-ID = %q, want sess-1", got)
			}
			if got := req.Header.Get("X-Resume-Downlink"); got == "" {
				t.Errorf("X-Resume-Downlink missing")
			}
			if got := req.Header.Get("X-Resume-Version"); got != "2" {
				t.Errorf("X-Resume-Version = %q, want 2", got)
			}
			if got := req.Header.Get("X-Resume-Caps"); got == "" {
				t.Errorf("X-Resume-Caps missing")
			}
			if got := req.Header.Get("X-Resume-Params"); got == "" {
				t.Errorf("X-Resume-Params missing")
			}
			if got := req.Header.Get("X-Target"); got != "db.internal:5432" {
				t.Errorf("X-Target = %q, want db.internal:5432", got)
			}
			if got := req.Header.Get("Content-Type"); got != tc.wantCT {
				t.Errorf("Content-Type = %q, want %q", got, tc.wantCT)
			}
			if cfg.usesMasque() {
				if got := req.Header.Get("Protocol"); got != "connect-tcp" {
					t.Errorf("Protocol = %q, want connect-tcp", got)
				}
			}
			if cfg.usesGRPC() {
				if got := req.Header.Get("TE"); got != "trailers" {
					t.Errorf("TE = %q, want trailers", got)
				}
			}
		})
	}
}
