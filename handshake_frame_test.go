package h2tunnel

import (
	"bytes"
	"errors"
	"testing"
)

// ================= resume v2 frame codec (writeFrame / readFrame) =================
// Note: this file historically contained unit tests for the frameMux dual-queue
// priority scheduler; that scheduler was never wired into the production write
// path (serialization of control vs DATA frames is guaranteed by
// resumeSessionWriter.mu) and has been removed as dead code. Only the basic
// frame codec unit tests remain below.

func TestFrameV2RoundTrip(t *testing.T) {
	var buf bytes.Buffer
	data := []byte("hello resume v2")
	seq := uint64(42)
	if err := writeResumeFrame(&buf, seq, data, 0); err != nil {
		t.Fatalf("writeResumeFrame: %v", err)
	}
	payload := make([]byte, 64*1024)
	typ, gotSeq, n, err := readFrame(&buf, payload)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if typ != resumeFrameData {
		t.Fatalf("type = 0x%02x, want DATA(0x01)", typ)
	}
	if gotSeq != seq {
		t.Fatalf("seq = %d, want %d", gotSeq, seq)
	}
	if n != len(data) || !bytes.Equal(payload[:n], data) {
		t.Fatalf("data mismatch: got %q want %q", payload[:n], data)
	}
}

func TestFrameV2Types(t *testing.T) {
	cases := []struct {
		name string
		typ  byte
		enc  func(*bytes.Buffer) error
	}{
		{"END", resumeFrameEnd, func(b *bytes.Buffer) error { return writeResumeEndFrame(b, paddingPolicy{}) }},
		{"ERROR", resumeFrameError, func(b *bytes.Buffer) error {
			return writeResumeErrorFrame(b, resumeErrVersionUnsupported, paddingPolicy{})
		}},
		{"HANDSHAKE", resumeFrameHandshake, func(b *bytes.Buffer) error { return writeFrame(b, resumeFrameHandshake, 0, []byte("caps-hash"), 0) }},
		{"HANDSHAKE-ACK", resumeFrameHandshakeAck, func(b *bytes.Buffer) error { return writeFrame(b, resumeFrameHandshakeAck, 0, nil, 0) }},
		{"KEEPALIVE", resumeFrameKeepalive, func(b *bytes.Buffer) error { return writeFrame(b, resumeFrameKeepalive, 0, nil, 0) }},
		{"KEEPALIVE-ACK", resumeFrameKeepaliveAck, func(b *bytes.Buffer) error { return writeFrame(b, resumeFrameKeepaliveAck, 0, nil, 0) }},
	}
	payload := make([]byte, 64*1024)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.enc(&buf); err != nil {
				t.Fatalf("encode: %v", err)
			}
			typ, _, n, err := readFrame(&buf, payload)
			if err != nil && !errors.Is(err, errResumeEndFrame) {
				t.Fatalf("decode: %v", err)
			}
			if typ != tc.typ {
				t.Fatalf("type = 0x%02x, want 0x%02x", typ, tc.typ)
			}
			_ = n
		})
	}
}

func TestFrameV2VersionMismatch(t *testing.T) {
	// Manually construct a frame with an invalid ver
	var raw bytes.Buffer
	raw.Write([]byte{resumeFrameData, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) // ver=1
	payload := make([]byte, 1024)
	_, _, _, err := readFrame(&raw, payload)
	if err == nil {
		t.Fatal("expected version mismatch error")
	}
}

func TestFrameV2BadSeqRead(t *testing.T) {
	// readResumeFrame should fail on a non-DATA frame
	var buf bytes.Buffer
	if err := writeResumeEndFrame(&buf, paddingPolicy{}); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 1024)
	_, _, err := readResumeFrame(&buf, payload)
	if !errors.Is(err, errResumeEndFrame) {
		t.Fatalf("readResumeFrame on END: got %v, want errResumeEndFrame", err)
	}
}
