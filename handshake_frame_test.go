package main

import (
	"bytes"
	"errors"
	"testing"
)

// ================= resume v2 帧编解码（writeFrame / readFrame） =================
// 注：历史上本文件曾含 frameMux 双队列优先级调度器的单测；该调度器从未接入
// 生产写路径（控制帧与 DATA 帧的串行化由 resumeSessionWriter.mu 保证），已作为
// 死代码移除。以下仅保留帧编解码的基础单测。

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
		{"END", resumeFrameEnd, func(b *bytes.Buffer) error { return writeResumeEndFrame(b) }},
		{"ERROR", resumeFrameError, func(b *bytes.Buffer) error { return writeResumeErrorFrame(b, resumeErrVersionUnsupported) }},
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
			if err != nil && !errors.Is(err, ErrResumeEndFrame) {
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
	// 手工构造一个 ver 非法的帧
	var raw bytes.Buffer
	raw.Write([]byte{resumeFrameData, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) // ver=1
	payload := make([]byte, 1024)
	_, _, _, err := readFrame(&raw, payload)
	if err == nil {
		t.Fatal("expected version mismatch error")
	}
}

func TestFrameV2BadSeqRead(t *testing.T) {
	// readResumeFrame 遇非 DATA 帧应报错
	var buf bytes.Buffer
	if err := writeResumeEndFrame(&buf); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 1024)
	_, _, err := readResumeFrame(&buf, payload)
	if !errors.Is(err, ErrResumeEndFrame) {
		t.Fatalf("readResumeFrame on END: got %v, want ErrResumeEndFrame", err)
	}
}
