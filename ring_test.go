package h2tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

// TestRingBufferBasic 验证环形缓冲的常规读写
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

// TestRingBufferRolling 测试覆盖最旧时的窗口滚动语义
func TestRingBufferRolling(t *testing.T) {
	rb := newRingBuffer(1) // 1KB
	// 写入 2KB 触发窗口滚动
	rb.Append(make([]byte, 1024))
	rb.Append(make([]byte, 1024))
	// WindowStartSeq 应已推进到 1024
	if rb.WindowStartSeq() != 1024 {
		t.Fatalf("WindowStartSeq=%d, want 1024", rb.WindowStartSeq())
	}
	// seq=512（被覆盖）应返回 errGap
	if _, err := rb.ReadAt(512, make([]byte, 16)); !errors.Is(err, errGap) {
		t.Fatalf("expected errGap, got %v", err)
	}
	// seq=1024 起还能读到 1024 字节
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

// TestResumeFrameRoundTrip 验证 resume 帧格式的读写
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

// TestResumeEndFrame 验证 END 控制帧
func TestResumeEndFrame(t *testing.T) {
	var wire bytes.Buffer
	if err := writeResumeEndFrame(&wire); err != nil {
		t.Fatalf("write end: %v", err)
	}
	_, _, err := readResumeFrame(&wire, make([]byte, 1024))
	if !errors.Is(err, errResumeEndFrame) {
		t.Fatalf("expected errResumeEndFrame, got %v", err)
	}
}

// TestResumeClientRingBufReplay 验证客户端 ring 的重放语义
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

// io.AssignTo 把测试跑通后追加一些额外 sanity —— 强制 io 接口依赖
var _ io.Reader = (*bytes.Buffer)(nil)

// TestResumeRequestBuilderTransports 验证 resume 请求构造器能覆盖
// h2 / grpc / masque-tcp 三种传输，各自生成正确的 method / path / 头。
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
			wantPathPrefix: "/.well-known/masque/tcp/",
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
