package h2tunnel

import (
	"strings"
	"testing"
)

// ================= 能力列表解析 =================

func TestHandshakeCapsParse(t *testing.T) {
	c := parseCaps("datagram,compress,backup-line")
	if !c.datagram || !c.compress || !c.backupLine {
		t.Fatalf("parse caps: %+v", c)
	}
	// 空
	c = parseCaps("")
	if c.datagram || c.compress || c.backupLine {
		t.Fatalf("empty caps should be all false: %+v", c)
	}
	// 未知项忽略
	c = parseCaps("datagram,unknown-feature,compress")
	if !c.datagram || !c.compress {
		t.Fatalf("unknown cap should be ignored: %+v", c)
	}
}

func TestHandshakeCapsIntersect(t *testing.T) {
	client := resumeCaps{datagram: true, compress: true, backupLine: true}
	server := resumeCaps{datagram: true, compress: false, backupLine: true}
	got := intersectCaps(client, server)
	if !got.datagram || got.compress || !got.backupLine {
		t.Fatalf("intersect = %+v, want datagram+backup only", got)
	}
	// 全交
	got = intersectCaps(client, client)
	if got.datagram != true || got.compress != true || got.backupLine != true {
		t.Fatalf("full intersect failed: %+v", got)
	}
	// 无交
	got = intersectCaps(resumeCaps{datagram: true}, resumeCaps{compress: true})
	if got.datagram || got.compress || got.backupLine {
		t.Fatalf("no-common should be empty: %+v", got)
	}
}

func TestHandshakeCapsString(t *testing.T) {
	c := resumeCaps{datagram: true, backupLine: true}
	s := c.String()
	if !strings.Contains(s, "datagram") || !strings.Contains(s, "backup-line") {
		t.Fatalf("String() = %q", s)
	}
}

// ================= 参数解析与对齐 =================

func TestHandshakeParamsParse(t *testing.T) {
	p := parseParams("window_kb=512;handshake_ack_timeout=5000;keepalive_interval=30")
	if p.windowKB != 512 || p.handshakeAckMs != 5000 || p.keepaliveSec != 30 {
		t.Fatalf("parse params: %+v", p)
	}
	// 未知键忽略
	p = parseParams("window_kb=128;bogus=999")
	if p.windowKB != 128 || p.handshakeAckMs != defaultHandshakeAckMs {
		t.Fatalf("unknown key should be ignored: %+v", p)
	}
	// 非法值回退默认
	p = parseParams("window_kb=notanumber;handshake_ack_timeout=abc")
	if p.windowKB != defaultWindowKB || p.handshakeAckMs != defaultHandshakeAckMs {
		t.Fatalf("invalid values should fall back: %+v", p)
	}
	// 空串
	p = parseParams("")
	if p != defaultParams() {
		t.Fatalf("empty params should be defaults: %+v", p)
	}
}

func TestHandshakeParamsAlign(t *testing.T) {
	// 越界 clamp
	p := alignParams(resumeParams{windowKB: 999999, handshakeAckMs: 9999999, keepaliveSec: -5})
	if p.windowKB != defaultWindowKB || p.handshakeAckMs != defaultHandshakeAckMs || p.keepaliveSec != defaultKeepaliveSec {
		t.Fatalf("clamp to default: %+v", p)
	}
	// 合法值保留
	p = alignParams(resumeParams{windowKB: 512, handshakeAckMs: 4000, keepaliveSec: 20})
	if p.windowKB != 512 || p.handshakeAckMs != 4000 || p.keepaliveSec != 20 {
		t.Fatalf("valid params preserved: %+v", p)
	}
}

func TestHandshakeParamsStringRoundTrip(t *testing.T) {
	p := resumeParams{windowKB: 512, handshakeAckMs: 4000, keepaliveSec: 20}
	s := p.String()
	back := parseParams(s)
	if back != p {
		t.Fatalf("round trip mismatch: %+v != %+v", back, p)
	}
}

// ================= 版本协商 =================

func TestHandshakeVersionNegotiate(t *testing.T) {
	// v2 双方 → 2
	if v := negotiateVersion(2, 2); v != 2 {
		t.Fatalf("v2+v2 = %d, want 2", v)
	}
	// 服务端只支持 1（旧），客户端 2 → 0 (version-unsupported)
	if v := negotiateVersion(2, 1); v != 0 {
		t.Fatalf("client2/server1 = %d, want 0", v)
	}
	// 客户端只支持 1，服务端 2 → 0
	if v := negotiateVersion(1, 2); v != 0 {
		t.Fatalf("client1/server2 = %d, want 0", v)
	}
	// 无版本（0）→ 0
	if v := negotiateVersion(0, 2); v != 0 {
		t.Fatalf("client0/server2 = %d, want 0", v)
	}
}
