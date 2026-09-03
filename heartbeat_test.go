package main

import (
	"bytes"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// =========================================
// 心跳（Keepalive）机制专项测试
//
// resume/2 已移除 v1 的 PaddingReader/PaddingWriter/copyWithHeartbeat
// 保活路径，改由控制帧 KEEPALIVE 承担存活探测（其编解码与优先级已由
// handshake_frame_test.go 覆盖）。本文件仅保留端到端空闲隧道保活验证：
// 隧道建立后双方静默多个心跳周期后仍可继续收发数据。
// =========================================

// TestHeartbeatIdleTunnelE2E 端到端验证：隧道建立后双方静默多个心跳周期，
// 然后恢复收发，数据必须无损。这模拟了「SSH 会话挂机数分钟后继续操作」
// 的真实场景 —— 在修复前，CDN 会在 60~100s 时把这种隧道静默切断。
func TestHeartbeatIdleTunnelE2E(t *testing.T) {
	certFile := "test_hb_cert.pem"
	keyFile := "test_hb_key.pem"
	generateTestCerts(certFile, keyFile)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	targetAddr := "127.0.0.1:20900"
	startEchoServer(targetAddr)

	serverAddr := "127.0.0.1:20901"
	testToken := "hb-e2e-token"
	go startServerDirect(ServerConfig{
		ListenAddr:    serverAddr,
		TLSCert:       certFile,
		TLSKey:        keyFile,
		EnableTLS:     true,
		Path:          "/tunnel",
		Transport:     transportH2,
		ExpectedToken: testToken,
		LogLevel:      "error",
		// 测试专用短心跳：直接构造配置不走 clampHeartbeat，
		// 300ms 间隔下 1.2s 空闲覆盖 4 个完整心跳周期
	})
	time.Sleep(2 * time.Second)

	clientListen := "127.0.0.1:20902"
	go startClientDirect(ClientConfig{
		ListenAddr:        clientListen,
		ServerUrl:         "https://" + serverAddr,
		Path:              "/tunnel",
		TargetAddr:        targetAddr,
		Insecure:          true,
		Token:             testToken,
		LogLevel:          "error",
		HeartbeatInterval: 300 * time.Millisecond,
	})
	time.Sleep(1 * time.Second)

	conn, err := net.Dial("tcp", clientListen)
	if err != nil {
		t.Fatalf("连接本地客户端失败: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	// 第一阶段：先跑一轮正常收发，确认隧道建立
	msg1 := []byte("before-idle-probe")
	if _, err := conn.Write(msg1); err != nil {
		t.Fatalf("空闲前发送失败: %v", err)
	}
	buf := make([]byte, len(msg1))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("空闲前回显失败: %v", err)
	}
	if !bytes.Equal(buf, msg1) {
		t.Fatalf("空闲前数据即已损坏: %q", buf)
	}

	// 第二阶段：静默 1.2s（4 个心跳周期）。
	// 期间客户端上行与服务端下行各自发出心跳帧维持链路。
	t.Logf("开始空闲 1.2s，等待心跳帧往返...")
	time.Sleep(1200 * time.Millisecond)

	// 第三阶段：恢复收发。若心跳未工作或帧边界被撕裂，这里会超时或数据损坏
	msg2 := []byte("after-idle-data-must-survive-keepalive-frames")
	if _, err := conn.Write(msg2); err != nil {
		t.Fatalf("空闲后发送失败（上行心跳失效？）: %v", err)
	}
	got := make([]byte, len(msg2))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("空闲后未收到回显（下行心跳失效？）: %v", err)
	}
	if !bytes.Equal(got, msg2) {
		t.Fatalf("空闲后数据损坏（心跳帧撕裂了帧边界？）: 期望 %q 实际 %q", msg2, got)
	}
	t.Logf("✅ 空闲 1.2s（4 个心跳周期）后数据链路完好，心跳机制有效")
}
