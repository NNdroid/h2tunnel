package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// splitTestEnv 解析 startBackupTestEnv 返回的 "https://addr|echoPort"。
func splitTestEnv(s string) (serverURL, echoAddr string) {
	parts := strings.Split(s, "|")
	return parts[0], "127.0.0.1:" + parts[1]
}

// ================= 三、主备线路集成测试 =================

// startBackupTestEnv 启动备用测试所需环境：echo target + 隧道服务端。
// seq 用于隔离端口，避免测试间冲突。返回 serverURL。
func startBackupTestEnv(t *testing.T, seq int) string {
	certFile := fmt.Sprintf("test_cert_backup_%d.pem", seq)
	keyFile := fmt.Sprintf("test_key_backup_%d.pem", seq)
	if err := generateTestCerts(certFile, keyFile); err != nil {
		t.Fatalf("gen certs: %v", err)
	}
	t.Cleanup(func() { os.Remove(certFile); os.Remove(keyFile) })

	// 端口基址选在 27000 段，避免与 e2e_test 的 StrictDemux (22000-22003)
	// 等硬编码端口段冲突 —— 各测试的 go startXxx 后台协程不会退出，会长期占用端口。
	echoPort := 27000 + seq*2
	serverPort := 27443 + seq*2
	startEchoServer(fmt.Sprintf("127.0.0.1:%d", echoPort))
	serverAddr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	go startServerDirect(ServerConfig{
		ListenAddr:    serverAddr,
		TLSCert:       certFile,
		TLSKey:        keyFile,
		EnableTLS:     true,
		Path:          "/tunnel",
		ExpectedToken: "backup-token",
		LogLevel:      "error",
		SessionWindow: 256,
		BackupLine:    "hot",
		Network:       "all",
	})
	time.Sleep(2 * time.Second)
	return "https://" + serverAddr + "|" + fmt.Sprintf("%d", echoPort)
}

func newInsecureHTTPClient() *http.Client {
	// 与真实客户端一致：HTTP/2（h2c/TLS h2），帧流式传输依赖多路复用。
	return &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// TestBackupHotStandbyAlive 热备：备用独立握手成功后进入 Alive 状态。
func TestBackupHotStandbyAlive(t *testing.T) {
	env := startBackupTestEnv(t, 1)
	serverURL, echoAddr := splitTestEnv(env)
	cfg := ClientConfig{
		ServerUrl:      serverURL,
		Path:           "/tunnel",
		TargetAddr:     echoAddr,
		Insecure:       true,
		Token:          "backup-token",
		Network:        "tcp",
		LogLevel:       "error",
		SessionWindow:  256,
		BackupLine:     "hot",
		HandshakeAckMs: 3000,
		KeepaliveSec:   1,
	}
	hc := newInsecureHTTPClient()

	bl := newBackupLine("sess-backup-test", cfg, serverURL+"/tunnel", hc)
	go bl.Start()
	defer bl.close()

	// 等待备用握手完成 → Alive
	deadline := time.After(8 * time.Second)
	for {
		if bl.Alive() {
			break
		}
		if bl.State() == backupFailed {
			t.Fatalf("备用握手失败，state=%s", bl.State())
		}
		select {
		case <-deadline:
			t.Fatalf("备用未在期限内变为 Alive，state=%s", bl.State())
		default:
			time.Sleep(50 * time.Millisecond)
		}
	}
	t.Logf("✅ 备用热备进入 Alive（可接管）")
}

// TestBackupTakeoverOnlyIfConfirmed 只有已确认存活的备用才允许接管。
func TestBackupTakeoverOnlyIfConfirmed(t *testing.T) {
	env := startBackupTestEnv(t, 2)
	serverURL, echoAddr := splitTestEnv(env)
	cfg := ClientConfig{
		ServerUrl:      serverURL,
		Path:           "/tunnel",
		TargetAddr:     echoAddr,
		Insecure:       true,
		Token:          "backup-token",
		Network:        "tcp",
		LogLevel:       "error",
		SessionWindow:  256,
		BackupLine:     "hot",
		HandshakeAckMs: 3000,
		KeepaliveSec:   1,
	}
	hc := newInsecureHTTPClient()

	// 场景 A：新建未启动的备用 → 未确认 → 禁止接管
	bl := newBackupLine("sess-takeover-a", cfg, serverURL+"/tunnel", hc)
	if bl.Alive() {
		t.Fatal("未启动的备用不应 Alive（禁止接管）")
	}
	if bl.State() != backupIdle {
		t.Fatalf("未启动备用 state = %s, want idle", bl.State())
	}

	// 场景 B：启动后变为 Alive → 允许接管
	go bl.Start()
	defer bl.close()
	deadline := time.After(8 * time.Second)
	for {
		if bl.Alive() {
			break
		}
		if bl.State() == backupFailed {
			t.Fatalf("备用握手失败")
		}
		select {
		case <-deadline:
			t.Fatalf("备用未 Alive")
		default:
			time.Sleep(50 * time.Millisecond)
		}
	}
	if !bl.Alive() {
		t.Fatal("已确认存活的备用应允许接管")
	}
	t.Logf("✅ 只有确认存活的备用允许接管")
}

// TestBackupWrongTokenRejected 鉴权失败 → 备用握手被拒 → 不可接管。
func TestBackupWrongTokenRejected(t *testing.T) {
	env := startBackupTestEnv(t, 3)
	serverURL, echoAddr := splitTestEnv(env)
	cfg := ClientConfig{
		ServerUrl:      serverURL,
		Path:           "/tunnel",
		TargetAddr:     echoAddr,
		Insecure:       true,
		Token:          "WRONG-token", // 错误 token
		Network:        "tcp",
		LogLevel:       "error",
		SessionWindow:  256,
		BackupLine:     "hot",
		HandshakeAckMs: 3000,
		KeepaliveSec:   1,
	}
	hc := newInsecureHTTPClient()

	bl := newBackupLine("sess-bad-token", cfg, serverURL+"/tunnel", hc)
	go bl.Start()
	defer bl.close()

	time.Sleep(1 * time.Second)
	if bl.Alive() {
		t.Fatal("鉴权失败的备用不应 Alive（禁止接管）")
	}
	t.Logf("✅ 鉴权失败备用被拒，不可接管")
}
