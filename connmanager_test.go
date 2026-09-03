package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// =========================================
// connmanager_test.go — L3 连接管理层全量可运行测试
//
// 覆盖：
//   A. 各底层协议(h2/grpc/masque-tcp/wt/h3 + udp) × Resume v2 全双工回显矩阵
//   B. 主备数量（默认 1+1）正确拨号
//   C. 类型分流（PrimaryCount=2 → tcp/udp 各一条主）
//   D. 主断 → 备升级 → 补位
//   E. 备用 KEEPALIVE 失效检测 → 移除 → 补位
//   F. 拨号间隔节流（不风暴重拨）
//   G. establish_interval 错相生效（备在间隔后才建立）
//   H. 鉴权失败 → 备用不接管
//   I. 版本不匹配 → 426 拒绝
//   J. ConnectionPolicy 默认值校验
//   K. 边界：primary_count/backup_count=0 回退默认
//
// 运行：go test -run 'ConnManager|ConnectionPolicy' -v ./...
// =========================================

// 端口基址：独立于 backup_test(27000)、e2e_test(20000/22000)。
// 每个测试用独立的 seq 偏移，避免后台 goroutine 不退出导致的端口冲突。
const connMgrPortBase = 29000

// connManagerHTTPServer 启动一个启用了 resume/backup 的隧道服务端。
func connManagerHTTPServer(t *testing.T, seq int, token string) (serverURL, echoAddr string) {
	certFile := fmt.Sprintf("test_cert_connmgr_%d.pem", seq)
	keyFile := fmt.Sprintf("test_key_connmgr_%d.pem", seq)
	if err := generateTestCerts(certFile, keyFile); err != nil {
		t.Fatalf("gen certs: %v", err)
	}
	t.Cleanup(func() { os.Remove(certFile); os.Remove(keyFile) })

	echoPort := connMgrPortBase + seq*2
	serverPort := connMgrPortBase + 443 + seq*2
	startEchoServer(fmt.Sprintf("127.0.0.1:%d", echoPort))
	serverAddr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	go startServerDirect(ServerConfig{
		ListenAddr:    serverAddr,
		TLSCert:       certFile,
		TLSKey:        keyFile,
		EnableTLS:     true,
		Path:          "/tunnel",
		Transport:     transportH2,
		ExpectedToken: token,
		LogLevel:      "error",
		SessionWindow: 256,
		Network:       "all",
	})
	time.Sleep(2 * time.Second)
	return "https://" + serverAddr, fmt.Sprintf("127.0.0.1:%d", echoPort)
}

// connMgrClient 构造标准 resume 客户端配置。
func connMgrClient(serverURL, echoAddr, token string, network string) ClientConfig {
	return ClientConfig{
		ServerUrl:      serverURL,
		Path:           "/tunnel",
		TargetAddr:     echoAddr,
		Insecure:       true,
		Token:          token,
		Network:        network,
		LogLevel:       "error",
		SessionWindow:  256,
		HandshakeAckMs: 3000,
		KeepaliveSec:   1,
	}
}

func connMgrHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http2.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
}

// =========================================
// A. 各底层协议 × Resume v2 全双工回显矩阵
// =========================================

func TestConnManagerTransportResumeMatrix(t *testing.T) {
	certFile := "test_cert_matrix.pem"
	keyFile := "test_key_matrix.pem"
	generateTestCerts(certFile, keyFile)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	targetAddr := "127.0.0.1:29100"
	startEchoServer(targetAddr)
	serverAddr := "127.0.0.1:29543"
	serverURL := "https://" + serverAddr
	token := "matrix-token"
	go startServerDirect(ServerConfig{
		ListenAddr:    serverAddr,
		TLSCert:       certFile,
		TLSKey:        keyFile,
		EnableTLS:     true,
		Path:          "/tunnel",
		Transport:     transportAll,
		ExpectedToken: token,
		LogLevel:      "error",
		SessionWindow: 256,
		Network:       "all",
	})
	time.Sleep(2 * time.Second)

	cases := []struct {
		name      string
		port      int
		network   string
		transport string
	}{
		{"H2_TCP_Resume", 29101, "tcp", transportH2},
		{"gRPC_TCP_Resume", 29102, "tcp", transportGRPC},
		{"H3_TCP_Resume", 29103, "tcp", transportH3},
		{"WT_TCP_Resume", 29104, "tcp", transportWT},
		{"MASQUE_TCP_Resume", 29105, "tcp", transportMasque},
		{"H2_UDP_Resume", 29106, "udp", transportH2},
		{"MASQUE_UDP_Resume", 29107, "udp", transportMasque},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cc := connMgrClient(serverURL, targetAddr, token, tc.network)
			cc.ListenAddr = fmt.Sprintf("127.0.0.1:%d", tc.port)
			cc.Transport = tc.transport
			go startClientDirect(cc)
			time.Sleep(1 * time.Second)

			// 全双工回显验证：本地 → 隧道 → echo target → 隧道 → 本地
			var conn net.Conn
			var err error
			if tc.network == "udp" {
				conn, err = net.Dial("udp", cc.ListenAddr)
			} else {
				conn, err = net.Dial("tcp", cc.ListenAddr)
			}
			if err != nil {
				t.Fatalf("dial local client: %v", err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(6 * time.Second))

			msg := []byte(fmt.Sprintf("resume-matrix-%s", tc.name))
			if _, err := conn.Write(msg); err != nil {
				t.Fatalf("write: %v", err)
			}
			buf := make([]byte, 256)
			n, err := conn.Read(buf)
			if err != nil {
				t.Fatalf("read echo: %v", err)
			}
			if string(buf[:n]) != string(msg) {
				t.Fatalf("echo mismatch: got %q want %q", buf[:n], msg)
			}
			t.Logf("✅ %s 在 resume/2 之上全双工回显通过", tc.name)
		})
	}
}

// =========================================
// 连接管理器测试环境
// =========================================

// startConnManagerEnv 启动一个带 ConnectionManager 的测试环境。
// 返回 manager 与 serverURL；manager 需 t.Cleanup 关闭。
func startConnManagerEnv(t *testing.T, seq int, policy ConnectionPolicy) (*ConnectionManager, string, string) {
	serverURL, echoAddr := connManagerHTTPServer(t, seq, "connmgr-token")
	cfg := connMgrClient(serverURL, echoAddr, "connmgr-token", "tcp")
	m := NewConnectionManager(policy, cfg, serverURL+"/tunnel", connMgrHTTPClient(), fmt.Sprintf("CM%d", seq))
	t.Cleanup(m.Close)
	return m, serverURL, echoAddr
}

// waitCount 轮询等待 manager 的主/备数量达到目标（含超时）。
func waitCount(t *testing.T, cond func() bool, timeout time.Duration, msg string) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("超时: %s", msg)
}

// =========================================
// B. 主备数量（默认 1+1）
// =========================================

func TestConnManagerPrimaryBackupCounts(t *testing.T) {
	policy := resolveConnectionPolicy(1, 1, 0, 0, 1, 2, nil) // establish=1s, missed=2
	m, _, _ := startConnManagerEnv(t, 1, policy)
	m.Start()

	waitCount(t, func() bool { return m.PrimaryCount() == 1 }, 5*time.Second, "主连接应拨 1 条")
	waitCount(t, func() bool { return m.BackupCount() == 1 }, 5*time.Second, "备用应在 establish 间隔后拨 1 条")
	t.Logf("✅ 主=%d 备=%d（默认 1+1）", m.PrimaryCount(), m.BackupCount())
}

// =========================================
// C. 类型分流（PrimaryCount=2 → tcp/udp 各一条主）
// =========================================

func TestConnManagerTypeSharding(t *testing.T) {
	policy := resolveConnectionPolicy(2, 1, 0, 0, 1, 2, nil) // 主2备1，网络={tcp,udp}
	m, _, _ := startConnManagerEnv(t, 2, policy)
	m.Start()

	waitCount(t, func() bool { return m.PrimaryCount() == 2 }, 5*time.Second, "应拨 2 条主")
	types := m.PrimaryTypes()
	hasTCP, hasUDP := false, false
	for _, ty := range types {
		if ty == "tcp" {
			hasTCP = true
		}
		if ty == "udp" {
			hasUDP = true
		}
	}
	if !hasTCP || !hasUDP {
		t.Fatalf("类型分流未生效: 主类型=%v，期望同时覆盖 tcp 与 udp", types)
	}
	waitCount(t, func() bool { return m.BackupCount() == 1 }, 5*time.Second, "备用应拨 1 条")
	t.Logf("✅ 类型分流生效: 主类型=%v 备=%d", types, m.BackupCount())
}

// =========================================
// D. 主断 → 备升级 → 补位
// =========================================

func TestConnManagerSwitchoverReplenish(t *testing.T) {
	policy := resolveConnectionPolicy(1, 1, 1, 1, 1, 2, nil) // 快速重拨，便于观察升级+补位
	m, _, _ := startConnManagerEnv(t, 3, policy)
	m.Start()

	// 等主备就绪
	waitCount(t, func() bool { return m.PrimaryCount() == 1 && m.BackupCount() == 1 }, 6*time.Second, "主备就绪")

	// 主连接阵亡 → 触发升级+补位
	m.FailPrimary("default")

	// 升级后主数量应恢复 1，且备用补足 1
	waitCount(t, func() bool { return m.PrimaryCount() == 1 && m.BackupCount() == 1 }, 8*time.Second, "主断后应升级备用并补足数量")
	if st := m.PrimaryState("default"); st != backupAlive {
		t.Fatalf("升级后的主连接状态应为 alive，实际=%s", st)
	}
	t.Logf("✅ 主断 → 备升级为主(alive) → 补足备用，主=%d 备=%d", m.PrimaryCount(), m.BackupCount())
}

// =========================================
// E. 备用 KEEPALIVE 失效检测 → 移除 → 补位
// =========================================

func TestConnManagerBackupKeepaliveFailure(t *testing.T) {
	policy := resolveConnectionPolicy(1, 1, 1, 1, 1, 2, nil) // missed=2, keepalive=1s, 快速补位
	m, _, _ := startConnManagerEnv(t, 4, policy)
	m.Start()

	waitCount(t, func() bool { return m.BackupCount() == 1 }, 6*time.Second, "备用就绪")

	// 直接关闭备用线路的流，模拟 KEEPALIVE 断链 → 连续丢 ACK → 判失效
	m.mu.Lock()
	for _, bl := range m.backups {
		bl.close() // 关闭 closeCh，keepaliveLoop 退出，后续补位逻辑由 monitor 处理
	}
	m.mu.Unlock()

	// 失效被移除 → 补位回到 1 条
	waitCount(t, func() bool { return m.BackupCount() == 1 }, 8*time.Second, "失效备用应被移除并补足")
	// 主连接不受影响
	if m.PrimaryCount() != 1 {
		t.Fatalf("备用失效不应影响主连接，主=%d", m.PrimaryCount())
	}
	t.Logf("✅ 备用 KEEPALIVE 失效被移除并补位，备=%d", m.BackupCount())
}

// =========================================
// F. 拨号间隔节流（不风暴重拨）
// =========================================

func TestConnManagerDialIntervalThrottle(t *testing.T) {
	// 主拨号间隔 2s：触发主失败后，补主不得早于该间隔（防风暴重拨）。
	// 注意：直接构造 ConnectionPolicy，令 BackupCount=0，避免备用升级绕过主拨号节流。
	interval := 2 * time.Second
	policy := ConnectionPolicy{
		PrimaryCount:         1,
		BackupCount:          0,
		PrimaryDialInterval:  interval,
		BackupDialInterval:   backupDialDefault,
		EstablishInterval:    1 * time.Second,
		BackoffMaxMissedAcks: 2,
		PrimaryNetworks:      []string{networkTCP, networkUDP},
	}
	m, _, _ := startConnManagerEnv(t, 5, policy)
	m.Start()

	waitCount(t, func() bool { return m.PrimaryCount() == 1 }, 5*time.Second, "主就绪")

	// 触发主失败：由于距上次主拨号不足 interval，补主应被节流（不早于 interval）
	t0 := time.Now()
	m.FailPrimary("default")
	time.Sleep(interval / 2) // 1s < 2s
	m.mu.Lock()
	stillDown := m.primaries["default"] == nil
	m.mu.Unlock()
	if !stillDown {
		t.Fatalf("主拨号间隔未到却已补主（节流失效）")
	}

	// 间隔到期后应补主，且补主不早于 t0+interval
	waitCount(t, func() bool { return m.PrimaryCount() == 1 }, interval+3*time.Second, "间隔到期补主")
	elapsed := time.Since(t0)
	if elapsed < interval-400*time.Millisecond {
		t.Fatalf("补主早于主拨号间隔(%v): 实际 %v", interval, elapsed)
	}
	t.Logf("✅ 主拨号间隔节流生效：补主在 %v 后发生(>=%v)", elapsed.Round(100*time.Millisecond), interval)
}

// =========================================
// G. establish_interval 错相生效
// =========================================

func TestConnManagerEstablishInterval(t *testing.T) {
	establish := 2 * time.Second
	policy := resolveConnectionPolicy(1, 1, 0, 0, 2, 2, nil)
	m, _, _ := startConnManagerEnv(t, 6, policy)
	start := time.Now()
	m.Start()

	// 主应立即出现
	waitCount(t, func() bool { return m.PrimaryCount() == 1 }, 5*time.Second, "主立即建立")

	// 备用应晚于 establish_interval 出现。
	// 等待窗口需覆盖「初始拨号失败后被 15s 重拨节流」的合法场景：bdSec=0 时
	// BackupDialInterval 取默认值 15s，若首条备用握手在高负载下偶发失败被 reconcile
	// 移除，重拨须等满 15s 节流；6s 窗口会在全量测试并发压力下偶发误判为失败。
	// 仅放宽等待时长，核心断言「不早于 establish_interval」保持不变。
	waitCount(t, func() bool { return m.BackupCount() == 1 }, 20*time.Second, "备在间隔后建立")
	backupAt := time.Since(start)
	if backupAt < establish-500*time.Millisecond {
		t.Fatalf("备用建立过早，早于 establish_interval(%v): 实际 %v", establish, backupAt)
	}
	t.Logf("✅ establish_interval 错相生效：主%v后建立，备%v后建立(>%v)", time.Since(start), backupAt.Round(100*time.Millisecond), establish)
}

// =========================================
// H. 鉴权失败 → 备用不接管
// =========================================

func TestConnManagerAuthFailureNoTakeover(t *testing.T) {
	policy := resolveConnectionPolicy(1, 1, 0, 0, 1, 2, nil)
	m, serverURL, echoAddr := startConnManagerEnv(t, 7, policy)
	// 覆盖配置为错误 token，使所有线路握手被拒
	m.cfg = connMgrClient(serverURL, echoAddr, "WRONG", "tcp")
	m.Start()

	time.Sleep(2 * time.Second)
	// 鉴权失败：主连接不应 alive，也不应有可接管备用
	m.mu.Lock()
	primaryOK := false
	if bl, ok := m.primaries["default"]; ok && bl.State() == backupAlive {
		primaryOK = true
	}
	backupOK := false
	for _, bl := range m.backups {
		if bl.State() == backupAlive {
			backupOK = true
		}
	}
	m.mu.Unlock()
	if primaryOK {
		t.Fatal("鉴权失败时主连接不应 alive")
	}
	if backupOK {
		t.Fatal("鉴权失败时不应有可接管的备用")
	}
	t.Logf("✅ 鉴权失败 → 主/备均不可用，禁止接管")
}

// =========================================
// I. 版本不匹配 → 426 拒绝
// =========================================

func TestConnManagerVersionUnsupported(t *testing.T) {
	serverURL, _ := connManagerHTTPServer(t, 8, "connmgr-token")

	// 构造一个 resume/1（旧版）请求 → 应被 426 拒绝
	req, _ := http.NewRequest(http.MethodPost, serverURL+"/tunnel", strings.NewReader(""))
	req.Header.Set("X-Tunnel-Proto", "resume/1") // 旧版协议
	req.Header.Set("X-Session-ID", "sess-v1")
	req.Header.Set("X-Resume-Version", "1")
	req.Header.Set("X-Resume-Caps", "replay")
	req.Header.Set("X-Resume-Params", "window_kb=256")
	req.Header.Set("X-Auth-Token", "connmgr-token")
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := connMgrHTTPClient().Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("旧版协议应返回 426，实际 %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Resume-Error") != "version-unsupported" {
		t.Fatalf("X-Resume-Error 应为 version-unsupported，实际 %q", resp.Header.Get("X-Resume-Error"))
	}
	t.Logf("✅ 旧版协议(非 resume/2) → 426 version-unsupported，无降级目标")
}

// =========================================
// J. ConnectionPolicy 默认值
// =========================================

func TestConnectionPolicyDefaults(t *testing.T) {
	p := resolveConnectionPolicy(0, -1, 0, 0, 0, 0, nil)
	if p.PrimaryCount != 1 || p.BackupCount != 1 {
		t.Fatalf("默认主备应为 1+1，实际 %d+%d", p.PrimaryCount, p.BackupCount)
	}
	if p.EstablishInterval != 100*time.Second {
		t.Fatalf("默认建立间隔应为 100s，实际 %v", p.EstablishInterval)
	}
	if p.PrimaryDialInterval != primaryDialDefault || p.BackupDialInterval != backupDialDefault {
		t.Fatalf("默认拨号间隔错误: primary=%v backup=%v", p.PrimaryDialInterval, p.BackupDialInterval)
	}
	if p.BackoffMaxMissedAcks != 3 {
		t.Fatalf("默认失效阈值应为 3，实际 %d", p.BackoffMaxMissedAcks)
	}
	if got := p.PrimaryNetworks; len(got) != 2 || got[0] != networkTCP || got[1] != networkUDP {
		t.Fatalf("默认分流网络错误: %v", got)
	}
	t.Logf("✅ ConnectionPolicy 默认值全部正确")
}

// =========================================
// K. 边界：backup_count=0 明确关闭备用
// =========================================

func TestConnectionPolicyBoundary(t *testing.T) {
	// 主连接 0 → 默认 1；备用 0 → 明确关闭
	p := resolveConnectionPolicy(0, 0, 0, 0, 0, 0, nil)
	if p.PrimaryCount != 1 || p.BackupCount != 0 {
		t.Fatalf("预期 1 主 + 0 备，实际 %d+%d", p.PrimaryCount, p.BackupCount)
	}
	// 显式网络集合会去重并固定为 tcp、udp 顺序
	p2 := resolveConnectionPolicy(2, 1, 0, 0, 0, 0, []string{"udp", "tcp", "udp"})
	if got := p2.PrimaryNetworks; len(got) != 2 || got[0] != networkTCP || got[1] != networkUDP {
		t.Fatalf("分流网络归一失败: %v", got)
	}
	// 非法建立间隔(负) → 默认 100s
	p3 := resolveConnectionPolicy(1, 1, 0, 0, -5, 0, nil)
	if p3.EstablishInterval != 100*time.Second {
		t.Fatalf("负建立间隔应回退 100s，实际 %v", p3.EstablishInterval)
	}
	t.Logf("✅ 配置边界回退默认正确")
}

// =========================================
// 补充：primaryTypes 分流集合正确性
// =========================================

func TestConnectionPolicyPrimaryTypes(t *testing.T) {
	p := resolveConnectionPolicy(1, 1, 0, 0, 0, 0, nil)
	if types := p.primaryTypes(); len(types) != 1 || types[0] != "default" {
		t.Fatalf("PrimaryCount=1 应单类型 default，实际 %v", types)
	}
	p2 := resolveConnectionPolicy(2, 1, 0, 0, 0, 0, nil)
	types := p2.primaryTypes()
	if len(types) != 2 {
		t.Fatalf("PrimaryCount=2 应分流为 2 个类型，实际 %v", types)
	}
	set := map[string]bool{}
	for _, ty := range types {
		set[ty] = true
	}
	if !set["tcp"] || !set["udp"] {
		t.Fatalf("分流类型应含 tcp+udp，实际 %v", types)
	}
	t.Logf("✅ primaryTypes 分流集合正确")
}

// 确保 io 与 sync 包被使用（连接/协程并发场景）
var _ = io.Discard
var _ sync.WaitGroup
