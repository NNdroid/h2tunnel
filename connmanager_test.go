package h2tunnel

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
// connmanager_test.go — full runnable tests for the L3 connection-manager layer
//
// Coverage:
//   A. Underlying protocols (h2/grpc/masque-tcp/wt/h3 + udp) × Resume v2 full-duplex echo matrix
//   B. Primary/backup counts (default 1+1) dial correctly
//   C. Type sharding (PrimaryCount=2 → one primary each for tcp/udp)
//   D. Primary down → backup promoted → replenished
//   E. Backup KEEPALIVE failure detection → removal → replenishment
//   F. Dial-interval throttling (no redial storms)
//   G. establish_interval phase offset takes effect (backups establish only after the interval)
//   H. Auth failure → backups do not take over
//   I. Version mismatch → 426 rejection
//   J. connectionPolicy default-value validation
//   K. Boundaries: primary_count/backup_count=0 fall back to defaults
//
// Run: go test -run 'ConnManager|connectionPolicy' -v ./...
// =========================================

// Port base: independent of backup_test(27000) and e2e_test(20000/22000).
// Each test uses its own seq offset to avoid port conflicts from background goroutines that never exit.
const connMgrPortBase = 29000

// connManagerHTTPServer starts a tunnel server side with resume/backup enabled.
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
	go startServerDirect(serverConfig{
		ListenAddr:    serverAddr,
		TLSCert:       certFile,
		TLSKey:        keyFile,
		EnableTLS:     true,
		Path:          "/tunnel",
		Transport:     transportH2,
		Authenticator: tokenAuth(token),
		LogLevel:      "error",
		SessionWindow: 256,
		Network:       "all",
	})
	waitTCPOrTLSReady(t, serverAddr, 30*time.Second)
	return "https://" + serverAddr, fmt.Sprintf("127.0.0.1:%d", echoPort)
}

// connMgrClient builds a standard resume client config.
func connMgrClient(serverURL, echoAddr, token string, network string) clientConfig {
	return clientConfig{
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
// A. Underlying protocols × Resume v2 full-duplex echo matrix
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
	go startServerDirect(serverConfig{
		ListenAddr:    serverAddr,
		TLSCert:       certFile,
		TLSKey:        keyFile,
		EnableTLS:     true,
		Path:          "/tunnel",
		Transport:     transportAll,
		Authenticator: tokenAuth(token),
		LogLevel:      "error",
		SessionWindow: 256,
		Network:       "all",
	})
	waitTCPOrTLSReady(t, serverAddr, 30*time.Second)

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
			if tc.network == "udp" {
				waitUDPReady(t, cc.ListenAddr, 30*time.Second)
			} else {
				waitTCPOrTLSReady(t, cc.ListenAddr, 30*time.Second)
			}

			// Full-duplex echo verification: local → tunnel → echo target → tunnel → local
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
			t.Logf("✅ %s full-duplex echo passed on top of resume/2", tc.name)
		})
	}
}

// =========================================
// Connection manager test environment
// =========================================

// startConnManagerEnv starts a test environment backed by a connectionManager.
// Returns the manager and serverURL; the manager is closed via t.Cleanup.
func startConnManagerEnv(t *testing.T, seq int, policy connectionPolicy) (*connectionManager, string, string) {
	serverURL, echoAddr := connManagerHTTPServer(t, seq, "connmgr-token")
	cfg := connMgrClient(serverURL, echoAddr, "connmgr-token", "tcp")
	m := newConnectionManager(policy, cfg, serverURL+"/tunnel", connMgrHTTPClient(), fmt.Sprintf("CM%d", seq))
	t.Cleanup(m.Close)
	return m, serverURL, echoAddr
}

// waitCount polls until the manager's primary/backup counts reach the target (with timeout).
func waitCount(t *testing.T, cond func() bool, timeout time.Duration, msg string) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout: %s", msg)
}

// =========================================
// B. Primary/backup counts (default 1+1)
// =========================================

func TestConnManagerPrimaryBackupCounts(t *testing.T) {
	policy := resolveConnectionPolicy(1, 1, 0, 0, 1, 2, nil) // establish=1s, missed=2
	m, _, _ := startConnManagerEnv(t, 1, policy)
	m.Start()

	waitCount(t, func() bool { return m.PrimaryCount() == 1 }, 30*time.Second, "primary should dial 1 connection")
	waitCount(t, func() bool { return m.BackupCount() == 1 }, 30*time.Second, "backup should dial 1 after the establish interval")
	t.Logf("✅ primary=%d backup=%d (default 1+1)", m.PrimaryCount(), m.BackupCount())
}

// =========================================
// C. Type sharding (PrimaryCount=2 → one primary each for tcp/udp)
// =========================================

func TestConnManagerTypeSharding(t *testing.T) {
	// The test environment uses a 1s backup redial throttle; if a shared CI host briefly
	// jitters during the first handshake, the final 2-primary 1-backup state can still be
	// verified without waiting for the production default of 15s.
	policy := resolveConnectionPolicy(2, 1, 0, 1, 1, 2, nil) // 2 primaries 1 backup, networks={tcp,udp}
	m, _, _ := startConnManagerEnv(t, 2, policy)
	m.Start()

	waitCount(t, func() bool { return m.PrimaryCount() == 2 }, 30*time.Second, "should dial 2 primaries")
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
		t.Fatalf("type sharding not in effect: primary types=%v, expected to cover both tcp and udp", types)
	}
	waitCount(t, func() bool { return m.BackupCount() == 1 }, 30*time.Second, "backup should dial 1")
	t.Logf("✅ type sharding in effect: primary types=%v backup=%d", types, m.BackupCount())
}

// =========================================
// D. Primary down → backup promoted → replenished
// =========================================

func TestConnManagerSwitchoverReplenish(t *testing.T) {
	policy := resolveConnectionPolicy(1, 1, 1, 1, 1, 2, nil) // fast redial, easier to observe promotion + replenishment
	m, _, _ := startConnManagerEnv(t, 3, policy)
	m.Start()

	// wait for primary and backup to be ready
	waitCount(t, func() bool { return m.PrimaryCount() == 1 && m.BackupCount() == 1 }, 30*time.Second, "primary and backup ready")

	// primary connection dies → trigger promotion + replenishment
	m.FailPrimary("default")

	// after promotion the primary count should recover to 1, and the backup count refill to 1
	waitCount(t, func() bool { return m.PrimaryCount() == 1 && m.BackupCount() == 1 }, 30*time.Second, "after primary loss a backup should be promoted and counts refilled")
	if st := m.PrimaryState("default"); st != backupAlive {
		t.Fatalf("promoted primary connection state should be alive, got=%s", st)
	}
	t.Logf("✅ primary down → backup promoted to primary(alive) → backup refilled, primary=%d backup=%d", m.PrimaryCount(), m.BackupCount())
}

// =========================================
// E. Backup KEEPALIVE failure detection → removal → replenishment
// =========================================

func TestConnManagerBackupKeepaliveFailure(t *testing.T) {
	policy := resolveConnectionPolicy(1, 1, 1, 1, 1, 2, nil) // missed=2, keepalive=1s, fast replenishment
	m, _, _ := startConnManagerEnv(t, 4, policy)
	m.Start()

	waitCount(t, func() bool { return m.BackupCount() == 1 }, 30*time.Second, "backup ready")

	// close the backup lines' streams directly to simulate KEEPALIVE link loss → consecutive missed ACKs → marked dead
	m.mu.Lock()
	for _, bl := range m.backups {
		bl.close() // closes closeCh, keepaliveLoop exits; further replenishment is handled by the monitor
	}
	m.mu.Unlock()

	// the dead one is removed → replenished back to 1
	waitCount(t, func() bool { return m.BackupCount() == 1 }, 30*time.Second, "dead backup should be removed and replenished")
	// the primary connection is unaffected
	if m.PrimaryCount() != 1 {
		t.Fatalf("backup failure must not affect the primary connection, primary=%d", m.PrimaryCount())
	}
	t.Logf("✅ backup KEEPALIVE failure removed and replenished, backup=%d", m.BackupCount())
}

// =========================================
// F. Dial-interval throttling (no redial storms)
// =========================================

func TestConnManagerDialIntervalThrottle(t *testing.T) {
	// Primary dial interval 2s: after a primary failure, the replacement primary must not appear
	// before the interval (anti redial-storm).
	// Note: build connectionPolicy directly with BackupCount=0 so backup promotion cannot bypass the primary dial throttle.
	interval := 2 * time.Second
	policy := connectionPolicy{
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

	waitCount(t, func() bool { return m.PrimaryCount() == 1 }, 30*time.Second, "primary ready")

	// trigger primary failure: less than interval since the last primary dial, so replenishment should be throttled (not before the interval)
	t0 := time.Now()
	m.FailPrimary("default")
	time.Sleep(interval / 2) // 1s < 2s
	m.mu.Lock()
	stillDown := m.primaries["default"] == nil
	m.mu.Unlock()
	if !stillDown {
		t.Fatalf("primary was replenished before the dial interval elapsed (throttle broken)")
	}

	// after the interval expires the primary should be refilled, and not before t0+interval
	waitCount(t, func() bool { return m.PrimaryCount() == 1 }, interval+3*time.Second, "primary replenished after interval elapsed")
	elapsed := time.Since(t0)
	if elapsed < interval-400*time.Millisecond {
		t.Fatalf("primary replenished earlier than the dial interval (%v): actual %v", interval, elapsed)
	}
	t.Logf("✅ primary dial interval throttle in effect: replenishment happened after %v (>=%v)", elapsed.Round(100*time.Millisecond), interval)
}

// =========================================
// G. establish_interval phase offset takes effect
// =========================================

func TestConnManagerEstablishInterval(t *testing.T) {
	establish := 2 * time.Second
	policy := resolveConnectionPolicy(1, 1, 0, 0, 2, 2, nil)
	m, _, _ := startConnManagerEnv(t, 6, policy)
	start := time.Now()
	m.Start()

	// the primary should appear immediately
	waitCount(t, func() bool { return m.PrimaryCount() == 1 }, 30*time.Second, "primary established immediately")

	// The backup should appear later than establish_interval.
	// The wait window must cover the legitimate scenario "initial dial fails, then the redial is
	// throttled by the 15s interval": with bdSec=0 BackupDialInterval takes the default 15s, and if
	// the first backup handshake occasionally fails under high load and is removed by reconcile, the
	// redial must wait out the full 15s throttle; a 6s window would occasionally be misjudged as a
	// failure under the concurrency pressure of the full test run.
	// Only the wait duration is relaxed; the core assertion "not earlier than establish_interval" stays unchanged.
	waitCount(t, func() bool { return m.BackupCount() == 1 }, 30*time.Second, "backup established after the interval")
	backupAt := time.Since(start)
	if backupAt < establish-500*time.Millisecond {
		t.Fatalf("backup established too early, earlier than establish_interval(%v): actual %v", establish, backupAt)
	}
	t.Logf("✅ establish_interval phase offset in effect: primary after %v, backup after %v (>%v)", time.Since(start), backupAt.Round(100*time.Millisecond), establish)
}

// =========================================
// H. Auth failure → backups do not take over
// =========================================

func TestConnManagerAuthFailureNoTakeover(t *testing.T) {
	policy := resolveConnectionPolicy(1, 1, 0, 0, 1, 2, nil)
	m, serverURL, echoAddr := startConnManagerEnv(t, 7, policy)
	// override the config with a wrong token so every line's handshake is rejected
	m.cfg = connMgrClient(serverURL, echoAddr, "WRONG", "tcp")
	m.Start()

	time.Sleep(2 * time.Second)
	// auth failure: the primary must not be alive, and there must be no takeover-capable backup
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
		t.Fatal("primary must not be alive when auth fails")
	}
	if backupOK {
		t.Fatal("no takeover-capable backup should exist when auth fails")
	}
	t.Logf("✅ auth failure → primary/backup both unavailable, takeover forbidden")
}

// =========================================
// I. Version mismatch → 426 rejection
// =========================================

func TestConnManagerVersionUnsupported(t *testing.T) {
	serverURL, _ := connManagerHTTPServer(t, 8, "connmgr-token")

	// build a resume/1 (legacy) request → should be rejected with 426
	req, _ := http.NewRequest(http.MethodPost, serverURL+"/tunnel", strings.NewReader(""))
	req.Header.Set("X-Tunnel-Proto", "resume/1") // legacy protocol
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
		t.Fatalf("legacy protocol should return 426, got %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Resume-Error") != "version-unsupported" {
		t.Fatalf("X-Resume-Error should be version-unsupported, got %q", resp.Header.Get("X-Resume-Error"))
	}
	t.Logf("✅ legacy protocol (not resume/2) → 426 version-unsupported, no downgrade target")
}

// =========================================
// J. connectionPolicy defaults
// =========================================

func TestConnectionPolicyDefaults(t *testing.T) {
	p := resolveConnectionPolicy(0, -1, 0, 0, 0, 0, nil)
	if p.PrimaryCount != 1 || p.BackupCount != 1 {
		t.Fatalf("default primary/backup should be 1+1, got %d+%d", p.PrimaryCount, p.BackupCount)
	}
	if p.EstablishInterval != 100*time.Second {
		t.Fatalf("default establish interval should be 100s, got %v", p.EstablishInterval)
	}
	if p.PrimaryDialInterval != primaryDialDefault || p.BackupDialInterval != backupDialDefault {
		t.Fatalf("default dial intervals wrong: primary=%v backup=%v", p.PrimaryDialInterval, p.BackupDialInterval)
	}
	if p.BackoffMaxMissedAcks != 3 {
		t.Fatalf("default failure threshold should be 3, got %d", p.BackoffMaxMissedAcks)
	}
	if got := p.PrimaryNetworks; len(got) != 2 || got[0] != networkTCP || got[1] != networkUDP {
		t.Fatalf("default sharding networks wrong: %v", got)
	}
	t.Logf("✅ connectionPolicy defaults all correct")
}

// =========================================
// K. Boundary: backup_count=0 explicitly disables backups
// =========================================

func TestConnectionPolicyBoundary(t *testing.T) {
	// primary 0 → default 1; backup 0 → explicitly disabled
	p := resolveConnectionPolicy(0, 0, 0, 0, 0, 0, nil)
	if p.PrimaryCount != 1 || p.BackupCount != 0 {
		t.Fatalf("expected 1 primary + 0 backup, got %d+%d", p.PrimaryCount, p.BackupCount)
	}
	// an explicit network set is deduplicated and fixed to tcp, udp order
	p2 := resolveConnectionPolicy(2, 1, 0, 0, 0, 0, []string{"udp", "tcp", "udp"})
	if got := p2.PrimaryNetworks; len(got) != 2 || got[0] != networkTCP || got[1] != networkUDP {
		t.Fatalf("sharding network normalization failed: %v", got)
	}
	// invalid (negative) establish interval → default 100s
	p3 := resolveConnectionPolicy(1, 1, 0, 0, -5, 0, nil)
	if p3.EstablishInterval != 100*time.Second {
		t.Fatalf("negative establish interval should fall back to 100s, got %v", p3.EstablishInterval)
	}
	t.Logf("✅ config boundary fallbacks to defaults correctly")
}

// =========================================
// Supplement: primaryTypes shard-set correctness
// =========================================

func TestConnectionPolicyPrimaryTypes(t *testing.T) {
	p := resolveConnectionPolicy(1, 1, 0, 0, 0, 0, nil)
	if types := p.primaryTypes(); len(types) != 1 || types[0] != "default" {
		t.Fatalf("PrimaryCount=1 should yield single type default, got %v", types)
	}
	p2 := resolveConnectionPolicy(2, 1, 0, 0, 0, 0, nil)
	types := p2.primaryTypes()
	if len(types) != 2 {
		t.Fatalf("PrimaryCount=2 should shard into 2 types, got %v", types)
	}
	set := map[string]bool{}
	for _, ty := range types {
		set[ty] = true
	}
	if !set["tcp"] || !set["udp"] {
		t.Fatalf("shard types should include tcp+udp, got %v", types)
	}
	t.Logf("✅ primaryTypes shard set correct")
}

// keep the io and sync packages used (connection/goroutine concurrency scenarios)
var _ = io.Discard
var _ sync.WaitGroup
