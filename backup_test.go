package h2tunnel

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

// splitTestEnv parses the "https://addr|echoPort" returned by startBackupTestEnv.
func splitTestEnv(s string) (serverURL, echoAddr string) {
	parts := strings.Split(s, "|")
	return parts[0], "127.0.0.1:" + parts[1]
}

// ================= 3. Primary/backup line integration tests =================

// startBackupTestEnv starts the environment needed by the backup tests:
// echo target + tunnel server. seq isolates the ports to avoid conflicts
// between tests. Returns serverURL.
func startBackupTestEnv(t *testing.T, seq int) string {
	certFile := fmt.Sprintf("test_cert_backup_%d.pem", seq)
	keyFile := fmt.Sprintf("test_key_backup_%d.pem", seq)
	if err := generateTestCerts(certFile, keyFile); err != nil {
		t.Fatalf("gen certs: %v", err)
	}
	t.Cleanup(func() { os.Remove(certFile); os.Remove(keyFile) })

	// Port bases sit in the 27000 range to avoid colliding with hardcoded
	// ranges such as e2e_test's StrictDemux (22000-22003) — the go startXxx
	// background goroutines of each test never exit and hold their ports for a long time.
	echoPort := 27000 + seq*2
	serverPort := 27443 + seq*2
	startEchoServer(fmt.Sprintf("127.0.0.1:%d", echoPort))
	serverAddr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	go startServerDirect(serverConfig{
		ListenAddr:    serverAddr,
		TLSCert:       certFile,
		TLSKey:        keyFile,
		EnableTLS:     true,
		Path:          "/tunnel",
		Transport:     transportH2,
		Authenticator: tokenAuth("backup-token"),
		LogLevel:      "error",
		SessionWindow: 256,
		Network:       "all",
	})
	waitTCPOrTLSReady(t, serverAddr, 30*time.Second)
	return "https://" + serverAddr + "|" + fmt.Sprintf("%d", echoPort)
}

func newInsecureHTTPClient() *http.Client {
	// Consistent with the real client: HTTP/2 (h2c / TLS h2); frame streaming relies on multiplexing.
	return &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// TestBackupHotStandbyAlive hot standby: the backup enters Alive after its independent handshake succeeds.
func TestBackupHotStandbyAlive(t *testing.T) {
	env := startBackupTestEnv(t, 1)
	serverURL, echoAddr := splitTestEnv(env)
	cfg := clientConfig{
		ServerUrl:      serverURL,
		Path:           "/tunnel",
		TargetAddr:     echoAddr,
		Insecure:       true,
		Token:          "backup-token",
		Network:        "tcp",
		LogLevel:       "error",
		SessionWindow:  256,
		HandshakeAckMs: 3000,
		KeepaliveSec:   1,
	}
	hc := newInsecureHTTPClient()

	bl := newManagedLine("sess-backup-test", roleBackup, networkTCP, cfg, serverURL+"/tunnel", hc, nil, 0)
	go bl.Start()
	defer bl.close()

	// Wait for the backup handshake to complete → Alive
	deadline := time.After(8 * time.Second)
	for {
		if bl.Alive() {
			break
		}
		if bl.State() == backupFailed {
			t.Fatalf("backup handshake failed, state=%s", bl.State())
		}
		select {
		case <-deadline:
			t.Fatalf("backup did not become Alive within the deadline, state=%s", bl.State())
		default:
			time.Sleep(50 * time.Millisecond)
		}
	}
	t.Logf("✅ backup hot standby reached Alive (takeover-ready)")
}

// TestBackupTakeoverOnlyIfConfirmed only a backup confirmed alive may take over.
func TestBackupTakeoverOnlyIfConfirmed(t *testing.T) {
	env := startBackupTestEnv(t, 2)
	serverURL, echoAddr := splitTestEnv(env)
	cfg := clientConfig{
		ServerUrl:      serverURL,
		Path:           "/tunnel",
		TargetAddr:     echoAddr,
		Insecure:       true,
		Token:          "backup-token",
		Network:        "tcp",
		LogLevel:       "error",
		SessionWindow:  256,
		HandshakeAckMs: 3000,
		KeepaliveSec:   1,
	}
	hc := newInsecureHTTPClient()

	// Scenario A: freshly created, not started backup → unconfirmed → takeover forbidden
	bl := newManagedLine("sess-takeover-a", roleBackup, networkTCP, cfg, serverURL+"/tunnel", hc, nil, 0)
	if bl.Alive() {
		t.Fatal("a not-started backup must not be Alive (takeover forbidden)")
	}
	if bl.State() != backupIdle {
		t.Fatalf("not-started backup state = %s, want idle", bl.State())
	}

	// Scenario B: becomes Alive after start → takeover allowed
	go bl.Start()
	defer bl.close()
	deadline := time.After(8 * time.Second)
	for {
		if bl.Alive() {
			break
		}
		if bl.State() == backupFailed {
			t.Fatalf("backup handshake failed")
		}
		select {
		case <-deadline:
			t.Fatalf("backup not Alive")
		default:
			time.Sleep(50 * time.Millisecond)
		}
	}
	if !bl.Alive() {
		t.Fatal("a backup confirmed alive should allow takeover")
	}
	t.Logf("✅ only a backup confirmed alive is allowed to take over")
}

// TestBackupWrongTokenRejected auth failure → backup handshake rejected → no takeover.
func TestBackupWrongTokenRejected(t *testing.T) {
	env := startBackupTestEnv(t, 3)
	serverURL, echoAddr := splitTestEnv(env)
	cfg := clientConfig{
		ServerUrl:      serverURL,
		Path:           "/tunnel",
		TargetAddr:     echoAddr,
		Insecure:       true,
		Token:          "WRONG-token", // wrong token
		Network:        "tcp",
		LogLevel:       "error",
		SessionWindow:  256,
		HandshakeAckMs: 3000,
		KeepaliveSec:   1,
	}
	hc := newInsecureHTTPClient()

	bl := newManagedLine("sess-bad-token", roleBackup, networkTCP, cfg, serverURL+"/tunnel", hc, nil, 0)
	go bl.Start()
	defer bl.close()

	time.Sleep(1 * time.Second)
	if bl.Alive() {
		t.Fatal("a backup that failed auth must not be Alive (takeover forbidden)")
	}
	t.Logf("✅ auth-failed backup rejected, no takeover")
}
