package h2tunnel

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"testing"
	"time"
)

// =========================================
// 1. Generate one-shot test certificates (TLS)
// =========================================
func generateTestCerts(certFile, keyFile string) error {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour)
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"h2tunnel e2e test"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)

	certOut, _ := os.Create(certFile)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, _ := os.Create(keyFile)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()

	return nil
}

// =========================================
// 2. Start the Target echo servers (TCP & UDP)
// =========================================
// waitTCPOrTLSReady polls until the TCP port accepts connections (the TLS server
// handshake completes at the http.Server layer, so a successful TCP accept means
// the listener is ready).
// Replaces a fixed sleep: 2s may not be enough on slow CI runners, and locally it would just be wasted waiting.
func waitTCPOrTLSReady(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server %s not ready within %v", addr, timeout)
}

// waitPortReady polls until a TCP port is connectable; takes no *testing.T (for
// benchmarks / environments without t) and panics on timeout.
func waitPortReady(addr string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	panic("port " + addr + " not ready within " + timeout.String())
}

// waitUDPReady probes UDP client readiness with a real echo (local → client → tunnel →
// echo target → tunnel → client → local). Do not probe by "trying to bind the same
// port": the probe socket races with the client's ListenUDP, and within that window
// the client's bind can fail (the legacy path would even Fatal and kill the whole test
// process). The echo probe has no race and verifies the entire UDP chain along the
// way. Precondition: the client's target is an echo service (true for all tests).
func waitUDPReady(t *testing.T, clientAddr string, timeout time.Duration) {
	t.Helper()
	conn, err := net.Dial("udp", clientAddr)
	if err != nil {
		t.Fatalf("dial udp client %s: %v", clientAddr, err)
	}
	defer conn.Close()
	msg := []byte("udp-ready-probe")
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := conn.Write(msg); err != nil {
			continue
		}
		buf := make([]byte, len(msg))
		n, err := conn.Read(buf)
		if err == nil && n == len(msg) && string(buf[:n]) == string(msg) {
			return
		}
	}
	t.Fatalf("udp client %s not ready within %v", clientAddr, timeout)
}

// waitUDPBound probes that a UDP port is bound without racing (no tunnel data plane
// is established). Used for scenarios where the server is expected to reject and an
// echo will never arrive (e.g. network=tcp gating tests).
// How it works: a connected UDP socket sending to an unlistened port receives an ICMP
// Port Unreachable, which the kernel turns into a connection-refused error on the
// *next* read/write — leaving time for the ICMP to arrive between two sends, an error
// on the second means unbound, success on the second means bound.
func waitUDPBound(t *testing.T, clientAddr string, timeout time.Duration) {
	t.Helper()
	conn, err := net.Dial("udp", clientAddr)
	if err != nil {
		t.Fatalf("dial udp client %s: %v", clientAddr, err)
	}
	defer conn.Close()
	probe := []byte("udp-bound-probe")
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_, _ = conn.Write(probe)
		time.Sleep(30 * time.Millisecond)
		if _, wErr := conn.Write(probe); wErr == nil {
			return
		}
	}
	t.Fatalf("udp client %s not bound within %v", clientAddr, timeout)
}

func startEchoServer(addr string) { // TCP Echo
	go func() {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return
		}
		for {
			conn, err := l.Accept()
			if err != nil {
				continue
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(conn)
		}
	}()

	// UDP Echo (buffer enlarged to 64KB to prevent large-packet truncation deadlock)
	go func() {
		uAddr, _ := net.ResolveUDPAddr("udp", addr)
		conn, err := net.ListenUDP("udp", uAddr)
		if err != nil {
			return
		}

		// 🚨 The 65536 here is critical! It must be larger than the load-test payloadSize (16384)
		buf := make([]byte, 65536)
		for {
			n, cAddr, err := conn.ReadFromUDP(buf)
			if err == nil {
				conn.WriteToUDP(buf[:n], cAddr)
			}
		}
	}()
}

// =========================================
// 3. The ultimate automated test matrix
// =========================================
func TestH2TunnelAllModes(t *testing.T) {
	// 1. Prepare the environment
	certFile := "test_cert.pem"
	keyFile := "test_key.pem"
	generateTestCerts(certFile, keyFile)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	targetAddr := "127.0.0.1:20000"
	startEchoServer(targetAddr)

	serverAddr := "127.0.0.1:18443"
	serverURL := "https://" + serverAddr
	testToken := "secret-e2e-token"

	// 2. Start the tunnel server (config-only: build serverConfig directly, avoiding dependency on the removed CLI flags)
	go startServerDirect(serverConfig{
		ListenAddr:    serverAddr,
		TLSCert:       certFile,
		TLSKey:        keyFile,
		EnableTLS:     true,
		Path:          "/tunnel",
		Transport:     transportAll,
		Authenticator: tokenAuth(testToken),
		LogLevel:      "error", // reduce log spam during tests; change to debug to see the detailed flow
	})

	// Give the server some time to start (polling wait instead of a fixed sleep: slow CI cold starts make this flaky)
	waitTCPOrTLSReady(t, serverAddr, 30*time.Second)

	// 3. Test case matrix
	type testCase struct {
		name       string
		clientPort string
		isUDP      bool
		args       []string
	}

	// 3. Test case matrix (full coverage of the 10 protocol combinations)
	cases := []testCase{
		// ---- TCP series ----
		{"H2_TCP", "20001", false, []string{}},
		{"gRPC_TCP", "20002", false, []string{"-grpc"}},
		{"H3_TCP", "20003", false, []string{"-h3"}},
		{"WT_TCP", "20004", false, []string{"-wt"}},
		{"MASQUE_TCP", "20005", false, []string{"-masque"}},

		// ---- UDP series ----
		{"H2_UDP_Stream", "20006", true, []string{"-udp"}},
		{"gRPC_UDP_Stream", "20007", true, []string{"-udp", "-grpc"}},
		{"H3_UDP_Stream", "20008", true, []string{"-udp", "-h3"}},
		{"WT_UDP_Stream", "20009", true, []string{"-udp", "-wt"}},
		{"MASQUE_UDP", "20010", true, []string{"-udp", "-masque"}},
	}

	// 4. Run the test matrix
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clientListen := "127.0.0.1:" + tc.clientPort

			// Start the matching client (config-only: protocol switches from tc.args mapped to clientConfig fields)
			cc := clientConfig{
				ListenAddr: clientListen,
				ServerUrl:  serverURL,
				Path:       "/tunnel",
				TargetAddr: targetAddr,
				Insecure:   true,
				Token:      testToken,
				LogLevel:   "error",
			}
			for i := 0; i < len(tc.args); i++ {
				switch tc.args[i] {
				case "-grpc":
					cc.Transport = transportGRPC
				case "-h3":
					cc.Transport = transportH3
				case "-wt":
					cc.Transport = transportWT
				case "-masque":
					cc.Transport = transportMasque
				case "-udp":
					cc.Network = "udp"
				}
			}
			go startClientDirect(cc)
			if tc.isUDP {
				waitUDPReady(t, clientListen, 30*time.Second)
			} else {
				waitTCPOrTLSReady(t, clientListen, 30*time.Second)
			}

			// Run a real data test
			testMsg := []byte(fmt.Sprintf("Hello h2tunnel via %s", tc.name))
			var conn net.Conn
			var err error

			if tc.isUDP {
				conn, err = net.Dial("udp", clientListen)
			} else {
				conn, err = net.Dial("tcp", clientListen)
			}

			if err != nil {
				t.Fatalf("cannot connect to the local client listen port: %v", err)
			}
			defer conn.Close()

			// set a timeout so the test cannot hang
			conn.SetDeadline(time.Now().Add(5 * time.Second))

			// send test data
			_, err = conn.Write(testMsg)
			if err != nil {
				t.Fatalf("data send failed: %v", err)
			}

			// read the echoed data
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil {
				t.Fatalf("data receive failed (no echo received): %v", err)
			}

			// verify data integrity
			if string(buf[:n]) != string(testMsg) {
				t.Fatalf("data corrupted! expected: %s, actually received: %s", testMsg, buf[:n])
			}

			t.Logf("✅ passed perfectly!")
		})
	}
}

// =========================================
// 4. Realistic non-Echo service interaction test (e.g. SSH protocol handshake)
// Verifies Padding is correctly unwrapped and wrapped on a real server, with no data pollution
// =========================================
func TestH2Tunnel_NonEchoService_Realistic(t *testing.T) {
	certFile := "test_cert_realistic.pem"
	keyFile := "test_key_realistic.pem"
	generateTestCerts(certFile, keyFile)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	targetAddr := "127.0.0.1:21000"
	serverAddr := "127.0.0.1:21443"
	serverURL := "https://" + serverAddr
	testToken := "realistic-token"

	// start the non-Echo mock service (server sends a Banner first, then interacts)
	ln, err := net.Listen("tcp", targetAddr)
	if err != nil {
		t.Fatalf("cannot listen on the test service port: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))

				// 1. server proactively sends the SSH-Banner to the client first
				_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.0\r\n"))

				// 2. server reads the Client-Banner sent by the client
				buf := make([]byte, 100)
				n, err := conn.Read(buf)
				if err != nil || string(buf[:n]) != "SSH-2.0-CustomClient\r\n" {
					return
				}

				// 3. server replies with a confirmation packet
				_, _ = conn.Write([]byte("SERVER_HANDSHAKE_OK\r\n"))
			}(c)
		}
	}()

	// start the H2Tunnel server
	go startServerDirect(serverConfig{
		ListenAddr:    serverAddr,
		TLSCert:       certFile,
		TLSKey:        keyFile,
		EnableTLS:     true,
		Path:          "/tunnel",
		Transport:     transportH2,
		Authenticator: tokenAuth(testToken),
		LogLevel:      "error",
	})
	waitTCPOrTLSReady(t, serverAddr, 30*time.Second)

	clientListen := "127.0.0.1:21001"
	go startClientDirect(clientConfig{
		ListenAddr: clientListen,
		ServerUrl:  serverURL,
		Path:       "/tunnel",
		TargetAddr: targetAddr,
		Insecure:   true,
		Token:      testToken,
		LogLevel:   "error",
	})
	waitTCPOrTLSReady(t, clientListen, 30*time.Second)

	conn, err := net.Dial("tcp", clientListen)
	if err != nil {
		t.Fatalf("failed to connect to the client: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 1. the client should first read the Banner proactively pushed down by the server
	serverBanner := make([]byte, 21)
	_, err = io.ReadFull(conn, serverBanner)
	if err != nil {
		t.Fatalf("failed to read server Banner: %v", err)
	}
	if string(serverBanner) != "SSH-2.0-OpenSSH_9.0\r\n" {
		t.Fatalf("server Banner corrupted! received: %q", string(serverBanner))
	}

	// 2. client sends the Client-Banner
	_, err = conn.Write([]byte("SSH-2.0-CustomClient\r\n"))
	if err != nil {
		t.Fatalf("failed to send client Banner: %v", err)
	}

	// 3. client reads the server's second reply
	reply := make([]byte, 21)
	_, err = io.ReadFull(conn, reply)
	if err != nil {
		t.Fatalf("failed to read confirmation reply: %v", err)
	}
	if string(reply) != "SERVER_HANDSHAKE_OK\r\n" {
		t.Fatalf("confirmation reply corrupted! received: %q", string(reply))
	}

	t.Log("✅ realistic non-Echo protocol full-duplex handshake test passed perfectly!")
}

// =========================================
// 5. Strict protocol demux and network-type gating tests (Strict Demux)
// =========================================
func TestH2Tunnel_StrictDemux(t *testing.T) {
	certFile := "test_cert_demux.pem"
	keyFile := "test_key_demux.pem"
	generateTestCerts(certFile, keyFile)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	targetAddr := "127.0.0.1:22000"
	startEchoServer(targetAddr)

	serverAddr := "127.0.0.1:22443"
	serverURL := "https://" + serverAddr
	testToken := "demux-token"

	// start the strict-mode server: gRPC only and TCP only
	go startServerDirect(serverConfig{
		ListenAddr:    serverAddr,
		TLSCert:       certFile,
		TLSKey:        keyFile,
		EnableTLS:     true,
		Path:          "/tunnel",
		Transport:     "grpc", // strictly require gRPC
		Network:       "tcp",  // strictly allow TCP only, reject UDP
		Authenticator: tokenAuth(testToken),
		LogLevel:      "error",
	})
	waitTCPOrTLSReady(t, serverAddr, 30*time.Second)

	// Test case 1: client without gRPC sends an H2 POST request -> should be intercepted by the server's strict demux (403)
	t.Run("Reject_Non_gRPC_When_Server_Requires_gRPC", func(t *testing.T) {
		clientListen := "127.0.0.1:22001"
		go startClientDirect(clientConfig{
			ListenAddr: clientListen,
			ServerUrl:  serverURL,
			Path:       "/tunnel",
			TargetAddr: targetAddr,
			Insecure:   true,
			Transport:  transportH2, // deliberately not using gRPC
			Token:      testToken,
			LogLevel:   "error",
		})
		waitTCPOrTLSReady(t, clientListen, 30*time.Second)

		conn, err := net.Dial("tcp", clientListen)
		if err != nil {
			t.Fatalf("failed to connect to the local client: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))

		_, err = conn.Write([]byte("ping"))
		if err != nil {
			t.Fatalf("write failed: %v", err)
		}

		buf := make([]byte, 100)
		_, err = conn.Read(buf)
		// the remote returns 403 so the tunnel handshake fails and the local connection is closed immediately (EOF)
		if err == nil {
			t.Fatalf("connection expected to be strictly intercepted and closed by the server, but data was read successfully: %s", string(buf))
		}
		t.Log("✅ non-gRPC request successfully intercepted by strict mode!")
	})

	// Test case 2: client with gRPC enabled sends a request -> should pass through
	t.Run("Accept_gRPC_When_Server_Requires_gRPC", func(t *testing.T) {
		clientListen := "127.0.0.1:22002"
		go startClientDirect(clientConfig{
			ListenAddr: clientListen,
			ServerUrl:  serverURL,
			Path:       "/tunnel",
			TargetAddr: targetAddr,
			Insecure:   true,
			Transport:  transportGRPC, // correctly using gRPC
			Token:      testToken,
			LogLevel:   "error",
		})
		waitTCPOrTLSReady(t, clientListen, 30*time.Second)

		conn, err := net.Dial("tcp", clientListen)
		if err != nil {
			t.Fatalf("failed to connect to the local client: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))

		testMsg := []byte("Hello Strict gRPC")
		_, err = conn.Write(testMsg)
		if err != nil {
			t.Fatalf("write failed: %v", err)
		}

		buf := make([]byte, 100)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("failed to read echo: %v", err)
		}
		if string(buf[:n]) != string(testMsg) {
			t.Fatalf("data mismatch: %s != %s", buf[:n], testMsg)
		}
		t.Log("✅ compliant gRPC request passed through successfully!")
	})

	// Test case 3: client tries to send UDP data -> should be blocked by the server's Network="tcp" restriction
	t.Run("Reject_UDP_When_Server_Requires_TCP_Only", func(t *testing.T) {
		clientListen := "127.0.0.1:22003"
		go startClientDirect(clientConfig{
			ListenAddr: clientListen,
			ServerUrl:  serverURL,
			Path:       "/tunnel",
			TargetAddr: targetAddr,
			Insecure:   true,
			Transport:  transportGRPC,
			Network:    "udp", // requests UDP
			Token:      testToken,
			LogLevel:   "error",
		})
		// expect the server to reject UDP: no echo will ever arrive, so only verify the client port is bound
		waitUDPBound(t, clientListen, 30*time.Second)

		conn, err := net.Dial("udp", clientListen)
		if err != nil {
			t.Fatalf("failed to connect to the local client: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))

		_, err = conn.Write([]byte("udp ping"))
		if err != nil {
			t.Fatalf("UDP write failed: %v", err)
		}

		buf := make([]byte, 100)
		_, err = conn.Read(buf)
		if err == nil {
			t.Fatalf("UDP request expected to be rejected by the server with no echo, but data was received")
		}
		t.Log("✅ non-compliant UDP request successfully intercepted by the server!")
	})
}
