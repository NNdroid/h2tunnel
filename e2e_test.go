package main

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
// 1. 生成一次性测试证书 (TLS)
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
// 2. 启动 Target 回显服务器 (TCP & UDP)
// =========================================
func startEchoServer(addr string) {
	// TCP Echo
	go func() {
		l, err := net.Listen("tcp", addr)
		if err != nil { return }
		for {
			conn, err := l.Accept()
			if err != nil { continue }
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(conn)
		}
	}()

	// UDP Echo (缓冲区加大到 64KB，防止大包截断死锁)
	go func() {
		uAddr, _ := net.ResolveUDPAddr("udp", addr)
		conn, err := net.ListenUDP("udp", uAddr)
		if err != nil { return }
		
		// 🚨 这里的 65536 是关键！必须大于压测的 payloadSize (16384)
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
// 3. 终极自动化测试矩阵
// =========================================
func TestH2TunnelAllModes(t *testing.T) {
	// 1. 准备环境
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

	// 2. 启动隧道服务端
	go runServer([]string{
		"-listen", serverAddr,
		"-cert", certFile,
		"-key", keyFile,
		"-h3", // 开启 H3 以支持 WT 和 MASQUE
		"-token", testToken,
		"-loglevel", "error", // 减少测试时的日志刷屏，想看详细过程可以改为 debug
	})

	// 给服务端一点时间启动
	time.Sleep(2 * time.Second)

	// 3. 测试用例矩阵
	type testCase struct {
		name       string
		clientPort string
		isUDP      bool
		args       []string
	}

	// 3. 测试用例矩阵 (全量覆盖 10 种协议组合)
	cases := []testCase{
		// ---- TCP 系列 ----
		{"H2_TCP", "20001", false, []string{}},
		{"gRPC_TCP", "20002", false, []string{"-grpc"}},
		{"H3_TCP", "20003", false, []string{"-h3"}},
		{"WT_TCP", "20004", false, []string{"-wt"}},
		{"MASQUE_TCP", "20005", false, []string{"-masque"}},
		
		// ---- UDP 系列 ----
		{"H2_UDP_Stream", "20006", true, []string{"-udp"}},
		{"gRPC_UDP_Stream", "20007", true, []string{"-udp", "-grpc"}},
		{"H3_UDP_Stream", "20008", true, []string{"-udp", "-h3"}},
		{"WT_UDP_Stream", "20009", true, []string{"-udp", "-wt"}},
		{"MASQUE_UDP", "20010", true, []string{"-udp", "-masque"}},
	}

	// 4. 执行测试矩阵
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clientListen := "127.0.0.1:" + tc.clientPort
			
			// 组装客户端启动参数
			baseArgs := []string{
				"-listen", clientListen,
				"-server", serverURL,
				"-target", targetAddr,
				"-insecure",
				"-token", testToken,
				"-loglevel", "error",
			}
			clientArgs := append(baseArgs, tc.args...)

			// 启动对应的客户端
			go runClient(clientArgs)
			time.Sleep(1 * time.Second) // 等待客户端监听就绪

			// 发起真实数据测试
			testMsg := []byte(fmt.Sprintf("Hello h2tunnel via %s", tc.name))
			var conn net.Conn
			var err error

			if tc.isUDP {
				conn, err = net.Dial("udp", clientListen)
			} else {
				conn, err = net.Dial("tcp", clientListen)
			}

			if err != nil {
				t.Fatalf("无法连接到本地客户端监听端口: %v", err)
			}
			defer conn.Close()

			// 设置超时防止测试卡死
			conn.SetDeadline(time.Now().Add(5 * time.Second))

			// 发送测试数据
			_, err = conn.Write(testMsg)
			if err != nil {
				t.Fatalf("数据发送失败: %v", err)
			}

			// 读取回显数据
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil {
				t.Fatalf("数据接收失败 (未收到回显): %v", err)
			}

			// 校验数据完整性
			if string(buf[:n]) != string(testMsg) {
				t.Fatalf("数据损坏! 预期: %s, 实际收到: %s", testMsg, buf[:n])
			}
			
			t.Logf("✅ 完美通过!")
		})
	}
}