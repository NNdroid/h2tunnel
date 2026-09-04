package h2tunnel

import (
	"crypto/rand"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// setupBenchmarkEnv 初始化压测服务端环境
func setupBenchmarkEnv() (serverURL, targetAddr, testToken string) {
	certFile := "bench_cert.pem"
	keyFile := "bench_key.pem"
	generateTestCerts(certFile, keyFile) // 依赖 e2e_test.go 中的证书生成函数

	targetAddr = "127.0.0.1:30000"
	startEchoServer(targetAddr) // 依赖 e2e_test.go 中的回显服务器

	serverAddr := "127.0.0.1:28443"
	serverURL = "https://" + serverAddr
	testToken = "bench-token"

	// 启动服务端 (config-only: 直接构造 serverConfig)
	go startServerDirect(serverConfig{
		ListenAddr:    serverAddr,
		TLSCert:       certFile,
		TLSKey:        keyFile,
		EnableTLS:     true,
		Path:          "/tunnel",
		Transport:     transportAll,
		ExpectedToken: testToken,
		LogLevel:      "fatal", // 压测时关掉服务端日志
	})

	time.Sleep(2 * time.Second)
	return serverURL, targetAddr, testToken
}

// BenchmarkH2TunnelAllProtocols 极限吞吐量测试 (全量 10 种协议)
func BenchmarkH2TunnelAllProtocols(b *testing.B) {
	serverURL, targetAddr, testToken := setupBenchmarkEnv()

	// 压测矩阵：覆盖全部 10 种组合
	cases := []struct {
		name       string
		clientPort string
		isUDP      bool
		args       []string
	}{
		// ---- TCP 代理组 ----
		{"H2_TCP", "30001", false, []string{}},
		{"gRPC_TCP", "30002", false, []string{"-grpc"}},
		{"H3_TCP", "30003", false, []string{"-h3"}},
		{"WT_TCP", "30004", false, []string{"-wt"}},
		{"MASQUE_TCP", "30005", false, []string{"-masque"}},

		// ---- UDP 代理组 ----
		{"H2_UDP_Stream", "30006", true, []string{"-udp"}},
		{"gRPC_UDP_Stream", "30007", true, []string{"-udp", "-grpc"}},
		{"H3_UDP_Stream", "30008", true, []string{"-udp", "-h3"}},
		{"WT_UDP_Stream", "30009", true, []string{"-udp", "-wt"}},
		{"MASQUE_UDP", "30010", true, []string{"-udp", "-masque"}},
	}

	// 提前启动所有的客户端进行预热 (协议开关映射到 clientConfig 字段)
	for _, tc := range cases {
		clientListen := "127.0.0.1:" + tc.clientPort
		cc := clientConfig{
			ListenAddr: clientListen,
			ServerUrl:  serverURL,
			Path:       "/tunnel",
			TargetAddr: targetAddr,
			Insecure:   true,
			Token:      testToken,
			LogLevel:   "fatal", // 压测时关掉客户端日志
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
	}
	time.Sleep(2 * time.Second) // 等待所有客户端端口绑定完毕

	// 每次发送 16KB 的数据块 (既能测出吞吐量，又不会超过 UDP 的安全边界)
	payloadSize := 16 * 1024
	payload := make([]byte, payloadSize)
	rand.Read(payload) // 随机数据填充，防止底层连接进行数据压缩作弊

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			clientListen := "127.0.0.1:" + tc.clientPort
			network := "tcp"
			if tc.isUDP {
				network = "udp"
			}

			// 建立压测连接
			conn, err := net.Dial(network, clientListen)
			if err != nil {
				b.Fatalf("无法连接到客户端: %v", err)
			}
			defer conn.Close()

			// 为 UDP 和 TCP 设置读写超时，防止异常时死锁
			conn.SetDeadline(time.Now().Add(30 * time.Second))

			readBuf := make([]byte, payloadSize)

			// ⚠️ 告诉框架每次操作的字节数，让它自动计算 MB/s 吞吐量
			b.SetBytes(int64(payloadSize))

			// ⚠️ 极其关键：排除前面启动、建连的耗时，从这里才开始纯净的 IO 测速！
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				// 1. 发送数据
				_, err := conn.Write(payload)
				if err != nil {
					b.Fatalf("写入失败: %v", err)
				}

				// 2. 接收数据 (UDP 和 TCP 的读取策略不同)
				if tc.isUDP {
					// UDP 面向报文：由于是 loopback 且 payload 没超上限，通常一次 Read 就能拿完
					var readTotal int
					for readTotal < payloadSize {
						n, err := conn.Read(readBuf[readTotal:])
						if err != nil {
							b.Fatalf("UDP 读取失败: %v", err)
						}
						readTotal += n
					}
				} else {
					// TCP 面向字节流：必须用 ReadFull 确保读满 16KB
					_, err = io.ReadFull(conn, readBuf)
					if err != nil {
						b.Fatalf("TCP 读取失败: %v", err)
					}
				}
			}

			// 停止计时，准备下一次循环
			b.StopTimer()
		})
	}

	// 清理临时证书
	os.Remove("bench_cert.pem")
	os.Remove("bench_key.pem")
}
