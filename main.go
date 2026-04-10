package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// 定义全局版本号变量（默认值设为 dev，编译时会被覆盖）
var Version = "dev"

// 全局 Zap Logger 实例，默认赋予一个空操作 Logger 以防空指针
var zlog *zap.SugaredLogger = zap.NewNop().Sugar()

// initLogger 初始化全局 Zap Logger
func initLogger(levelStr string) {
	var level zapcore.Level
	switch strings.ToLower(levelStr) {
	case "debug":
		level = zapcore.DebugLevel
	case "info":
		level = zapcore.InfoLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	default:
		level = zapcore.InfoLevel
	}

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder // 终端带颜色的级别输出

	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig),
		zapcore.AddSync(os.Stdout),
		level,
	)

	logger := zap.New(core)
	zlog = logger.Sugar()
}

// ==========================================
// gRPC 数据帧封装器 (核心黑科技)
// ==========================================

// grpcWriter 负责将普通 TCP 流量打包为 gRPC 数据帧
type grpcWriter struct {
	w io.Writer
}

func (g *grpcWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	// gRPC 帧头: 1 byte 压缩标志 (0) + 4 bytes 长度 (BigEndian)
	buf := make([]byte, 5+len(p))
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(p)))
	copy(buf[5:], p)

	if _, err := g.w.Write(buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

// grpcReader 负责从 gRPC 数据帧中解包出普通 TCP 流量
type grpcReader struct {
	r    io.Reader
	left uint32
}

func (g *grpcReader) Read(p []byte) (n int, err error) {
	for g.left == 0 {
		var header [5]byte
		if _, err := io.ReadFull(g.r, header[:]); err != nil {
			return 0, err
		}
		g.left = binary.BigEndian.Uint32(header[1:5])
	}

	toRead := uint32(len(p))
	if toRead > g.left {
		toRead = g.left
	}

	n, err = g.r.Read(p[:toRead])
	g.left -= uint32(n)
	return n, err
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		runServer(os.Args[2:])
	case "client":
		runClient(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("h2tunnel version %s\n", Version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Printf("未知的子命令: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("使用方法: h2tunnel <子命令> [参数]")
	fmt.Println("\n子命令:")
	fmt.Println("  server    启动隧道服务端")
	fmt.Println("  client    启动隧道客户端")
	fmt.Println("  version   查看当前版本号")
	fmt.Println("\n示例:")
	fmt.Println("  h2tunnel server -h")
	fmt.Println("  h2tunnel client -h")
}

// ==========================================
// 服务端逻辑 (Server)
// ==========================================
func runServer(args []string) {
	serverCmd := flag.NewFlagSet("server", flag.ExitOnError)
	listenAddr := serverCmd.String("listen", ":8443", "服务端监听地址 (如 :8443 或 0.0.0.0:8443)")
	tlsCert := serverCmd.String("cert", "", "TLS 证书文件路径 (为空则启动 h2c 明文模式)")
	tlsKey := serverCmd.String("key", "", "TLS 私钥文件路径")
	path := serverCmd.String("path", "/tunnel", "代理路径，需与客户端一致")
	allowLocal := serverCmd.Bool("local-only", true, "安全选项：是否只允许转发到服务端的 127.0.0.1 (强烈建议开启)")
	logLevel := serverCmd.String("loglevel", "info", "日志等级: debug, info, warn, error")
	enableH3 := serverCmd.Bool("h3", false, "是否在相同端口同时开启 HTTP/3 (UDP/QUIC) 监听 (必须配置证书)")

	serverCmd.Parse(args)
	initLogger(*logLevel)
	defer zlog.Sync()

	mux := http.NewServeMux()
	mux.HandleFunc(*path, func(w http.ResponseWriter, r *http.Request) {
		tunnelHandler(w, r, *allowLocal)
	})

	if *tlsCert != "" && *tlsKey != "" {
		// 🌟 如果开启了 H3，在后台 Goroutine 启动 HTTP/3 监听
		if *enableH3 {
			go func() {
				h3Server := &http3.Server{
					Addr:    *listenAddr,
					Handler: mux,
				}
				zlog.Infof("[H3 Server] 🚀 启动 HTTP/3 隧道 (UDP/QUIC), 监听: %s, 路径: %s", *listenAddr, *path)
				if err := h3Server.ListenAndServeTLS(*tlsCert, *tlsKey); err != nil {
					zlog.Fatalf("HTTP/3 启动失败: %v", err)
				}
			}()
		}

		server := &http.Server{
			Addr:    *listenAddr,
			Handler: mux,
		}
		zlog.Infof("[H2 Server] 🟢 启动标准 HTTP/2 隧道 (TLS/TCP), 监听: %s, 路径: %s", *listenAddr, *path)
		if err := server.ListenAndServeTLS(*tlsCert, *tlsKey); err != nil {
			zlog.Fatalf("启动失败: %v", err)
		}
	} else {
		if *enableH3 {
			zlog.Fatalf("[Error] 开启 HTTP/3 必须提供 TLS 证书 (-cert 和 -key)")
		}
		h2s := &http2.Server{}
		server := &http.Server{
			Addr:    *listenAddr,
			Handler: h2c.NewHandler(mux, h2s),
		}
		zlog.Infof("[H2C Server] 🟡 启动明文 HTTP/2 隧道 (无加密), 监听: %s, 路径: %s", *listenAddr, *path)
		zlog.Warnf("[H2C Server] ⚠️ 警告：明文传输通常仅用于配合 Nginx 等前置反代使用")
		if err := server.ListenAndServe(); err != nil {
			zlog.Fatalf("启动失败: %v", err)
		}
	}
}

// tunnelHandler 处理核心的隧道转发逻辑
func tunnelHandler(w http.ResponseWriter, r *http.Request, allowLocal bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	target := r.Header.Get("X-Target")
	if target == "" {
		http.Error(w, "Missing X-Target header", http.StatusBadRequest)
		return
	}

	if allowLocal && !strings.HasPrefix(target, "127.0.0.1:") && !strings.HasPrefix(target, "localhost:") {
		zlog.Warnf("[Reject] 拒绝连接到非本地目标: %s", target)
		http.Error(w, "Target forbidden", http.StatusForbidden)
		return
	}

	// 🌟 动态识别当前请求的底层协议 (HTTP/2.0 或 HTTP/3.0)
	protoName := r.Proto
	isGRPC := r.Header.Get("Content-Type") == "application/grpc"
	
	if isGRPC {
		protoName = "gRPC over " + r.Proto
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Add("Trailer", "Grpc-Status")
		w.Header().Add("Trailer", "Grpc-Message")
	}

	zlog.Infof("[Connect] 收到 %s 隧道请求 -> 目标: %s", protoName, target)

	targetConn, err := net.Dial("tcp", target)
	if err != nil {
		zlog.Errorf("[Error] 拨号目标 %s 失败: %v", target, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	flusher, ok := w.(http.Flusher)
	if !ok {
		zlog.Error("[Error] 客户端/中间件不支持 HTTP 流式传输")
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	var writer io.Writer = w
	var reader io.Reader = r.Body

	if isGRPC {
		writer = &grpcWriter{w: w}
		reader = &grpcReader{r: r.Body}
	}

	errChan := make(chan error, 2)

	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := targetConn.Read(buf)
			if n > 0 {
				if _, writeErr := writer.Write(buf[:n]); writeErr != nil {
					errChan <- writeErr
					return
				}
				flusher.Flush()
			}
			if err != nil {
				errChan <- err
				return
			}
		}
	}()

	go func() {
		_, err := io.Copy(targetConn, reader)
		errChan <- err
	}()

	<-errChan

	if isGRPC {
		w.Header().Set("Grpc-Status", "0")
		w.Header().Set("Grpc-Message", "OK")
	}

	zlog.Infof("[Disconnect] %s 隧道已释放 -> 目标: %s", protoName, target)
}

// ==========================================
// 客户端逻辑 (Client)
// ==========================================
func runClient(args []string) {
	clientCmd := flag.NewFlagSet("client", flag.ExitOnError)
	listenAddr := clientCmd.String("listen", "127.0.0.1:2222", "本地监听的 TCP 地址 (如 127.0.0.1:2222)")
	serverUrl := clientCmd.String("server", "http://127.0.0.1:8443", "远端 H2/H2C 服务端 URL (需携带 http:// 或 https://)")
	path := clientCmd.String("path", "/tunnel", "请求路径，需与服务端一致")
	targetAddr := clientCmd.String("target", "127.0.0.1:22", "要求远端服务器代理访问的最终目标 TCP 地址")
	insecure := clientCmd.Bool("insecure", true, "是否跳过 TLS 证书校验 (适用于自签证书)")
	customHost := clientCmd.String("host", "", "自定义伪装的 SNI / Host 域名 (用于突破 CDN 或前置反代)")
	useGRPC := clientCmd.Bool("grpc", false, "开启 gRPC 协议伪装 (适用于严格审查的 CDN 或 nginx grpc_pass)")
	logLevel := clientCmd.String("loglevel", "info", "日志等级: debug, info, warn, error")
	useH3 := clientCmd.Bool("h3", false, "使用 HTTP/3 (QUIC/UDP) 协议连接服务端")

	clientCmd.Parse(args)
	initLogger(*logLevel)
	defer zlog.Sync()

	reqUrl := strings.TrimRight(*serverUrl, "/") + *path
	isHTTPS := strings.HasPrefix(reqUrl, "https://")

	var httpClient *http.Client

	// 🌟 核心：根据 -h3 标志动态选择底层 Transport
	if *useH3 {
		if !isHTTPS {
			zlog.Fatalf("[Client Error] HTTP/3 必须使用 https:// 协议的 Server URL")
		}
		tlsConfig := &tls.Config{
			InsecureSkipVerify: *insecure,
		}
		if *customHost != "" {
			tlsConfig.ServerName = *customHost
		}
		rt := &http3.Transport{
			TLSClientConfig: tlsConfig,
			QUICConfig: &quic.Config{
				MaxIdleTimeout:  30 * time.Second,
				KeepAlivePeriod: 15 * time.Second, // 维持 UDP NAT 映射
			},
		}
		httpClient = &http.Client{Transport: rt}
	} else {
		transport := &http2.Transport{}
		if isHTTPS {
			tlsConfig := &tls.Config{
				InsecureSkipVerify: *insecure,
			}
			if *customHost != "" {
				tlsConfig.ServerName = *customHost
			}
			transport.TLSClientConfig = tlsConfig
		} else {
			transport.AllowHTTP = true
			transport.DialTLSContext = func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			}
		}
		httpClient = &http.Client{Transport: transport}
	}

	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		zlog.Fatalf("[Client Error] 无法监听本地端口 %s: %v", *listenAddr, err)
	}
	defer listener.Close()

	if *useH3 {
		zlog.Infof("[Client] 🚀 客户端已启动 (HTTP/3 模式), 监听本地: %s", *listenAddr)
	} else {
		zlog.Infof("[Client] 🚀 客户端已启动 (HTTP/2 模式), 监听本地: %s", *listenAddr)
	}
	zlog.Infof("[Client] 🔗 隧道目标: %s", reqUrl)
	zlog.Infof("[Client] 🎯 最终目标: %s", *targetAddr)
	if *customHost != "" {
		zlog.Infof("[Client] 🎭 伪装 Host/SNI: %s", *customHost)
	}
	if *useGRPC {
		zlog.Infof("[Client] 🧬 已启用 gRPC 模式伪装")
	}

	for {
		localConn, err := listener.Accept()
		if err != nil {
			zlog.Errorf("[Client Error] 接收连接失败: %v", err)
			continue
		}
		go handleClientConn(localConn, httpClient, reqUrl, *targetAddr, *customHost, *useGRPC)
	}
}

func handleClientConn(localConn net.Conn, httpClient *http.Client, reqUrl string, target string, customHost string, useGRPC bool) {
	defer localConn.Close()
	zlog.Debugf("[Client] 🟢 接收到本地连接，正在打通隧道...")

	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", reqUrl, pr)
	if err != nil {
		zlog.Errorf("[Client Error] 创建请求失败: %v", err)
		return
	}

	if customHost != "" {
		req.Host = customHost
	}

	if useGRPC {
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("TE", "trailers")
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
	req.Header.Set("X-Target", target)

	var writer io.Writer = pw
	if useGRPC {
		writer = &grpcWriter{w: pw}
	}

	go func() {
		io.Copy(writer, localConn)
		pw.Close()
	}()

	resp, err := httpClient.Do(req)
	if err != nil {
		zlog.Errorf("[Client Error] 隧道请求失败: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		zlog.Errorf("[Client Error] 服务端拒绝连接, 状态码: %d", resp.StatusCode)
		return
	}

	zlog.Infof("[Client] ✅ 隧道已建立，开始传输数据")

	var reader io.Reader = resp.Body
	if useGRPC {
		reader = &grpcReader{r: resp.Body}
	}

	io.Copy(localConn, reader)
	zlog.Debugf("[Client] 🔴 隧道连接已断开")
}