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
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

var Version = "dev"

var zlog *zap.SugaredLogger = zap.NewNop().Sugar()

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
	encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig),
		zapcore.AddSync(os.Stdout),
		level,
	)

	logger := zap.New(core)
	zlog = logger.Sugar()
}

// ==========================================
// gRPC 数据帧封装器
// ==========================================

type grpcWriter struct {
	w io.Writer
}

func (g *grpcWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	buf := make([]byte, 5+len(p))
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(p)))
	copy(buf[5:], p)

	if _, err := g.w.Write(buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

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
}

// ==========================================
// 服务端逻辑 (Server)
// ==========================================
func runServer(args []string) {
	serverCmd := flag.NewFlagSet("server", flag.ExitOnError)
	listenAddr := serverCmd.String("listen", ":8443", "服务端监听地址")
	tlsCert := serverCmd.String("cert", "", "TLS 证书文件路径")
	tlsKey := serverCmd.String("key", "", "TLS 私钥文件路径")
	path := serverCmd.String("path", "/tunnel", "代理路径")
	allowLocal := serverCmd.Bool("local-only", true, "是否只允许转发到本地")
	logLevel := serverCmd.String("loglevel", "info", "日志等级")
	enableH3 := serverCmd.Bool("h3", false, "是否在相同端口开启 HTTP/3 与 WebTransport (必须配置证书)")

	serverCmd.Parse(args)
	initLogger(*logLevel)
	defer zlog.Sync()

	mux := http.NewServeMux()

	var wtServer *webtransport.Server
	if *enableH3 {
		if *tlsCert == "" || *tlsKey == "" {
			zlog.Fatalf("[Error] 开启 H3/WT 必须提供 TLS 证书")
		}
		wtServer = &webtransport.Server{
			H3: &http3.Server{
				Addr:    *listenAddr,
				Handler: mux,
			},
			CheckOrigin: func(r *http.Request) bool { return true },
		}
		go func() {
			zlog.Infof("[H3/WT Server] 🚀 启动 HTTP/3 & WebTransport (UDP), 监听: %s, 路径: %s", *listenAddr, *path)
			if err := wtServer.ListenAndServeTLS(*tlsCert, *tlsKey); err != nil {
				zlog.Fatalf("H3/WT 启动失败: %v", err)
			}
		}()
	}

	mux.HandleFunc(*path, func(w http.ResponseWriter, r *http.Request) {
		tunnelHandler(w, r, *allowLocal, wtServer)
	})

	if *tlsCert != "" && *tlsKey != "" {
		server := &http.Server{
			Addr:    *listenAddr,
			Handler: mux,
		}
		zlog.Infof("[H2 Server] 🟢 启动标准 HTTP/2 隧道 (TCP), 监听: %s, 路径: %s", *listenAddr, *path)
		if err := server.ListenAndServeTLS(*tlsCert, *tlsKey); err != nil {
			zlog.Fatalf("启动失败: %v", err)
		}
	} else {
		h2s := &http2.Server{}
		server := &http.Server{
			Addr:    *listenAddr,
			Handler: h2c.NewHandler(mux, h2s),
		}
		zlog.Infof("[H2C Server] 🟡 启动明文 HTTP/2 隧道 (TCP), 监听: %s, 路径: %s", *listenAddr, *path)
		if err := server.ListenAndServe(); err != nil {
			zlog.Fatalf("启动失败: %v", err)
		}
	}
}

func tunnelHandler(w http.ResponseWriter, r *http.Request, allowLocal bool, wtServer *webtransport.Server) {
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

	// 🌟 WebTransport 处理分支
	if wtServer != nil && r.Method == http.MethodConnect {
		session, err := wtServer.Upgrade(w, r)
		if err != nil {
			zlog.Errorf("[Error] WT Upgrade 失败: %v", err)
			return
		}
		zlog.Infof("[Connect] WebTransport 会话已建立 -> 路由目标: %s", target)

		for {
			stream, err := session.AcceptStream(r.Context())
			if err != nil {
				break
			}
			zlog.Debugf("[Stream] 接收到新的 WT 子流转发请求")

			// 🌟 核心修正：这里直接将取到的指针流传递进去
			go handleWTServerStream(stream, target)
		}

		zlog.Infof("[Disconnect] WebTransport 会话已释放 -> 目标: %s", target)
		return
	}

	// =====================================
	// 常规 H2 / H3 / gRPC 处理分支
	// =====================================
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

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

// 🌟 核心修正：接收的参数显式声明为指针 `*webtransport.Stream`
func handleWTServerStream(stream *webtransport.Stream, target string) {
	targetConn, err := net.Dial("tcp", target)
	if err != nil {
		zlog.Errorf("[Error] WT 子流拨号目标 %s 失败: %v", target, err)
		(*stream).CancelWrite(1)
		return
	}
	defer targetConn.Close()

	defer func() {
		(*stream).CancelRead(0)
		(*stream).CancelWrite(0)
		(*stream).Close()
	}()

	errChan := make(chan error, 2)
	go func() {
		// 因为 stream 是指针，天然实现了 io.Writer
		_, err := io.Copy(targetConn, stream)
		errChan <- err
	}()
	go func() {
		// 因为 stream 是指针，天然实现了 io.Reader
		_, err := io.Copy(stream, targetConn)
		errChan <- err
	}()

	<-errChan
}

// ==========================================
// 客户端逻辑 (Client)
// ==========================================

type WTSessionManager struct {
	dialer  *webtransport.Dialer
	reqUrl  string
	headers http.Header
	session *webtransport.Session
	mu      sync.Mutex
}

func (m *WTSessionManager) GetSession(ctx context.Context) (*webtransport.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.session != nil {
		return m.session, nil
	}

	zlog.Infof("[Client] ⚡ 正在建立 WebTransport 底层主会话...")
	_, session, err := m.dialer.Dial(ctx, m.reqUrl, m.headers)
	if err != nil {
		return nil, err
	}
	m.session = session
	zlog.Infof("[Client] ✅ WebTransport 主会话建立成功")
	return session, nil
}

func (m *WTSessionManager) ClearSession() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.session = nil
}

func runClient(args []string) {
	clientCmd := flag.NewFlagSet("client", flag.ExitOnError)
	listenAddr := clientCmd.String("listen", "127.0.0.1:2222", "本地监听地址")
	serverUrl := clientCmd.String("server", "https://127.0.0.1:8443", "服务端 URL")
	path := clientCmd.String("path", "/tunnel", "代理路径")
	targetAddr := clientCmd.String("target", "127.0.0.1:22", "远端最终目标 TCP 地址")
	insecure := clientCmd.Bool("insecure", true, "跳过 TLS 证书校验")
	customHost := clientCmd.String("host", "", "自定义伪装 Host")
	useGRPC := clientCmd.Bool("grpc", false, "使用 gRPC 协议伪装")
	useH3 := clientCmd.Bool("h3", false, "使用 HTTP/3 协议连接")
	useWT := clientCmd.Bool("wt", false, "使用 WebTransport 协议连接")
	logLevel := clientCmd.String("loglevel", "info", "日志等级")

	clientCmd.Parse(args)
	initLogger(*logLevel)
	defer zlog.Sync()

	if *useH3 && *useWT {
		zlog.Fatalf("[Client Error] -h3 和 -wt 标志互斥，不能同时使用")
	}

	reqUrl := strings.TrimRight(*serverUrl, "/") + *path
	isHTTPS := strings.HasPrefix(reqUrl, "https://")

	var httpClient *http.Client
	var wtManager *WTSessionManager

	if *useWT {
		if !isHTTPS {
			zlog.Fatalf("[Client Error] WebTransport 必须使用 HTTPS URL")
		}
		tlsConfig := &tls.Config{InsecureSkipVerify: *insecure}
		if *customHost != "" {
			tlsConfig.ServerName = *customHost
		}
		
		headers := make(http.Header)
		headers.Set("X-Target", *targetAddr)
		headers.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		if *customHost != "" {
			headers.Set("Host", *customHost)
		}

		wtManager = &WTSessionManager{
			dialer: &webtransport.Dialer{
				TLSClientConfig: tlsConfig,
				QUICConfig: &quic.Config{
					HandshakeIdleTimeout: 10 * time.Second,
					MaxIdleTimeout:       30 * time.Second,
					KeepAlivePeriod:      8 * time.Second,
				},
			},
			reqUrl:  reqUrl,
			headers: headers,
		}
	} else if *useH3 {
		if !isHTTPS {
			zlog.Fatalf("[Client Error] HTTP/3 必须使用 HTTPS URL")
		}
		tlsConfig := &tls.Config{InsecureSkipVerify: *insecure}
		if *customHost != "" {
			tlsConfig.ServerName = *customHost
		}
		rt := &http3.Transport{
			TLSClientConfig: tlsConfig,
			QUICConfig: &quic.Config{
				HandshakeIdleTimeout: 10 * time.Second,
				MaxIdleTimeout:       30 * time.Second,
				KeepAlivePeriod:      8 * time.Second,
			},
		}
		httpClient = &http.Client{Transport: rt}
	} else {
		transport := &http2.Transport{}
		if isHTTPS {
			tlsConfig := &tls.Config{InsecureSkipVerify: *insecure}
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
		zlog.Fatalf("无法监听本地端口: %v", err)
	}
	defer listener.Close()

	if *useWT {
		zlog.Infof("[Client] 🚀 启动模式: WebTransport, 监听本地: %s", *listenAddr)
	} else if *useH3 {
		zlog.Infof("[Client] 🚀 启动模式: HTTP/3, 监听本地: %s", *listenAddr)
	} else {
		zlog.Infof("[Client] 🚀 启动模式: HTTP/2 (或 gRPC), 监听本地: %s", *listenAddr)
	}
	zlog.Infof("[Client] 🔗 隧道目标: %s -> %s", reqUrl, *targetAddr)

	for {
		localConn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleClientConn(localConn, httpClient, wtManager, reqUrl, *targetAddr, *customHost, *useGRPC, *useWT)
	}
}

func handleClientConn(localConn net.Conn, httpClient *http.Client, wtManager *WTSessionManager, reqUrl string, target string, customHost string, useGRPC bool, useWT bool) {
	defer localConn.Close()
	zlog.Debugf("[Client] 🟢 接收到本地连接，正在打通隧道...")

	// =====================================
	// WebTransport 传输
	// =====================================
	if useWT {
		session, err := wtManager.GetSession(context.Background())
		if err != nil {
			zlog.Errorf("[Client Error] 获取 WebTransport 会话失败: %v", err)
			return
		}

		stream, err := session.OpenStreamSync(context.Background())
		if err != nil {
			zlog.Warnf("[Client] ⚠️ 检测到 WebTransport 僵尸会话，正在清理重试...")
			wtManager.ClearSession()
			session, err = wtManager.GetSession(context.Background())
			if err != nil {
				zlog.Errorf("[Client Error] 重试建立会话失败: %v", err)
				return
			}
			stream, err = session.OpenStreamSync(context.Background())
			if err != nil {
				zlog.Errorf("[Client Error] 重试开启 WT 流失败: %v", err)
				return
			}
		}

		zlog.Debugf("[Client] ✅ WT 虚拟数据流通道已建立")

		errChan := make(chan error, 2)
		go func() {
			// 🌟 核心修正：stream 已经是 *webtransport.Stream 指针了，直接传即可！
			_, err := io.Copy(stream, localConn)
			(*stream).CancelRead(0)
			errChan <- err
		}()
		go func() {
			// 🌟 核心修正：同理，直接传 stream
			_, err := io.Copy(localConn, stream)
			(*stream).CancelWrite(0)
			errChan <- err
		}()

		<-errChan
		(*stream).Close()
		zlog.Debugf("[Client] 🔴 隧道流连接已断开 (底层 Session 仍保持连接)")
		return
	}

	// =====================================
	// 常规 H2 / H3 / gRPC 握手及传输
	// =====================================
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

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
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

	zlog.Debugf("[Client] ✅ HTTP 隧道已建立")

	var reader io.Reader = resp.Body
	if useGRPC {
		reader = &grpcReader{r: resp.Body}
	}

	io.Copy(localConn, reader)
	zlog.Debugf("[Client] 🔴 隧道连接已断开")
}