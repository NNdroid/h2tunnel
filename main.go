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
	"net/url"
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
	case "debug": level = zapcore.DebugLevel
	case "info":  level = zapcore.InfoLevel
	case "warn":  level = zapcore.WarnLevel
	case "error": level = zapcore.ErrorLevel
	default:      level = zapcore.InfoLevel
	}

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig),
		zapcore.AddSync(os.Stdout),
		level,
	)
	zlog = zap.New(core).Sugar()
}

// ==========================================
// 🌟 1. 核心工具与编解码引擎
// ==========================================

func parseMasqueTarget(reqPath string) (string, error) {
	parts := strings.Split(reqPath, "/")
	if len(parts) < 6 {
		return "", fmt.Errorf("invalid masque path format")
	}
	host, err1 := url.PathUnescape(parts[4])
	port, err2 := url.PathUnescape(parts[5])
	if err1 != nil || err2 != nil {
		return "", fmt.Errorf("failed to unescape host/port")
	}
	return net.JoinHostPort(host, port), nil
}

func writeVarInt(w io.Writer, val uint64) error {
	if val <= 0x3f {
		_, err := w.Write([]byte{byte(val)})
		return err
	} else if val <= 0x3fff {
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, uint16(val)|0x4000)
		_, err := w.Write(buf)
		return err
	} else if val <= 0x3fffffff {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(val)|0x80000000)
		_, err := w.Write(buf)
		return err
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, val|0xc000000000000000)
	_, err := w.Write(buf)
	return err
}

type byteReader struct{ io.Reader }

func (b *byteReader) ReadByte() (byte, error) {
	var buf [1]byte
	_, err := io.ReadFull(b.Reader, buf[:])
	return buf[0], err
}

func readVarInt(r io.Reader) (uint64, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	prefix := b[0] >> 6
	length := 1 << prefix
	val := uint64(b[0] & 0x3f)

	if length > 1 {
		buf := make([]byte, length-1)
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, err
		}
		for _, v := range buf {
			val = (val << 8) | uint64(v)
		}
	}
	return val, nil
}

func writeUDPCapsule(w io.Writer, p []byte) error {
	if err := writeVarInt(w, 0x00); err != nil { return err }
	if err := writeVarInt(w, uint64(1+len(p))); err != nil { return err }
	if err := writeVarInt(w, 0x00); err != nil { return err }
	_, err := w.Write(p)
	return err
}

func readUDPCapsule(r io.Reader) ([]byte, error) {
	for {
		capsuleType, err := readVarInt(r)
		if err != nil { return nil, err }
		capsuleLen, err := readVarInt(r)
		if err != nil { return nil, err }
		lr := &io.LimitedReader{R: r, N: int64(capsuleLen)}
		if capsuleType == 0x00 {
			contextID, err := readVarInt(lr)
			if err != nil { return nil, err }
			if contextID == 0 {
				buf := make([]byte, lr.N)
				if _, err := io.ReadFull(lr, buf); err != nil { return nil, err }
				return buf, nil
			}
		}
		if lr.N > 0 { io.Copy(io.Discard, lr) }
	}
}

func writeUDPPacket(w io.Writer, p []byte) error {
	if len(p) > 65535 { return fmt.Errorf("UDP payload > 65535") }
	buf := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(p)))
	copy(buf[2:], p)
	_, err := w.Write(buf)
	return err
}

func readUDPPacket(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil { return nil, err }
	length := binary.BigEndian.Uint16(hdr[:])
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil { return nil, err }
	return buf, nil
}

// ==========================================
// 🌟 gRPC 数据帧封装器
// ==========================================

type grpcWriter struct{ w io.Writer }

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

// ==========================================
// 🌟 2. 流媒体代理核心引擎
// ==========================================

func proxyStream(sessionID string, network string, targetConn net.Conn, tunnelReader io.Reader, tunnelWriter io.Writer, flusher http.Flusher) {
	zlog.Debugf("[%s] 代理引擎启动, Network: %s", sessionID, network)

	if network == "udp" {
		errChan := make(chan error, 2)
		go func() {
			buf := make([]byte, 65536)
			for {
				n, err := targetConn.Read(buf)
				if err != nil { errChan <- err; return }
				if err := writeUDPPacket(tunnelWriter, buf[:n]); err != nil { errChan <- err; return }
				if flusher != nil { flusher.Flush() }
			}
		}()
		go func() {
			for {
				pkt, err := readUDPPacket(tunnelReader)
				if err != nil { errChan <- err; return }
				if _, err := targetConn.Write(pkt); err != nil { errChan <- err; return }
			}
		}()
		err := <-errChan
		zlog.Debugf("[%s] UDP 代理关闭: %v", sessionID, err)
	} else {
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			buf := make([]byte, 32*1024)
			for {
				n, err := targetConn.Read(buf)
				if n > 0 {
					_, wErr := tunnelWriter.Write(buf[:n])
					if wErr != nil {
						zlog.Debugf("[%s] 写入隧道失败: %v", sessionID, wErr)
						return
					}
					if flusher != nil {
						flusher.Flush()
					}
				}
				if err != nil {
					zlog.Debugf("[%s] 下行传输结束: %v", sessionID, err)
					return
				}
			}
		}()

		go func() {
			defer wg.Done()
			n, err := io.Copy(targetConn, tunnelReader)
			zlog.Debugf("[%s] 上行传输结束: Size %d, Err %v", sessionID, n, err)
			if cw, ok := targetConn.(interface{ CloseWrite() error }); ok {
				cw.CloseWrite()
			}
		}()

		wg.Wait()
		zlog.Debugf("[%s] TCP 代理流双向传输结束", sessionID)
	}
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "server": runServer(os.Args[2:])
	case "client": runClient(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("h2tunnel version %s\n", Version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Printf("未知子命令: %s\n", os.Args[1])
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
// 🌟 服务端核心逻辑
// ==========================================

func handleMasqueUDP(w http.ResponseWriter, r *http.Request, localOnlyFlag bool) {
	target, err := parseMasqueTarget(r.URL.Path)
	if err != nil { http.Error(w, "bad target", 400); return }

	if target == "" || (localOnlyFlag && !strings.HasPrefix(target, "127.0.0.1:")) {
		zlog.Warnf("[M-UDP] Forbidden Target: %s", target)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	
	tAddr, _ := net.ResolveUDPAddr("udp", target)
	tConn, err := net.DialUDP("udp", nil, tAddr)
	if err != nil {
		zlog.Errorf("[M-UDP] 无法连接到目标 UDP: %v", err)
		return
	}
	defer tConn.Close()

	w.WriteHeader(200)
	flusher := w.(http.Flusher)
	flusher.Flush()

	errChan := make(chan error, 2)

	go func() {
		buf := make([]byte, 65536)
		for {
			tConn.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, _, err := tConn.ReadFromUDP(buf)
			if err != nil {
				errChan <- err
				return
			}
			zlog.Debugf("[M-UDP] 收到远端数据包: %d bytes", n)
			if err := writeUDPCapsule(w, buf[:n]); err != nil {
				errChan <- err
				return
			}
			flusher.Flush()
		}
	}()

	go func() {
		for {
			p, err := readUDPCapsule(r.Body)
			if err != nil {
				errChan <- err
				return
			}
			zlog.Debugf("[M-UDP] 向远端转发数据包: %d bytes", len(p))
			if _, err := tConn.Write(p); err != nil {
				errChan <- err
				return
			}
		}
	}()

	err = <-errChan
	zlog.Infof("[M-UDP] 隧道关闭原因: %v", err)
}

func runServer(args []string) {
	serverCmd := flag.NewFlagSet("server", flag.ExitOnError)
	listenAddr := serverCmd.String("listen", ":8443", "服务端监听地址")
	tlsCert := serverCmd.String("cert", "", "TLS 证书文件路径")
	tlsKey := serverCmd.String("key", "", "TLS 私钥文件路径")
	path := serverCmd.String("path", "/tunnel", "代理路径")
	localOnlyFlag := serverCmd.Bool("local-only", false, "是否只允许转发到本地")
	logLevel := serverCmd.String("loglevel", "info", "日志等级")
	enableH3 := serverCmd.Bool("h3", false, "开启 HTTP/3 监听")

	serverCmd.Parse(args)
	initLogger(*logLevel)
	defer zlog.Sync()

	zlog.Infof("[Server] h2tunnel %s 正在启动...", Version)

	mux := http.NewServeMux()
	var wtServer *webtransport.Server

	mux.HandleFunc(*path, func(w http.ResponseWriter, r *http.Request) {
		tunnelHandler(w, r, *localOnlyFlag, wtServer)
	})

	rootHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fullPath := r.RequestURI
		if fullPath == "" || !strings.HasPrefix(fullPath, "/") {
			fullPath = r.URL.Path
		}

		zlog.Debugf("[Root] Request: %s %s (Host: %s)", r.Method, fullPath, r.Host)

		if r.Method == http.MethodConnect {
			matchedPath := ""
			if strings.HasPrefix(r.RequestURI, "/") {
				matchedPath = r.RequestURI
			} else if strings.HasPrefix(r.URL.Path, "/") {
				matchedPath = r.URL.Path
			}

			if matchedPath != "" {
				if strings.HasPrefix(matchedPath, "/.well-known/masque/tcp/") {
					zlog.Debugf("[Server] 成功命中 MASQUE-TCP: %s", matchedPath)
					r.URL.Path = matchedPath
					tunnelHandler(w, r, *localOnlyFlag, wtServer)
					return
				}
				if strings.HasPrefix(matchedPath, "/.well-known/masque/udp/") {
					zlog.Debugf("[Server] 成功命中 MASQUE-UDP: %s", matchedPath)
					r.URL.Path = matchedPath
					handleMasqueUDP(w, r, *localOnlyFlag)
					return
				}
				if matchedPath == *path {
					zlog.Debugf("[Server] 命中自定义路径 CONNECT (WT): %s", matchedPath)
					tunnelHandler(w, r, *localOnlyFlag, wtServer)
					return
				}
			}
			
			zlog.Warnf("[Server] 拒绝未知的 CONNECT 请求 | 匹配路径: '%s' | Host: '%s'", matchedPath, r.URL.Host)
			http.Error(w, "Unknown CONNECT Target", http.StatusNotFound)
			return
		}
		mux.ServeHTTP(w, r)
	})

	if *enableH3 {
		cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil { zlog.Fatalf("无法加载证书: %v", err) }
		wtServer = &webtransport.Server{
			H3: &http3.Server{
				Addr:    *listenAddr,
				Handler: rootHandler,
				TLSConfig: &tls.Config{
					Certificates: []tls.Certificate{cert},
					NextProtos:   []string{http3.NextProtoH3},
				},
				EnableDatagrams: true,
				QUICConfig: &quic.Config{
					EnableDatagrams:                  true,
					EnableStreamResetPartialDelivery: true,
					KeepAlivePeriod:                  10 * time.Second,
				},
			},
		}
		webtransport.ConfigureHTTP3Server(wtServer.H3)
		go func() {
			zlog.Infof("[H3 Server] 🚀 Listening: %s", *listenAddr)
			zlog.Debugf("[Server] 已激活 MASQUE 路径拦截引擎")
			wtServer.ListenAndServe()
		}()
	}

	if *tlsCert != "" {
		server := &http.Server{Addr: *listenAddr, Handler: rootHandler}
		zlog.Infof("[H2 Server] 🟢 Listening (TLS): %s", *listenAddr)
		server.ListenAndServeTLS(*tlsCert, *tlsKey)
	} else {
		server := &http.Server{Addr: *listenAddr, Handler: h2c.NewHandler(rootHandler, &http2.Server{})}
		zlog.Infof("[H2C Server] 🟡 Listening (H2C): %s", *listenAddr)
		server.ListenAndServe()
	}
}

func tunnelHandler(w http.ResponseWriter, r *http.Request, localOnlyFlag bool, wtServer *webtransport.Server) {
	isMasqueTCP := r.Method == http.MethodConnect && r.Header.Get("Protocol") == "connect-tcp"
	network := r.Header.Get("X-Network")
	if network != "udp" { network = "tcp" }
	if isMasqueTCP { network = "tcp" }
	
	// 检测是否为 gRPC 伪装
	isGRPC := r.Header.Get("Content-Type") == "application/grpc"

	sessionID := fmt.Sprintf("%s-%d", strings.ToUpper(network), time.Now().UnixNano()%10000)

	if wtServer != nil && r.Method == http.MethodConnect && !isMasqueTCP {
		session, err := wtServer.Upgrade(w, r)
		if err != nil { return }
		target := r.Header.Get("X-Target")
		zlog.Debugf("[%s] WebTransport Session Upgrade Success", sessionID)
		
		for {
			stream, err := session.AcceptStream(r.Context())
			if err != nil { break }
			go func(s *webtransport.Stream, t string, netType string) {
				tConn, errDial := net.Dial(netType, t)
				if errDial != nil { s.CancelWrite(1); return }
				defer tConn.Close()
				zlog.Infof("[%s] WT Stream Established -> %s", sessionID, t)
				proxyStream(sessionID, netType, tConn, s, s, nil)
				s.CancelRead(0)
			}(stream, target, network)
		}
		return
	}

	if r.Method != http.MethodPost && !isMasqueTCP {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	target := r.Header.Get("X-Target")
	if isMasqueTCP && target == "" {
		parsedTarget, err := parseMasqueTarget(r.URL.Path)
		if err == nil { target = parsedTarget }
	}

	if target == "" || (localOnlyFlag && !strings.HasPrefix(target, "127.0.0.1:")) {
		zlog.Warnf("[%s] Forbidden Target: %s", sessionID, target)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	zlog.Debugf("[%s] Dialing Target: %s", sessionID, target)
	targetConn, err := net.Dial(network, target)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	if isGRPC {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Add("Trailer", "Grpc-Status")
		w.Header().Add("Trailer", "Grpc-Message")
	}

	flusher, _ := w.(http.Flusher)
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	var tunnelReader io.Reader = r.Body
	var tunnelWriter io.Writer = w

	// 如果是 gRPC 模式，套上 gRPC Frame 壳
	if isGRPC {
		tunnelReader = &grpcReader{r: r.Body}
		tunnelWriter = &grpcWriter{w: w}
	}

	zlog.Infof("[%s] Tunnel Established -> %s (gRPC: %v)", sessionID, target, isGRPC)
	proxyStream(sessionID, network, targetConn, tunnelReader, tunnelWriter, flusher)

	// gRPC 结尾状态
	if isGRPC {
		w.Header().Set("Grpc-Status", "0")
		w.Header().Set("Grpc-Message", "OK")
	}
	zlog.Infof("[%s] Tunnel Closed", sessionID)
}

// ==========================================
// 🌟 客户端核心逻辑
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
	if m.session != nil { return m.session, nil }
	
	zlog.Debugf("[WT] Negotiating Session...")
	start := time.Now()
	_, session, err := m.dialer.Dial(ctx, m.reqUrl, m.headers)
	if err != nil { return nil, err }
	m.session = session
	zlog.Debugf("[WT] 底层会话协商成功, 耗时: %v", time.Since(start))
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
	targetAddr := clientCmd.String("target", "127.0.0.1:22", "远端目标地址")
	insecure := clientCmd.Bool("insecure", true, "跳过证书校验")
	customHost := clientCmd.String("host", "", "Host 伪装")
	serverName := clientCmd.String("sni", "", "SNI 伪装")
	useH3 := clientCmd.Bool("h3", false, "使用 H3 POST")
	useWT := clientCmd.Bool("wt", false, "使用 WebTransport")
	useMasque := clientCmd.Bool("masque", false, "使用 MASQUE CONNECT")
	useUDP := clientCmd.Bool("udp", false, "代理 UDP")
	useGRPC := clientCmd.Bool("grpc", false, "使用 gRPC 协议伪装 (仅作用于非 H3/WT 模式)")
	logLevel := clientCmd.String("loglevel", "info", "日志等级")

	clientCmd.Parse(args)
	initLogger(*logLevel)
	defer zlog.Sync()

	zlog.Infof("[Client] h2tunnel %s 正在启动...", Version)

	reqUrl := strings.TrimRight(*serverUrl, "/") + *path
	isHTTPS := strings.HasPrefix(reqUrl, "https://")
	network := "tcp"
	if *useUDP { network = "udp" }

	var httpClient *http.Client
	var wtManager *WTSessionManager

	if *useMasque || *useH3 {
		if !isHTTPS { zlog.Fatalf("H3/MASQUE 必须使用 HTTPS") }
		tlsConfig := &tls.Config{InsecureSkipVerify: *insecure, NextProtos: []string{"h3"}}
		if *serverName != "" { tlsConfig.ServerName = *serverName }
		rt := &http3.Transport{
			TLSClientConfig: tlsConfig,
			QUICConfig: &quic.Config{
				EnableDatagrams:                  true,
				EnableStreamResetPartialDelivery: true,
				HandshakeIdleTimeout:             10 * time.Second,
				MaxIdleTimeout:                   30 * time.Second,
				KeepAlivePeriod:                  8 * time.Second,
			},
		}
		httpClient = &http.Client{Transport: rt}
		zlog.Debugf("[Client] HTTP/3 Transport 初始化完成")
	} else if *useWT {
		if !isHTTPS { zlog.Fatalf("WebTransport 必须使用 HTTPS") }
		tlsConfig := &tls.Config{InsecureSkipVerify: *insecure, NextProtos: []string{http3.NextProtoH3}}
		if *serverName != "" { tlsConfig.ServerName = *serverName }
		headers := make(http.Header)
		headers.Set("X-Target", *targetAddr)
		headers.Set("X-Network", network)
		if *customHost != "" { headers.Set("Host", *customHost) }
		wtManager = &WTSessionManager{
			dialer: &webtransport.Dialer{
				TLSClientConfig: tlsConfig,
				QUICConfig: &quic.Config{
					EnableDatagrams:                  true,
					EnableStreamResetPartialDelivery: true,
					HandshakeIdleTimeout:             10 * time.Second,
					MaxIdleTimeout:                   30 * time.Second,
					KeepAlivePeriod:                  8 * time.Second,
				},
			},
			reqUrl: reqUrl, headers: headers,
		}
		zlog.Debugf("[Client] WebTransport Dialer 初始化完成")
	} else {
		transport := &http2.Transport{}
		if isHTTPS {
			tlsConfig := &tls.Config{InsecureSkipVerify: *insecure}
			if *serverName != "" { tlsConfig.ServerName = *serverName }
			transport.TLSClientConfig = tlsConfig
		} else {
			transport.AllowHTTP = true
			transport.DialTLSContext = func(ctx context.Context, n, a string, c *tls.Config) (net.Conn, error) {
				return net.Dial(n, a)
			}
		}
		httpClient = &http.Client{Transport: transport}
		zlog.Debugf("[Client] HTTP/2 Transport 初始化完成")
	}

	if *useUDP {
		if *useMasque {
			runMasqueUDPClient(*listenAddr, *serverUrl, *targetAddr, *customHost, httpClient)
		} else {
			runStreamUDPClient(*listenAddr, reqUrl, *targetAddr, *customHost, httpClient, wtManager, *useWT)
		}
		return
	}

	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil { zlog.Fatalf("无法监听本地 TCP 端口: %v", err) }
	defer listener.Close()

	modeName := "HTTP/2 (POST)"
	if *useWT { modeName = "WebTransport" }
	if *useH3 { modeName = "HTTP/3 (POST)" }
	if *useMasque { modeName = "MASQUE (CONNECT-TCP)" }

	zlog.Infof("[Client] 🚀 启动模式: %s (gRPC: %v)", modeName, *useGRPC)
	zlog.Infof("[Client] 🔗 监听: TCP %s -> 隧道 -> 目标: %s", *listenAddr, *targetAddr)

	for {
		localConn, err := listener.Accept()
		if err != nil { continue }
		zlog.Debugf("[Client] 接入本地连接: %s", localConn.RemoteAddr())
		go handleTCPClientConn(localConn, httpClient, wtManager, reqUrl, *targetAddr, *customHost, *useWT, *useMasque, *useGRPC)
	}
}

func runMasqueUDPClient(listenAddr, serverUrl, targetAddr, customHost string, httpClient *http.Client) {
	localAddr, _ := net.ResolveUDPAddr("udp", listenAddr)
	localConn, _ := net.ListenUDP("udp", localAddr)
	defer localConn.Close()

	zlog.Infof("[Client] 🚀 MASQUE UDP Mode: %s -> %s", listenAddr, targetAddr)
	
	host, port, _ := net.SplitHostPort(targetAddr)
	if host == "" { host = targetAddr; port = "53" }
	masqueUrl := fmt.Sprintf("%s/.well-known/masque/udp/%s/%s/", strings.TrimRight(serverUrl, "/"), url.PathEscape(host), url.PathEscape(port))

	var activeConns sync.Map
	buf := make([]byte, 65536)

	for {
		n, clientAddr, err := localConn.ReadFromUDP(buf)
		if err != nil { continue }
		data := make([]byte, n)
		copy(data, buf[:n])

		v, ok := activeConns.Load(clientAddr.String())
		if !ok {
			zlog.Debugf("[Client] New UDP Client: %s", clientAddr.String())
			ch := make(chan []byte, 100)
			activeConns.Store(clientAddr.String(), ch)

			go func(cAddr *net.UDPAddr, dataCh chan []byte) {
				defer activeConns.Delete(cAddr.String())
				pr, pw := io.Pipe()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				u, _ := url.Parse(masqueUrl)
				req, _ := http.NewRequestWithContext(ctx, http.MethodConnect, u.String(), pr)
				req.Proto = "HTTP/3"
				req.ProtoMajor = 3
				req.ProtoMinor = 0
				req.Header.Set("Protocol", "connect-udp")
				req.Header.Set("Capsule-Protocol", "?1")
				if customHost != "" { req.Host = customHost; req.Header.Set("Host", customHost) }

				go func() {
					for payload := range dataCh { writeUDPCapsule(pw, payload) }
					pw.Close()
				}()

				var resp *http.Response
				var rtErr error
				if rt, ok := httpClient.Transport.(http.RoundTripper); ok {
					zlog.Debugf("[Client] RoundTrip MASQUE-UDP: %s", masqueUrl)
					resp, rtErr = rt.RoundTrip(req)
				} else {
					resp, rtErr = httpClient.Do(req)
				}

				if rtErr != nil || resp.StatusCode >= 300 {
					zlog.Errorf("[Client] MASQUE-UDP Failed: %v", rtErr)
					return
				}
				defer resp.Body.Close()

				for {
					pkt, err := readUDPCapsule(resp.Body)
					if err != nil {
						zlog.Debugf("[Client] 隧道数据流结束或解析失败: %v", err)
						return
					}
					zlog.Debugf("[Client] 从隧道收到下行数据包: %d bytes", len(pkt))
					localConn.WriteToUDP(pkt, cAddr)
				}
			}(clientAddr, ch)
			ch <- data
		} else {
			v.(chan []byte) <- data
		}
	}
}

func runStreamUDPClient(listenAddr, reqUrl, targetAddr, customHost string, httpClient *http.Client, wtManager *WTSessionManager, useWT bool) {
	localAddr, _ := net.ResolveUDPAddr("udp", listenAddr)
	localConn, _ := net.ListenUDP("udp", localAddr)
	defer localConn.Close()

	zlog.Infof("[Client] 🚀 Stream UDP Mode: %s -> %s", listenAddr, targetAddr)
	var activeConns sync.Map
	buf := make([]byte, 65536)

	for {
		n, clientAddr, err := localConn.ReadFromUDP(buf)
		if err != nil { continue }
		data := make([]byte, n)
		copy(data, buf[:n])

		v, ok := activeConns.Load(clientAddr.String())
		if !ok {
			ch := make(chan []byte, 100)
			activeConns.Store(clientAddr.String(), ch)
			go func(cAddr *net.UDPAddr, dataCh chan []byte) {
				defer activeConns.Delete(cAddr.String())
				var r io.Reader
				var w io.Writer
				var closer func()

				if useWT {
					session, _ := wtManager.GetSession(context.Background())
					stream, _ := session.OpenStreamSync(context.Background())
					r, w = stream, stream
					closer = func() { stream.Close() }
				} else {
					pr, pw := io.Pipe()
					req, _ := http.NewRequest("POST", reqUrl, pr)
					req.Header.Set("X-Target", targetAddr)
					req.Header.Set("X-Network", "udp")
					if customHost != "" { req.Host = customHost }
					go func() {
						for payload := range dataCh { writeUDPPacket(pw, payload) }
						pw.Close()
					}()
					resp, _ := httpClient.Do(req)
					r = resp.Body
					closer = func() { resp.Body.Close() }
				}

				if useWT {
					go func() {
						for payload := range dataCh { writeUDPPacket(w, payload) }
						if cw, ok := w.(interface{ CloseWrite() error }); ok { cw.CloseWrite() }
					}()
				}

				for {
					pkt, err := readUDPPacket(r)
					if err != nil { closer(); return }
					localConn.WriteToUDP(pkt, cAddr)
				}
			}(clientAddr, ch)
			ch <- data
		} else {
			v.(chan []byte) <- data
		}
	}
}

func handleTCPClientConn(localConn net.Conn, httpClient *http.Client, wtManager *WTSessionManager, reqUrl, target, customHost string, useWT, useMasque, useGRPC bool) {
	defer localConn.Close()
	sessionID := fmt.Sprintf("C-%d", time.Now().UnixNano()%1000)

	if useWT {
		session, _ := wtManager.GetSession(context.Background())
		stream, _ := session.OpenStreamSync(context.Background())
		zlog.Debugf("[%s] WT TCP Stream Open", sessionID)
		go func() { io.Copy(stream, localConn); stream.Close() }()
		io.Copy(localConn, stream)
		return
	}

	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var req *http.Request
	if useMasque {
		host, port, _ := net.SplitHostPort(target)
		if host == "" { host = target; port = "22" }
		masquePath := fmt.Sprintf("/.well-known/masque/tcp/%s/%s/", url.PathEscape(host), url.PathEscape(port))
		u, _ := url.Parse(reqUrl)
		u.Path = masquePath
		req, _ = http.NewRequestWithContext(ctx, http.MethodConnect, u.String(), pr)
		req.Proto = "HTTP/3"
		req.ProtoMajor = 3
		req.ProtoMinor = 0
		req.Header.Set("Protocol", "connect-tcp")
		zlog.Debugf("[%s] MASQUE-TCP Path: %s", sessionID, u.Path)
	} else {
		req, _ = http.NewRequestWithContext(ctx, "POST", reqUrl, pr)
	}

	if customHost != "" { req.Host = customHost; req.Header.Set("Host", customHost) }
	req.Header.Set("X-Target", target)
	req.Header.Set("X-Network", "tcp")

	// gRPC 伪装逻辑
	if useGRPC {
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("TE", "trailers")
	}

	zlog.Debugf("[%s] 发起 HTTP 握手 (RoundTrip)...", sessionID)

	var writer io.Writer = pw
	if useGRPC {
		writer = &grpcWriter{w: pw}
	}

	go func() { io.Copy(writer, localConn); pw.Close() }()

	var resp *http.Response
	var err error
	if useMasque {
		if rt, ok := httpClient.Transport.(http.RoundTripper); ok {
			resp, err = rt.RoundTrip(req)
		} else {
			resp, err = httpClient.Do(req)
		}
	} else {
		resp, err = httpClient.Do(req)
	}

	if err != nil || (resp != nil && resp.StatusCode >= 300) {
		status := 0
		if resp != nil { status = resp.StatusCode }
		zlog.Errorf("[%s] Handshake Failed: %d, Err: %v", sessionID, status, err)
		return
	}
	defer resp.Body.Close()

	zlog.Infof("[%s] Tunnel Active", sessionID)
	
	var reader io.Reader = resp.Body
	if useGRPC {
		reader = &grpcReader{r: resp.Body}
	}
	io.Copy(localConn, reader)
}