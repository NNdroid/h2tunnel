package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
	"golang.org/x/net/http2"
)

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
	
	zlog.Debugf("[WT Manager] 正在发起底层 WebTransport 握手...")
	start := time.Now()
	_, session, err := m.dialer.Dial(ctx, m.reqUrl, m.headers)
	if err != nil { 
		zlog.Errorf("[WT Manager] ❌ WT 握手失败: %v", err)
		return nil, err 
	}
	m.session = session
	zlog.Infof("[WT Manager] ✅ 底层 WT 会话建立成功 (耗时: %v)", time.Since(start))
	return session, nil
}

func runClient(args []string) {
	clientCmd := flag.NewFlagSet("client", flag.ExitOnError)
	cfg := ClientConfig{}
	clientCmd.StringVar(&cfg.ListenAddr, "listen", "127.0.0.1:2222", "本地监听地址")
	clientCmd.StringVar(&cfg.ServerUrl, "server", "https://127.0.0.1:8443", "服务端 URL")
	clientCmd.StringVar(&cfg.Path, "path", "/tunnel", "代理路径")
	clientCmd.StringVar(&cfg.TargetAddr, "target", "127.0.0.1:22", "远端目标地址")
	clientCmd.BoolVar(&cfg.Insecure, "insecure", true, "跳过证书校验")
	clientCmd.StringVar(&cfg.CustomHost, "host", "", "Host 伪装")
	clientCmd.StringVar(&cfg.ServerName, "sni", "", "SNI 伪装")
	clientCmd.BoolVar(&cfg.UseH3, "h3", false, "使用 H3 POST")
	clientCmd.BoolVar(&cfg.UseWT, "wt", false, "使用 WebTransport")
	clientCmd.BoolVar(&cfg.UseMasque, "masque", false, "使用 MASQUE CONNECT")
	clientCmd.BoolVar(&cfg.UseUDP, "udp", false, "代理 UDP")
	clientCmd.BoolVar(&cfg.UseGRPC, "grpc", false, "使用 gRPC 协议伪装")
	clientCmd.StringVar(&cfg.LogLevel, "loglevel", "info", "日志等级")
	clientCmd.StringVar(&cfg.Token, "token", "", "Proxy-Authorization Token")
	clientCmd.Parse(args)

	initLogger(cfg.LogLevel)
	defer zlog.Sync()
	zlog.Infof("[Client] 🚀 h2tunnel %s 正在启动...", Version)

	reqUrl := strings.TrimRight(cfg.ServerUrl, "/") + cfg.Path
	isHTTPS := strings.HasPrefix(reqUrl, "https://")
	network := "tcp"
	if cfg.UseUDP { network = "udp" }

	var httpClient *http.Client
	var wtManager *WTSessionManager

	if cfg.UseMasque || cfg.UseH3 {
		if !isHTTPS { zlog.Fatalf("[Client] ❌ H3/MASQUE 必须使用 HTTPS") }
		tlsConfig := &tls.Config{InsecureSkipVerify: cfg.Insecure, NextProtos: []string{"h3"}}
		if cfg.ServerName != "" { tlsConfig.ServerName = cfg.ServerName }
		rt := &http3.Transport{
			TLSClientConfig: tlsConfig,
			QUICConfig: &quic.Config{
				EnableDatagrams:                  true,
				EnableStreamResetPartialDelivery: true,
				KeepAlivePeriod:                  8 * time.Second,
			},
		}
		httpClient = &http.Client{Transport: rt}
		zlog.Debugf("[Client] 已初始化 HTTP/3 Transport")
	} else if cfg.UseWT {
		tlsConfig := &tls.Config{InsecureSkipVerify: cfg.Insecure, NextProtos: []string{http3.NextProtoH3}}
		if cfg.ServerName != "" { tlsConfig.ServerName = cfg.ServerName }
		headers := make(http.Header)
		headers.Set("X-Target", cfg.TargetAddr)
		headers.Set("X-Network", network)
		if cfg.Token != "" { headers.Set("Proxy-Authorization", "Bearer "+cfg.Token) }
		wtManager = &WTSessionManager{
			dialer: &webtransport.Dialer{TLSClientConfig: tlsConfig},
			reqUrl: reqUrl, headers: headers,
		}
		zlog.Debugf("[Client] 已初始化 WebTransport Dialer")
	} else {
		transport := &http2.Transport{}
		if isHTTPS {
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: cfg.Insecure, ServerName: cfg.ServerName}
		} else {
			transport.AllowHTTP = true
			transport.DialTLSContext = func(ctx context.Context, n, a string, c *tls.Config) (net.Conn, error) { return net.Dial(n, a) }
		}
		httpClient = &http.Client{Transport: transport}
		zlog.Debugf("[Client] 已初始化 HTTP/2 Transport (gRPC: %v)", cfg.UseGRPC)
	}

	if cfg.UseUDP {
		if cfg.UseMasque {
			runMasqueUDPClient(cfg, httpClient)
		} else {
			runStreamUDPClient(reqUrl, cfg, httpClient, wtManager)
		}
		return
	}

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil { zlog.Fatalf("[Client] ❌ 无法监听本地 TCP: %v", err) }
	defer listener.Close()

	zlog.Infof("[Client] 🔗 监听就绪: TCP %s -> 隧道 -> %s", cfg.ListenAddr, cfg.TargetAddr)

	for {
		localConn, err := listener.Accept()
		if err != nil {
			zlog.Errorf("[Client] Accept 失败: %v", err)
			continue 
		}
		
		sessionID := fmt.Sprintf("CLI-%s-%d", localConn.RemoteAddr().String(), time.Now().UnixNano()%1000)
		zlog.Infof("[%s] 🟢 接入新本地连接 (客户端应用: %s)", sessionID, localConn.RemoteAddr())
		
		if cfg.UseWT {
			go handleWTTCPClientConn(localConn, sessionID, cfg, wtManager)
		} else if cfg.UseMasque {
			go handleMasqueTCPClientConn(localConn, sessionID, reqUrl, cfg, httpClient)
		} else {
			go handleH2TCPClientConn(localConn, sessionID, reqUrl, cfg, httpClient)
		}
	}
}

// 🆕 辅助函数：为 Request 注入底层连接追踪器
func withConnectionTrace(ctx context.Context, sessionID string) context.Context {
	trace := &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			if connInfo.Reused {
				zlog.Infof("[%s] ⚡ [连接复用生效] 底层物理通道已复用! (空闲时间: %v, 本地物理端口: %s)", sessionID, connInfo.IdleTime, connInfo.Conn.LocalAddr())
			} else {
				zlog.Infof("[%s] 🔌 [新建连接] 建立全新的底层物理 TLS 通道 (本地物理端口: %s)", sessionID, connInfo.Conn.LocalAddr())
			}
		},
	}
	return httptrace.WithClientTrace(ctx, trace)
}

// ---> 客户端 TCP: WebTransport
func handleWTTCPClientConn(localConn net.Conn, sessionID string, cfg ClientConfig, wtManager *WTSessionManager) {
	defer localConn.Close()
	session, err := wtManager.GetSession(context.Background())
	if err != nil { 
		zlog.Errorf("[%s] ❌ 无法获取 WT Session: %v", sessionID, err)
		return 
	}
	
	zlog.Debugf("[%s] 正在请求打开 WT Stream...", sessionID)
	start := time.Now()
	stream, err := session.OpenStreamSync(context.Background())
	if err != nil { 
		zlog.Errorf("[%s] ❌ WT Stream 打开失败: %v", sessionID, err)
		return 
	}
	zlog.Infof("[%s] 🚀 WT Stream 开启成功 (耗时: %v), 开始转发数据", sessionID, time.Since(start))

	go func() { io.Copy(stream, localConn); stream.Close() }()
	io.Copy(localConn, stream)
	zlog.Debugf("[%s] 🏁 连接结束", sessionID)
}

// ---> 客户端 TCP: MASQUE
func handleMasqueTCPClientConn(localConn net.Conn, sessionID, reqUrl string, cfg ClientConfig, httpClient *http.Client) {
	defer localConn.Close()
	pr, pw := io.Pipe()
	
	// 🆕 注入 Trace
	ctx, cancel := context.WithCancel(withConnectionTrace(context.Background(), sessionID))
	defer cancel()

	host, port, _ := net.SplitHostPort(cfg.TargetAddr)
	if host == "" { host = cfg.TargetAddr; port = "22" }
	masquePath := fmt.Sprintf("/.well-known/masque/tcp/%s/%s/", url.PathEscape(host), url.PathEscape(port))
	u, _ := url.Parse(reqUrl)
	u.Path = masquePath

	req, _ := http.NewRequestWithContext(ctx, http.MethodConnect, u.String(), pr)
	req.Proto = "HTTP/3"
	req.Header.Set("Protocol", "connect-tcp")
	if cfg.CustomHost != "" { req.Host = cfg.CustomHost }
	if cfg.Token != "" { req.Header.Set("Proxy-Authorization", "Bearer "+cfg.Token) }

	go func() { io.Copy(pw, localConn); pw.Close() }()

	start := time.Now()
	var resp *http.Response
	var err error
	if rt, ok := httpClient.Transport.(http.RoundTripper); ok {
		resp, err = rt.RoundTrip(req)
	} else {
		resp, err = httpClient.Do(req)
	}

	if err != nil {
		zlog.Errorf("[%s] ❌ HTTP 握手异常: %v", sessionID, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		zlog.Warnf("[%s] ❌ 远端拒绝连接: HTTP %d", sessionID, resp.StatusCode)
		return
	}

	zlog.Infof("[%s] 🚀 MASQUE-TCP 隧道建立 (握手耗时: %v)", sessionID, time.Since(start))
	io.Copy(localConn, resp.Body)
	zlog.Debugf("[%s] 🏁 连接结束", sessionID)
}

// ---> 客户端 TCP: HTTP/2 (POST) 与 gRPC
func handleH2TCPClientConn(localConn net.Conn, sessionID, reqUrl string, cfg ClientConfig, httpClient *http.Client) {
	defer localConn.Close()
	pr, pw := io.Pipe()
	
	// 🆕 注入 Trace
	ctx, cancel := context.WithCancel(withConnectionTrace(context.Background(), sessionID))
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "POST", reqUrl, pr)
	req.Header.Set("X-Target", cfg.TargetAddr)
	req.Header.Set("X-Network", "tcp")
	if cfg.CustomHost != "" { req.Host = cfg.CustomHost }
	if cfg.Token != "" { req.Header.Set("Proxy-Authorization", "Bearer "+cfg.Token) }
	
	if cfg.UseGRPC {
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("TE", "trailers")
	}

	var writer io.Writer = pw
	if cfg.UseGRPC { writer = &grpcWriter{w: pw} }
	go func() { io.Copy(writer, localConn); pw.Close() }()

	start := time.Now()
	resp, err := httpClient.Do(req)
	if err != nil {
		zlog.Errorf("[%s] ❌ HTTP 请求失败: %v", sessionID, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		zlog.Warnf("[%s] ❌ 远端拒绝连接: HTTP %d", sessionID, resp.StatusCode)
		return
	}

	zlog.Infof("[%s] 🚀 H2 隧道建立 (握手耗时: %v)", sessionID, time.Since(start))

	var reader io.Reader = resp.Body
	if cfg.UseGRPC { reader = &grpcReader{r: resp.Body} }
	io.Copy(localConn, reader)
	zlog.Debugf("[%s] 🏁 连接结束", sessionID)
}

// ---> 客户端 UDP: MASQUE
func runMasqueUDPClient(cfg ClientConfig, httpClient *http.Client) {
	localAddr, _ := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	localConn, err := net.ListenUDP("udp", localAddr)
	if err != nil { zlog.Fatalf("[M-UDP] ❌ 监听失败: %v", err) }
	defer localConn.Close()

	host, port, _ := net.SplitHostPort(cfg.TargetAddr)
	if host == "" { host = cfg.TargetAddr; port = "53" }
	masqueUrl := fmt.Sprintf("%s/.well-known/masque/udp/%s/%s/", strings.TrimRight(cfg.ServerUrl, "/"), url.PathEscape(host), url.PathEscape(port))

	zlog.Infof("[M-UDP] 🔗 监听就绪: UDP %s -> MASQUE -> %s", cfg.ListenAddr, cfg.TargetAddr)

	var activeConns sync.Map
	buf := make([]byte, 65536)

	for {
		n, clientAddr, err := localConn.ReadFromUDP(buf)
		if err != nil { continue }
		data := make([]byte, n)
		copy(data, buf[:n])

		v, ok := activeConns.Load(clientAddr.String())
		if !ok {
			zlog.Infof("[M-UDP] 🟢 发现新 UDP 客户端: %s", clientAddr.String())
			ch := make(chan []byte, 100)
			activeConns.Store(clientAddr.String(), ch)
			
			go func(cAddr *net.UDPAddr, dataCh chan []byte) {
				defer activeConns.Delete(cAddr.String())
				pr, pw := io.Pipe()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				req, _ := http.NewRequestWithContext(ctx, http.MethodConnect, masqueUrl, pr)
				req.Proto = "HTTP/3"
				req.Header.Set("Protocol", "connect-udp")
				req.Header.Set("Capsule-Protocol", "?1")
				if cfg.CustomHost != "" { req.Host = cfg.CustomHost }
				if cfg.Token != "" { req.Header.Set("Proxy-Authorization", "Bearer "+cfg.Token) }

				go func() {
					for payload := range dataCh { 
						zlog.Debugf("[M-UDP] 发送 Capsule -> %d bytes", len(payload))
						writeUDPCapsule(pw, payload) 
					}
					pw.Close()
				}()

				start := time.Now()
				var resp *http.Response
				var rtErr error
				if rt, ok := httpClient.Transport.(http.RoundTripper); ok {
					resp, rtErr = rt.RoundTrip(req)
				} else {
					resp, rtErr = httpClient.Do(req)
				}

				if rtErr != nil {
					zlog.Errorf("[M-UDP] ❌ 握手失败: %v", rtErr)
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode >= 300 {
					zlog.Warnf("[M-UDP] ❌ 远端拒绝: HTTP %d", resp.StatusCode)
					return
				}

				zlog.Infof("[M-UDP] 🚀 隧道握手成功 (耗时: %v) -> 准备接收回包", time.Since(start))

				for {
					pkt, err := readUDPCapsule(resp.Body)
					if err != nil {
						zlog.Debugf("[M-UDP] 🏁 读取回包结束或异常: %v", err)
						return
					}
					zlog.Debugf("[M-UDP] 收到 Capsule 回包 <- %d bytes", len(pkt))
					localConn.WriteToUDP(pkt, cAddr)
				}
			}(clientAddr, ch)
			ch <- data
		} else {
			v.(chan []byte) <- data
		}
	}
}

// ---> 客户端 UDP: Stream (H2/WT)
func runStreamUDPClient(reqUrl string, cfg ClientConfig, httpClient *http.Client, wtManager *WTSessionManager) {
	localAddr, _ := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	localConn, err := net.ListenUDP("udp", localAddr)
	if err != nil { zlog.Fatalf("[S-UDP] ❌ 监听失败: %v", err) }
	defer localConn.Close()

	zlog.Infof("[S-UDP] 🔗 监听就绪: UDP %s -> Stream隧道 -> %s", cfg.ListenAddr, cfg.TargetAddr)
	var activeConns sync.Map
	buf := make([]byte, 65536)

	for {
		n, clientAddr, err := localConn.ReadFromUDP(buf)
		if err != nil { continue }
		data := make([]byte, n)
		copy(data, buf[:n])

		v, ok := activeConns.Load(clientAddr.String())
		if !ok {
			zlog.Infof("[S-UDP] 🟢 发现新 UDP 客户端: %s", clientAddr.String())
			ch := make(chan []byte, 100)
			activeConns.Store(clientAddr.String(), ch)
			go func(cAddr *net.UDPAddr, dataCh chan []byte) {
				defer activeConns.Delete(cAddr.String())
				var r io.Reader
				var w io.Writer
				var closer func()

				if cfg.UseWT {
					session, _ := wtManager.GetSession(context.Background())
					stream, _ := session.OpenStreamSync(context.Background())
					r, w = stream, stream
					closer = func() { stream.Close() }
				} else {
					pr, pw := io.Pipe()
					req, _ := http.NewRequest("POST", reqUrl, pr)
					req.Header.Set("X-Target", cfg.TargetAddr)
					req.Header.Set("X-Network", "udp")
					if cfg.CustomHost != "" { req.Host = cfg.CustomHost }
					if cfg.Token != "" { req.Header.Set("Proxy-Authorization", "Bearer "+cfg.Token) }
					
					go func() {
						for payload := range dataCh { writeUDPPacket(pw, payload) }
						pw.Close()
					}()
					resp, reqErr := httpClient.Do(req)
					if reqErr != nil {
						zlog.Errorf("[S-UDP] ❌ HTTP 请求失败: %v", reqErr)
						return
					}
					if resp.StatusCode >= 300 {
						zlog.Warnf("[S-UDP] ❌ 远端拒绝: HTTP %d", resp.StatusCode)
						resp.Body.Close()
						return
					}
					r = resp.Body
					closer = func() { resp.Body.Close() }
				}

				zlog.Infof("[S-UDP] 🚀 数据流通道建立成功")

				if cfg.UseWT {
					go func() {
						for payload := range dataCh { writeUDPPacket(w, payload) }
						if cw, ok := w.(interface{ CloseWrite() error }); ok { cw.CloseWrite() }
					}()
				}

				for {
					pkt, err := readUDPPacket(r)
					if err != nil {
						zlog.Debugf("[S-UDP] 🏁 读取回包结束或异常: %v", err)
						closer()
						return
					}
					localConn.WriteToUDP(pkt, cAddr)
				}
			}(clientAddr, ch)
			ch <- data
		} else {
			v.(chan []byte) <- data
		}
	}
}