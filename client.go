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
				KeepAlivePeriod:                  10 * time.Second,
				MaxIdleTimeout:                   30 * time.Second,
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
			dialer: &webtransport.Dialer{
				TLSClientConfig: tlsConfig,
				QUICConfig: &quic.Config{
					EnableDatagrams:                  true,
					EnableStreamResetPartialDelivery: true,
					KeepAlivePeriod:                  10 * time.Second,
					MaxIdleTimeout:                   30 * time.Second,
				},
			},
			reqUrl: reqUrl,
			headers: headers,
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

// ==========================================
// 🌟 客户端 TCP 专属抽象引擎 (带 WaitGroup 完美生命周期保护)
// ==========================================
func executeHTTPTunnel(sessionID string, localConn net.Conn, req *http.Request, pw *io.PipeWriter, cfg ClientConfig, httpClient *http.Client) {
	var writer io.Writer = pw
	if cfg.UseGRPC { writer = &grpcWriter{w: pw} }

	var wg sync.WaitGroup
	wg.Add(2)

	// 1. 上行 (本地 -> 隧道)
	go func() {
		defer wg.Done()
		n, err := io.Copy(writer, localConn)
		if err != nil && err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
			zlog.Warnf("[%s] ⚠️ [本地->隧道] 上行异常: %v", sessionID, err)
		} else {
			zlog.Debugf("[%s] ⬆️ [本地->隧道] 完成 (共上传 %d bytes)", sessionID, n)
		}
		pw.Close() // 触发 HTTP EOF
	}()

	start := time.Now()
	var resp *http.Response
	var err error
	if rt, ok := httpClient.Transport.(http.RoundTripper); ok && cfg.UseMasque {
		resp, err = rt.RoundTrip(req)
	} else {
		resp, err = httpClient.Do(req)
	}

	if err != nil {
		zlog.Errorf("[%s] ❌ HTTP 握手异常: %v", sessionID, err)
		// 如果握手失败，伪造一个错误让 wg 正常退出
		localConn.Close()
		wg.Done() // 抵消下行的 wg.Done()
		wg.Wait()
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		zlog.Warnf("[%s] ❌ 远端拒绝: HTTP %d", sessionID, resp.StatusCode)
		localConn.Close()
		wg.Done()
		wg.Wait()
		return
	}
	zlog.Infof("[%s] 🚀 隧道握手建立成功 (耗时: %v)", sessionID, time.Since(start))

	// 2. 下行 (隧道 -> 本地)
	go func() {
		defer wg.Done()
		var reader io.Reader = resp.Body
		if cfg.UseGRPC { reader = &grpcReader{r: resp.Body} }

		n, err := io.Copy(localConn, reader)
		if err != nil && err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
			zlog.Warnf("[%s] ⚠️ [隧道->本地] 下行异常: %v", sessionID, err)
		} else {
			zlog.Debugf("[%s] ⬇️ [隧道->本地] 完成 (共下发 %d bytes)", sessionID, n)
		}

		if tc, ok := localConn.(*net.TCPConn); ok {
			zlog.Debugf("[%s] 🔌 本地 TCP 半关闭触发", sessionID)
			tc.CloseWrite()
		} else if cw, ok := localConn.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()

	// ⚠️ 极其关键：阻塞等待上下行都安全结束，再由外层的 defer 释放 localConn
	wg.Wait()
}

// 辅助函数：为 Request 注入底层连接追踪器
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
	
	start := time.Now()
	stream, err := session.OpenStreamSync(context.Background())
	if err != nil { 
		zlog.Errorf("[%s] ❌ WT Stream 打开失败: %v", sessionID, err)
		return 
	}
	zlog.Infof("[%s] 🚀 WT Stream 开启成功 (耗时: %v)", sessionID, time.Since(start))

	var wg sync.WaitGroup
	wg.Add(2)

	// 上行
	go func() {
		defer wg.Done()
		n, _ := io.Copy(stream, localConn)
		zlog.Debugf("[%s] ⬆️ [本地->隧道] WT 上传完成 (共 %d bytes)", sessionID, n)
		stream.Close() // 通知远端结束
	}()

	// 下行
	go func() {
		defer wg.Done()
		n, _ := io.Copy(localConn, stream)
		zlog.Debugf("[%s] ⬇️ [隧道->本地] WT 下发完成 (共 %d bytes)", sessionID, n)
		if tc, ok := localConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
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

	zlog.Debugf("[%s] 构造 MASQUE-TCP 请求: %s", sessionID, u.String())
	executeHTTPTunnel(sessionID, localConn, req, pw, cfg, httpClient)
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

	zlog.Debugf("[%s] 构造 H2-Stream POST 请求 -> %s", sessionID, cfg.TargetAddr)
	executeHTTPTunnel(sessionID, localConn, req, pw, cfg, httpClient)
}

// ---> 客户端 UDP: MASQUE 终极优化版
func runMasqueUDPClient(cfg ClientConfig, httpClient *http.Client) {
	localAddr, _ := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	localConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		zlog.Fatalf("[M-UDP] ❌ 监听失败: %v", err)
	}
	defer localConn.Close()

	host, port, _ := net.SplitHostPort(cfg.TargetAddr)
	if host == "" {
		host = cfg.TargetAddr
		port = "53"
	}
	// 预格式化基础 URL 减少循环内的字符串拼接
	baseServerUrl := strings.TrimRight(cfg.ServerUrl, "/")
	masqueUrl := fmt.Sprintf("%s/.well-known/masque/udp/%s/%s/", baseServerUrl, url.PathEscape(host), url.PathEscape(port))

	zlog.Infof("[M-UDP] 🔗 监听就绪: UDP %s -> MASQUE -> %s", cfg.ListenAddr, cfg.TargetAddr)

	var activeConns sync.Map

	for {
		// 1. 🌟 每一跳从池子获取独立缓冲区
		bufPtr := udpBufPool.Get().(*[]byte)
		buf := *bufPtr

		n, clientAddr, err := localConn.ReadFromUDP(buf)
		if err != nil {
			udpBufPool.Put(bufPtr)
			continue
		}

		payload := buf[:n]

		v, ok := activeConns.Load(clientAddr.String())
		if !ok {
			zlog.Infof("[M-UDP] 🟢 发现新 UDP 客户端: %s", clientAddr.String())
			ch := make(chan []byte, 200) // 增大队列长度应对突发
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

				// 上行：封装 Capsule
				go func() {
					// ⚠️ 这里不需要归还池子，因为 payload 是由主循环或复用逻辑控制的
					for p := range dataCh {
						if err := writeUDPCapsule(pw, p); err != nil {
							break
						}
					}
					pw.Close()
				}()

				start := time.Now()
				var resp *http.Response
				var rtErr error
				// 直接使用 Transport 避开 http.Client 的一些额外开销
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

				zlog.Infof("[M-UDP] 🚀 MASQUE 隧道就绪 (耗时: %v)", time.Since(start))

				// 下行：零分配解封装
				bufRPtr := udpBufPool.Get().(*[]byte)
				bufR := *bufRPtr
				defer udpBufPool.Put(bufRPtr)

				for {
					// 🌟 使用改进后的 readUDPCapsule，直接写入 bufR
					nR, err := readUDPCapsule(resp.Body, bufR)
					if err != nil {
						zlog.Debugf("[M-UDP] 🏁 读取结束: %v", err)
						return
					}
					localConn.WriteToUDP(bufR[:nR], cAddr)
				}
			}(clientAddr, ch)

			ch <- payload
		} else {
			// 复用连接时的内存策略：
			// 如果包很小，直接拷贝比占用 64KB 的池化内存更划算
			tmp := make([]byte, n)
			copy(tmp, payload)
			
			select {
			case v.(chan []byte) <- tmp:
			default:
				zlog.Warnf("[M-UDP] 队列溢出，丢弃来自 %s 的包", clientAddr)
			}
			udpBufPool.Put(bufPtr) // 归还主循环申请的缓冲区
		}
	}
}

// ---> 客户端 UDP: Stream (H2/WT) 终极优化版
func runStreamUDPClient(reqUrl string, cfg ClientConfig, httpClient *http.Client, wtManager *WTSessionManager) {
	localAddr, _ := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	localConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		zlog.Fatalf("[S-UDP] ❌ 监听失败: %v", err)
	}
	defer localConn.Close()

	zlog.Infof("[S-UDP] 🔗 监听就绪: UDP %s -> Stream隧道 -> %s", cfg.ListenAddr, cfg.TargetAddr)
	var activeConns sync.Map

	for {
		// 1. ⚠️ 必须为每一跳数据准备独立的缓冲区
		bufPtr := udpBufPool.Get().(*[]byte)
		buf := *bufPtr

		n, clientAddr, err := localConn.ReadFromUDP(buf)
		if err != nil {
			udpBufPool.Put(bufPtr) // 失败则归还
			continue
		}

		// 只取出有效载荷部分（切片引用，不产生新拷贝）
		payload := buf[:n]

		v, ok := activeConns.Load(clientAddr.String())
		if !ok {
			zlog.Infof("[S-UDP] 🟢 发现新 UDP 客户端: %s", clientAddr.String())
			// 传输指针，避免在大并发下 channel 拷贝字节切片头的开销
			ch := make(chan []byte, 200) 
			activeConns.Store(clientAddr.String(), ch)

			go func(cAddr *net.UDPAddr, dataCh chan []byte) {
				defer activeConns.Delete(cAddr.String())
				var r io.Reader
				var w io.Writer
				var closer func()

				// --- 隧道建立逻辑 ---
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
					if cfg.UseGRPC {
						req.Header.Set("Content-Type", "application/grpc")
						req.Header.Set("TE", "trailers")
					}
					
					go func() {
						var writer io.Writer = pw
						if cfg.UseGRPC { writer = &grpcWriter{w: pw} }
						for p := range dataCh {
							writeUDPPacket(writer, p)
							// 重点：payload p 是从主循环传递过来的，包含了原有的 bufPtr 引用
							// 但为了简单，我们在主循环统一处理 Put，或者这里加逻辑。
							// 优化方案：这里写完后，不在这里放回池子，因为主循环会处理。
						}
						pw.Close()
					}()
					resp, reqErr := httpClient.Do(req)
					if reqErr != nil { return }
					if resp.StatusCode >= 300 { resp.Body.Close(); return }
					r = resp.Body
					if cfg.UseGRPC { r = &grpcReader{r: resp.Body} }
					closer = func() { resp.Body.Close() }
				}

				zlog.Infof("[S-UDP] 🚀 通道就绪: %s", cAddr)

				// WT 模式的额外写入协程
				if cfg.UseWT {
					go func() {
						for p := range dataCh { writeUDPPacket(w, p) }
						if cw, ok := w.(interface{ CloseWrite() error }); ok { cw.CloseWrite() }
					}()
				}

				// 下行：从隧道读取并写回本地 UDP
				bufRPtr := udpBufPool.Get().(*[]byte)
				bufR := *bufRPtr
				defer udpBufPool.Put(bufRPtr)
				for {
					n, err := readUDPPacket(r, bufR)
					if err != nil {
						closer()
						return
					}
					localConn.WriteToUDP(bufR[:n], cAddr)
				}
			}(clientAddr, ch)
			
			// 首次数据进入
			ch <- payload
		} else {
			// 复用连接：由于 payload 引用的是 buf，这里需要小心生命周期
			// 为了绝对安全，建议在主循环中做一次小拷贝，或者直接通过 dataCh 传递后由子协程归还池子
			// 这里我们采取简单的“按需拷贝”，只在复用时产生一次内存分配，平衡复杂度和性能
			tmp := make([]byte, n)
			copy(tmp, payload)
			v.(chan []byte) <- tmp
			udpBufPool.Put(bufPtr) // 归还原始大缓冲区
		}
	}
}