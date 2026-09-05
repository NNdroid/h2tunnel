package h2tunnel

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
	"golang.org/x/net/http2"
)

// clientListenerRegistry 记录客户端持有的全部监听器（TCP listener 与 UDP
// socket），供优雅下线时统一关闭。关闭后 Accept / ReadFromUDP 返回
// net.ErrClosed，对应的 accept 循环据此退出，不再接受新连接。
var clientListenerRegistry struct {
	sync.Mutex
	closers []io.Closer
}

func registerClientListener(c io.Closer) {
	clientListenerRegistry.Lock()
	clientListenerRegistry.closers = append(clientListenerRegistry.closers, c)
	clientListenerRegistry.Unlock()
}

func closeAllClientListeners() {
	clientListenerRegistry.Lock()
	defer clientListenerRegistry.Unlock()
	for _, c := range clientListenerRegistry.closers {
		_ = c.Close()
	}
	clientListenerRegistry.closers = nil
}

// installSignalHandler 注册 SIGINT/SIGTERM 处理：关闭所有监听器停止接新，
// 然后给存量隧道一个排空窗口；窗口内再次收到信号则立即退出。
// 这是 README 所承诺的 Graceful Connection Draining 的客户端侧实现
// （此前版本只写了文档没有实现，systemd restart 会硬断所有隧道）。
func installSignalHandler(cfg clientConfig) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-quit
		drain := cfg.DrainTimeout
		if drain <= 0 {
			drain = drainDefault
		}
		zlog.Infof("[Client] 🛑 收到 %v，停止接收新连接，开始排空存量隧道 (上限 %v)", sig, drain)
		closeAllClientListeners()

		second := make(chan os.Signal, 1)
		signal.Notify(second, syscall.SIGINT, syscall.SIGTERM)
		select {
		case <-time.After(drain):
			zlog.Infof("[Client] ✅ 排空窗口结束，进程退出")
		case s2 := <-second:
			zlog.Infof("[Client] 收到 %v，立即退出", s2)
		}
		os.Exit(0)
	}()
}

// startClientDirect 是 legacy 兼容入口（旧 CLI 形态，绑定本地监听、信号处理
// 与 os.Exit）；库用户请改用 NewClient + DialContext/DialPacketContext。
// 仅供包内白盒测试与旧调用方使用。
func startClientDirect(cfg clientConfig) {
	initLogger(cfg.LogLevel)
	defer zlog.Sync()
	zlog.Infof("[Client] 🚀 Starting h2tunnel client v%s...", Version())

	installSignalHandler(cfg)

	reqUrl := strings.TrimRight(cfg.ServerUrl, "/") + cfg.Path
	isHTTPS := strings.HasPrefix(reqUrl, "https://")

	var mgr *connectionManager // L3 连接管理（非 WT 传输：h2/h3/grpc/masque 的主备/分流）
	var wtManager *wtSessionManager

	if cfg.usesWT() {
		// WT 使用独立的 WebTransport 会话模型（自身有主/备 session 预热），不走 http.Client。
		tlsConfig := &tls.Config{InsecureSkipVerify: cfg.Insecure, NextProtos: []string{http3.NextProtoH3}}
		if cfg.ServerName != "" {
			tlsConfig.ServerName = cfg.ServerName
		}
		headers := make(http.Header)
		headers.Set("Protocol", "webtransport")
		setXDst(headers, cfg)
		setXAuth(headers, cfg)
		wtManager = &wtSessionManager{
			dialer: &webtransport.Dialer{
				TLSClientConfig: tlsConfig,
				QUICConfig:      getDefaultQUICConfig(),
			},
			reqUrl:  reqUrl,
			headers: headers,
		}
		zlog.Debugf("[Client] Initialized WebTransport Dialer")
	} else {
		// 非 WT：resume/2 是唯一数据面，L3 connectionManager 管理主/备连接。
		// 每条主/备线路拥有独立 http.Client（独立传输/连接池，传输层彼此隔离）。
		// 业务隧道经 mgr.PickClient(typ) 取当前活跃主线路的客户端；
		// 主线路阵亡 → 备用（含其预热传输池）升级为主 → 业务隧道立即切到备用传输。
		if cfg.usesMasque() || cfg.usesH3() {
			if !isHTTPS {
				zlog.Fatalf("[Client] ❌ HTTP/3 and MASQUE require HTTPS")
			}
		}
		// 策略归一：直接构造（如测试）时 connectionPolicy 可能为全零值，
		// 用默认 1 主 + 1 备 + 建立间隔 100s 兜底。
		policy := normalizePolicy(cfg.connectionPolicy)
		mgr = newConnectionManager(policy, cfg, reqUrl, nil, "CM")
		mgr.SetClientFactory(func() *http.Client {
			if cfg.usesMasque() || cfg.usesH3() {
				// h3 / masque（均走 QUIC）用独立 http3.Transport（见 transport_h3.go）。
				return newH3Transport(cfg)
			}
			t2 := &http2.Transport{
				// 连接级保活：空闲超 ReadIdleTimeout 主动发 HTTP/2 PING 探测，
				// 超 PingTimeout 判定连接死亡并重建（需小于 CDN 空闲超时）。
				ReadIdleTimeout: 15 * time.Second,
				PingTimeout:     10 * time.Second,
			}
			if isHTTPS {
				t2.TLSClientConfig = &tls.Config{InsecureSkipVerify: cfg.Insecure, ServerName: cfg.ServerName}
			} else {
				t2.AllowHTTP = true
				t2.DialTLSContext = func(ctx context.Context, n, a string, c *tls.Config) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, n, a)
				}
			}
			return &http.Client{Transport: t2}
		})
		mgr.Start()
		if cfg.usesMasque() || cfg.usesH3() {
			zlog.Infof("[Client] 🚀 L3 连接管理已启用 (HTTP/3/MASQUE, 主=%d 备=%d)",
				policy.PrimaryCount, policy.BackupCount)
		} else {
			zlog.Infof("[Client] 🚀 L3 连接管理已启用 (HTTP/2, 主=%d 备=%d)",
				policy.PrimaryCount, policy.BackupCount)
		}
	}

	netMode := normalizeNetwork(cfg.Network, networkTCP)

	isTCP := netMode == networkTCP || netMode == networkAll
	isUDP := netMode == networkUDP || netMode == networkAll

	zlog.Infof("[Client] 🎯 Protocol Network Mode: [%s] (TCP Active: %v, UDP Active: %v)", netMode, isTCP, isUDP)

	if netMode == networkUDP {
		runUDPClient(reqUrl, cfg, mgr, wtManager)
	} else if netMode == networkAll {
		cfgUDP := cfg
		cfgUDP.Network = networkUDP
		go runUDPClient(reqUrl, cfgUDP, mgr, wtManager)
		cfgTCP := cfg
		cfgTCP.Network = networkTCP
		runTCPClient(reqUrl, cfgTCP, mgr, wtManager)
	} else {
		cfgTCP := cfg
		cfgTCP.Network = networkTCP
		runTCPClient(reqUrl, cfgTCP, mgr, wtManager)
	}
}

func runUDPClient(reqUrl string, cfg clientConfig, mgr *connectionManager, wtManager *wtSessionManager) {
	if cfg.usesMasque() {
		runMasqueUDPClient(cfg, mgr)
	} else {
		runStreamUDPClient(reqUrl, cfg, mgr, wtManager)
	}
}
func newClientSessionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// 极罕见；失败用 time 拼一个仍可用的 ID
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}

// pickClient 经 L3 连接管理取当前活跃主线路的 http.Client。
// typ 为业务类型（"tcp"/"udp"，类型分流维度）。mgr 为 nil（如 WT 专属路径）时返回 nil。
func pickClient(mgr *connectionManager, typ string) *http.Client {
	if mgr == nil {
		return nil
	}
	return mgr.PickClient(typ)
}

// runTCPClient 启动本地 TCP 监听，将每个入站连接隧穿到远端目标。
func runTCPClient(reqUrl string, cfg clientConfig, mgr *connectionManager, wtManager *wtSessionManager) {
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		zlog.Fatalf("[Client] ❌ Failed to listen on local TCP: %v", err)
	}
	defer listener.Close()
	registerClientListener(listener)

	zlog.Infof("[Client] 🟢 [TCP] Listening on %s -> Tunnel -> %s", cfg.ListenAddr, cfg.TargetAddr)

	for {
		localConn, err := listener.Accept()
		if err != nil {
			// 优雅下线关闭 listener 时走到这里：正常退出而非错误
			if errors.Is(err, net.ErrClosed) {
				zlog.Infof("[Client] 🔇 TCP listener 已关闭，停止接受新连接")
				return
			}
			zlog.Errorf("[Client] Accept failed: %v", err)
			continue
		}

		sessionID := fmt.Sprintf("CLI-%s-%d", localConn.RemoteAddr().String(), time.Now().UnixNano()%1000)
		zlog.Infof("[%s] 🟢 New client connection from %s", sessionID, localConn.RemoteAddr())

		if cfg.usesWT() {
			// WT 接入 resume/2：每条隧道独立 wtSessionManager（headers 带该隧道
			// X-Session-ID），executeResumeWT 在 stream 断后同 session id 重开新流续传。
			wtMgr := newWTManagerForTunnel(cfg, reqUrl, sessionID)
			go executeResumeWT(localConn, cfg, wtMgr, sessionID)
		} else {
			// resume/2 是唯一数据面（v1 已移除）。覆盖 h2 / h3 / grpc / masque-tcp
			// 全部 TCP 传输（executeResumableTunnel 经 L3 取当前活跃主线路客户端）。
			go executeResumableTunnel(newClientSessionID(), localConn, reqUrl, cfg, mgr)
		}
	}
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
