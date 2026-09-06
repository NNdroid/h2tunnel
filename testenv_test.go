package h2tunnel

// =========================================
// 测试环境助手（仅测试编译）：
// 承接原 legacy 入口 startServerDirect / startClientDirect 的测试依赖，
// 内部改由 SDK（NewServer / NewClient）实现。库本体不再包含这些入口。
// =========================================

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// tokenAuth 测试便捷构造：token 鉴权器。
func tokenAuth(token string) Authenticator {
	a, err := NewTokenAuthenticator(token)
	if err != nil {
		panic(err)
	}
	return a
}

// startServerDirect 测试服务端入口：按 serverConfig 构建 SDK 服务端并
// 阻塞服务。监听失败直接 panic（与原 legacy Fatal 语义一致）。
func startServerDirect(cfg serverConfig) {
	prepared, err := prepareServerConfig(cfg)
	if err != nil {
		panic(fmt.Sprintf("test server: %v", err))
	}
	options, err := serverOptionsFromConfig(prepared)
	if err != nil {
		panic(fmt.Sprintf("test server: %v", err))
	}
	srv, err := NewServer(options)
	if err != nil {
		panic(fmt.Sprintf("test server: %v", err))
	}

	needTCP, needQUIC := srv.requiredListeners()
	var listeners Listeners
	if needTCP {
		listeners.TCP, err = net.Listen("tcp", prepared.ListenAddr)
		if err != nil {
			panic(fmt.Sprintf("test server listen: %v", err))
		}
	}
	if needQUIC {
		quicAddr := prepared.ListenAddr
		if listeners.TCP != nil {
			_, port, splitErr := net.SplitHostPort(listeners.TCP.Addr().String())
			if splitErr != nil {
				panic(splitErr)
			}
			host, _, _ := net.SplitHostPort(prepared.ListenAddr)
			if host == "" {
				quicAddr = net.JoinHostPort("", port)
			} else {
				quicAddr = net.JoinHostPort(host, port)
			}
		}
		listeners.QUIC, err = net.ListenPacket("udp", quicAddr)
		if err != nil {
			panic(fmt.Sprintf("test server quic listen: %v", err))
		}
	}
	if err := srv.Serve(listeners); err != nil {
		panic(fmt.Sprintf("test server serve: %v", err))
	}
}

// startClientDirect 测试客户端入口：按 clientConfig 构建 SDK 客户端，
// 复刻 legacy 的本地端口转发形态（TCP 和/或 UDP 监听 → 隧道 → 目标），
// 阻塞直到监听器关闭。测试从不停止这些客户端（与原行为一致）。
func startClientDirect(cfg clientConfig) {
	var credentials CredentialProvider
	if cfg.Credentials != nil {
		credentials = cfg.Credentials
	} else if strings.TrimSpace(cfg.Token) != "" {
		c, err := NewTokenCredentials(cfg.Token)
		if err != nil {
			panic(err)
		}
		credentials = c
	}
	var tlsConfig *tls.Config
	if cfg.TLSConfig != nil {
		tlsConfig = cfg.TLSConfig
	} else if strings.HasPrefix(strings.ToLower(cfg.ServerUrl), "https://") {
		tlsConfig = &tls.Config{InsecureSkipVerify: cfg.Insecure, ServerName: cfg.ServerName}
	}
	client, err := NewClient(ClientOptions{
		Endpoint:    cfg.ServerUrl,
		Path:        cfg.Path,
		Transport:   Transport(cfg.Transport),
		Host:        cfg.CustomHost,
		TLSConfig:   tlsConfig,
		Credentials: credentials,
		Tuning: ClientTuning{
			SessionWindowBytes: cfg.SessionWindow * 1024,
			HeartbeatInterval:  cfg.HeartbeatInterval,
			KeepaliveInterval:  time.Duration(cfg.KeepaliveSec) * time.Second,
			HandshakeTimeout:   time.Duration(cfg.HandshakeAckMs) * time.Millisecond,
		},
	})
	if err != nil {
		panic(fmt.Sprintf("test client: %v", err))
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// legacy 语义：Start 失败（如鉴权被拒）不 panic，监听器照常运行，
	// 失败在拨号阶段暴露 —— 严格分流类测试依赖这一行为。
	_ = client.Start(ctx)

	network := normalizeNetwork(cfg.Network, networkTCP)
	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	if network == networkTCP || network == networkAll {
		listener, listenErr := net.Listen("tcp", cfg.ListenAddr)
		if listenErr != nil {
			panic(fmt.Sprintf("test client tcp listen: %v", listenErr))
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- testForwardTCP(ctx, listener, client, cfg.TargetAddr)
		}()
	}
	if network == networkUDP || network == networkAll {
		packetListener, listenErr := net.ListenPacket("udp", cfg.ListenAddr)
		if listenErr != nil {
			panic(fmt.Sprintf("test client udp listen: %v", listenErr))
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- testForwardUDP(ctx, packetListener, client, cfg.TargetAddr)
		}()
	}
	// 阻塞到任一转发器退出（监听器被外部关闭 = 正常退出）。
	if err := <-errCh; err != nil && !errors.Is(err, net.ErrClosed) {
		panic(fmt.Sprintf("test client forwarder: %v", err))
	}
	wg.Wait()
}

func testForwardTCP(ctx context.Context, listener net.Listener, client *Client, target string) error {
	for {
		local, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer local.Close()
			remote, err := client.DialContext(ctx, NetworkTCP, target)
			if err != nil {
				return
			}
			defer remote.Close()
			go func() {
				_, _ = io.Copy(remote, local)
			}()
			_, _ = io.Copy(local, remote)
		}()
	}
}

func testForwardUDP(ctx context.Context, listener net.PacketConn, client *Client, target string) error {
	var sessions sync.Map
	buffer := make([]byte, 64*1024)
	for {
		n, clientAddr, err := listener.ReadFrom(buffer)
		if err != nil {
			return err
		}
		key := clientAddr.String()
		value, ok := sessions.Load(key)
		if !ok {
			packetConn, dialErr := client.DialPacketContext(ctx, NetworkUDP, target)
			if dialErr != nil {
				continue
			}
			actual, loaded := sessions.LoadOrStore(key, packetConn)
			if loaded {
				_ = packetConn.Close()
				packetConn = actual.(PacketConn)
			} else {
				go func(addr net.Addr, conn PacketConn) {
					defer sessions.Delete(addr.String())
					defer conn.Close()
					downlink := make([]byte, 64*1024)
					for {
						n, err := conn.Read(downlink)
						if err != nil {
							return
						}
						if _, err := listener.WriteTo(downlink[:n], addr); err != nil {
							return
						}
					}
				}(clientAddr, packetConn)
			}
			value = packetConn
		}
		packet := append([]byte(nil), buffer[:n]...)
		_ = value.(PacketConn).SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := value.(PacketConn).Write(packet); err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			sessions.Delete(key)
			_ = value.(PacketConn).Close()
		}
	}
}
