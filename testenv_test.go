package h2tunnel

// =========================================
// Test environment helpers (test compilation only):
// Carries the test dependencies on the legacy entry points
// startServerDirect / startClientDirect, now implemented internally via
// the SDK (NewServer / NewClient). The library itself no longer ships these entry points.
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

// tokenAuth test convenience constructor: a token authenticator.
func tokenAuth(token string) Authenticator {
	a, err := NewTokenAuthenticator(token)
	if err != nil {
		panic(err)
	}
	return a
}

// startServerDirect test server entry: builds an SDK server from serverConfig and
// serves blocking. A listen failure panics directly (matching the legacy Fatal semantics).
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

	listeners, err := srv.listenersPlan().bind(prepared.ListenAddr)
	if err != nil {
		panic(fmt.Sprintf("test server listen: %v", err))
	}
	if err := srv.Serve(listeners); err != nil {
		panic(fmt.Sprintf("test server serve: %v", err))
	}
}

// startClientDirect test client entry: builds an SDK client from clientConfig,
// replicating the legacy local port-forwarding shape (TCP and/or UDP listen →
// tunnel → target), blocking until the listeners close. Tests never stop
// these clients (same as the original behavior).
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
	// Legacy semantics: a Start failure (e.g. auth rejected) does not panic, the
	// listener keeps running and the failure surfaces at dial time —
	// strict routing-class tests rely on this behavior.
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
	// Block until any forwarder exits (listener closed externally = normal exit).
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
