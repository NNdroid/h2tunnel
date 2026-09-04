package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	h2tunnel "github.com/NNdroid/h2tunnel"
	"github.com/NNdroid/h2tunnel/internal/certutil"
	"github.com/NNdroid/h2tunnel/internal/share"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "h2tunnel:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if configPath, ok, err := parseLeadingConfig(args); err != nil {
		return err
	} else if ok {
		return runFromConfig(configPath)
	}
	if len(args) == 0 {
		if _, err := os.Stat("config.json"); err == nil {
			return runFromConfig("config.json")
		}
		printUsage()
		return errors.New("a command or -c config.json is required")
	}
	switch args[0] {
	case "server", "client":
		fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
		path := fs.String("c", "config.json", "configuration file")
		fs.StringVar(path, "config", "config.json", "configuration file")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return runFromConfig(*path)
	case "gen-uri":
		return runGenURI(args[1:])
	case "gen-systemd":
		RunGenSystemd(args[1:])
		return nil
	case "gen-nginx":
		RunGenNginx(args[1:])
		return nil
	case "version", "-v", "--version":
		fmt.Printf("h2tunnel version %s\n", h2tunnel.Version())
		return nil
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func parseLeadingConfig(args []string) (string, bool, error) {
	if len(args) == 0 {
		return "", false, nil
	}
	arg := args[0]
	switch {
	case arg == "-c" || arg == "--config":
		if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
			return "", false, errors.New("missing configuration path")
		}
		return args[1], true, nil
	case strings.HasPrefix(arg, "-c="):
		if len(arg) == 3 {
			return "", false, errors.New("missing configuration path")
		}
		return arg[3:], true, nil
	case strings.HasPrefix(arg, "--config="):
		if len(arg) == len("--config=") {
			return "", false, errors.New("missing configuration path")
		}
		return arg[len("--config="):], true, nil
	default:
		return "", false, nil
	}
}

func runFromConfig(path string) error {
	cfg, err := loadConfig(path)
	if err != nil {
		return fmt.Errorf("load %s: %w", path, err)
	}
	logger := newLogger(cfg.LogLevel)
	switch cfg.Mode {
	case "server", "":
		return runServer(cfg, logger)
	case "client":
		return runClient(cfg, logger)
	default:
		return fmt.Errorf("invalid mode %q", cfg.Mode)
	}
}

func runServer(cfg *config, logger *slog.Logger) error {
	var err error
	auth := h2tunnel.Authenticator(func(context.Context, *http.Request) (h2tunnel.Principal, error) {
		return h2tunnel.Principal{ID: "anonymous"}, nil
	})
	if cfg.Token != "" {
		auth, err = h2tunnel.NewTokenAuthenticator(cfg.Token)
		if err != nil {
			return err
		}
	}
	serverTLS, err := serverTLSConfig(cfg)
	if err != nil {
		return err
	}
	server, err := h2tunnel.NewServer(h2tunnel.ServerOptions{
		Path:          cfg.Path,
		Transports:    parseTransports(cfg.Transport),
		Networks:      parseNetworks(cfg.Network),
		TLSConfig:     serverTLS,
		Authenticator: auth,
		Dialer:        directTargetDialer(cfg.LocalOnly),
		Tuning: h2tunnel.ServerTuning{
			SessionWindowBytes: cfg.SessionWindowKB * 1024,
		},
		Logger: logger,
	})
	if err != nil {
		return err
	}
	return serveUntilSignal(server, cfg.Listen, time.Duration(cfg.DrainTimeoutSec)*time.Second, logger)
}

func runClient(cfg *config, logger *slog.Logger) error {
	var err error
	var credentials h2tunnel.CredentialProvider
	if cfg.Token != "" {
		credentials, err = h2tunnel.NewTokenCredentials(cfg.Token)
		if err != nil {
			return err
		}
	}
	var tlsConfig *tls.Config
	if strings.HasPrefix(strings.ToLower(cfg.Server), "https://") {
		tlsConfig = &tls.Config{InsecureSkipVerify: cfg.Insecure, ServerName: cfg.SNI}
	}
	client, err := h2tunnel.NewClient(h2tunnel.ClientOptions{
		Endpoint:    cfg.Server,
		Path:        cfg.Path,
		Transport:   h2tunnel.Transport(cfg.Transport),
		Host:        cfg.Host,
		TLSConfig:   tlsConfig,
		Credentials: credentials,
		Tuning: h2tunnel.ClientTuning{
			SessionWindowBytes: cfg.SessionWindowKB * 1024,
			HeartbeatInterval:  durationOrDefaultSeconds(cfg.HeartbeatSec),
			KeepaliveInterval:  time.Duration(cfg.KeepaliveSec) * time.Second,
			HandshakeTimeout:   time.Duration(cfg.HandshakeAckMS) * time.Millisecond,
			StandbyConnections: cfg.StandbyCount,
		},
		Logger: logger,
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := client.Start(ctx); err != nil {
		_ = client.Close()
		return err
	}

	var closers []io.Closer
	errCh := make(chan error, 2)
	network := strings.ToLower(cfg.Network)
	if network == "tcp" || network == "all" {
		listener, err := net.Listen("tcp", cfg.Listen)
		if err != nil {
			_ = client.Close()
			return err
		}
		closers = append(closers, listener)
		go func() { errCh <- runTCPForwarder(ctx, listener, client, cfg.Target) }()
	}
	if network == "udp" || network == "all" {
		packetListener, err := net.ListenPacket("udp", cfg.Listen)
		if err != nil {
			for _, closer := range closers {
				_ = closer.Close()
			}
			_ = client.Close()
			return err
		}
		closers = append(closers, packetListener)
		go func() { errCh <- runUDPForwarder(ctx, packetListener, client, cfg.Target) }()
	}
	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			logger.Error("local forwarder stopped", "error", err)
		}
	}
	for _, closer := range closers {
		_ = closer.Close()
	}
	drain := time.Duration(cfg.DrainTimeoutSec) * time.Second
	if drain <= 0 {
		drain = 30 * time.Second
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), drain)
	defer cancel()
	if err := client.Shutdown(shutdownCtx); err != nil {
		_ = client.Close()
		return err
	}
	return nil
}

func runTCPForwarder(ctx context.Context, listener net.Listener, client *h2tunnel.Client, target string) error {
	for {
		local, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer local.Close()
			remote, err := client.DialContext(ctx, h2tunnel.NetworkTCP, target)
			if err != nil {
				return
			}
			defer remote.Close()
			copyBoth(local, remote)
		}()
	}
}

func runUDPForwarder(ctx context.Context, listener net.PacketConn, client *h2tunnel.Client, target string) error {
	type session struct {
		conn h2tunnel.PacketConn
	}
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
			remote, err := client.DialPacketContext(ctx, h2tunnel.NetworkUDP, target)
			if err != nil {
				continue
			}
			entry := &session{conn: remote}
			actual, loaded := sessions.LoadOrStore(key, entry)
			if loaded {
				_ = remote.Close()
				entry = actual.(*session)
			} else {
				go func(addr net.Addr, current *session) {
					defer sessions.Delete(addr.String())
					defer current.conn.Close()
					downlink := make([]byte, 64*1024)
					for {
						n, err := current.conn.Read(downlink)
						if err != nil {
							return
						}
						if _, err := listener.WriteTo(downlink[:n], addr); err != nil {
							return
						}
					}
				}(clientAddr, entry)
			}
			value = entry
		}
		packet := append([]byte(nil), buffer[:n]...)
		if _, err := value.(*session).conn.Write(packet); err != nil {
			sessions.Delete(key)
			_ = value.(*session).conn.Close()
		}
	}
}

func copyBoth(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(a, b) }()
	go func() { defer wg.Done(); _, _ = io.Copy(b, a) }()
	wg.Wait()
}

func serveUntilSignal(server *h2tunnel.Server, address string, drain time.Duration, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.ListenAndServe(address) }()
	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
	}
	if drain <= 0 {
		drain = 30 * time.Second
	}
	logger.Info("shutting down", "timeout", drain)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), drain)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
		return err
	}
	return <-serveErr
}

func directTargetDialer(localOnly bool) h2tunnel.TargetDialer {
	return func(ctx context.Context, request h2tunnel.DialRequest) (net.Conn, error) {
		network := string(request.Network)
		if network != h2tunnel.NetworkTCP && network != h2tunnel.NetworkUDP {
			return nil, h2tunnel.ErrUnsupportedNetwork
		}
		address := request.Target
		if localOnly {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, h2tunnel.ErrForbidden
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil || len(ips) == 0 {
				return nil, h2tunnel.ErrForbidden
			}
			for _, ip := range ips {
				if !ip.IP.IsLoopback() {
					return nil, h2tunnel.ErrForbidden
				}
			}
			address = net.JoinHostPort(ips[0].IP.String(), port)
		}
		dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		return dialer.DialContext(ctx, network, address)
	}
}

func serverTLSConfig(cfg *config) (*tls.Config, error) {
	requiresTLS := cfg.TLS || cfg.Cert != "" || cfg.Key != ""
	for _, transport := range strings.Split(cfg.Transport, ",") {
		switch strings.TrimSpace(transport) {
		case "all", "h2", "h3", "wt", "masque":
			requiresTLS = true
		}
	}
	if !requiresTLS {
		return nil, nil
	}
	if cfg.Cert != "" || cfg.Key != "" {
		if cfg.Cert == "" || cfg.Key == "" {
			return nil, errors.New("both cert and key are required")
		}
		cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
		if err != nil {
			return nil, err
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
	}
	cert, err := certutil.GenerateSelfSigned("localhost")
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}

func durationOrDefaultSeconds(seconds int) time.Duration {
	if seconds < 0 {
		return -time.Second
	}
	return time.Duration(seconds) * time.Second
}

func parseTransports(value string) []h2tunnel.Transport {
	if value == "all" {
		return []h2tunnel.Transport{h2tunnel.TransportH2, h2tunnel.TransportH3, h2tunnel.TransportWebTransport, h2tunnel.TransportMASQUE, h2tunnel.TransportGRPC}
	}
	parts := strings.Split(value, ",")
	result := make([]h2tunnel.Transport, 0, len(parts))
	for _, part := range parts {
		result = append(result, h2tunnel.Transport(strings.TrimSpace(part)))
	}
	return result
}

func parseNetworks(value string) []h2tunnel.Network {
	if value == "udp" {
		return []h2tunnel.Network{h2tunnel.NetworkUDP}
	}
	if value == "all" {
		return []h2tunnel.Network{h2tunnel.NetworkTCP, h2tunnel.NetworkUDP}
	}
	return []h2tunnel.Network{h2tunnel.NetworkTCP}
}

func newLogger(level string) *slog.Logger {
	logLevel := slog.LevelInfo
	switch strings.ToLower(level) {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	}
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
}

func runGenURI(args []string) error {
	fs := flag.NewFlagSet("gen-uri", flag.ContinueOnError)
	cfgPath := fs.String("c", "", "configuration file")
	host := fs.String("host", "", "server public IP or domain")
	port := fs.String("port", "", "server port")
	path := fs.String("path", "", "tunnel path")
	transport := fs.String("transport", "h2", "transport")
	target := fs.String("target", "127.0.0.1:22", "target")
	token := fs.String("token", "", "token")
	sni := fs.String("sni", "", "TLS server name")
	remark := fs.String("name", "H2Tunnel Node", "node name")
	insecure := fs.Bool("insecure", true, "skip TLS verification")
	pin := fs.String("pin", "", "sharing PIN")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath != "" {
		cfg, err := loadConfig(*cfgPath)
		if err != nil {
			return err
		}
		if parsed, err := url.Parse(cfg.Server); err == nil && parsed.Host != "" {
			if *host == "" {
				*host = parsed.Hostname()
			}
			if *port == "" {
				*port = parsed.Port()
			}
		}
		if *path == "" {
			*path = cfg.Path
		}
		if *token == "" {
			*token = cfg.Token
		}
		if *sni == "" {
			*sni = cfg.SNI
		}
	}
	if *host == "" {
		*host = "your-server"
	}
	if *port == "" {
		*port = "8443"
	}
	if *path == "" {
		*path = "/tunnel"
	}
	uri, usedPIN, direct, err := share.Generate(*transport, *host, *port, *path, *target, *token, *sni, *remark, *pin, *insecure)
	if err != nil {
		return err
	}
	fmt.Printf("Encrypted Stun URI:\n%s\n\nPIN: %s\n\nDirect URI:\n%s\n", uri, usedPIN, direct)
	return nil
}

func printUsage() {
	fmt.Println("Usage: h2tunnel -c config.json")
	fmt.Println("       h2tunnel <server|client> [-c config.json]")
	fmt.Println("       h2tunnel <gen-uri|gen-systemd|gen-nginx|version|help>")
}
