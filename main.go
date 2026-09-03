package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var Version = "1.1.0"
var zlog *zap.SugaredLogger = zap.NewNop().Sugar()

type Config struct {
	Mode      string `json:"mode"`       // "server" or "client"
	Listen    string `json:"listen"`     // Server listen address (e.g. ":8443") or client listen address (e.g. "127.0.0.1:2222")
	Server    string `json:"server"`     // Client upstream server URL (e.g. "https://example.com:8443")
	Target    string `json:"target"`     // Target address to forward to (e.g. "127.0.0.1:22")
	Path      string `json:"path"`       // HTTP proxy path (e.g. "/tunnel")
	Token     string `json:"token"`      // Authorization token
	Transport string `json:"transport"`  // "all", "h2", "h2c", "h3", "wt", "masque", "grpc"
	Network   string `json:"network"`    // "all", "tcp", "udp"
	TLS       bool   `json:"tls"`        // Enable TLS (auto self-signed if cert/key not provided)
	Cert      string `json:"cert"`       // TLS certificate path
	Key       string `json:"key"`        // TLS private key path
	Insecure  bool   `json:"insecure"`   // Skip TLS certificate verification (client)
	Host      string `json:"host"`       // Custom Host header (client)
	SNI       string `json:"sni"`        // Custom SNI (client)
	LocalOnly bool   `json:"local_only"` // Allow forwarding to localhost only (server)
	LogLevel  string `json:"log_level"`  // debug, info, warn, error
	// HeartbeatSec 应用层心跳间隔（秒）。CDN / 反代后面必须小于其空闲超时，
	// 默认 25s（ALB 与 Nginx 默认 60s、Cloudflare 100s 的最小公约数的一半）。
	// 设为 0 表示沿用默认值；设为负数则彻底关闭（仅限源站直连）。
	HeartbeatSec int `json:"heartbeat_sec"`
	// DrainTimeoutSec 收到 SIGTERM 后等待存量隧道排空的上限（秒），超时强制关闭。
	DrainTimeoutSec int `json:"drain_timeout_sec"`
	// 注：resume 配置字段已移除——resume/2 是唯一数据面（恒启用），
	// TCP 与 UDP 均无 resume:false 逃生通道（v1 已彻底删除）。
	// SessionWindowKB 会话恢复窗口大小（KB），决定能恢复的断线时间上限
	// （与服务端在此窗口内能接收/发送的最大字节量）。默认 256KB。
	SessionWindowKB int `json:"session_window_kb"`
	// HandshakeAckMs 数据面握手 HANDSHAKE-ACK 超时（毫秒），默认 3000ms。
	HandshakeAckMs int `json:"handshake_ack_ms"`
	// KeepaliveSec 备用线路/会话 KEEPALIVE 心跳间隔（秒），默认 15s。
	KeepaliveSec int `json:"keepalive_sec"`
	// PrimaryCount 主连接数量，默认 1。>1 时启用类型分流（tcp/udp 各管一条）。
	PrimaryCount int `json:"primary_count"`
	// BackupCount 备用连接数量；nil=默认 1，0=关闭备用。
	BackupCount *int `json:"backup_count"`
	// PrimaryDialIntervalSec 主连接拨号间隔（秒），默认 30s（节流防重拨风暴）。
	PrimaryDialIntervalSec int `json:"primary_dial_interval_sec"`
	// BackupDialIntervalSec 备用连接拨号间隔（秒），默认 15s（节流防重拨风暴）。
	BackupDialIntervalSec int `json:"backup_dial_interval_sec"`
	// EstablishIntervalSec 主/备建立间隔（秒），默认 100s。先拨主、错相后再拨备。
	EstablishIntervalSec int `json:"establish_interval_sec"`
}

func applyEnvOverrides(cfg *Config) error {
	setString := func(key string, dst *string) {
		if value, ok := os.LookupEnv(key); ok {
			*dst = strings.TrimSpace(value)
		}
	}
	setBool := func(key string, dst *bool) error {
		value, ok := os.LookupEnv(key)
		if !ok {
			return nil
		}
		parsed, err := strconv.ParseBool(strings.TrimSpace(value))
		if err != nil {
			return fmt.Errorf("%s must be a boolean: %w", key, err)
		}
		*dst = parsed
		return nil
	}
	setInt := func(key string, dst *int) error {
		value, ok := os.LookupEnv(key)
		if !ok {
			return nil
		}
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return fmt.Errorf("%s must be an integer: %w", key, err)
		}
		*dst = parsed
		return nil
	}

	setString("H2TUNNEL_MODE", &cfg.Mode)
	setString("H2TUNNEL_LISTEN", &cfg.Listen)
	setString("H2TUNNEL_SERVER", &cfg.Server)
	setString("H2TUNNEL_TARGET", &cfg.Target)
	setString("H2TUNNEL_PATH", &cfg.Path)
	setString("H2TUNNEL_TOKEN", &cfg.Token)
	setString("H2TUNNEL_TRANSPORT", &cfg.Transport)
	setString("H2TUNNEL_NETWORK", &cfg.Network)
	setString("H2TUNNEL_CERT", &cfg.Cert)
	setString("H2TUNNEL_KEY", &cfg.Key)
	setString("H2TUNNEL_HOST", &cfg.Host)
	setString("H2TUNNEL_SNI", &cfg.SNI)
	setString("H2TUNNEL_LOG_LEVEL", &cfg.LogLevel)

	for _, field := range []struct {
		key string
		dst *bool
	}{
		{"H2TUNNEL_TLS", &cfg.TLS},
		{"H2TUNNEL_INSECURE", &cfg.Insecure},
		{"H2TUNNEL_LOCAL_ONLY", &cfg.LocalOnly},
	} {
		if err := setBool(field.key, field.dst); err != nil {
			return err
		}
	}

	for _, field := range []struct {
		key string
		dst *int
	}{
		{"H2TUNNEL_HEARTBEAT_SEC", &cfg.HeartbeatSec},
		{"H2TUNNEL_DRAIN_TIMEOUT_SEC", &cfg.DrainTimeoutSec},
		{"H2TUNNEL_SESSION_WINDOW_KB", &cfg.SessionWindowKB},
		{"H2TUNNEL_HANDSHAKE_ACK_MS", &cfg.HandshakeAckMs},
		{"H2TUNNEL_KEEPALIVE_SEC", &cfg.KeepaliveSec},
		{"H2TUNNEL_PRIMARY_COUNT", &cfg.PrimaryCount},
		{"H2TUNNEL_PRIMARY_DIAL_INTERVAL_SEC", &cfg.PrimaryDialIntervalSec},
		{"H2TUNNEL_BACKUP_DIAL_INTERVAL_SEC", &cfg.BackupDialIntervalSec},
		{"H2TUNNEL_ESTABLISH_INTERVAL_SEC", &cfg.EstablishIntervalSec},
	} {
		if err := setInt(field.key, field.dst); err != nil {
			return err
		}
	}
	if value, ok := os.LookupEnv("H2TUNNEL_BACKUP_COUNT"); ok {
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return fmt.Errorf("H2TUNNEL_BACKUP_COUNT must be an integer: %w", err)
		}
		cfg.BackupCount = &parsed
	}
	return nil
}

func validateConfig(cfg *Config) error {
	cfg.Mode = strings.ToLower(strings.TrimSpace(cfg.Mode))
	if cfg.Mode == "" {
		cfg.Mode = "server"
	}
	if cfg.Mode != "server" && cfg.Mode != "client" {
		return fmt.Errorf("mode must be server or client, got %q", cfg.Mode)
	}
	cfg.Path = normalizeTunnelPath(cfg.Path)
	cfg.LogLevel = strings.ToLower(strings.TrimSpace(cfg.LogLevel))
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	switch cfg.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("unsupported log_level %q", cfg.LogLevel)
	}
	if cfg.DrainTimeoutSec < 0 {
		return fmt.Errorf("drain_timeout_sec must be >= 0")
	}
	if cfg.SessionWindowKB < 0 || cfg.SessionWindowKB > maxWindowKB {
		return fmt.Errorf("session_window_kb must be 0 or between 1 and %d", maxWindowKB)
	}

	if cfg.Mode == "server" {
		if cfg.Server != "" || cfg.Target != "" || cfg.Insecure || cfg.Host != "" || cfg.SNI != "" {
			return fmt.Errorf("server mode contains client-only endpoint or TLS fields")
		}
		if cfg.HeartbeatSec != 0 || cfg.HandshakeAckMs != 0 || cfg.KeepaliveSec != 0 ||
			cfg.PrimaryCount != 0 || cfg.BackupCount != nil || cfg.PrimaryDialIntervalSec != 0 ||
			cfg.BackupDialIntervalSec != 0 || cfg.EstablishIntervalSec != 0 {
			return fmt.Errorf("server mode contains client-only connection policy fields")
		}
		prepared, err := prepareServerConfig(ServerConfig{
			EnableTLS: cfg.TLS,
			Transport: cfg.Transport,
			Network:   cfg.Network,
		})
		if err != nil {
			return err
		}
		cfg.Transport = prepared.Transport
		cfg.Network = prepared.Network
		cfg.TLS = prepared.EnableTLS
		return nil
	}

	if cfg.TLS || cfg.Cert != "" || cfg.Key != "" || cfg.LocalOnly {
		return fmt.Errorf("client mode contains server-only TLS or local_only fields")
	}
	if cfg.Server == "" {
		cfg.Server = "https://127.0.0.1:8443"
	}
	transport, err := resolveClientEndpointTransport(cfg, cfg.Server)
	if err != nil {
		return err
	}
	cfg.Transport = transport
	cfg.Network = normalizeNetwork(cfg.Network, networkTCP)
	if !validNetwork(cfg.Network) {
		return fmt.Errorf("unsupported network %q", cfg.Network)
	}
	if cfg.HeartbeatSec > 300 {
		return fmt.Errorf("heartbeat_sec must be <= 300; use a negative value to disable it")
	}
	if cfg.HandshakeAckMs < 0 || cfg.HandshakeAckMs > maxHandshakeAckMs {
		return fmt.Errorf("handshake_ack_ms must be 0 or between 1 and %d", maxHandshakeAckMs)
	}
	if cfg.KeepaliveSec < 0 || cfg.KeepaliveSec > maxKeepaliveSec {
		return fmt.Errorf("keepalive_sec must be 0 or between 1 and %d", maxKeepaliveSec)
	}
	if cfg.PrimaryCount < 0 {
		return fmt.Errorf("primary_count must be >= 0")
	}
	maxPrimary := 1
	if cfg.Network == networkAll {
		maxPrimary = 2
	}
	if cfg.PrimaryCount > maxPrimary {
		return fmt.Errorf("primary_count must not exceed enabled network count %d", maxPrimary)
	}
	if cfg.BackupCount != nil && *cfg.BackupCount < 0 {
		return fmt.Errorf("backup_count must be >= 0")
	}
	if cfg.PrimaryDialIntervalSec < 0 || cfg.BackupDialIntervalSec < 0 || cfg.EstablishIntervalSec < 0 {
		return fmt.Errorf("connection interval fields must be >= 0")
	}
	return nil
}

type ServerConfig struct {
	ListenAddr    string        `json:"listen"`
	TLSCert       string        `json:"cert"`
	TLSKey        string        `json:"key"`
	EnableTLS     bool          `json:"tls"`
	Path          string        `json:"path"`
	LocalOnly     bool          `json:"local_only"`
	LogLevel      string        `json:"log_level"`
	EnableH3      bool          `json:"-"`
	Transport     string        `json:"transport"`
	Network       string        `json:"network"` // "all", "tcp", "udp"
	ExpectedToken string        `json:"token"`
	DrainTimeout  time.Duration `json:"-"` // 由 drain_timeout_sec 换算
	// SessionWindow 会话恢复环形缓冲容量（KB），服务端侧必须实现才能配合客户端恢复。
	SessionWindow int `json:"-"`
	// routingPolicy 在启动时编译，供请求热路径做无分配位掩码判断。
	routingPolicy routingPolicy
}

type ClientConfig struct {
	ListenAddr string `json:"listen"`
	ServerUrl  string `json:"server"`
	Path       string `json:"path"`
	TargetAddr string `json:"target"`
	Insecure   bool   `json:"insecure"`
	CustomHost string `json:"host"`
	ServerName string `json:"sni"`
	Transport  string `json:"transport"`
	Network    string `json:"network"` // "all", "tcp", "udp"
	LogLevel   string `json:"log_level"`
	Token      string `json:"token"`

	// 以下两项为客户端侧的保活与排空参数，语义同 ServerConfig
	HeartbeatInterval time.Duration `json:"-"`
	DrainTimeout      time.Duration `json:"-"`
	// SessionWindow 会话恢复环形缓冲容量（KB）
	SessionWindow int `json:"-"`
	// HandshakeAckMs 数据面握手 HANDSHAKE-ACK 超时（毫秒），默认 3000ms。
	HandshakeAckMs int `json:"handshake_ack_ms"`
	// KeepaliveSec 备用线路/会话 KEEPALIVE 心跳间隔（秒），默认 15s。
	KeepaliveSec int `json:"keepalive_sec"`
	// RoleBackup 标记当前请求是备用线路（内部透传，由 backupLine 设置）。
	RoleBackup bool `json:"-"`
	// ConnectionPolicy 连接管理策略（主备数量/间隔/类型分流）。
	ConnectionPolicy ConnectionPolicy `json:"-"`
}

func (c *ClientConfig) IsUDP() bool {
	netMode := normalizeNetwork(c.Network, networkTCP)
	return netMode == networkUDP || netMode == networkAll
}

func (c *ClientConfig) IsTCP() bool {
	netMode := normalizeNetwork(c.Network, networkTCP)
	return netMode == networkTCP || netMode == networkAll
}

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
	zlog = zap.New(core).Sugar()
}

func loadConfigFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("configuration must contain exactly one JSON object")
	}
	if err := applyEnvOverrides(&cfg); err != nil {
		return nil, err
	}
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "-c" || os.Args[1] == "--config" || strings.HasPrefix(os.Args[1], "-c=") || strings.HasPrefix(os.Args[1], "--config=")) {
		confPath := "config.json"
		if strings.Contains(os.Args[1], "=") {
			confPath = strings.SplitN(os.Args[1], "=", 2)[1]
		} else if len(os.Args) > 2 {
			confPath = os.Args[2]
		}
		runFromConfig(confPath)
		return
	}

	if len(os.Args) < 2 {
		if _, err := os.Stat("config.json"); err == nil {
			runFromConfig("config.json")
			return
		}
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		runServer(os.Args[2:])
	case "client":
		runClient(os.Args[2:])
	case "gen-uri":
		runGenURI(os.Args[2:])
	case "gen-systemd":
		runGenSystemd(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("h2tunnel version %s\n", Version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Printf("Unknown subcommand: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func runGenURI(args []string) {
	fs := flag.NewFlagSet("gen-uri", flag.ExitOnError)
	cfgPath := fs.String("c", "", "Path to configuration file")
	host := fs.String("host", "", "Server public IP or domain")
	port := fs.String("port", "", "Server listen port")
	path := fs.String("path", "", "Proxy path")
	transport := fs.String("transport", "", "Transport (h2, h3, wt, masque, grpc)")
	target := fs.String("target", "", "Forward target")
	token := fs.String("token", "", "Token")
	sni := fs.String("sni", "", "SNI disguise")
	remark := fs.String("name", "", "Node remark name")
	insecure := fs.Bool("insecure", true, "Skip TLS verify")
	pin := fs.String("pin", "", "Share PIN (6 digits). Empty = auto-generate a random PIN")
	_ = fs.Parse(args)

	// 配置优先于内置默认，但命令行 flag 可覆盖配置中的任意字段
	if *cfgPath != "" {
		fileCfg, err := loadConfigFile(*cfgPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load config file %s: %v\n", *cfgPath, err)
			os.Exit(1)
		}
		// 优先从 client 配置的 server URL 反解出公网 host/port
		if *host == "" && fileCfg.Server != "" {
			if u, err := url.Parse(fileCfg.Server); err == nil && u.Host != "" {
				*host = u.Hostname()
				if u.Port() != "" {
					*port = u.Port()
				}
			}
		}
		if *port == "" && fileCfg.Listen != "" {
			if _, p, err := net.SplitHostPort(fileCfg.Listen); err == nil {
				*port = p
			}
		}
		if *path == "" && fileCfg.Path != "" {
			*path = fileCfg.Path
		}
		if *target == "" && fileCfg.Target != "" {
			*target = fileCfg.Target
		}
		if *token == "" && fileCfg.Token != "" {
			*token = fileCfg.Token
		}
		if *sni == "" && fileCfg.SNI != "" {
			*sni = fileCfg.SNI
		}
		if *transport == "" && fileCfg.Transport != "" {
			*transport = fileCfg.Transport
		}
	}

	// 内置默认兜底
	if *host == "" {
		*host = "your-server-ip"
	}
	if *port == "" {
		*port = "8443"
	}
	if *path == "" {
		*path = "/tunnel"
	}
	if *transport == "" {
		*transport = "h2"
	}
	*transport = canonicalTransport(*transport)
	if !validTransport(*transport, false) {
		fmt.Fprintf(os.Stderr, "Invalid transport %q\n", *transport)
		os.Exit(1)
	}
	if *target == "" {
		*target = "127.0.0.1:22"
	}
	if *remark == "" {
		*remark = "H2Tunnel Node"
	}

	uri := GenerateH2TunnelURI(*transport, *host, *port, *path, *target, *token, *sni, *remark, *pin, *insecure)
	fmt.Printf("=== 📱 h2tunnel Sharing URI ===\n\n%s\n", uri)
	PrintTerminalQR(uri)
}

// loadConfigFromArgs parses only -c/--config and returns the merged Config.
// The per-parameter command-line flags have been removed; the configuration
// file and H2TUNNEL_* environment variables are the only configuration inputs.
// When no file is given, the build*Config helpers apply secure defaults.
func loadConfigFromArgs(args []string, mode string) *Config {
	fs := flag.NewFlagSet("config", flag.ExitOnError)
	c := fs.String("c", "", "Path to configuration file")
	conf := fs.String("config", "", "Path to configuration file")
	_ = fs.Parse(args)

	cp := *c
	if cp == "" {
		cp = *conf
	}
	cfg := &Config{}
	if cp != "" {
		fileCfg, err := loadConfigFile(cp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load config file %s: %v\n", cp, err)
			os.Exit(1)
		}
		if fileCfg.Mode != mode {
			fmt.Fprintf(os.Stderr, "Config mode %q does not match %s subcommand\n", fileCfg.Mode, mode)
			os.Exit(1)
		}
		cfg = fileCfg
	} else {
		cfg.Mode = mode
		if err := applyEnvOverrides(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Invalid environment configuration: %v\n", err)
			os.Exit(1)
		}
		if err := validateConfig(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Invalid configuration: %v\n", err)
			os.Exit(1)
		}
	}
	return cfg
}

// resolveHeartbeat 把秒级配置换算为心跳间隔。
//
//	0  → 采用默认值（推荐，25s）
//	<0 → 关闭心跳（仅源站直连、中间无 CDN/反代时使用）
//	>0 → 收敛到 [5s, 5min]
func resolveHeartbeat(sec int) time.Duration {
	if sec < 0 {
		return 0
	}
	if sec == 0 {
		return clampHeartbeat(0)
	}
	return clampHeartbeat(time.Duration(sec) * time.Second)
}

// resolveDrainTimeout 把秒级配置换算为优雅下线排空上限，默认 30s。
func resolveDrainTimeout(sec int) time.Duration {
	if sec <= 0 {
		return drainDefault
	}
	return time.Duration(sec) * time.Second
}

// resolveSessionWindow 会话恢复环形缓冲容量；0 或非法值 → 默认 256KB。
// 上限与握手协商保持一致，避免错误配置在每个会话创建时分配过大的内存。
const sessionWindowDefaultKB = 256

func resolveSessionWindow(kb int) int {
	if kb <= 0 || kb > maxWindowKB {
		return sessionWindowDefaultKB
	}
	return kb
}

// resolveKeepaliveSec 会话/备用 KEEPALIVE 心跳间隔（秒）；0 或非法 → 默认 15s。
func resolveKeepaliveSec(sec int) int {
	if sec <= 0 || sec > maxKeepaliveSec {
		return defaultKeepaliveSec
	}
	return sec
}

// resolveHandshakeAckMs 数据面握手 HANDSHAKE-ACK 超时（毫秒）；0 或非法 → 默认 3000ms。
func resolveHandshakeAckMs(ms int) int {
	if ms <= 0 || ms > maxHandshakeAckMs {
		return defaultHandshakeAckMs
	}
	return ms
}

func buildServerConfig(cfg *Config) ServerConfig {
	listen := cfg.Listen
	if listen == "" {
		listen = ":8443"
	}
	path := normalizeTunnelPath(cfg.Path)
	logLevel := cfg.LogLevel
	if logLevel == "" {
		logLevel = "info"
	}
	netMode := normalizeNetwork(cfg.Network, networkAll)
	transport, err := normalizeTransportList(cfg.Transport)
	if err != nil {
		zlog.Fatalf("[Server] ❌ %v", err)
	}
	if transport == "" {
		transport = transportH2
	}

	return ServerConfig{
		ListenAddr:    listen,
		TLSCert:       cfg.Cert,
		TLSKey:        cfg.Key,
		EnableTLS:     cfg.TLS,
		Path:          path,
		LocalOnly:     cfg.LocalOnly,
		LogLevel:      logLevel,
		Transport:     transport,
		Network:       netMode,
		ExpectedToken: cfg.Token,
		DrainTimeout:  resolveDrainTimeout(cfg.DrainTimeoutSec),
		SessionWindow: resolveSessionWindow(cfg.SessionWindowKB),
	}
}

func buildClientConfig(cfg *Config) ClientConfig {
	listen := cfg.Listen
	if listen == "" {
		listen = "127.0.0.1:2222"
	}
	server := cfg.Server
	if server == "" {
		server = "https://127.0.0.1:8443"
	}
	transport, err := resolveClientEndpointTransport(cfg, server)
	if err != nil {
		zlog.Fatalf("[Client] ❌ %s", err)
	}
	path := normalizeTunnelPath(cfg.Path)
	target := cfg.Target
	if target == "" {
		target = "127.0.0.1:22"
	}
	logLevel := cfg.LogLevel
	if logLevel == "" {
		logLevel = "info"
	}
	netMode := normalizeNetwork(cfg.Network, networkTCP)
	if !validNetwork(netMode) {
		zlog.Fatalf("[Client] ❌ unsupported network %q", cfg.Network)
	}
	primaryNetworks := []string{netMode}
	backupCount := defaultBackupCount
	if cfg.BackupCount != nil {
		if *cfg.BackupCount < 0 {
			zlog.Fatalf("[Client] ❌ backup_count must be >= 0")
		}
		backupCount = *cfg.BackupCount
	}
	policy := resolveConnectionPolicy(
		cfg.PrimaryCount, backupCount,
		cfg.PrimaryDialIntervalSec, cfg.BackupDialIntervalSec,
		cfg.EstablishIntervalSec, defaultBackupMissedAck, primaryNetworks,
	)

	return ClientConfig{
		ListenAddr:        listen,
		ServerUrl:         server,
		Path:              path,
		TargetAddr:        target,
		Insecure:          cfg.Insecure,
		CustomHost:        cfg.Host,
		ServerName:        cfg.SNI,
		Transport:         transport,
		Network:           netMode,
		LogLevel:          logLevel,
		Token:             cfg.Token,
		HeartbeatInterval: resolveHeartbeat(cfg.HeartbeatSec),
		DrainTimeout:      resolveDrainTimeout(cfg.DrainTimeoutSec),
		SessionWindow:     resolveSessionWindow(cfg.SessionWindowKB),
		HandshakeAckMs:    resolveHandshakeAckMs(cfg.HandshakeAckMs),
		KeepaliveSec:      resolveKeepaliveSec(cfg.KeepaliveSec),
		ConnectionPolicy:  policy,
	}
}

func runFromConfig(path string) {
	cfg, err := loadConfigFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read config file %s: %v\n", path, err)
		os.Exit(1)
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Mode)) {
	case "client":
		startClientDirect(buildClientConfig(cfg))
	case "", "server":
		startServerDirect(buildServerConfig(cfg))
	default:
		fmt.Fprintf(os.Stderr, "Invalid mode %q: expected server or client\n", cfg.Mode)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: h2tunnel <command> [options] or h2tunnel -c config.json")
	fmt.Println("\nCommands:")
	fmt.Println("  server       Start h2tunnel multiplexing proxy server")
	fmt.Println("  client       Start h2tunnel proxy client")
	fmt.Println("  gen-uri      Generate Stun client sharing URI link & QR Code")
	fmt.Println("  gen-systemd  Generate Linux systemd service unit")
	fmt.Println("  version      Show version information")
	fmt.Println("  help         Show help message")
}
