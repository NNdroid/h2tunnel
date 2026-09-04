package h2tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var buildVersion = "1.1.0"

// Version returns the build version embedded by the release workflow.
func Version() string { return buildVersion }

// zlog 是库内共享的日志器，默认 Nop（库嵌入时不打扰宿主程序的 stdout）。
// CLI 通过 setLogLevel 初始化；库用户可用 setLogger / setLogLevel 注入。
var zlog *zap.SugaredLogger = zap.NewNop().Sugar()

// setLogger 注入自定义日志器（库嵌入推荐方式）。传 nil 恢复为静默。
func setLogger(l *zap.SugaredLogger) {
	if l == nil {
		zlog = zap.NewNop().Sugar()
		return
	}
	zlog = l
}

// setLogLevel 按级别构建控制台日志器并设为默认（CLI 使用）。
func setLogLevel(levelStr string) {
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

func initLogger(levelStr string) { setLogLevel(levelStr) }

type fileConfig struct {
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
	// StandbyCount 是当前 CLI 使用的精简字段。旧 fileConfig 仅保留给内部测试工具；
	// 真正的命令行解析位于 cmd/h2tunnel，且会拒绝 backup_count 等旧字段。
	StandbyCount *int `json:"standby_connections"`
	// PrimaryDialIntervalSec 主连接拨号间隔（秒），默认 30s（节流防重拨风暴）。
	PrimaryDialIntervalSec int `json:"primary_dial_interval_sec"`
	// BackupDialIntervalSec 备用连接拨号间隔（秒），默认 15s（节流防重拨风暴）。
	BackupDialIntervalSec int `json:"backup_dial_interval_sec"`
	// EstablishIntervalSec 主/备建立间隔（秒），默认 100s。先拨主、错相后再拨备。
	EstablishIntervalSec int `json:"establish_interval_sec"`
}

// applyEnvOverrides 用 H2TUNNEL_* 环境变量覆盖 fileConfig 字段。
func applyEnvOverrides(cfg *fileConfig) error {
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
	if value, ok := os.LookupEnv("H2TUNNEL_STANDBY_CONNECTIONS"); ok {
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return fmt.Errorf("H2TUNNEL_STANDBY_CONNECTIONS must be an integer: %w", err)
		}
		cfg.StandbyCount = &parsed
	}
	return nil
}

// validateConfig 校验并规范化 fileConfig（按 mode 分别校验）。
func validateConfig(cfg *fileConfig) error {
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
			cfg.PrimaryCount != 0 || cfg.BackupCount != nil || cfg.StandbyCount != nil || cfg.PrimaryDialIntervalSec != 0 ||
			cfg.BackupDialIntervalSec != 0 || cfg.EstablishIntervalSec != 0 {
			return fmt.Errorf("server mode contains client-only connection policy fields")
		}
		prepared, err := prepareServerConfig(serverConfig{
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
	if cfg.StandbyCount != nil && *cfg.StandbyCount < 0 {
		return fmt.Errorf("standby_connections must be >= 0")
	}
	if cfg.PrimaryDialIntervalSec < 0 || cfg.BackupDialIntervalSec < 0 || cfg.EstablishIntervalSec < 0 {
		return fmt.Errorf("connection interval fields must be >= 0")
	}
	return nil
}

// serverConfig 服务端运行时配置。可直接程序化构造（零值字段自动取默认）。
type serverConfig struct {
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

	// DialTarget 自定义上游拨号函数（库嵌入用）。nil 时使用默认
	// net.Dialer{Timeout: 10s} 直连目标。外部程序可借此把隧道流量统一
	// 引到自己的服务（net.Pipe 内存服务、unix socket、按目标 ACL 过滤等）。
	// target 地址来自客户端 X-Target 头（LocalOnly=true 时仅允许回环地址）。
	DialTarget func(ctx context.Context, network, addr string) (net.Conn, error) `json:"-"`
	// API-only hooks. CLI construction maps its token and direct-address policy
	// to these callbacks before creating a Server.
	Authenticator      Authenticator   `json:"-"`
	TargetDialer       TargetDialer    `json:"-"`
	TLSConfig          *tls.Config     `json:"-"`
	ServerContext      context.Context `json:"-"`
	SessionIdleTimeout time.Duration   `json:"-"`

	// routingPolicy 在启动时编译，供请求热路径做无分配位掩码判断。
	routingPolicy routingPolicy
}

// clientConfig 客户端运行时配置。可直接程序化构造（零值字段自动取默认）。
type clientConfig struct {
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

	// 以下两项为客户端侧的保活与排空参数，语义同 serverConfig
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
	// connectionPolicy 连接管理策略（主备数量/间隔/类型分流）。
	connectionPolicy connectionPolicy   `json:"-"`
	Credentials      CredentialProvider `json:"-"`
	TLSConfig        *tls.Config        `json:"-"`
	LogicalTargets   bool               `json:"-"`
}

func (c *clientConfig) IsUDP() bool {
	netMode := normalizeNetwork(c.Network, networkTCP)
	return netMode == networkUDP || netMode == networkAll
}

func (c *clientConfig) IsTCP() bool {
	netMode := normalizeNetwork(c.Network, networkTCP)
	return netMode == networkTCP || netMode == networkAll
}

// loadConfigFile 从 JSON 文件加载配置（含 H2TUNNEL_* 环境变量覆盖与校验）。
func loadConfigFile(path string) (*fileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg fileConfig
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

// buildServerConfig 由文件配置构建服务端运行时配置（应用默认值）。
func buildServerConfigChecked(cfg *fileConfig) (serverConfig, error) {
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
		return serverConfig{}, err
	}
	if transport == "" {
		transport = transportH2
	}

	return serverConfig{
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
	}, nil
}

func buildServerConfig(cfg *fileConfig) serverConfig {
	result, err := buildServerConfigChecked(cfg)
	if err != nil {
		panic(err)
	}
	return result
}

// buildClientConfig 由文件配置构建客户端运行时配置（应用默认值与连接策略）。
func buildClientConfigChecked(cfg *fileConfig) (clientConfig, error) {
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
		return clientConfig{}, err
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
		return clientConfig{}, fmt.Errorf("unsupported network %q", cfg.Network)
	}
	primaryNetworks := []string{netMode}
	backupCount := defaultBackupCount
	if cfg.BackupCount != nil {
		if *cfg.BackupCount < 0 {
			return clientConfig{}, fmt.Errorf("backup_count must be >= 0")
		}
		backupCount = *cfg.BackupCount
	}
	if cfg.StandbyCount != nil {
		if *cfg.StandbyCount < 0 {
			return clientConfig{}, fmt.Errorf("standby_connections must be >= 0")
		}
		backupCount = *cfg.StandbyCount
	}
	policy := resolveConnectionPolicy(
		cfg.PrimaryCount, backupCount,
		cfg.PrimaryDialIntervalSec, cfg.BackupDialIntervalSec,
		cfg.EstablishIntervalSec, defaultBackupMissedAck, primaryNetworks,
	)

	return clientConfig{
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
		connectionPolicy:  policy,
	}, nil
}

func buildClientConfig(cfg *fileConfig) clientConfig {
	result, err := buildClientConfigChecked(cfg)
	if err != nil {
		panic(err)
	}
	return result
}
