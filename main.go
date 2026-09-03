package main

import (
	"encoding/json"
	"flag"
	"fmt"
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
	Transport string `json:"transport"`  // "all", "h2", "h2c", "h3", "wt", "webtransport", "masque", "grpc"
	Network   string `json:"network"`    // "all" (or "tcp,udp"), "tcp", "udp"
	TLS       bool   `json:"tls"`        // Enable TLS (auto self-signed if cert/key not provided)
	Cert      string `json:"cert"`       // TLS certificate path
	Key       string `json:"key"`        // TLS private key path
	H3        bool   `json:"h3"`         // Enable HTTP/3 (QUIC)
	WT        bool   `json:"wt"`         // Enable WebTransport (client)
	Masque    bool   `json:"masque"`     // Enable MASQUE CONNECT (client)
	GRPC      bool   `json:"grpc"`       // Enable gRPC mode
	Insecure  bool   `json:"insecure"`   // Skip TLS certificate verification (client)
	Host      string `json:"host"`       // Custom Host header (client)
	SNI       string `json:"sni"`        // Custom SNI (client)
	ALPN      string `json:"alpn"`       // Custom ALPN (client)
	LocalOnly bool   `json:"local_only"` // Allow forwarding to localhost only (server)
	LogLevel  string `json:"log_level"`  // debug, info, warn, error
	// HeartbeatSec 应用层心跳间隔（秒）。CDN / 反代后面必须小于其空闲超时，
	// 默认 25s（ALB 与 Nginx 默认 60s、Cloudflare 100s 的最小公约数的一半）。
	// 设为 0 表示沿用默认值；设为负数则彻底关闭（仅限源站直连）。
	HeartbeatSec int `json:"heartbeat_sec"`
	// DrainTimeoutSec 收到 SIGTERM 后等待存量隧道排空的上限（秒），超时强制关闭。
	DrainTimeoutSec int `json:"drain_timeout_sec"`
	// Standby 已废弃：被 L3 ConnectionManager（primary_count/backup_count/
	// establish_interval_sec）取代。保留解析但不再生效（no-op）。
	Standby bool `json:"standby"`
	// ConnMaxAgeSec 已废弃：被 ConnectionPolicy.EstablishInterval 取代。
	// 保留解析但不再生效（no-op）。
	ConnMaxAgeSec int `json:"conn_max_age_sec"`
	// 注：resume 配置字段已移除——resume/2 是唯一数据面（恒启用），
	// TCP 与 UDP 均无 resume:false 逃生通道（v1 已彻底删除）。
	// SessionWindowKB 会话恢复窗口大小（KB），决定能恢复的断线时间上限
	// （与服务端在此窗口内能接收/发送的最大字节量）。默认 256KB。
	SessionWindowKB int `json:"session_window_kb"`
	// BackupLine 备用线路策略：none=单线路；hot=热备；cold=冷备。默认 none。
	BackupLine string `json:"backup_line"`
	// HandshakeAckMs 数据面握手 HANDSHAKE-ACK 超时（毫秒），默认 3000ms。
	HandshakeAckMs int `json:"handshake_ack_ms"`
	// KeepaliveSec 备用线路/会话 KEEPALIVE 心跳间隔（秒），默认 15s。
	KeepaliveSec int `json:"keepalive_sec"`
	// PrimaryCount 主连接数量，默认 1。>1 时启用类型分流（tcp/udp 各管一条）。
	PrimaryCount int `json:"primary_count"`
	// BackupCount 备用连接数量，默认 1。
	BackupCount int `json:"backup_count"`
	// PrimaryDialIntervalSec 主连接拨号间隔（秒），默认 30s（节流防重拨风暴）。
	PrimaryDialIntervalSec int `json:"primary_dial_interval_sec"`
	// BackupDialIntervalSec 备用连接拨号间隔（秒），默认 15s（节流防重拨风暴）。
	BackupDialIntervalSec int `json:"backup_dial_interval_sec"`
	// EstablishIntervalSec 主/备建立间隔（秒），默认 100s。先拨主、错相后再拨备。
	EstablishIntervalSec int `json:"establish_interval_sec"`
}

func (c *Config) UnmarshalJSON(data []byte) error {
	type Alias Config
	aux := struct {
		*Alias
		RawToken     interface{} `json:"token"`
		RawAuthToken interface{} `json:"auth_token"`
		RawPSK       interface{} `json:"psk"`
		RawProtocol  string      `json:"protocol"`
	}{
		Alias: (*Alias)(c),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	collectToken := func(v interface{}) {
		if v == nil || c.Token != "" {
			return
		}
		switch val := v.(type) {
		case string:
			c.Token = strings.TrimSpace(val)
		case []interface{}:
			var tokens []string
			for _, item := range val {
				if s, ok := item.(string); ok {
					trimmed := strings.TrimSpace(s)
					if trimmed != "" {
						tokens = append(tokens, trimmed)
					}
				}
			}
			c.Token = strings.Join(tokens, ",")
		}
	}

	collectToken(aux.RawToken)
	collectToken(aux.RawAuthToken)
	collectToken(aux.RawPSK)

	if aux.RawProtocol != "" && c.Transport == "" {
		c.Transport = aux.RawProtocol
	}

	switch strings.ToLower(c.Transport) {
	case "h3", "http3", "http/3":
		c.H3 = true
	case "wt", "webtransport":
		c.WT = true
	case "masque":
		c.Masque = true
	case "grpc":
		c.GRPC = true
	}

	return nil
}

func applyEnvOverrides(cfg *Config) {
	getEnv := func(keys ...string) string {
		for _, k := range keys {
			if v := os.Getenv(k); v != "" {
				return strings.TrimSpace(v)
			}
		}
		return ""
	}

	if v := getEnv("H2TUNNEL_MODE", "MODE"); v != "" {
		cfg.Mode = v
	}
	if v := getEnv("H2TUNNEL_LISTEN", "LISTEN", "PORT"); v != "" {
		if !strings.Contains(v, ":") && len(v) < 6 {
			cfg.Listen = ":" + v
		} else {
			cfg.Listen = v
		}
	}
	if v := getEnv("H2TUNNEL_SERVER", "SERVER"); v != "" {
		cfg.Server = v
	}
	if v := getEnv("H2TUNNEL_TARGET", "TARGET"); v != "" {
		cfg.Target = v
	}
	if v := getEnv("H2TUNNEL_PATH", "TUNNEL_PATH", "PROXY_PATH"); v != "" {
		cfg.Path = v
	}
	if v := getEnv("H2TUNNEL_TOKEN", "H2TUNNEL_PSK", "TOKEN", "PSK"); v != "" {
		cfg.Token = v
	}
	if v := getEnv("H2TUNNEL_TRANSPORT", "TRANSPORT"); v != "" {
		cfg.Transport = v
	}
	if v := getEnv("H2TUNNEL_NETWORK", "NETWORK"); v != "" {
		cfg.Network = v
	}
	if v := getEnv("H2TUNNEL_TLS", "TLS"); v != "" {
		cfg.TLS = v == "1" || strings.ToLower(v) == "true"
	}
	if v := getEnv("H2TUNNEL_LOG_LEVEL", "LOG_LEVEL", "LOGLEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := getEnv("H2TUNNEL_HEARTBEAT_SEC", "HEARTBEAT_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.HeartbeatSec = n
		}
	}
	if v := getEnv("H2TUNNEL_DRAIN_TIMEOUT_SEC", "DRAIN_TIMEOUT_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.DrainTimeoutSec = n
		}
	}
	if v := getEnv("H2TUNNEL_BACKUP_LINE", "BACKUP_LINE"); v != "" {
		cfg.BackupLine = strings.ToLower(strings.TrimSpace(v))
	}
	if v := getEnv("H2TUNNEL_HANDSHAKE_ACK_MS", "HANDSHAKE_ACK_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.HandshakeAckMs = n
		}
	}
	if v := getEnv("H2TUNNEL_KEEPALIVE_SEC", "KEEPALIVE_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.KeepaliveSec = n
		}
	}
	if v := getEnv("H2TUNNEL_PRIMARY_COUNT", "PRIMARY_COUNT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.PrimaryCount = n
		}
	}
	if v := getEnv("H2TUNNEL_BACKUP_COUNT", "BACKUP_COUNT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.BackupCount = n
		}
	}
	if v := getEnv("H2TUNNEL_PRIMARY_DIAL_INTERVAL_SEC", "PRIMARY_DIAL_INTERVAL_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.PrimaryDialIntervalSec = n
		}
	}
	if v := getEnv("H2TUNNEL_BACKUP_DIAL_INTERVAL_SEC", "BACKUP_DIAL_INTERVAL_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.BackupDialIntervalSec = n
		}
	}
	if v := getEnv("H2TUNNEL_ESTABLISH_INTERVAL_SEC", "ESTABLISH_INTERVAL_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.EstablishIntervalSec = n
		}
	}
}

type ServerConfig struct {
	ListenAddr        string        `json:"listen"`
	TLSCert           string        `json:"cert"`
	TLSKey            string        `json:"key"`
	EnableTLS         bool          `json:"tls"`
	Path              string        `json:"path"`
	LocalOnly         bool          `json:"local_only"`
	LogLevel          string        `json:"log_level"`
	EnableH3          bool          `json:"h3"`
	Transport         string        `json:"transport"`
	Network           string        `json:"network"` // "all", "tcp", "udp"
	ExpectedToken     string        `json:"token"`
	HeartbeatInterval time.Duration `json:"-"` // 由 heartbeat_sec 换算
	DrainTimeout      time.Duration `json:"-"` // 由 drain_timeout_sec 换算
	// SessionWindow 会话恢复环形缓冲容量（KB），服务端侧必须实现才能配合客户端恢复。
	SessionWindow int `json:"-"`
	// BackupLine 备用线路策略：none=单线路；hot=热备；cold=冷备。默认 none。
	BackupLine string `json:"backup_line"`
}

type ClientConfig struct {
	ListenAddr string `json:"listen"`
	ServerUrl  string `json:"server"`
	Path       string `json:"path"`
	TargetAddr string `json:"target"`
	Insecure   bool   `json:"insecure"`
	CustomHost string `json:"host"`
	ServerName string `json:"sni"`
	Alpn       string `json:"alpn"`
	UseH3      bool   `json:"h3"`
	UseWT      bool   `json:"wt"`
	UseMasque  bool   `json:"masque"`
	UseGRPC    bool   `json:"grpc"`
	Network    string `json:"network"` // "all" / "both", "tcp", "udp"
	LogLevel   string `json:"log_level"`
	Token      string `json:"token"`

	// 以下两项为客户端侧的保活与排空参数，语义同 ServerConfig
	HeartbeatInterval time.Duration `json:"-"`
	DrainTimeout      time.Duration `json:"-"`
	// SessionWindow 会话恢复环形缓冲容量（KB）
	SessionWindow int `json:"-"`
	// BackupLine 备用线路策略：none=单线路；hot=热备；cold=冷备。默认 none。
	BackupLine string `json:"backup_line"`
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
	netMode := strings.ToLower(strings.TrimSpace(c.Network))
	return netMode == "udp" || netMode == "all" || netMode == "both" || netMode == "tcp+udp" || netMode == "tcp,udp"
}

func (c *ClientConfig) IsTCP() bool {
	netMode := strings.ToLower(strings.TrimSpace(c.Network))
	return netMode == "tcp" || netMode == "all" || netMode == "both" || netMode == "tcp+udp" || netMode == "tcp,udp" || netMode == ""
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
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	applyEnvOverrides(&cfg)
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
		if fileCfg, err := loadConfigFile(*cfgPath); err == nil {
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
			// transport 兼容 "transport":"h3" 字符串与 {"h3":true} 布尔两种写法
			if *transport == "" {
				switch {
				case fileCfg.H3:
					*transport = "h3"
				case fileCfg.WT:
					*transport = "wt"
				case fileCfg.Masque:
					*transport = "masque"
				case fileCfg.GRPC:
					*transport = "grpc"
				case fileCfg.Transport != "":
					*transport = fileCfg.Transport
				}
			}
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
// file is now the single source of truth. When no file is given, built-in
// defaults are applied by the build*Config helpers, and the old `-insecure`
// default (true) is preserved so a bare client run still works.
func loadConfigFromArgs(args []string) *Config {
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
		cfg = fileCfg
	} else {
		// bare run: preserve the old `-insecure` flag default
		cfg.Insecure = true
		fmt.Fprintln(os.Stderr, "⚠️ 警告: 未指定配置文件，客户端默认跳过 TLS 证书校验 (Insecure=true)，在不可信网络中易被中间人攻击。生产环境请通过配置文件显式设置并校验证书指纹。")
	}
	applyEnvOverrides(cfg)
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
	path := cfg.Path
	if path == "" {
		path = "/tunnel"
	}
	logLevel := cfg.LogLevel
	if logLevel == "" {
		logLevel = "info"
	}
	netMode := strings.ToLower(strings.TrimSpace(cfg.Network))
	if netMode == "" || netMode == "both" || netMode == "tcp+udp" || netMode == "tcp,udp" {
		netMode = "all"
	}

	return ServerConfig{
		ListenAddr:        listen,
		TLSCert:           cfg.Cert,
		TLSKey:            cfg.Key,
		EnableTLS:         cfg.TLS,
		Path:              path,
		LocalOnly:         cfg.LocalOnly,
		LogLevel:          logLevel,
		EnableH3:          cfg.H3,
		Transport:         cfg.Transport,
		Network:           netMode,
		ExpectedToken:     cfg.Token,
		HeartbeatInterval: resolveHeartbeat(cfg.HeartbeatSec),
		DrainTimeout:      resolveDrainTimeout(cfg.DrainTimeoutSec),
		SessionWindow:     resolveSessionWindow(cfg.SessionWindowKB),
		BackupLine:        cfg.BackupLine,
	}
}

// validateClientTransport 校验客户端传输互斥。一个客户端进程每次出站只走一种
// 主传输（h3 / wt / masque / grpc），代码分派从不并行跑多协议——若同时开多个，
// 之前只会按优先级静默取一（wt > h3/masque QUIC > h2/grpc），极易让人误以为
// "多开=多路并行"。这里改为显式报错。返回空串表示无冲突，否则返回可读描述。
func validateClientTransport(c *Config) string {
	enabled := []string{}
	if c.H3 {
		enabled = append(enabled, "h3")
	}
	if c.WT {
		enabled = append(enabled, "wt")
	}
	if c.Masque {
		enabled = append(enabled, "masque")
	}
	if c.GRPC {
		enabled = append(enabled, "grpc")
	}
	if len(enabled) > 1 {
		return fmt.Sprintf("client transport 只能选一个，不能同时开启 %s（h3/wt/masque/grpc 互斥，代码不会并行跑多协议）",
			strings.Join(enabled, " + "))
	}
	return ""
}

func buildClientConfig(cfg *Config) ClientConfig {
	if msg := validateClientTransport(cfg); msg != "" {
		zlog.Fatalf("[Client] ❌ %s", msg)
	}
	listen := cfg.Listen
	if listen == "" {
		listen = "127.0.0.1:2222"
	}
	server := cfg.Server
	if server == "" {
		server = "https://127.0.0.1:8443"
	}
	path := cfg.Path
	if path == "" {
		path = "/tunnel"
	}
	target := cfg.Target
	if target == "" {
		target = "127.0.0.1:22"
	}
	logLevel := cfg.LogLevel
	if logLevel == "" {
		logLevel = "info"
	}
	netMode := strings.ToLower(strings.TrimSpace(cfg.Network))
	if netMode == "" {
		netMode = "tcp"
	} else if netMode == "both" || netMode == "tcp+udp" || netMode == "tcp,udp" {
		netMode = "all"
	}

	return ClientConfig{
		ListenAddr:        listen,
		ServerUrl:         server,
		Path:              path,
		TargetAddr:        target,
		Insecure:          cfg.Insecure,
		CustomHost:        cfg.Host,
		ServerName:        cfg.SNI,
		Alpn:              cfg.ALPN,
		UseH3:             cfg.H3,
		UseWT:             cfg.WT,
		UseMasque:         cfg.Masque,
		UseGRPC:           cfg.GRPC,
		Network:           netMode,
		LogLevel:          logLevel,
		Token:             cfg.Token,
		HeartbeatInterval: resolveHeartbeat(cfg.HeartbeatSec),
		DrainTimeout:      resolveDrainTimeout(cfg.DrainTimeoutSec),
		SessionWindow:     resolveSessionWindow(cfg.SessionWindowKB),
		BackupLine:        cfg.BackupLine,
		HandshakeAckMs:    resolveHandshakeAckMs(cfg.HandshakeAckMs),
		KeepaliveSec:      resolveKeepaliveSec(cfg.KeepaliveSec),
		ConnectionPolicy: resolveConnectionPolicy(
			cfg.PrimaryCount, cfg.BackupCount,
			cfg.PrimaryDialIntervalSec, cfg.BackupDialIntervalSec,
			cfg.EstablishIntervalSec, defaultBackupMissedAck, nil,
		),
	}
}

func runFromConfig(path string) {
	cfg, err := loadConfigFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read config file %s: %v\n", path, err)
		os.Exit(1)
	}
	applyEnvOverrides(cfg)
	if strings.ToLower(cfg.Mode) == "client" {
		startClientDirect(buildClientConfig(cfg))
	} else {
		startServerDirect(buildServerConfig(cfg))
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
