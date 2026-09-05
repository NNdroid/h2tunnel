package h2tunnel

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
)

// =========================================
// backup.go — 备用线路执行器（热备 / 冷备）
//
// 备用线路是独立于主线路的第二条冗余通道。关键设计（§3.3）：
//   - 备用用独立 session id（<主id>+b）与 role=backup，避免与服务端会话表冲突。
//   - 备用不传输业务数据，只做周期 KEEPALIVE 存活探测。
//   - 只有「经过握手确认且 KEEPALIVE 存活」的备用才允许被接管，
//     未确认的备用禁止自动接管（避免盲切到死线）。
//
// 热备：主线路活跃期间持续维持备用流 + KEEPALIVE 心跳，主断秒切。
// 冷备：不常驻流，切换时才建立备用握手。
// =========================================

// backupLineState 备用线路存活状态机。
type backupLineState int

const (
	backupIdle        backupLineState = iota // 未启动
	backupHandshaking                        // 握手进行中
	backupAlive                              // 已确认存活（可接管）
	backupFailed                             // 已失效
)

func (s backupLineState) String() string {
	switch s {
	case backupIdle:
		return "idle"
	case backupHandshaking:
		return "handshaking"
	case backupAlive:
		return "alive"
	case backupFailed:
		return "failed"
	}
	return "unknown"
}

// 备用心跳连续丢失判定失效的阈值
const backupMaxMissedAcks = 3

// managedRole 线路角色：主连接 / 备用连接。
type managedRole int

const (
	rolePrimary managedRole = iota
	roleBackup
)

func (r managedRole) String() string {
	if r == roleBackup {
		return "backup"
	}
	return "primary"
}

// backupLine 单条备用线路执行器。
// 同时也是 connectionManager 中「主/备线路」的通用探活执行器：
//   - role=backup   → 独立 session id(<主>+b) + X-Resume-Role: backup，只 KEEPALIVE 保活
//   - role=primary  → 使用自身 session id + X-Resume-Role 空，建流后 KEEPALIVE 保活探活
//
// 主/备都做 A+B 握手 + KEEPALIVE 保活；只有 role=backup 且 state==backupAlive
// 才允许被接管（backupLine.Alive）。
type backupLine struct {
	primaryID  string
	backupID   string
	role       managedRole
	netType    string // "tcp" / "udp"（类型分流维度）
	cfg        clientConfig
	reqUrl     string
	httpClient *http.Client // 共享默认客户端（后备）
	client     *http.Client // 本线路专属客户端（独立传输/连接池，接入真实数据路径时使用）

	mu            sync.Mutex
	state         backupLineState
	missedAcks    int
	maxMissedAcks int // 心跳连续丢失判定失效阈值（0 → 默认 backupMaxMissedAcks）
	pipe          *io.PipeWriter
	respBody      io.ReadCloser
	closeCh       chan struct{}
	closeOnce     sync.Once
	ctxCancel     context.CancelFunc // 握手请求上下文取消函数（close 时调用，终止 keepalive 流）
	lastErr       error
	keepaliveNs   int64 // 心跳周期纳秒
	handshakeMs   int   // 握手超时毫秒
}

// newManagedLine 创建通用线路执行器（主或备）。
// role 决定 session id 后缀与 X-Resume-Role 头；netType 用于类型分流标识。
// client 为线路专属 http.Client（独立传输/连接池）；为空则回退用共享 httpClient。
func newManagedLine(id string, role managedRole, netType string, cfg clientConfig, reqUrl string, httpClient, client *http.Client, maxMissedAcks int) *backupLine {
	bl := &backupLine{
		primaryID:     id,
		role:          role,
		netType:       netType,
		cfg:           cfg,
		reqUrl:        reqUrl,
		httpClient:    httpClient,
		client:        client,
		state:         backupIdle,
		maxMissedAcks: maxMissedAcks,
		keepaliveNs:   int64(resolveKeepaliveSec(cfg.KeepaliveSec)) * int64(time.Second),
		handshakeMs:   resolveHandshakeAckMs(cfg.HandshakeAckMs),
		closeCh:       make(chan struct{}),
	}
	if bl.maxMissedAcks <= 0 {
		bl.maxMissedAcks = backupMaxMissedAcks
	}
	if role == roleBackup {
		bl.backupID = id + "+b"
	} else {
		bl.backupID = id
	}
	return bl
}

// Client 返回本线路使用的 http.Client：优先线路专属 client，否则共享 httpClient。
func (b *backupLine) Client() *http.Client {
	if b.client != nil {
		return b.client
	}
	return b.httpClient
}

func (b *backupLine) close() {
	b.closeOnce.Do(func() {
		close(b.closeCh)
		b.mu.Lock()
		if b.respBody != nil {
			_ = b.respBody.Close()
			b.respBody = nil
		}
		ctxCancel := b.ctxCancel
		b.mu.Unlock()
		if ctxCancel != nil {
			ctxCancel()
		}
		if b.client != nil && b.client.Transport != nil {
			if closer, ok := b.client.Transport.(interface{ Close() error }); ok {
				_ = closer.Close()
			} else if closer, ok := b.client.Transport.(interface{ CloseIdleConnections() }); ok {
				closer.CloseIdleConnections()
			}
		}
	})
}

func (b *backupLine) setState(s backupLineState) {
	b.mu.Lock()
	b.state = s
	b.mu.Unlock()
}

func (b *backupLine) setError(err error) {
	b.mu.Lock()
	b.lastErr = err
	b.mu.Unlock()
}

func (b *backupLine) Err() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lastErr
}

// Alive 返回备用是否已确认存活（可接管）。
func (b *backupLine) Alive() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state == backupAlive
}

func (b *backupLine) State() backupLineState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

// Role 返回线路角色。
func (b *backupLine) Role() managedRole { return b.role }

// ID 返回线路 session id。
func (b *backupLine) ID() string { return b.backupID }

// NetType 返回线路类型分流维度。
func (b *backupLine) NetType() string { return b.netType }

// IsClosed 返回线路是否已被显式关闭（closeCh 已关）。
func (b *backupLine) IsClosed() bool {
	select {
	case <-b.closeCh:
		return true
	default:
		return false
	}
}

// Start 启动备用握手 + KEEPALIVE 心跳循环（热备常驻）。
// 阻塞直到 close。若握手失败或心跳失效，状态置 backupFailed 后返回。
func (b *backupLine) Start() {
	b.setState(backupHandshaking)
	if !b.doHandshake() {
		b.setState(backupFailed)
		return
	}
	b.setState(backupAlive)
	b.keepaliveLoop()
}

// doHandshake 完成备用线路 A+B 层握手，返回是否成功。
// 请求上下文绑定线路生命周期：不在此处 cancel（否则握手后 keepalive 流被杀），
// 而是存 ctxCancel 供 close() 调用终止整条流。
func (b *backupLine) doHandshake() bool {
	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	b.mu.Lock()
	b.ctxCancel = cancel
	b.mu.Unlock()

	cfg := b.cfg
	cfg.RoleBackup = b.role == roleBackup
	req, reqErr := buildResumeRequestChecked(ctx, pr, b.backupID, new(uint64), newResumeClientRingBuf(256), b.reqUrl, cfg)
	if reqErr != nil {
		b.setError(reqErr)
		zlog.Warnf("[Backup:%s] 备用凭据构建失败: %v", b.backupID, reqErr)
		return false
	}

	var resp *http.Response
	var err error
	client := b.Client()
	if rt, ok := client.Transport.(http.RoundTripper); ok && cfg.usesMasque() {
		resp, err = rt.RoundTrip(req)
	} else {
		resp, err = client.Do(req)
	}
	if err != nil {
		b.setError(err)
		zlog.Warnf("[Backup:%s] 备用握手建流失败: %v", b.backupID, err)
		return false
	}
	if resp.StatusCode != http.StatusOK {
		b.setError(&tunnelHTTPError{status: resp.StatusCode})
		zlog.Warnf("[Backup:%s] 备用握手被拒: HTTP %d", b.backupID, resp.StatusCode)
		resp.Body.Close()
		return false
	}
	if resp.Header.Get("X-Resume-Ack") != "ok" {
		b.setError(errors.New("h2tunnel: transport readiness handshake was not acknowledged"))
		zlog.Warnf("[Backup:%s] 备用握手未确认: %s", b.backupID, resp.Header.Get("X-Resume-Error"))
		resp.Body.Close()
		return false
	}

	// 备用不传业务数据，但 stream 模式仍需完成 B 层握手以证明端到端活性。
	if !isDatagramCap(cfg) {
		if err := writeFrame(pw, resumeFrameHandshake, 0, nil, 0); err != nil {
			resp.Body.Close()
			return false
		}
		buf := make([]byte, 64*1024)
		typ, _, _, err := readFrame(resp.Body, buf)
		if err != nil || typ != resumeFrameHandshakeAck {
			zlog.Warnf("[Backup:%s] 备用 B 层握手失败: %v", b.backupID, err)
			resp.Body.Close()
			return false
		}
	}

	// 保存流引用供心跳读写
	b.mu.Lock()
	b.pipe = pw
	b.respBody = resp.Body
	b.mu.Unlock()
	zlog.Infof("[Backup:%s] ✅ 备用握手完成，进入 KEEPALIVE 心跳", b.backupID)
	return true
}

// keepaliveLoop 周期发 KEEPALIVE，监听 KEEPALIVE-ACK。
// 连续 N 次丢失 → 判定失效。
func (b *backupLine) keepaliveLoop() {
	interval := time.Duration(b.keepaliveNs)
	if interval <= 0 {
		interval = 15 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	ackCh := make(chan struct{}, 8)
	go b.listenKeepaliveAck(ackCh)

	for {
		select {
		case <-b.closeCh:
			return
		case <-ackCh:
			b.mu.Lock()
			b.missedAcks = 0
			b.state = backupAlive
			b.mu.Unlock()
		case <-ticker.C:
			b.mu.Lock()
			pw := b.pipe
			b.mu.Unlock()
			if pw == nil {
				return
			}
			if err := writeFrame(pw, resumeFrameKeepalive, 0, nil, 0); err != nil {
				zlog.Warnf("[Backup:%s] 发 KEEPALIVE 失败: %v", b.backupID, err)
			}
			// 每发一帧记一次「待确认」；收到 KEEPALIVE-ACK 时清零（见 listenKeepaliveAck）。
			// 连续 maxMissedAcks 次未确认即判定失效（checkFailure）。
			b.mu.Lock()
			b.missedAcks++
			b.mu.Unlock()
			b.checkFailure()
		}
	}
}

// checkFailure 连续丢失超阈值则判定失效。
func (b *backupLine) checkFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.missedAcks >= b.maxMissedAcks {
		b.state = backupFailed
		zlog.Warnf("[Backup:%s] 连续 %d 次心跳丢失，判定备用失效", b.backupID, b.missedAcks)
	}
}

// listenKeepaliveAck 读取 KEEPALIVE-ACK，读到则通知 ackCh。
func (b *backupLine) listenKeepaliveAck(ackCh chan struct{}) {
	buf := make([]byte, 64*1024)
	for {
		b.mu.Lock()
		body := b.respBody
		b.mu.Unlock()
		if body == nil {
			return
		}
		typ, _, _, err := readFrame(body, buf)
		if err != nil {
			return // 流结束
		}
		if typ == resumeFrameKeepaliveAck {
			select {
			case ackCh <- struct{}{}:
			default:
			}
		}
	}
}

// isDatagramCap 判断该客户端传输是否为 datagram（UDP）模式。
// UDP 备用不做 B 层握手（服务端对 datagram 跳过），仅 A 层。
func isDatagramCap(cfg clientConfig) bool {
	return cfg.IsUDP() && !cfg.usesWT()
}
