package h2tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

// =========================================
// WebTransport（WT）传输层 adapter
//
// WT 已从「独立会话模型」收编进 resume/2 引擎：每条业务隧道拥有自己的
// wtSessionManager（headers 携带该隧道 X-Session-ID + resume A 层协商头），
// 服务端把每个业务 stream 派发到 v2 会话表（prepareResumeSession），
// 与 h2/grpc/masque 同级：ring buffer 上行重放 + 服务端 targetConn 保留 +
// A/B 握手。断线（stream 断）后用同一 session id 重开新流续传。
//
// 因 WT stream 无 per-stream HTTP 头，clientDownlink（本地已收下行字节）经
// 数据面 HANDSHAKE 帧 payload 透传，使服务端能从正确位置补发下行缺口。
// =========================================

type wtSessionManager struct {
	lg      *slog.Logger
	dialer  *webtransport.Dialer
	reqUrl  string
	headers http.Header
	mu      sync.Mutex
	primary *webtransport.Session
	backup  *webtransport.Session
	ctx     context.Context
}

// GetSession 返回当前可用 session：主健康则主，否则备用顶上；
// 命中后异步触发备用预热（与 L3 connectionManager 的主备/错相思路一致：
// 任意时刻至少两条可用 session 且状态不同，CDN 或 NAT 强杀不致两者同死）。
func (m *wtSessionManager) GetSession(ctx context.Context) (*webtransport.Session, error) {
	// 快路径：主健康
	m.mu.Lock()
	if m.primary != nil && m.primary.Context().Err() == nil {
		primary := m.primary
		needBackup := m.backup == nil || m.backup.Context().Err() != nil
		m.mu.Unlock()
		if needBackup {
			go m.warmupBackup()
		}
		return primary, nil
	}
	m.mu.Unlock()

	// 备用健康：切主
	m.mu.Lock()
	if m.backup != nil && m.backup.Context().Err() == nil {
		m.primary = m.backup
		m.backup = nil
		primary := m.primary
		m.mu.Unlock()
		go m.warmupBackup()
		lgInfof(m.lg, "[WT Manager] 🔁 主 session 已死，切到备用 session")
		return primary, nil
	}
	m.mu.Unlock()

	// 都没有：现拨
	return m.dialAndInstall(ctx)
}

func (m *wtSessionManager) warmupBackup() {
	ctx := m.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	session, err := m.dialSession(ctx)
	if err != nil {
		lgDebugf(m.lg, "[WT Manager] 备用 session 预热失败: %v", err)
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.backup != nil && m.backup.Context().Err() == nil {
		return
	}
	m.backup = session
	lgDebugf(m.lg, "[WT Manager] 🔥 备用 session 已预热")
}

func (m *wtSessionManager) dialAndInstall(ctx context.Context) (*webtransport.Session, error) {
	lgDebugf(m.lg, "[WT Manager] Initiating WebTransport handshake...")
	start := time.Now()
	session, err := m.dialSession(ctx)
	if err != nil {
		lgErrorf(m.lg, "[WT Manager] ❌ WebTransport handshake failed: %v", err)
		return nil, err
	}
	m.mu.Lock()
	m.primary = session
	m.mu.Unlock()
	lgInfof(m.lg, "[WT Manager] ✅ Underlying WebTransport session established successfully (duration: %v)", time.Since(start))
	go m.warmupBackup()
	return session, nil
}

func (m *wtSessionManager) dialSession(ctx context.Context) (*webtransport.Session, error) {
	_, session, err := m.dialer.Dial(ctx, m.reqUrl, m.headers)
	return session, err
}

// newWTManagerForTunnel 为单条业务隧道构建独立的 wtSessionManager。
// 每条隧道拥有自己的 WT session（headers 携带该隧道的 X-Session-ID 与 resume
// A 层协商头），使服务端能按 session id 区分多隧道并各自续传——这是 WT 接入
// resume/2 会话表的前提（一个 WT session 对应一个逻辑会话）。
func newWTManagerForTunnel(cfg clientConfig, reqUrl, sessionID string) *wtSessionManager {
	mgr, _ := newWTManagerForTunnelContext(context.Background(), cfg, reqUrl, sessionID)
	return mgr
}

func newWTManagerForTunnelContext(ctx context.Context, cfg clientConfig, reqUrl, sessionID string) (*wtSessionManager, error) {
	var tlsConfig *tls.Config
	if cfg.TLSConfig != nil {
		tlsConfig = cfg.TLSConfig.Clone()
	} else {
		tlsConfig = &tls.Config{InsecureSkipVerify: cfg.Insecure}
	}
	tlsConfig.NextProtos = []string{http3.NextProtoH3}
	if cfg.ServerName != "" {
		tlsConfig.ServerName = cfg.ServerName
	}
	headers := make(http.Header)
	if err := applyClientCredentials(ctx, headers, cfg); err != nil {
		return nil, err
	}
	headers.Set("Protocol", "webtransport")
	setXDst(headers, cfg)
	// resume/2 A 层协商头（X-Resume-Downlink 为 per-stream 值，经数据面 HANDSHAKE
	// 帧 payload 透传，不在此设置）。
	headers.Set("X-Tunnel-Proto", resumeFrameTypeResume)
	headers.Set("X-Session-ID", sessionID)
	headers.Set("X-Resume-Version", "2")
	headers.Set("X-Resume-Caps", clientCapabilities(cfg).String())
	headers.Set("X-Resume-Params", clientParams(cfg).String())
	if cfg.RoleBackup {
		headers.Set("X-Resume-Role", "backup")
	}
	return &wtSessionManager{
		lg: cfg.lg(),
		dialer: &webtransport.Dialer{
			TLSClientConfig: tlsConfig,
			QUICConfig:      getDefaultQUICConfig(),
			DialAddr:        cfg.QUICDialer,
		},
		reqUrl:  reqUrl,
		headers: headers,
		ctx:     ctx,
	}, nil
}

// ---> 客户端 TCP: WebTransport（resume/2 接入）
// WT 接入 resume/2 引擎后，断线（stream 断）用同一 session id 重开新流续传，
// 与 h2/grpc/masque 同级：ring buffer 上行重放 + 服务端 targetConn 保留 +
// A/B 握手。clientDownlink（本地已收下行字节）经数据面 HANDSHAKE 帧 payload 透传，
// 使服务端能从正确位置补发下行缺口。
func executeResumeWT(localConn net.Conn, cfg clientConfig, wtManager *wtSessionManager, sessionID string) {
	_ = executeResumeWTWithManagerContext(context.Background(), localConn, cfg, wtManager, sessionID, nil)
}

func executeResumeWTContext(ctx context.Context, localConn net.Conn, cfg clientConfig, reqURL, sessionID string, ready chan<- error) error {
	wtManager, err := newWTManagerForTunnelContext(ctx, cfg, reqURL, sessionID)
	if err != nil {
		if ready != nil {
			ready <- err
		}
		return err
	}
	return executeResumeWTWithManagerContext(ctx, localConn, cfg, wtManager, sessionID, ready)
}

func executeResumeWTWithManagerContext(ctx context.Context, localConn net.Conn, cfg clientConfig, wtManager *wtSessionManager, sessionID string, ready chan<- error) error {
	defer localConn.Close()
	readyOnce := sync.Once{}
	notifyReady := func(err error) {
		if ready != nil {
			readyOnce.Do(func() { ready <- err })
		}
	}
	ringBuf := newResumeClientRingBuf(cfg.SessionWindow)
	var serverUplink uint64
	var clientDownlink uint64

	for attempt := 1; attempt <= resumeMaxAttempts; attempt++ {
		ok, err := runResumeWTTryContext(ctx, sessionID, &serverUplink, &clientDownlink, localConn, ringBuf, cfg, wtManager, func() { notifyReady(nil) })
		if ok {
			return nil // 正常结束（EOF/对端 END）
		}
		if err != nil {
			if isPermanentTunnelError(err) || ctx.Err() != nil {
				notifyReady(err)
				return err
			}
			lgWarnf(cfg.lg(), "[Resume/WT] ❌ 会话不可恢复: %v", err)
		}
		// stream 断：同 session id 重开新流续传（backoff 后）。
		delay := time.Duration(attempt) * 200 * time.Millisecond
		if delay > resumeBackoffMax {
			delay = resumeBackoffMax
		}
		lgInfof(cfg.lg(), "[Resume/WT] 🔁 第 %d 次重开 WT 流（同 session 续传），等待 %v", attempt, delay)
		select {
		case <-ctx.Done():
			notifyReady(ctx.Err())
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	lgWarnf(cfg.lg(), "[Resume/WT] 超过最大重试次数 (%d)，会话终止", resumeMaxAttempts)
	err := errors.New("h2tunnel: WebTransport resume attempts exhausted")
	notifyReady(err)
	return err
}

// runResumeWTTry 单条 WT 流的完整生命周期：建流 → B 层握手（携带 clientDownlink）
// → 上行重放/实时 + 下行收帧。返回 (normalEnd, err) 语义同 runResumeAttempt。
func runResumeWTTry(sessionID string, serverUplink, clientDownlink *uint64,
	localConn net.Conn, ringBuf *resumeClientRingBuf, cfg clientConfig,
	wtManager *wtSessionManager) (bool, error) {
	return runResumeWTTryContext(context.Background(), sessionID, serverUplink, clientDownlink, localConn, ringBuf, cfg, wtManager, nil)
}

func runResumeWTTryContext(ctx context.Context, sessionID string, serverUplink, clientDownlink *uint64,
	localConn net.Conn, ringBuf *resumeClientRingBuf, cfg clientConfig,
	wtManager *wtSessionManager, onReady func()) (bool, error) {

	// 本 attempt 结束时打断可能阻塞在 localConn.Read 的发送协程，避免旧 sendLoop
	// 与下一 attempt 的 sendLoop 并发读同一条连接（见 resumeSendLoop 的 done 参数）。
	done := make(chan struct{})
	defer func() {
		close(done)
		_ = localConn.SetReadDeadline(time.Now())
	}()
	_ = localConn.SetReadDeadline(time.Time{})

	session, err := wtManager.GetSession(ctx)
	if err != nil || session == nil {
		lgWarnf(cfg.lg(), "[Resume/WT] ❌ 无法获取 WT Session: %v", err)
		return false, err
	}
	stream, err := session.OpenStreamSync(ctx)
	if err != nil || stream == nil {
		lgWarnf(cfg.lg(), "[Resume/WT] ❌ WT Stream 打开失败: %v", err)
		return false, err
	}
	defer stream.Close()

	// ===== B 层握手：HANDSHAKE 帧 payload 携带 clientDownlink，等 HANDSHAKE-ACK =====
	payload := strconv.FormatUint(*clientDownlink, 10)
	if err := writeFrame(stream, resumeFrameHandshake, 0, []byte(payload), 0); err != nil {
		lgWarnf(cfg.lg(), "[Resume/WT] ❌ 写 HANDSHAKE 控制帧失败: %v", err)
		return false, err
	}
	hsBuf := make([]byte, 64*1024)
	typ, _, _, err := readFrame(stream, hsBuf)
	if err != nil {
		lgWarnf(cfg.lg(), "[Resume/WT] ❌ 读 HANDSHAKE-ACK 失败: %v", err)
		return false, err
	}
	if typ != resumeFrameHandshakeAck {
		lgWarnf(cfg.lg(), "[Resume/WT] ❌ 期望 HANDSHAKE-ACK，收到帧 0x%02x", typ)
		return false, errors.New("h2tunnel: invalid WebTransport handshake response")
	}
	lgInfof(cfg.lg(), "[Resume/WT] ✅ B 层握手确认 (clientDownlink=%d)", *clientDownlink)
	if onReady != nil {
		onReady()
	}

	var wg sync.WaitGroup
	wg.Add(2)
	var recvErr error

	go func() {
		defer wg.Done()
		// 上行：从 ring 重放 serverUplink 起，再实时读 localConn。stream 作 io.Writer。
		_ = resumeSendLoop(stream, localConn, ringBuf, *serverUplink, done, cfg.HeartbeatInterval, cfg.lg(), cfg.stats)
	}()
	go func() {
		defer wg.Done()
		recvErr = resumeRecvLoopWT(stream, localConn, clientDownlink, cfg.lg(), cfg.stats)
	}()

	wg.Wait()
	if recvErr == nil {
		return true, nil
	}
	return false, nil
}

// resumeRecvLoopWT 从 WT 流读 resume 帧，校验 seq 连续后写 localConn，并累计
// clientDownlink（本地已收下行字节），供下次重开流时经 HANDSHAKE payload 透传，
// 服务端据此补发缺口。收到 END 帧 → 本地半关并正常返回。
func resumeRecvLoopWT(stream io.Reader, localConn net.Conn, clientDownlink *uint64, lg *slog.Logger, st *ClientStats) error {
	payloadBuf := make([]byte, 64*1024)
	expected := *clientDownlink // 下行坐标系跨流连续：重连流首帧 seq 必须等于上次已收字节数
	for {
		typ, seq, n, err := readFrame(stream, payloadBuf)
		if errors.Is(err, errResumeEndFrame) {
			if tc, ok := localConn.(*net.TCPConn); ok {
				_ = tc.CloseWrite()
			}
			*clientDownlink = expected
			return nil
		}
		if err != nil {
			*clientDownlink = expected
			return err
		}
		if typ == resumeFrameKeepaliveAck {
			continue
		}
		if typ != resumeFrameData {
			*clientDownlink = expected
			return fmt.Errorf("resume/WT: unexpected frame type 0x%02x", typ)
		}
		if seq != expected {
			lgWarnf(lg, "[Resume/WT] 下行 seq 不连续: 期望 %d, 收到 %d", expected, seq)
			*clientDownlink = expected
			return errGap
		}
		if _, wErr := localConn.Write(payloadBuf[:n]); wErr != nil {
			*clientDownlink = expected
			return wErr
		}
		if st != nil {
			st.DownlinkBytes.Add(int64(n))
		}
		expected += uint64(n)
		*clientDownlink = expected
	}
}

// ---> 服务端 WT：把每条业务 stream 派发到 resume/2 会话表（断线续传）
func handleWebTransportServer(w http.ResponseWriter, r *http.Request, sessionID string, cfg serverConfig, wtServer *webtransport.Server, sessions *sessionTable) {
	network, target := getRequestDestination(r, cfg)
	if !targetAllowedByRuntime(cfg, target) {
		lgWarnf(sessions.lg(), "[%s] 🚫 Access denied for target address: %s", sessionID, target)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// resume/2 是唯一数据面：WT 也统一走 resume 会话表（断线续传）。
	// A 层协商头（X-Tunnel-Proto / X-Session-ID / X-Resume-Version/Caps/Params）
	// 由客户端经 WebTransport CONNECT 请求头携带，Upgrade 前即可读取校验。
	if r.Header.Get("X-Tunnel-Proto") != resumeFrameTypeResume {
		lgWarnf(sessions.lg(), "[%s] ❌ WT 未携带 resume/2 头，拒绝（v1 已移除）", sessionID)
		w.Header().Set("X-Resume-Error", resumeErrVersionUnsupported.String())
		http.Error(w, "resume/2 required", http.StatusUpgradeRequired)
		return
	}
	if strings.TrimSpace(r.Header.Get("X-Session-ID")) == "" {
		w.Header().Set("X-Resume-Error", resumeErrInvalidParams.String())
		http.Error(w, errSessionIDRequired.Error(), http.StatusBadRequest)
		return
	}

	// ===== A 层握手：版本 / 能力 / 参数 协商 =====
	clientVersion := parseHeaderVersion(r.Header.Get("X-Resume-Version"))
	negotiated := negotiateVersion(clientVersion, 2)
	if negotiated == 0 {
		w.Header().Set("X-Resume-Error", resumeErrVersionUnsupported.String())
		lgWarnf(sessions.lg(), "[%s] ❌ 版本协商失败: client=%d server=2", sessionID, clientVersion)
		http.Error(w, "resume version unsupported", http.StatusUpgradeRequired)
		return
	}
	clientCaps := parseCaps(r.Header.Get("X-Resume-Caps"))
	serverCaps := serverCapabilities(cfg)
	caps := intersectCaps(clientCaps, serverCaps)
	params := alignParams(parseParams(r.Header.Get("X-Resume-Params")))
	// 下行 replay ring 属于服务端资源，容量以服务端配置为准并明确回传。
	params.windowKB = resolveSessionWindow(cfg.SessionWindow)

	// A 层确认响应头（客户端经 WebTransport 握手响应读到）。
	w.Header().Set("X-Resume-Version", "2")
	w.Header().Set("X-Resume-Caps", caps.String())
	w.Header().Set("X-Resume-Params", params.String())
	w.Header().Set("X-Resume-Ack", "ok")

	session, err := wtServer.Upgrade(w, r)
	if err != nil {
		lgErrorf(sessions.lg(), "[%s] ❌ WebTransport upgrade failed: %v", sessionID, err)
		return
	}
	lgInfof(sessions.lg(), "[%s] ✅ WT Session established | Target: %s (%s)", sessionID, target, network)

	datagram := network == "udp"
	isBackup := r.Header.Get("X-Resume-Role") == "backup"

	for {
		stream, err := session.AcceptStream(r.Context())
		if err != nil {
			lgDebugf(sessions.lg(), "[%s] WT Session ended: %v", sessionID, err)
			break
		}

		streamID := fmt.Sprintf("%s-ST%d", sessionID, time.Now().UnixNano()%10000)

		// 每个 WT 流是一个独立 resume 数据面，用同一 X-Session-ID 续传。
		go func(s *webtransport.Stream, sID string) {
			// 备用（探活）线路：不 dial 目标、不建业务会话，只做 A+B 握手 + KEEPALIVE。
			if isBackup {
				writer := &resumeSessionWriter{w: s}
				if !datagram {
					if !doServerHandshakeAck(s, writer, params.handshakeAckMs, sID, sessions.lg()) {
						return
					}
				}
				serveBackupKeepaliveOnly(s, writer, params, sID, sessions.lg())
				return
			}

			dialTarget := func() (net.Conn, error) {
				return dialTargetForRequest(r, cfg, network, target)
			}
			sess, isNew, err := sessions.prepareResumeSession(r, dialTarget, cfg.SessionWindow)
			if err != nil {
				lgErrorf(sessions.lg(), "[%s] ❌ WT Resume 拨号失败: %v", sID, err)
				s.CancelWrite(1)
				return
			}
			if cfg.stats != nil {
				if isNew {
					cfg.stats.SessionsCreated.Add(1)
				} else {
					cfg.stats.SessionsResumed.Add(1)
				}
			}
			if isNew {
				lgInfof(sessions.lg(), "[%s] 🆕 WT Resume 新会话建立 | Target: %s (%s, %s)", sID, target, network, modeLabel(datagram))
			} else {
				lgInfof(sessions.lg(), "[%s] 🔄 WT Resume 恢复已有会话 | Target: %s (%s)", sID, target, modeLabel(datagram))
			}

			writer := &resumeSessionWriter{w: s}
			// 注意：activeWriter 的挂载由 serveResumeDataPlane 在 B 层握手
			// 完成后才执行，避免 downlinkPump 在 HANDSHAKE-ACK 之前把 DATA 帧
			// 写进新流（客户端首帧必须是 HANDSHAKE-ACK）。
			var clientDownlink uint64
			handshakeDone := false
			if !datagram {
				cd, ok := doWTStreamHandshake(s, writer, params.handshakeAckMs, sID, sessions.lg())
				if !ok {
					return
				}
				clientDownlink = cd
				handshakeDone = true
			}
			serveResumeDataPlane(sess, s, writer, params, clientDownlink, sID, handshakeDone, sess.clearActiveWriter)
			s.CancelRead(0)
		}(stream, streamID)
	}
}

// doWTStreamHandshake WT 流上的 B 层握手：读客户端 HANDSHAKE 帧（payload 携带
// 该流的下行补发起点 clientDownlink，因为 WT 无 per-stream HTTP 头），回
// HANDSHAKE-ACK。返回解析出的 clientDownlink 与是否成功。超时/非 HANDSHAKE → false。
func doWTStreamHandshake(s *webtransport.Stream, writer *resumeSessionWriter, timeoutMs int, sessionID string, lg *slog.Logger) (uint64, bool) {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	type res struct {
		typ     byte
		seq     uint64
		payload []byte
		err     error
	}
	done := make(chan res, 1)
	go func() {
		payloadBuf := make([]byte, 64*1024)
		typ, seq, n, err := readFrame(s, payloadBuf)
		var pl []byte
		if n > 0 {
			pl = make([]byte, n)
			copy(pl, payloadBuf[:n])
		}
		done <- res{typ, seq, pl, err}
	}()
	var clientDownlink uint64
	select {
	case r := <-done:
		if r.err != nil {
			lgWarnf(lg, "[%s] ❌ WT HANDSHAKE 读取失败: %v", sessionID, r.err)
			return 0, false
		}
		if r.typ != resumeFrameHandshake {
			lgWarnf(lg, "[%s] ❌ WT 首个帧非 HANDSHAKE（0x%02x），握手失败", sessionID, r.typ)
			return 0, false
		}
		// HANDSHAKE payload 携带 clientDownlink（十进制字符串）。
		if len(r.payload) > 0 {
			if v, errParse := strconv.ParseUint(string(r.payload), 10, 64); errParse == nil {
				clientDownlink = v
			}
		}
	case <-time.After(timeout):
		lgWarnf(lg, "[%s] ❌ WT HANDSHAKE 超时 (%v)", sessionID, timeout)
		return 0, false
	}
	if err := writer.writeControl(resumeFrameHandshakeAck, nil); err != nil {
		lgWarnf(lg, "[%s] ❌ 写 WT HANDSHAKE-ACK 失败: %v", sessionID, err)
		return 0, false
	}
	lgDebugf(lg, "[%s] ✅ WT B 层握手确认完成 (HANDSHAKE→HANDSHAKE-ACK, clientDownlink=%d)", sessionID, clientDownlink)
	return clientDownlink, true
}
