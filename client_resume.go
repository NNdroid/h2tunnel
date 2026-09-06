package h2tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// =========================================
// 客户端会话恢复隧道执行器（executeResumableTunnel）
//
// 与 executeHTTPTunnel 的差异：
//   - 请求头带 X-Tunnel-Proto: resume/2、复用 X-Session-ID
//   - 帧格式为带 8 字节 seq 的 resume 帧（resumeframe.go）
//   - 上行先入 ring 再写流；新流建立时从服务端 ack 的 seq 处重放
//   - 流断（写失败/读错误）不立即关闭会话，而是回到外层 attempts 循环
//     用同一 session id 重新建流，断线 → 重拨 → 续传
// =========================================

const (
	resumeMaxAttempts = 16              // 单次 localConn 生命周期内的最大重建次数
	resumeBackoffMax  = 5 * time.Second // 重建 backoff 上限
)

// seqWriter 实现 io.Writer 并自动递增 seq —— 上行重放/实时共用。
type seqWriter struct {
	w   io.Writer
	seq *atomic.Uint64
}

func (s *seqWriter) Write(p []byte) (int, error) {
	seq := s.seq.Load()
	if err := writeResumeFrame(s.w, seq, p, 0); err != nil {
		return 0, err
	}
	s.seq.Store(seq + uint64(len(p)))
	return len(p), nil
}

// executeResumableTunnel 是启用 Resume 时客户端 TCP 入口。
// 它建立会话表中的逻辑会话，断线后自动用同一 session id 在新 HTTP 流
// 上续传，对 SSH 这种长流应用语义是「永不中断」（受 SessionWindowKB 限制）。
func executeResumableTunnel(sessionID string, localConn net.Conn, reqUrl string, cfg clientConfig, mgr *connectionManager) {
	_ = executeResumableTunnelContext(context.Background(), sessionID, localConn, reqUrl, cfg, mgr, nil)
}

func executeResumableTunnelContext(ctx context.Context, sessionID string, localConn net.Conn, reqUrl string, cfg clientConfig, mgr *connectionManager, ready chan<- error) error {
	defer localConn.Close()
	readyOnce := sync.Once{}
	notifyReady := func(err error) {
		if ready == nil {
			return
		}
		readyOnce.Do(func() { ready <- err })
	}
	defer func() {
		if ctx.Err() != nil {
			notifyReady(ctx.Err())
		}
	}()
	ringBuf := newResumeClientRingBuf(cfg.SessionWindow)
	sessID := sessionID
	var serverUplink uint64
	var clientDownlink uint64 // 本地已收下行字节；重连时作为 X-Resume-Downlink 上报，供服务端补发下行缺口
	// 经 L3 取当前活跃主线路的 http.Client（主断 → 备升级即切换传输池）。
	httpClient := pickClient(mgr, "tcp")
	if httpClient == nil {
		err := errors.New("h2tunnel: no ready transport connection")
		notifyReady(err)
		return err
	}

	for attempt := 1; attempt <= resumeMaxAttempts; attempt++ {
		ok, err := runResumeAttemptContext(ctx, sessID, &serverUplink, &clientDownlink, localConn, ringBuf, reqUrl, cfg, httpClient, func() { notifyReady(nil) })
		if ok {
			return nil // 正常结束（EOF/对端关闭）
		}
		if err != nil {
			if isPermanentTunnelError(err) || ctx.Err() != nil {
				notifyReady(err)
				return err
			}
			lgWarnf(cfg.lg(), "[Resume] ❌ 会话不可恢复: %v", err)
		}
		// 流断：每次重拨前重新取一次主线路客户端（若主已切换，则用新传输重拨续传）
		if mgr != nil {
			httpClient = mgr.PickClient("tcp")
			if httpClient == nil {
				err := errors.New("h2tunnel: no ready transport connection")
				notifyReady(err)
				return err
			}
		}
		// backoff 后尝试恢复（同 session id，同 serverUplink）
		delay := time.Duration(attempt) * 200 * time.Millisecond
		if delay > resumeBackoffMax {
			delay = resumeBackoffMax
		}
		lgInfof(cfg.lg(), "[Resume] 🔁 第 %d 次重拨（同 session 续传），等待 %v", attempt, delay)
		if cfg.stats != nil {
			cfg.stats.ResumeReconnects.Add(1)
		}
		select {
		case <-ctx.Done():
			notifyReady(ctx.Err())
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	lgWarnf(cfg.lg(), "[Resume] 超过最大重试次数 (%d)，会话终止", resumeMaxAttempts)
	err := errors.New("h2tunnel: resume attempts exhausted")
	notifyReady(err)
	return err
}

// TunnelError 表示服务端以 HTTP 状态码拒绝了隧道建立。除公开哨兵外，
// 嵌入方可用 errors.As(*TunnelError) 取回原始状态码做细分处理。
type TunnelError struct {
	status int
	// err 是映射出的公开哨兵（ErrUnauthenticated / ErrForbidden），
	// 经 Unwrap 暴露给 errors.Is；非鉴权/授权类错误为 nil。
	err error
}

func (e *TunnelError) Error() string {
	return fmt.Sprintf("h2tunnel: server rejected tunnel with HTTP %d", e.status)
}

func (e *TunnelError) Unwrap() error { return e.err }

// HTTPStatus 返回服务端拒绝时的 HTTP 状态码。
func (e *TunnelError) HTTPStatus() int { return e.status }

// newTunnelHTTPError 把服务端拒绝的 HTTP 状态映射为公开哨兵错误：
// 嵌入方可通过 errors.Is(err, h2tunnel.ErrUnauthenticated) /
// errors.Is(err, h2tunnel.ErrForbidden) 区分"换 token"和"换目标"。
func newTunnelHTTPError(status int) error {
	var sentinel error
	switch status {
	case http.StatusProxyAuthRequired, http.StatusUnauthorized:
		sentinel = ErrUnauthenticated
	case http.StatusForbidden:
		sentinel = ErrForbidden
	}
	return &TunnelError{status: status, err: sentinel}
}

func isPermanentTunnelError(err error) bool {
	var statusErr *TunnelError
	return errors.As(err, &statusErr) || errors.Is(err, errGap) || errors.Is(err, ErrUnauthenticated) || errors.Is(err, ErrForbidden)
}

// buildResumeRequest 依据传输类型构造 resume 会话请求。
// body 是 io.Pipe 的 reader（上行 resume 帧由 send goroutine 写入 pw）。
func buildResumeRequest(ctx context.Context, body io.Reader, sessID string, clientDownlink *uint64, ringBuf *resumeClientRingBuf, reqUrl string, cfg clientConfig) *http.Request {
	req, _ := buildResumeRequestChecked(ctx, body, sessID, clientDownlink, ringBuf, reqUrl, cfg)
	return req
}

func buildResumeRequestChecked(ctx context.Context, body io.Reader, sessID string, clientDownlink *uint64, ringBuf *resumeClientRingBuf, reqUrl string, cfg clientConfig) (*http.Request, error) {
	var method, reqURL string
	if cfg.usesMasque() {
		// MASQUE-TCP：CONNECT masque 路径，目标由 path + X-Dst 头携带
		method = http.MethodConnect
		host, port, _ := net.SplitHostPort(cfg.TargetAddr)
		if host == "" {
			host, port = cfg.TargetAddr, "22"
		}
		u, _ := url.Parse(reqUrl)
		u.Path = fmt.Sprintf("%s/tcp/%s/%s/", masquePathBase(cfg.Path), url.PathEscape(host), url.PathEscape(port))
		reqURL = u.String()
	} else {
		// h2 / h3 / grpc：POST cfg.Path
		method = http.MethodPost
		reqURL = reqUrl
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return nil, err
	}
	if err := applyClientCredentials(ctx, req.Header, cfg); err != nil {
		return nil, err
	}
	req.Header.Set("X-Tunnel-Proto", resumeFrameTypeResume)
	req.Header.Set("X-Session-ID", sessID)
	// 下行续传水位：本地已投递给应用的下行字节数（非上行环游标），服务端据此补发缺口。
	req.Header.Set("X-Resume-Downlink", strconv.FormatUint(*clientDownlink, 10))
	// ===== resume/2 握手头：版本 / 能力 / 参数 =====
	req.Header.Set("X-Resume-Version", "2")
	req.Header.Set("X-Resume-Caps", clientCapabilities(cfg).String())
	req.Header.Set("X-Resume-Params", clientParams(cfg).String())
	if cfg.RoleBackup {
		req.Header.Set("X-Resume-Role", "backup")
	}
	if cfg.CustomHost != "" {
		req.Host = cfg.CustomHost
	}
	setXDst(req.Header, cfg)
	setTunnelRequestHeaders(req.Header)

	if cfg.usesMasque() {
		req.Header.Set("Protocol", "connect-tcp")
		// http3.Transport 需要显式声明 HTTP/3，否则 CONNECT 目标路径可能被改写为空
		req.Proto = "HTTP/3"
	}
	if cfg.usesGRPC() {
		// gRPC 仅作为外层 Content-Type 标记，resume 帧不套 grpc 分帧
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("TE", "trailers")
	}
	return req, nil
}

// runResumeAttempt 单条流的完整生命周期：建流 → 重放/实时 → 收 END。
// 返回 (normalEnd=true, nil) 表示本端 EOF/对端 END；
// (false, nil) 表示流中断（应进入下次重拨）；
// (false, errGap) 表示缺口不可恢复（应终止会话）。
func runResumeAttempt(sessID string, serverUplink *uint64, clientDownlink *uint64,
	localConn net.Conn, ringBuf *resumeClientRingBuf,
	reqUrl string, cfg clientConfig, httpClient *http.Client,
) (bool, error) {
	return runResumeAttemptContext(context.Background(), sessID, serverUplink, clientDownlink, localConn, ringBuf, reqUrl, cfg, httpClient, nil)
}

func runResumeAttemptContext(parent context.Context, sessID string, serverUplink *uint64, clientDownlink *uint64,
	localConn net.Conn, ringBuf *resumeClientRingBuf,
	reqUrl string, cfg clientConfig, httpClient *http.Client, onReady func(),
) (bool, error) {
	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	// 本 attempt 结束时打断可能阻塞在 localConn.Read 的发送协程，避免旧 sendLoop
	// 与下一 attempt 的 sendLoop 并发读同一条连接（见 resumeSendLoop 的 done 参数）。
	done := make(chan struct{})
	defer func() {
		close(done)
		// 立即让阻塞中的 Read 返回：本 attempt 的 sendLoop 据此退出。
		_ = localConn.SetReadDeadline(time.Now())
	}()
	// 清掉上一轮可能残留的过期读超时，恢复为「无限等待」。
	_ = localConn.SetReadDeadline(time.Time{})

	// 依据传输类型构造 resume 请求：
	//  - h2 / h3 / grpc：POST cfg.Path，目标由 X-Target/X-Network 头携带
	//  - masque-tcp：CONNECT masque 路径，目标由 URL path + X-Dst 头携带
	// resume 帧作为内层统一数据面，各传输只贡献外层管道（grpc 仅打 Content-Type 标记）。
	req, err := buildResumeRequestChecked(ctx, pr, sessID, clientDownlink, ringBuf, reqUrl, cfg)
	if err != nil {
		return false, err
	}
	var resp *http.Response
	err = nil
	if rt, ok := httpClient.Transport.(http.RoundTripper); ok && cfg.usesMasque() {
		resp, err = rt.RoundTrip(req)
	} else {
		resp, err = httpClient.Do(req)
	}
	if err != nil {
		lgWarnf(cfg.lg(), "[Resume] 建流失败: %v", err)
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		lgWarnf(cfg.lg(), "[Resume] ❌ 服务端拒绝: HTTP %d", resp.StatusCode)
		return false, newTunnelHTTPError(resp.StatusCode)
	}

	if v := resp.Header.Get("X-Resume-Uplink"); v != "" {
		if n, errParse := strconv.ParseUint(v, 10, 64); errParse == nil {
			*serverUplink = n
		}
	}
	// ===== A 层确认校验 =====
	ack := resp.Header.Get("X-Resume-Ack")
	if ack != "ok" {
		if code := resp.Header.Get("X-Resume-Error"); code != "" {
			lgWarnf(cfg.lg(), "[Resume] ❌ 握手被拒绝: %s", code)
		} else {
			lgWarnf(cfg.lg(), "[Resume] ❌ 握手未确认 (X-Resume-Ack=%q)，终止", ack)
		}
		return false, errors.New("h2tunnel: resume handshake was not acknowledged")
	}
	// 以服务端回传参数为准（协商对齐）。ring 窗口保持本地配置（动态 resize 风险高），
	// 仅记录对齐值供日志与后续心跳使用。
	if v := resp.Header.Get("X-Resume-Params"); v != "" {
		aligned := alignParams(parseParams(v))
		lgDebugf(cfg.lg(), "[Resume] 服务端对齐参数: window_kb=%d handshake_ack=%dms keepalive=%ds",
			aligned.windowKB, aligned.handshakeAckMs, aligned.keepaliveSec)
	}
	lgInfof(cfg.lg(), "[Resume] ✅ 隧道恢复就绪 (serverUplink=%d)", *serverUplink)

	// ===== B 层握手：先发 HANDSHAKE，等 HANDSHAKE-ACK，ack 前零业务字节 =====
	if err := writeFrame(pw, resumeFrameHandshake, 0, nil, 0); err != nil {
		lgWarnf(cfg.lg(), "[Resume] ❌ 写 HANDSHAKE 控制帧失败: %v", err)
		return false, err
	}
	hsBuf := make([]byte, 64*1024)
	typ, _, _, err := readFrame(resp.Body, hsBuf)
	if err != nil {
		lgWarnf(cfg.lg(), "[Resume] ❌ 读 HANDSHAKE-ACK 失败: %v", err)
		return false, err
	}
	if typ != resumeFrameHandshakeAck {
		lgWarnf(cfg.lg(), "[Resume] ❌ 期望 HANDSHAKE-ACK，收到帧 0x%02x", typ)
		return false, errors.New("h2tunnel: invalid resume handshake response")
	}
	lgDebugf(cfg.lg(), "[Resume] ✅ B 层握手确认 (HANDSHAKE→HANDSHAKE-ACK)")
	if onReady != nil {
		onReady()
	}

	var wg sync.WaitGroup
	wg.Add(2)
	var sendErr, recvErr error

	go func() {
		defer wg.Done()
		defer pw.Close()
		sendErr = resumeSendLoop(pw, localConn, ringBuf, *serverUplink, done, cfg.HeartbeatInterval, cfg.lg(), cfg.stats)
	}()
	go func() {
		defer wg.Done()
		recvErr = resumeRecvLoop(resp.Body, localConn, clientDownlink, cfg.lg(), cfg.stats)
	}()

	wg.Wait()

	if recvErr == nil {
		return true, nil
	}
	_ = sendErr
	return false, nil
}

// resumeSendLoop：先从 ring 重放 serverUplink 起的数据，然后切换实时模式。
// 实时模式下：localConn.Read → Append ring → seqWriter.Write。
// w 是上行写目标（h2: io.PipeWriter；wt: webtransport.Stream）。stream 模式的
// 半关闭（END）由调用方在需要时触发（见 writeResumeEndFrame）。
// done 用于本 attempt 结束时打断可能阻塞在 localConn.Read 的本次发送协程，
// 避免旧 attempt 的 sendLoop 与下一 attempt 的 sendLoop 并发读同一条 localConn
// （两读者会按不可预测方式瓜分字节流，破坏上行帧）。
func resumeSendLoop(w io.Writer, localConn net.Conn, ringBuf *resumeClientRingBuf, startSeq uint64, done <-chan struct{}, heartbeat time.Duration, lg *slog.Logger, st *ClientStats) error {
	var seq atomic.Uint64
	seq.Store(startSeq)
	sw := &seqWriter{w: w, seq: &seq}

	// 阶段 A：从 ring 重放
	replayed, err := ringBuf.ReplayFrom(startSeq, sw)
	if err != nil {
		if errors.Is(err, errGap) {
			return errGap
		}
		return err
	}
	if replayed > 0 {
		lgDebugf(lg, "[Resume] ⏮️ 重放上行 %d 字节 (seq %d..%d)", replayed, startSeq, startSeq+uint64(replayed))
	}

	// 阶段 B：实时
	bufPtr := tcpBufPool.Get().(*[]byte)
	buf := *bufPtr
	defer tcpBufPool.Put(bufPtr)
	for {
		// A TCP Read has no select case. A bounded read deadline lets this sole
		// writer wake during an idle period and send a resume KEEPALIVE without
		// adding a competing writer to the HTTP request body.
		if heartbeat > 0 {
			_ = localConn.SetReadDeadline(time.Now().Add(heartbeat))
		}
		n, rErr := localConn.Read(buf)
		if n > 0 {
			ringBuf.Append(buf[:n])
			if st != nil {
				st.UplinkBytes.Add(int64(n))
			}
			if _, wErr := sw.Write(buf[:n]); wErr != nil {
				return wErr
			}
		}
		if rErr != nil {
			if rErr == io.EOF {
				return writeResumeEndFrame(w)
			}
			if heartbeat > 0 {
				if netErr, ok := rErr.(net.Error); ok && netErr.Timeout() {
					select {
					case <-done:
						return nil
					default:
					}
					if err := writeFrame(w, resumeFrameKeepalive, 0, nil, 0); err != nil {
						return err
					}
					continue
				}
			}
			// 本 attempt 结束（经 SetReadDeadline 打断的读超时）时静默退出，
			// 不把打断当作流错误去触发重拨。
			select {
			case <-done:
				return nil
			default:
			}
			return rErr
		}
	}
}

// resumeRecvLoop 从响应流读 resume DATA 帧，校验 seq 连续后写 localConn，并累计
// clientDownlink（本地已收下行字节），供下次重开流时经 X-Resume-Downlink 上报，
// 服务端据此补发下行缺口。下行坐标系跨流连续：首帧 seq 必须等于 *clientDownlink
// （首流为 0，重连流为上次已收字节数），否则视为缺口不可恢复。
// 收到 END 帧 → 本地半关并正常返回；读错误 → 返回 err 让外层重拨。
func resumeRecvLoop(body io.Reader, localConn net.Conn, clientDownlink *uint64, lg *slog.Logger, st *ClientStats) error {
	payloadBuf := make([]byte, 64*1024)
	expected := *clientDownlink
	for {
		typ, seq, n, err := readFrame(body, payloadBuf)
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
			// 主流空闲保活的确认帧不属于数据坐标系，也不投递给本地应用。
			continue
		}
		if typ != resumeFrameData {
			*clientDownlink = expected
			return fmt.Errorf("resume: unexpected frame type 0x%02x", typ)
		}
		if seq != expected {
			lgWarnf(lg, "[Resume] 下行 seq 不连续: 期望 %d, 收到 %d", expected, seq)
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
