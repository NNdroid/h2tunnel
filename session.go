package h2tunnel

import (
	"crypto/rand"
	"encoding/hex"
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
)

// =========================================
// session.go — 服务端会话表 + 恢复调度
//
// 每个 resume 模式的隧道会话对应一条服务端与 targetConn 的双向字节流，
// 跨多次 HTTP 流重建保持：
//   - targetConn：长连接到目标服务（SSH 等），不因 HTTP 流中断而关闭
//   - 下行缓冲 ring：服务端 targetConn.Read 出的字节帧化后双写：
//                   ① 当前活跃 HTTP 流（如果有），② ring 缓冲
//     流断时只停 ①，② 继续；新流 resume 时从 ring 补发缺口
//   - 上行：HTTP body 解出 seq 帧，按 seq 连续提交给 targetConn；
//           客户端在恢复请求中带下行收到的 seq，服务端响应上行已收的 seq
//     会话恢复上限：服务端上行收到 X，客户端应在 X 处续传（不能更早）
// =========================================

const (
	sessionIdleTimeout = 60 * time.Second // 无活跃流的最长保留时间
	sessionCleanupTick = 10 * time.Second
)

// tunnelSession 服务端会话
//
// 同一套会话表同时服务两类数据模型：
//
//	stream   —— TCP / SSH 等有序字节流。跨流重建用 seq + ring 重放补缺，
//	           上行按 seq 连续校验（缺口不可恢复）。
//	datagram —— UDP 等数据报。UDP 本身无序可丢，逐字节 seq 重放无意义
//	           甚至有害（会重发已发出的包），因此只做「保持 targetConn
//	           socket 存活 + 跨流重建」，不做重放。
//
// kind 在 prepareResumeSession 拨号前由 getXNetwork 决定并写入。
type tunnelSession struct {
	id        string
	createdAt time.Time
	lastSeen  time.Time    // 最后一次活跃（用于超时回收）
	datagram  bool         // true = UDP 数据报模式（无 seq 重放）
	logger    *slog.Logger // 实例日志器（来自 Server options，nil → discard）
	binding   sessionBinding

	mu              sync.Mutex
	targetConn      net.Conn
	targetCloseOnce sync.Once

	// 下行：服务端 targetConn → HTTP 流 / ring buffer
	downlinkSent uint64 // 累计写给客户端的字节
	downlinkRing *ringBuffer
	activeWriter *resumeSessionWriter // 当前活跃流下行 writer；nil 表示无流
	closed       bool

	// downlinkMu 串行化下行帧写（重放 vs 实时），保证客户端看到的
	// 下行 seq 严格连续；frameSentSeq 记录已写出到当前活跃流的终点。
	// 网络写在此锁下进行，不持 s.mu —— 避免与上行互锁（T2 拆分）。
	downlinkMu   sync.Mutex
	frameSentSeq uint64

	// 上行：客户端 → targetConn。按 seq 累计连续接收（缺口不可恢复）。
	// datagram 模式不使用（UDP 无顺序保证）。
	uplinkRecv uint64

	// frameW / frameR 数据面封装：stream 模式为 nil（走 writeResumeFrame /
	// readResumeFrame + seq 校验），datagram 模式为非 nil（走 writeUDPPacket /
	// readUDPPacket 或 masque 的 writeUDPCapsule / readUDPCapsule）。
	frameW func(io.Writer, []byte) error
	frameR func(io.Reader, []byte) (int, error)
}

// writeDownlink 向活跃流 + ring 写入一段下行数据。
//
// stream 模式：写活跃流 + 写 ring（供断线重放），字节累计。
// datagram 模式：data 是一个完整的 UDP 包（targetConn.Read 一次返回一个包），
//
//	经 frameW 封装成 wire 帧后写活跃流；不写 ring（UDP 无重放），
//	downlinkSent 语义从「字节累计」退化为「仅累计（非连续坐标系，不用于重放）」。
//
// 若无活跃流：stream 模式写 ring 等下次续传；datagram 模式直接丢弃该包
// （客户端断线期间到达的 UDP 包无可恢复意义，重放反而错乱）。
// 返回写入的字节数。
//
// 锁序：s.mu 只做状态决策 / ring 追加 / seq 分配（纯内存操作，持有时间与
// 网络无关）；网络写在 downlinkMu 下进行 —— 原实现持 s.mu 做网络写，
// 会把上行 acceptUplinkSeq 一并锁死，全双工高吞吐时两方向互锁。
func (s *tunnelSession) writeDownlink(data []byte) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, net.ErrClosed
	}
	writer := s.activeWriter
	datagram := s.datagram
	if datagram {
		// UDP：封装成 wire 帧写活跃流；无流则丢（跨流不重放）。
		s.downlinkSent += uint64(len(data))
		s.mu.Unlock()
		if writer == nil {
			return len(data), nil
		}
		s.downlinkMu.Lock()
		err := s.frameW(&resumeWriterAdapter{w: writer}, data)
		s.downlinkMu.Unlock()
		if err != nil {
			s.clearActiveWriter(writer)
		}
		return len(data), nil
	}
	// stream 模式：先入 ring 再分配 seq —— 保证任何 seq < downlinkSent
	// 的字节都已在 ring 中（重放读 ring 不踩空）。Append 是纯内存拷贝。
	s.downlinkRing.Append(data)
	seq := s.downlinkSent
	s.downlinkSent += uint64(len(data))
	s.mu.Unlock()

	if writer == nil {
		return len(data), nil
	}

	// downlinkMu 串行化「重放 vs 实时」的帧序：重放持锁期间 pump 的
	// 实时帧在此排队；重放完成后 frameSentSeq 推进到重放终点，与重放
	// 窗口重叠的排队帧（seq 已分配但未写出的竞态窗口）直接跳过，客户端
	// 看到的 seq 严格连续。
	s.downlinkMu.Lock()
	if seq+uint64(len(data)) <= s.frameSentSeq {
		s.downlinkMu.Unlock()
		return len(data), nil
	}
	// 本段的起始 seq = seq。写 resume 帧（客户端 readResumeFrame 按 seq 解析）。
	_, err := writer.writeFrame(seq, data)
	if err == nil {
		s.frameSentSeq = seq + uint64(len(data))
	}
	s.downlinkMu.Unlock()
	if err != nil {
		// 流挂了不致命：ring 已写，下次流接上时从下行 seq 续传
		s.clearActiveWriter(writer)
	}
	return len(data), nil
}

// lg 返回会话表日志器（nil 安全）。
func (t *sessionTable) lg() *slog.Logger {
	if t.logger != nil {
		return t.logger
	}
	return discardLogger
}

// lg 返回会话实例日志器（nil 安全，回落 discard）。
func (s *tunnelSession) lg() *slog.Logger {
	if s.logger != nil {
		return s.logger
	}
	return discardLogger
}

// setActiveWriter 设置当前活跃流的下行 writer
func (s *tunnelSession) setActiveWriter(w *resumeSessionWriter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeWriter = w
}

// clearActiveWriter 流关闭时清空
func (s *tunnelSession) clearActiveWriter(w *resumeSessionWriter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeWriter == w {
		s.activeWriter = nil
	}
}

// replayDownlink 从 fromSeq 起将已写入 ring 但未到达客户端的字节
// 补发到当前活跃 writer。不再 Append ring（避免重复）。
// 若 ring 窗口已被覆盖（fromSeq < windowStart），返回 errGap。
//
// ⚠️ 调用方必须持有 downlinkMu：与 writeDownlink 的实时帧共用该锁保证
// 客户端看到的下行 seq 严格连续（重放帧与实时帧不交叠）。持锁期间
// writeDownlink 已分配 seq 的帧在锁外排队，与重放窗口重叠的部分由
// frameSentSeq 跳过。写失败时由 writeDownlink 和调用方的 defer 清理
// activeWriter；writer 不会在持有自身锁时反向调用 session。
func (s *tunnelSession) replayDownlinkLocked(w *resumeSessionWriter, fromSeq uint64) error {
	// downlinkSent 的写点在 writeDownlink 的 s.mu 段内；重放侧在 downlinkMu
	// 下运行但不持 s.mu，必须先快照（锁序固定 downlinkMu→s.mu，单向无环）。
	s.mu.Lock()
	target := s.downlinkSent
	s.mu.Unlock()
	if fromSeq >= target {
		return nil
	}
	tmp := make([]byte, 8192)
	seq := fromSeq
	for seq < target {
		n, err := s.downlinkRing.ReadAt(seq, tmp)
		if n > 0 {
			if _, wErr := w.writeFrame(seq, tmp[:n]); wErr != nil {
				return wErr
			}
			seq += uint64(n)
		}
		if errors.Is(err, errGap) {
			return errGap
		}
		if err != nil {
			return err
		}
		if n == 0 {
			break
		}
	}
	if s.frameSentSeq < seq {
		s.frameSentSeq = seq
	}
	return nil
}

// attachAndReplay 在 downlinkMu 下原子完成「挂载活跃 writer + 下行重放」。
// 必须原子：若 setActiveWriter 与重放之间 pump 抢到 downlinkMu，实时帧会
// 插到重放帧之前，客户端立即看到 seq 跳变（ErrGap）。
// 返回的 error 仅表示重放失败（gap / 写失败）；writer 挂载总是成功。
func (s *tunnelSession) attachAndReplay(writer *resumeSessionWriter, fromSeq uint64) error {
	s.downlinkMu.Lock()
	defer s.downlinkMu.Unlock()
	s.setActiveWriter(writer)
	if s.datagram {
		// datagram 无重放（UDP 无 seq 坐标系）。
		return nil
	}
	return s.replayDownlinkLocked(writer, fromSeq)
}

// acceptUplinkSeq 接受一个上行帧的 seq+data，校验连续性，
// 连续则提交到 targetConn 并推进 uplinkRecv。
// datagram 模式：data 是一个已解出的 UDP 包，直接提交，不校验 seq。
func (s *tunnelSession) acceptUplinkSeq(seq uint64, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if s.targetConn == nil {
		return net.ErrClosed
	}
	if s.datagram {
		if _, err := s.targetConn.Write(data); err != nil {
			return err
		}
		s.lastSeen = time.Now()
		return nil
	}
	expected := s.uplinkRecv
	switch {
	case seq < expected:
		// 客户端重发了已收到的字节（恢复初期），按预期截掉头部重复部分
		skip := int(expected - seq)
		if skip >= len(data) {
			s.lastSeen = time.Now()
			return nil
		}
		data = data[skip:]
	case seq > expected:
		// 客户端跳了 seq：缺口不可恢复
		return errResumeBadSeq
	}
	if _, err := s.targetConn.Write(data); err != nil {
		return err
	}
	s.uplinkRecv += uint64(len(data))
	s.lastSeen = time.Now()
	return nil
}

// sessionTable 服务端会话表（实例级，挂在 Server 上；库嵌入时多个
// Server 互不共享）。
type sessionTable struct {
	logger      *slog.Logger
	mu          sync.Mutex
	sessions    map[string]*tunnelSession
	idleTimeout time.Duration
}

type sessionBinding struct {
	network     string
	target      string
	principalID string
}

func (b sessionBinding) matches(other sessionBinding) bool {
	return b.network == other.network && b.target == other.target && b.principalID == other.principalID
}

var errSessionIDRequired = errors.New("resume session id is required")

func newSessionID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// getOrCreate 查表：存在则续传，不存在则新开会话。
// dialTarget 是拨号函数（测试时可注入）。
// datagram/frameW/frameR 仅在新建会话时使用（datagram 为 true 时设置数据面封装）。
func (t *sessionTable) getOrCreate(id string, dialTarget func() (net.Conn, error), sizeKB int, datagram bool, frameW func(io.Writer, []byte) error, frameR func(io.Reader, []byte) (int, error)) (*tunnelSession, bool, error) {
	return t.getOrCreateBound(id, sessionBinding{}, dialTarget, sizeKB, datagram, frameW, frameR)
}

func (t *sessionTable) getOrCreateBound(id string, binding sessionBinding, dialTarget func() (net.Conn, error), sizeKB int, datagram bool, frameW func(io.Writer, []byte) error, frameR func(io.Reader, []byte) (int, error)) (*tunnelSession, bool, error) {
	if strings.TrimSpace(id) == "" {
		return nil, false, errSessionIDRequired
	}

	// Do not hold the table lock while dialing: a slow/unreachable target must
	// not serialize all unrelated new sessions behind its DialTimeout.
	t.mu.Lock()
	if existing, ok := t.sessions[id]; ok {
		existing.mu.Lock()
		bindingMatches := existing.binding.matches(binding)
		alive := !existing.closed && existing.targetConn != nil
		if !bindingMatches {
			return nil, false, fmt.Errorf("%w: resume session identity changed", ErrForbidden)
		}
		if alive {
			existing.lastSeen = time.Now()
		}
		existing.mu.Unlock()
		t.mu.Unlock()
		if alive {
			return existing, false, nil
		}
		return nil, false, errors.New("session exists but target is dead")
	}
	t.mu.Unlock()

	tconn, err := dialTarget()
	if err != nil {
		return nil, false, err
	}
	s := &tunnelSession{
		logger:       t.logger,
		id:           id,
		createdAt:    time.Now(),
		lastSeen:     time.Now(),
		targetConn:   tconn,
		datagram:     datagram,
		binding:      binding,
		frameW:       frameW,
		frameR:       frameR,
		downlinkRing: newRingBuffer(sizeKB),
	}

	// A competing request may have installed the same ID while this one dialed.
	// Keep the established session and close the losing connection immediately.
	t.mu.Lock()
	if existing, ok := t.sessions[id]; ok {
		existing.mu.Lock()
		bindingMatches := existing.binding.matches(binding)
		alive := !existing.closed && existing.targetConn != nil
		if !bindingMatches {
			return nil, false, fmt.Errorf("%w: resume session identity changed", ErrForbidden)
		}
		if alive {
			existing.lastSeen = time.Now()
		}
		existing.mu.Unlock()
		t.mu.Unlock()
		_ = tconn.Close()
		if alive {
			return existing, false, nil
		}
		return nil, false, errors.New("session exists but target is dead")
	}
	t.sessions[id] = s
	t.mu.Unlock()

	go s.downlinkPump()
	return s, true, nil
}

// remove 显式清理（会话结束或超时）
func (t *sessionTable) remove(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.sessions, id)
}

// reapIdle 周期性回收空闲超时的会话（默认 60s 无活跃流）
func (t *sessionTable) reapIdle() {
	t.mu.Lock()
	now := time.Now()
	idleTimeout := t.idleTimeout
	if idleTimeout <= 0 {
		idleTimeout = sessionIdleTimeout
	}
	var toRemove []string
	for id, s := range t.sessions {
		s.mu.Lock()
		idle := now.Sub(s.lastSeen)
		dead := s.closed || s.targetConn == nil
		s.mu.Unlock()
		if dead || idle > idleTimeout {
			toRemove = append(toRemove, id)
		}
	}
	t.mu.Unlock()
	for _, id := range toRemove {
		if s := t.removeLocked(id); s != nil {
			s.close()
		}
	}
}

func (t *sessionTable) removeLocked(id string) *tunnelSession {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.sessions[id]
	if !ok {
		return nil
	}
	delete(t.sessions, id)
	return s
}

// close 关掉 targetConn 并标记 closed
func (s *tunnelSession) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.targetCloseOnce.Do(func() {
		if s.targetConn != nil {
			_ = s.targetConn.Close()
		}
	})
}

// touch 更新最后活跃时间
func (s *tunnelSession) touch() {
	s.mu.Lock()
	s.lastSeen = time.Now()
	s.mu.Unlock()
}

// downlinkPump 后台泵：从 targetConn 读出数据并写入 session buffer（+活跃流）。
// 它独立于任何 HTTP 请求线程，跨流重建依然工作——targetConn 持续被读取，
// 数据持续写入 ring，待下次流建立时从 seq 补发。
func (s *tunnelSession) downlinkPump() {
	bufPtr := tcpBufPool.Get().(*[]byte)
	buf := *bufPtr
	defer tcpBufPool.Put(bufPtr)
	defer s.close()

	for {
		// 给 targetConn 设 5 分钟读超时；若会话空闲超时（60s）由
		// sessionTable.reapIdle 主动关闭本会话 → Read 返回 err 退出。
		_ = s.targetConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, err := s.targetConn.Read(buf)
		if n > 0 {
			s.writeDownlink(buf[:n])
			s.touch()
		}
		if err != nil {
			// targetConn 死或超时：停泵。
			// stream 模式：目标 EOF 时发 END 帧给当前活跃流，通知客户端会话结束。
			// datagram 模式：不发 END（客户端读侧 frameR 只会解析 UDP 数据报，
			//   END 帧会被当成非法包解析而破坏流）；客户端读到流 EOF 自然触发重连。
			if !s.datagram {
				s.mu.Lock()
				writer := s.activeWriter
				closed := s.closed
				s.mu.Unlock()
				if writer != nil && !closed {
					// 尝试发 END（若流还活着）
					_ = writer.writeEnd()
				}
			}
			return
		}
	}
}

// —— 活跃流下行 writer ——
// 同一时刻只有一个活跃流能写下行；活跃流由新流建立时设置，
// 流断（写失败或上下文取消）时清空。
type resumeSessionWriter struct {
	// w 是当前活跃流的下行写目标。h2/grpc/masque 传 http.ResponseWriter
	//（io.Writer 子集，flusher 可用）；wt 传 webtransport.Stream（自带流式写）。
	w       io.Writer
	flusher http.Flusher
	mu      sync.Mutex
	closed  bool
}

// resumeWriterAdapter 把 resumeSessionWriter 适配成 io.Writer，
// 供 datagram 数据面的 frameW（writeUDPPacket / writeUDPCapsule）写入。
// 用 writeRaw（UDP 数据报自封装，不再套 resume 帧）。
type resumeWriterAdapter struct {
	w *resumeSessionWriter
}

func (a *resumeWriterAdapter) Write(p []byte) (int, error) {
	return a.w.writeRaw(p)
}

// writeFrame 在流上写一段 resume 帧（stream 模式下行）并 flush。
// seq 是本段数据在会话下行坐标系里的起始偏移。
func (w *resumeSessionWriter) writeFrame(seq uint64, data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, net.ErrClosed
	}
	if err := writeResumeFrame(w.w, seq, data, 0); err != nil {
		w.closed = true
		return 0, err
	}
	if w.flusher != nil {
		w.flusher.Flush()
	}
	return len(data), nil
}

// writeRaw 在流上写一段原始字节并 flush，不做 resume 分帧。
// 供 datagram 数据面（frameW 已自封装 UDP 数据报）使用。
func (w *resumeSessionWriter) writeRaw(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, net.ErrClosed
	}
	if err := writeAll(w.w, data); err != nil {
		w.closed = true
		return 0, err
	}
	if w.flusher != nil {
		w.flusher.Flush()
	}
	return len(data), nil
}

// writeEnd 在流上写 END 控制帧
func (w *resumeSessionWriter) writeEnd() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return net.ErrClosed
	}
	if err := writeResumeEndFrame(w.w); err != nil {
		w.closed = true
		return err
	}
	if w.flusher != nil {
		w.flusher.Flush()
	}
	return nil
}

// writeControl 在流上写一个控制帧（HANDSHAKE-ACK / KEEPALIVE-ACK 等）并 flush。
// 供服务端握手与备用线路存活应答使用。
func (w *resumeSessionWriter) writeControl(typ byte, data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return net.ErrClosed
	}
	if err := writeFrame(w.w, typ, 0, data, 0); err != nil {
		w.closed = true
		return err
	}
	if w.flusher != nil {
		w.flusher.Flush()
	}
	return nil
}

// close 标记底层 HTTP handler 已返回，禁止后续写入（避免
// "Write called after Handler finished" panic）。由 handler 的 defer 调用。
func (w *resumeSessionWriter) close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
}

// —— 服务端 handler 入口 ——
//
// 由 server.go 在 routeTunnelRequest 收到 X-Tunnel-Proto: resume/2 时调用。
// 返回 (session, isNew, error)；isNew=true 表示新建会话，error 非空表示拨号失败。
// 参数：
//   - r: 请求（带 X-Session-ID、可能带 X-Resume-Downlink、X-Network）
//   - dialTarget: 拨号目标服务的函数
//   - sessionWindowKB: 服务端为下行重放保留的窗口容量
//
// datagram 模式（X-Network=udp）下依据请求头为会话设置数据面封装：
//   - Protocol: connect-udp（MASQUE-UDP）→ writeUDPCapsule / readUDPCapsule
//   - 其余（H2/H3/gRPC UDP 流）→ writeUDPPacket / readUDPPacket
//
// 调用方负责后续：① 响应头写 X-Resume-Uplink ② 进入帧循环读上行 ③ 通知下行泵绑定活跃 writer
func (t *sessionTable) prepareResumeSession(r *http.Request, dialTarget func() (net.Conn, error), sessionWindowKB int) (*tunnelSession, bool, error) {
	id := r.Header.Get("X-Session-ID")
	network := getXNetwork(r)
	datagram := network == "udp"
	var frameW func(io.Writer, []byte) error
	var frameR func(io.Reader, []byte) (int, error)
	if datagram {
		if r.Header.Get("Protocol") == "connect-udp" {
			frameW = writeUDPCapsule
			frameR = readUDPCapsule
		} else {
			frameW = writeUDPPacket
			frameR = readUDPPacket
		}
	}
	state := requestState(r)
	binding := sessionBinding{network: network, target: getXTarget(r), principalID: state.principal.ID}
	return t.getOrCreateBound(id, binding, dialTarget, sessionWindowKB, datagram, frameW, frameR)
}

// parseResumeDownlink 从请求头解析客户端已收到的下行字节数
func parseResumeDownlink(r *http.Request) uint64 {
	v := r.Header.Get("X-Resume-Downlink")
	if v == "" {
		return 0
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// runReaper 实例级会话回收器（Server 启动时调用，停止由关闭 stopCh 控制）。
func (t *sessionTable) runReaper(stopCh <-chan struct{}) {
	tick := time.NewTicker(sessionCleanupTick)
	defer tick.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-tick.C:
			t.reapIdle()
		}
	}
}

// len 返回当前活跃会话数（快照）。
func (t *sessionTable) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.sessions)
}

// closeAll 关闭表中所有会话（Server.Close/Shutdown 时调用）。
func (t *sessionTable) closeAll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, s := range t.sessions {
		s.close()
	}
	t.sessions = make(map[string]*tunnelSession)
}
