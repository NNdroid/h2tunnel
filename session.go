package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
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
// kind 在 prepareResumeSession 拨号前由 GetXNetwork 决定并写入。
type tunnelSession struct {
	id        string
	createdAt time.Time
	lastSeen  time.Time // 最后一次活跃（用于超时回收）
	datagram  bool      // true = UDP 数据报模式（无 seq 重放）

	mu              sync.Mutex
	targetConn      net.Conn
	targetCloseOnce sync.Once

	// 下行：服务端 targetConn → HTTP 流 / ring buffer
	downlinkSent uint64 // 累计写给客户端的字节
	downlinkRing *ringBuffer
	activeWriter *resumeSessionWriter // 当前活跃流下行 writer；nil 表示无流
	closed       bool

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
func (s *tunnelSession) writeDownlink(data []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, net.ErrClosed
	}
	s.downlinkSent += uint64(len(data))
	if s.datagram {
		// UDP：封装成 wire 帧写活跃流；无流则丢（跨流不重放）。
		if s.activeWriter == nil {
			return len(data), nil
		}
		if err := s.frameW(&resumeWriterAdapter{w: s.activeWriter}, data); err != nil {
			s.activeWriter = nil
		}
		return len(data), nil
	}
	s.downlinkRing.Append(data)
	if s.activeWriter != nil {
		// 本段的起始 seq = downlinkSent - len(data)（downlinkSent 刚自增）。
		// 写 resume 帧（客户端 readResumeFrame 按 seq 解析）。
		seq := s.downlinkSent - uint64(len(data))
		if _, err := s.activeWriter.writeFrame(seq, data); err != nil {
			// 流挂了不致命：ring 已写，下次流接上时从下行 seq 续传
			s.activeWriter = nil
		}
	}
	return len(data), nil
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
// 若 ring 窗口已被覆盖（fromSeq < windowStart），返回 ErrGap。
//
// ⚠️ 并发约束：重放期间必须持有 s.mu。downlinkPump 的 writeDownlink 同样需要
// s.mu 才能写 activeWriter；持锁期间 pump 的实时下行写被阻塞，保证「重放帧」
// 与「实时下行帧」不会并发写入同一条流（否则帧交叠 + seq 乱序，客户端判 ErrGap
// 直接断流）。锁内 downlinkSent 被冻结，重放完成后 pump 的实时帧从 target 处
// 无缝续传，既不缺口也不重复。
// 写失败时由 writeDownlink 和调用方的 defer 清理 activeWriter；writer 不会
// 在持有自身锁时反向调用 session，避免与这里的锁顺序发生死锁。
func (s *tunnelSession) replayDownlink(w *resumeSessionWriter, fromSeq uint64) error {
	s.mu.Lock()
	target := s.downlinkSent
	defer s.mu.Unlock()
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
		if errors.Is(err, ErrGap) {
			return ErrGap
		}
		if err != nil {
			return err
		}
		if n == 0 {
			break
		}
	}
	return nil
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
		return ErrResumeBadSeq
	}
	if _, err := s.targetConn.Write(data); err != nil {
		return err
	}
	s.uplinkRecv += uint64(len(data))
	s.lastSeen = time.Now()
	return nil
}

// sessionTable 全局会话表
type sessionTable struct {
	mu       sync.Mutex
	sessions map[string]*tunnelSession
}

var globalSessionTable = &sessionTable{sessions: make(map[string]*tunnelSession)}

var ErrSessionIDRequired = errors.New("resume session id is required")

func newSessionID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// getOrCreate 查表：存在则续传，不存在则新开会话。
// dialTarget 是拨号函数（测试时可注入）。
// datagram/frameW/frameR 仅在新建会话时使用（datagram 为 true 时设置数据面封装）。
func (t *sessionTable) getOrCreate(id string, dialTarget func() (net.Conn, error), sizeKB int, datagram bool, frameW func(io.Writer, []byte) error, frameR func(io.Reader, []byte) (int, error)) (*tunnelSession, bool, error) {
	if strings.TrimSpace(id) == "" {
		return nil, false, ErrSessionIDRequired
	}

	// Do not hold the table lock while dialing: a slow/unreachable target must
	// not serialize all unrelated new sessions behind its DialTimeout.
	t.mu.Lock()
	if existing, ok := t.sessions[id]; ok {
		existing.mu.Lock()
		alive := !existing.closed && existing.targetConn != nil
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
		id:           id,
		createdAt:    time.Now(),
		lastSeen:     time.Now(),
		targetConn:   tconn,
		datagram:     datagram,
		frameW:       frameW,
		frameR:       frameR,
		downlinkRing: newRingBuffer(sizeKB),
	}

	// A competing request may have installed the same ID while this one dialed.
	// Keep the established session and close the losing connection immediately.
	t.mu.Lock()
	if existing, ok := t.sessions[id]; ok {
		existing.mu.Lock()
		alive := !existing.closed && existing.targetConn != nil
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
	var toRemove []string
	for id, s := range t.sessions {
		s.mu.Lock()
		idle := now.Sub(s.lastSeen)
		dead := s.closed || s.targetConn == nil
		s.mu.Unlock()
		if dead || idle > sessionIdleTimeout {
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
	network := GetXNetwork(r)
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
	return t.getOrCreate(id, dialTarget, sessionWindowKB, datagram, frameW, frameR)
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

// startSessionReaper 启动后台回收器（只启动一次）
var reaperOnce sync.Once

func startSessionReaper() {
	reaperOnce.Do(func() {
		go func() {
			t := time.NewTicker(sessionCleanupTick)
			defer t.Stop()
			for range t.C {
				globalSessionTable.reapIdle()
			}
		}()
	})
}
