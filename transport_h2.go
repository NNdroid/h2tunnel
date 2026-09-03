package main

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"
)

// =========================================
// h2 / h2c 传输层 adapter —— 服务端 resume 流处理
//
// handleH2StreamResumeServer 是 h2（HTTP/2 POST 流）的服务端 resume handler，
// 同时被 grpc 与 masque-tcp / masque-udp 复用（这些传输在鉴权后直接转派到这里，
// resume/2 是唯一数据面）。h3 走 QUIC，但应用层 handler 与 h2 完全相同。
//
// 协议流程（v2，含握手协商）：
//  1. 客户端请求头带 X-Tunnel-Proto: resume/2、X-Session-ID、
//     X-Resume-Version/Caps/Params、X-Resume-Downlink
//  2. 服务端校验版本（v2 唯一，非 2 → 426）、能力交集、参数对齐
//  3. 服务端查表/新建会话；响应头带 X-Resume-Version/Caps/Params/
//     X-Resume-Ack:ok + X-Resume-Uplink
//  4. stream 模式：等客户端 HANDSHAKE 控制帧 → 回 HANDSHAKE-ACK（B 层确认）
//  5. role=backup：不进入业务循环，改为 KEEPALIVE↔KEEPALIVE-ACK 存活应答
//  6. 主线路：补发下行缺口 → 进入帧循环读上行
//
// =========================================
func handleH2StreamResumeServer(w http.ResponseWriter, r *http.Request, sessionID string, cfg ServerConfig) {
	// 版本是硬约束：非 resume/2 直接拒绝，无降级目标（v1 已移除）。
	if r.Header.Get("X-Tunnel-Proto") != resumeFrameTypeResume {
		w.Header().Set("X-Resume-Error", resumeErrVersionUnsupported.String())
		http.Error(w, "resume/2 required", http.StatusUpgradeRequired)
		return
	}

	network, target := GetXDst(r)
	datagram := network == "udp"
	isBackup := r.Header.Get("X-Resume-Role") == "backup"

	// ===== A 层握手：版本 / 能力 / 参数 协商 =====
	clientVersion := parseHeaderVersion(r.Header.Get("X-Resume-Version"))
	negotiated := negotiateVersion(clientVersion, 2)
	if negotiated == 0 {
		w.Header().Set("X-Resume-Error", resumeErrVersionUnsupported.String())
		zlog.Warnf("[%s] ❌ 版本协商失败: client=%d server=2", sessionID, clientVersion)
		http.Error(w, "resume version unsupported", http.StatusUpgradeRequired)
		return
	}
	clientCaps := parseCaps(r.Header.Get("X-Resume-Caps"))
	serverCaps := serverCapabilities(cfg)
	caps := intersectCaps(clientCaps, serverCaps)
	params := alignParams(parseParams(r.Header.Get("X-Resume-Params")))
	// 下行 replay ring 属于服务端资源，容量以服务端配置为准并明确回传。
	params.windowKB = resolveSessionWindow(cfg.SessionWindow)

	// ===== 备用线路（探活）：不 dial 目标、不建业务会话 =====
	//
	// 关键设计：role=backup 的线路只用于证明「这条隧道端到端活着」，
	// 通过 A 层（响应头 X-Resume-Ack） + B 层（HANDSHAKE↔HANDSHAKE-ACK 控制帧）
	// + 周期 KEEPALIVE 探活实现，**绝不拨号目标服务**。
	//
	// 若探活线路也拨号目标，会触发服务端 targetConn 下行泵立即推送 banner
	// DATA 帧，与 B 层握手的 HANDSHAKE-ACK 抢写响应体，客户端读到的首个帧
	// 将是 banner DATA 而非 HANDSHAKE-ACK，导致探活握手失败。因此探活线路
	// 必须跳过目标拨号与会话创建。
	if isBackup {
		flusher, _ := w.(http.Flusher)
		writer := &resumeSessionWriter{w: w, flusher: flusher}
		defer writer.close()

		if r.Header.Get("Content-Type") == "application/grpc" {
			setGRPCTunnelHeaders(w.Header())
		} else {
			setTunnelHeaders(w.Header())
		}
		w.Header().Set("X-Resume-Version", "2")
		w.Header().Set("X-Resume-Caps", caps.String())
		w.Header().Set("X-Resume-Params", params.String())
		w.Header().Set("X-Resume-Ack", "ok")
		w.WriteHeader(http.StatusOK)
		if flusher != nil {
			flusher.Flush()
		}

		// 先完成 B 层握手（证明活性），再只做 KEEPALIVE 存活应答。
		if !datagram {
			if !doServerHandshakeAck(r.Body, writer, params.handshakeAckMs, sessionID) {
				return
			}
		}
		serveBackupKeepaliveOnly(r.Body, writer, params, sessionID)
		return
	}

	// ===== 主线路：校验目标 + 建立/恢复业务会话 =====
	if target == "" || !checkTargetIsAvailable(target, cfg) {
		zlog.Warnf("[%s] 🚫 Resume target rejected: %s", sessionID, target)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	dialTarget := func() (net.Conn, error) {
		return net.DialTimeout(network, target, 10*time.Second)
	}
	sess, isNew, err := globalSessionTable.prepareResumeSession(r, dialTarget, cfg.SessionWindow)
	if err != nil {
		if errors.Is(err, ErrSessionIDRequired) {
			w.Header().Set("X-Resume-Error", resumeErrInvalidParams.String())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		zlog.Errorf("[%s] ❌ Resume 拨号失败: %v", sessionID, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	if isNew {
		zlog.Infof("[%s] 🆕 Resume 新会话建立 | Target: %s (%s, %s)", sessionID, target, network, modeLabel(datagram))
	} else {
		zlog.Infof("[%s] 🔄 Resume 恢复已有会话 | Target: %s (%s)", sessionID, target, modeLabel(datagram))
	}

	clientDownlink := parseResumeDownlink(r)
	sess.mu.Lock()
	serverUplink := sess.uplinkRecv
	sess.mu.Unlock()

	flusher, _ := w.(http.Flusher)
	writer := &resumeSessionWriter{w: w, flusher: flusher}
	defer writer.close() // handler 返回后禁止再写（防 panic）

	// gRPC：resume 帧作为内层数据面（raw resume frames，不做 grpc 二次分帧），
	// 外层仅打 application/grpc 的 Content-Type 标记以取悦 CDN/反代与中间件。
	if r.Header.Get("Content-Type") == "application/grpc" {
		setGRPCTunnelHeaders(w.Header())
	} else {
		setTunnelHeaders(w.Header())
	}
	// ===== A 层确认响应头 =====
	w.Header().Set("X-Resume-Version", "2")
	w.Header().Set("X-Resume-Caps", caps.String())
	w.Header().Set("X-Resume-Params", params.String())
	w.Header().Set("X-Resume-Ack", "ok")
	w.Header().Set("X-Resume-Uplink", strconv.FormatUint(serverUplink, 10))
	w.WriteHeader(http.StatusOK)
	if flusher != nil {
		flusher.Flush()
	}

	// ===== B 层握手 + 下行补发 + 上行帧循环（公共数据面，h2/wt 复用）=====
	// activeWriter 挂载由 serveResumeDataPlane 在 B 层握手完成后负责。
	serveResumeDataPlane(sess, r.Body, writer, params, clientDownlink, sessionID, false, sess.clearActiveWriter)
}
