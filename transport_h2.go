package h2tunnel

import (
	"errors"
	"net"
	"net/http"
	"strconv"
)

// =========================================
// h2 / h2c transport adapter — server-side resume stream handling
//
// handleH2StreamResumeServer is the server-side resume handler for h2 (HTTP/2
// POST stream), and is also reused by grpc and masque-tcp / masque-udp (those
// transports dispatch straight here after auth; resume/2 is the only data plane).
// h3 runs over QUIC, but its application-layer handler is identical to h2's.
//
// Protocol flow (v2, with handshake negotiation):
//  1. Client request carries X-Tunnel-Proto: resume/2, X-Session-ID,
//     X-Resume-Version/Caps/Params, X-Resume-Downlink
//  2. Server validates version (v2 only, non-2 → 426), capability intersection, parameter alignment
//  3. Server looks up/creates the session; response carries X-Resume-Version/Caps/Params/
//     X-Resume-Ack:ok + X-Resume-Uplink
//  4. stream mode: wait for the client HANDSHAKE control frame → reply HANDSHAKE-ACK (layer-B confirmation)
//  5. role=backup: skip the business loop, do KEEPALIVE↔KEEPALIVE-ACK liveness instead
//  6. primary lane: replay the downlink gap → enter the frame loop reading uplink
//
// =========================================
// handleBrutalExchangeServer answers a _BrutalBwExchange request: it negotiates
// and returns the decision, without dialing a target or creating a session.
//
// It still completes the resume/2 handshake (layer A ack + layer B
// HANDSHAKE<->HANDSHAKE-ACK) so the client can drive it through the same
// executor as a business tunnel — the sentinel is then just a tunnel whose
// server side never dials. X-Brutal-Params was already written before dispatch
// (routeTunnelRequest), after authentication.
func handleBrutalExchangeServer(w http.ResponseWriter, r *http.Request, sessionID string, cfg serverConfig, sessions *sessionTable) {
	if !cfg.Brutal.enabled {
		lgWarnf(sessions.lg(), "[%s] 🚫 Brutal bandwidth exchange requested but brutal is disabled", sessionID)
		http.Error(w, "brutal bandwidth exchange disabled", http.StatusServiceUnavailable)
		return
	}
	if r.Header.Get("X-Tunnel-Proto") != resumeFrameTypeResume {
		w.Header().Set("X-Resume-Error", resumeErrVersionUnsupported.String())
		http.Error(w, "resume/2 required", http.StatusUpgradeRequired)
		return
	}

	flusher, _ := w.(http.Flusher)
	writer := &resumeSessionWriter{w: w, flusher: flusher, padding: cfg.Padding}
	defer writer.close()

	w.Header().Set("X-Resume-Version", "2")
	w.Header().Set("X-Resume-Ack", "ok")
	w.WriteHeader(http.StatusOK)
	if flusher != nil {
		flusher.Flush()
	}

	// Complete layer B so the client's executor is satisfied, then close: there
	// is no target to dial and no session to keep alive.
	if !doServerHandshakeAck(r.Body, writer, defaultHandshakeAckMs, sessionID, sessions.lg()) {
		return
	}
	_ = writer.writeEnd()
}

func handleH2StreamResumeServer(w http.ResponseWriter, r *http.Request, sessionID string, tr tunnelRequest, cfg serverConfig, sessions *sessionTable) {
	// Version is a hard constraint: non resume/2 is rejected outright, no fallback (v1 removed).
	if r.Header.Get("X-Tunnel-Proto") != resumeFrameTypeResume {
		w.Header().Set("X-Resume-Error", resumeErrVersionUnsupported.String())
		http.Error(w, "resume/2 required", http.StatusUpgradeRequired)
		return
	}

	network, target := tr.network, tr.target
	datagram := network == "udp"
	isBackup := r.Header.Get("X-Resume-Role") == "backup"

	// ===== Layer-A handshake: version / capability / parameter negotiation =====
	clientVersion := parseHeaderVersion(r.Header.Get("X-Resume-Version"))
	negotiated := negotiateVersion(clientVersion, 2)
	if negotiated == 0 {
		w.Header().Set("X-Resume-Error", resumeErrVersionUnsupported.String())
		lgWarnf(sessions.lg(), "[%s] ❌ version negotiation failed: client=%d server=2", sessionID, clientVersion)
		http.Error(w, "resume version unsupported", http.StatusUpgradeRequired)
		return
	}
	clientCaps := parseCaps(r.Header.Get("X-Resume-Caps"))
	serverCaps := serverCapabilities(cfg)
	caps := intersectCaps(clientCaps, serverCaps)
	params := alignParams(parseParams(r.Header.Get("X-Resume-Params")))
	// The downlink replay ring is a server resource; its size follows the server config and is echoed back explicitly.
	params.windowKB = resolveSessionWindow(cfg.SessionWindow)

	// ===== Backup lane (probe): never dials the target, never creates a business session =====
	//
	// Key design: a role=backup lane exists only to prove "this tunnel is alive
	// end to end", via layer A (response header X-Resume-Ack) + layer B
	// (HANDSHAKE↔HANDSHAKE-ACK control frames) + periodic KEEPALIVE probes — it
	// **never dials the target service**.
	//
	// If a probe lane also dialed the target, the server's targetConn downlink pump
	// would immediately push a banner DATA frame, racing HANDSHAKE-ACK for the
	// response body; the client's first frame would be banner DATA instead of
	// HANDSHAKE-ACK, failing the probe handshake. So probe lanes must skip target
	// dialing and session creation.
	if isBackup {
		flusher, _ := w.(http.Flusher)
		writer := &resumeSessionWriter{w: w, flusher: flusher, padding: cfg.Padding}
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

		// Complete the layer-B handshake first (prove liveness), then do only KEEPALIVE liveness.
		if !datagram {
			if !doServerHandshakeAck(r.Body, writer, params.handshakeAckMs, sessionID, sessions.lg()) {
				return
			}
		}
		serveBackupKeepaliveOnly(r.Body, writer, params, sessionID, sessions.lg())
		return
	}

	// ===== Primary lane: validate target + create/resume the business session =====
	if !targetAllowedByRuntime(cfg, target) {
		lgWarnf(sessions.lg(), "[%s] 🚫 Resume target rejected: %s", sessionID, target)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	dialTarget := func() (net.Conn, error) {
		return dialTargetForRequest(r, cfg, network, target)
	}
	sess, isNew, err := sessions.prepareResumeSession(r, dialTarget, cfg.SessionWindow)
	if err != nil {
		if errors.Is(err, errSessionIDRequired) {
			w.Header().Set("X-Resume-Error", resumeErrInvalidParams.String())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		lgErrorf(sessions.lg(), "[%s] ❌ Resume dial failed: %v", sessionID, err)
		if cfg.events != nil && errors.Is(err, ErrForbidden) {
			cfg.events.dispatch(ServerEvent{
				Kind:       ServerEventTargetDenied,
				SessionID:  sessionID,
				Target:     target,
				Network:    Network(network),
				Transport:  TransportH2,
				Principal:  requestState(r).principal,
				RemoteAddr: clientIP(r),
				Reason:     "dialer denied target",
				Err:        err,
			})
		}
		writeTargetError(w, err)
		return
	}
	if cfg.stats != nil {
		if isNew {
			cfg.stats.SessionsCreated.Add(1)
		} else {
			cfg.stats.SessionsResumed.Add(1)
		}
	}
	if cfg.events != nil {
		kind := ServerEventSessionOpened
		if !isNew {
			kind = ServerEventSessionResumed
		}
		cfg.events.dispatch(ServerEvent{
			Kind:       kind,
			SessionID:  sessionID,
			Target:     target,
			Network:    Network(network),
			Transport:  tr.transport,
			Principal:  requestState(r).principal,
			RemoteAddr: clientIP(r),
		})
	}
	if isNew {
		lgInfof(sessions.lg(), "[%s] 🆕 new resume session established | Target: %s (%s, %s)", sessionID, target, network, modeLabel(datagram))
	} else {
		lgInfof(sessions.lg(), "[%s] 🔄 resumed existing session | Target: %s (%s)", sessionID, target, modeLabel(datagram))
	}

	clientDownlink := parseResumeDownlink(r)
	sess.mu.Lock()
	serverUplink := sess.uplinkRecv
	sess.mu.Unlock()

	flusher, _ := w.(http.Flusher)
	writer := &resumeSessionWriter{w: w, flusher: flusher, padding: cfg.Padding}
	defer writer.close() // disallow further writes after the handler returns (panic safety)

	// gRPC: resume frames are the inner data plane (raw resume frames, no
	// secondary gRPC framing); the outer layer only tags Content-Type
	// application/grpc to keep CDNs / reverse proxies and middleboxes happy.
	if r.Header.Get("Content-Type") == "application/grpc" {
		setGRPCTunnelHeaders(w.Header())
	} else {
		setTunnelHeaders(w.Header())
	}
	// ===== Layer-A confirmation response headers =====
	w.Header().Set("X-Resume-Version", "2")
	w.Header().Set("X-Resume-Caps", caps.String())
	w.Header().Set("X-Resume-Params", params.String())
	w.Header().Set("X-Resume-Ack", "ok")
	w.Header().Set("X-Resume-Uplink", strconv.FormatUint(serverUplink, 10))
	w.WriteHeader(http.StatusOK)
	if flusher != nil {
		flusher.Flush()
	}

	// ===== Layer-B handshake + downlink replay + uplink frame loop (shared data plane, reused by h2/wt) =====
	// activeWriter installation is serveResumeDataPlane's responsibility, after the layer-B handshake completes.
	serveResumeDataPlane(sess, r.Body, writer, params, clientDownlink, sessionID, false, sess.clearActiveWriter)
}
