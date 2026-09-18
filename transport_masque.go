package h2tunnel

import (
	"net/http"
)

// =========================================
// MASQUE (RFC 9298 CONNECT-UDP / CONNECT-TCP) transport adapter
//
// Authentication and transport/network policy are already done centrally in
// routeTunnelRequest; these two handlers only enforce target admission and
// dispatch to the resume/2 engine (a CONNECT stream is fundamentally a byte
// pipe). Target resolution (X-Target → URI template → X-Dst) is done once by
// classifyTunnelRequest.
// =========================================

// ---> server-side MASQUE-TCP
func handleMasqueTCPServer(w http.ResponseWriter, r *http.Request, sessionID string, tr tunnelRequest, cfg serverConfig, sessions *sessionTable) {
	if !targetAllowedByRuntime(cfg, tr.target) {
		lgWarnf(sessions.lg(), "[%s] 🚫 Access denied for target address: %s", sessionID, tr.target)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	// The session table reads the network and target back out of the request
	// headers, and the network decides whether the session is datagram-framed.
	// A CONNECT-TCP stream is byte-oriented regardless of what the client wrote
	// in X-Network, so pin both to the classification here; otherwise a
	// "X-Network: udp" CONNECT-TCP would create a UDP-framed session over a TCP
	// dial and lose packet boundaries on both sides.
	masqueSessionHeaders(r, tr)
	lgDebugf(sessions.lg(), "[%s] -> MASQUE-TCP dispatched to RESUME engine (target=%s)", sessionID, tr.target)
	handleH2StreamResumeServer(w, r, sessionID, tr, cfg, sessions)
}

// ---> server-side MASQUE-UDP
func handleMasqueUDPServer(w http.ResponseWriter, r *http.Request, sessionID string, tr tunnelRequest, cfg serverConfig, sessions *sessionTable) {
	if !targetAllowedByRuntime(cfg, tr.target) {
		lgWarnf(sessions.lg(), "[%s] 🚫 MASQUE-UDP target rejected: %q (path=%s)", sessionID, tr.target, r.URL.Path)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	// Standard MASQUE clients only carry the target in the URI path, so
	// normalize the classification back into the headers the session table reads.
	masqueSessionHeaders(r, tr)
	lgDebugf(sessions.lg(), "[%s] -> MASQUE-UDP dispatched to RESUME engine (target=%s)", sessionID, tr.target)
	handleH2StreamResumeServer(w, r, sessionID, tr, cfg, sessions)
}

// masqueSessionHeaders pins the request headers the session table reads back for
// a MASQUE request: the classified network and target, never the client's own
// values. prepareResumeSession decides datagram framing from X-Network, so the
// classification has to win here or a peer could pick the framing of its
// sessions.
func masqueSessionHeaders(r *http.Request, tr tunnelRequest) {
	r.Header.Set("X-Network", tr.network)
	r.Header.Set("X-Target", tr.target)
}
