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
	// The session table decides datagram mode and target from request headers;
	// standard MASQUE clients only carry the target in the URI path, so
	// normalize the classification back into headers for prepareResumeSession.
	r.Header.Set("X-Network", networkUDP)
	if tr.target != "" {
		r.Header.Set("X-Target", tr.target)
	}
	lgDebugf(sessions.lg(), "[%s] -> MASQUE-UDP dispatched to RESUME engine (target=%s)", sessionID, tr.target)
	handleH2StreamResumeServer(w, r, sessionID, tr, cfg, sessions)
}
