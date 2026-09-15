package h2tunnel

import "net/http"

// =========================================
// gRPC transport adapter
//
// The gRPC transport has no stream handler of its own: resume/2 frames are the
// inner data plane (raw resume frames, no secondary gRPC framing), and the outer
// layer only tags Content-Type application/grpc to keep CDNs / reverse proxies
// and middleboxes happy (e.g. Cloudflare needs gRPC enabled). So server-side
// gRPC requests are dispatched straight to handleH2StreamResumeServer (see
// transport_h2.go), and this file only supplies the gRPC-specific response headers.
//
// Data-plane flow:
//   client  ── X-Tunnel-Proto: resume/2 (Content-Type: application/grpc) ──> server
//   server  ── same resume data plane as h2 (A/B handshake + ring seq replay) ──> target service
// =========================================

// setGRPCTunnelHeaders is the gRPC-branch variant: Content-Type must stay
// application/grpc (resume frames are the inner data plane; the outer layer only
// tags Content-Type, no secondary gRPC framing), while the other anti-buffering
// headers are applied as usual.
func setGRPCTunnelHeaders(h http.Header) {
	h.Set("Content-Type", "application/grpc")
	h.Set("Cache-Control", "no-store, no-transform")
	h.Set("Pragma", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	h.Set("Content-Encoding", "identity")
}
