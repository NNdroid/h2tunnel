package main

import "net/http"

// =========================================
// gRPC 传输层 adapter
//
// gRPC 传输本身没有独立的流处理 handler：resume/2 帧作为内层数据面（raw
// resume frames，不做 grpc 二次分帧），外层仅打 application/grpc 的
// Content-Type 标记以取悦 CDN/反代与中间件（如 Cloudflare 需启用 gRPC）。
// 因此服务端 gRPC 请求直接转派到 handleH2StreamResumeServer（见 transport_h2.go），
// 本文件只负责 gRPC 特有的响应头。
//
// 数据面流程图：
//   client  ── X-Tunnel-Proto: resume/2 (Content-Type: application/grpc) ──> server
//   server  ── 同 h2 的 resume 数据面（A/B 握手 + ring seq 续传）───────> 目标服务
// =========================================

// setGRPCTunnelHeaders 是 gRPC 分支的变体：Content-Type 必须保持
// application/grpc（resume 帧作为内层数据面，外层仅打 Content-Type 标记，
// 不做 grpc 二次分帧），其余反缓冲头照常施加。
func setGRPCTunnelHeaders(h http.Header) {
	h.Set("Content-Type", "application/grpc")
	h.Set("Cache-Control", "no-store, no-transform")
	h.Set("Pragma", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	h.Set("Content-Encoding", "identity")
}
