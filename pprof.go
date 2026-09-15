package h2tunnel

// =========================================
// Runtime performance profiling (pprof)
//
// The library itself binds no management port — the embedder decides where to
// mount the handler on their own admin server (auth, TLS, bind address all under
// the host's control). The CLI enables it through its `pprof` config key.
//
// Collecting and flamegraphs:
//   curl -o cpu.pprof 'http://127.0.0.1:6060/debug/pprof/profile?seconds=30'
//   go tool pprof -http=:8080 cpu.pprof        # interactive flamegraph
//   go tool pprof -svg cpu.pprof > cpu.svg     # requires graphviz
// =========================================

import (
	"net/http"
	"net/http/pprof"
)

// PprofHandler returns a handler exposing the standard net/http/pprof endpoints
// (Go runtime CPU/heap/goroutine/block/mutex profiles). Zero configuration: it
// is safe to reuse with no arguments.
//
// Note: these endpoints can dump process memory and goroutine stacks — expose
// them only on a trusted network surface (an admin port, a localhost reverse
// proxy, or behind authentication).
func PprofHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}
