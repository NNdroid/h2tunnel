package h2tunnel_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NNdroid/h2tunnel"
)

// TestPprofHandler verifies the handler exposes the standard pprof index page and can be mounted and reused.
func TestPprofHandler(t *testing.T) {
	handler := h2tunnel.PprofHandler()
	srv := httptest.NewServer(handler)
	defer srv.Close()

	for _, path := range []string{"/debug/pprof/", "/debug/pprof/goroutine?debug=1"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s status %d", path, resp.StatusCode)
		}
	}
	resp, err := http.Get(srv.URL + "/debug/pprof/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	if page := string(body[:n]); !strings.Contains(page, "goroutine profile") && !strings.Contains(page, "Types of profiles") {
		t.Fatalf("index page unexpected: %s", page[:200])
	}
}
