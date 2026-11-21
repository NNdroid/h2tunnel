package h2tunnel

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Probe (backup) streams bypass the session table's own caps — no dial, no
// business session — so the per-principal probe quota is the only bound on
// their goroutine + frame-buffer cost.
func TestProbeStreamQuotaPerPrincipal(t *testing.T) {
	table := &sessionTable{}
	for i := 0; i < maxProbeStreamsPerPrincipal; i++ {
		if !table.acquireProbeStream("token") {
			t.Fatalf("acquire %d/%d rejected", i+1, maxProbeStreamsPerPrincipal)
		}
	}
	if table.acquireProbeStream("token") {
		t.Fatal("acquire beyond the quota must be refused")
	}
	if !table.acquireProbeStream("other") {
		t.Fatal("a different principal must have its own budget")
	}
	table.releaseProbeStream("token")
	if !table.acquireProbeStream("token") {
		t.Fatal("a released slot must be reacquirable")
	}
	// Double release must not push the counter negative (releasing an unknown
	// principal is a no-op, so a deleted entry stays deleted).
	table.releaseProbeStream("other")
	table.releaseProbeStream("other")
	if !table.acquireProbeStream("other") {
		t.Fatal("double release must not corrupt the counter")
	}
	if table.probeStreams["other"] != 1 {
		t.Fatalf("other's counter = %d, want 1", table.probeStreams["other"])
	}
}

// The keepalive ceiling pins the server's backup-lane hold time (3× it); it is
// deliberately aligned with the heartbeat ceiling so both idle knobs cap at the
// same order of magnitude.
func TestKeepaliveCeilingAlignsWithHeartbeat(t *testing.T) {
	if maxKeepaliveSec != 300 {
		t.Fatalf("maxKeepaliveSec = %d, want 300 (aligned with the heartbeat ceiling; a backup lane holds for 3× this)", maxKeepaliveSec)
	}
	if got := resolveKeepaliveSec(maxKeepaliveSec); got != maxKeepaliveSec {
		t.Fatalf("resolveKeepaliveSec(%d) = %d, want the ceiling itself", maxKeepaliveSec, got)
	}
	if got := resolveKeepaliveSec(maxKeepaliveSec + 1); got != defaultKeepaliveSec {
		t.Fatalf("resolveKeepaliveSec(above ceiling) = %d, want the default", got)
	}
	_, err := NewClient(ClientOptions{
		Endpoint: "http://127.0.0.1:1",
		Tuning:   ClientTuning{KeepaliveInterval: (maxKeepaliveSec + 1) * time.Second},
	})
	if err == nil || !strings.Contains(err.Error(), "KeepaliveInterval") {
		t.Fatalf("keepalive above the ceiling must be rejected at NewClient: %v", err)
	}
}

// Standby connections are full backup lanes: each holds a probe stream on the
// server for up to 3× the keepalive interval, so the client cap mirrors the
// server's per-principal probe quota.
func TestStandbyConnectionsCap(t *testing.T) {
	_, err := NewClient(ClientOptions{
		Endpoint: "http://127.0.0.1:1",
		Tuning:   ClientTuning{StandbyConnections: maxStandbyConnections + 1},
	})
	if err == nil || !strings.Contains(err.Error(), fmt.Sprint(maxStandbyConnections)) {
		t.Fatalf("standby above the cap must be rejected: %v", err)
	}
	if _, err := NewClient(ClientOptions{
		Endpoint: "http://127.0.0.1:1",
		Tuning:   ClientTuning{StandbyConnections: maxStandbyConnections},
	}); err != nil {
		t.Fatalf("standby at the cap must be accepted: %v", err)
	}
}
