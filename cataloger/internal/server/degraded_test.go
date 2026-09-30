package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kguardian-dev/kguardian/cataloger/internal/protocol"
)

// A failing capability probe (here: a child binary that does not exist)
// leaves the worker up and degraded instead of returning an error: pings
// get worker_unavailable, scans are refused, nothing is started.
func TestProbeFailureDegradesInsteadOfExiting(t *testing.T) {
	cfg := Config{
		AllowedPeerUIDs: []uint32{uint32(os.Getuid())},
		MemoryLimit:     64 << 20, TmpLimit: 1 << 20, TmpDir: worldDir(t), Version: "test",
		ChildPath: "/nonexistent/kguardian-cataloger",
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("an environment problem must not be fatal: %v", err)
	}
	if s.Why() == "" {
		t.Fatal("not marked unavailable")
	}
	sock := filepath.Join(worldDir(t), "worker.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve(ctx, l) }()
	e := &env{srv: s, sock: sock}

	ping, err := e.controller(t, &protocol.Request{ProtocolVersion: 1, Op: protocol.OpPing, ScanID: "p"}, -1)
	if err != nil || ping.Status != protocol.StatusFailed || ping.Reason != protocol.ReasonWorkerUnavailable ||
		ping.ScanID != "p" || ping.Message == "" {
		t.Fatalf("ping: %+v %v", ping, err)
	}
	start := time.Now()
	scan, err := e.controller(t, req("refused"), rootFD(t, alpineRoot(t, 1)))
	if err != nil || scan.Reason != protocol.ReasonWorkerUnavailable || len(scan.Components) != 0 {
		t.Fatalf("scan: %+v %v", scan, err)
	}
	if time.Since(start) > 5*time.Second || s.busy.Load() {
		t.Error("a degraded worker started a scan")
	}
}

func TestUnavailableServer(t *testing.T) {
	s := Unavailable(Config{}, context.DeadlineExceeded)
	if s.Why() != context.DeadlineExceeded.Error() {
		t.Errorf("why %q", s.Why())
	}
}

func TestHeartbeat(t *testing.T) {
	dir := t.TempDir()
	if _, ok := HeartbeatFresh(dir, time.Minute); ok {
		t.Fatal("fresh without a heartbeat")
	}
	if err := WriteHeartbeat(dir, "cannot create socket"); err != nil {
		t.Fatal(err)
	}
	if why, ok := HeartbeatFresh(dir, time.Minute); !ok || why != "cannot create socket" {
		t.Fatalf("%q %v", why, ok)
	}
	if _, ok := HeartbeatFresh(dir, -time.Second); ok {
		t.Error("a stale heartbeat counted as alive")
	}
	RemoveHeartbeat(dir)
	if _, ok := HeartbeatFresh(dir, time.Minute); ok {
		t.Error("still fresh after removal")
	}
}
