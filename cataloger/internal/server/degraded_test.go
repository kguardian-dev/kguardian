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
	if _, _, ok := HeartbeatFresh(dir, time.Minute); ok {
		t.Fatal("fresh without a heartbeat")
	}
	since := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := WriteHeartbeat(dir, "cannot create socket", since); err != nil {
		t.Fatal(err)
	}
	if why, got, ok := HeartbeatFresh(dir, time.Minute); !ok || why != "cannot create socket" || !got.Equal(since) {
		t.Fatalf("%q %v %v", why, got, ok)
	}
	if _, _, ok := HeartbeatFresh(dir, -time.Second); ok {
		t.Error("a stale heartbeat counted as alive")
	}
	// Owned by another uid (a scan child could write the shared temp
	// dir): not a heartbeat of ours.
	if os.Geteuid() == 0 {
		if err := os.Chown(filepath.Join(dir, heartbeatName), 4242, 4242); err != nil {
			t.Fatal(err)
		}
		if _, _, ok := HeartbeatFresh(dir, time.Minute); ok {
			t.Error("a heartbeat owned by another uid counted")
		}
	}
	RemoveHeartbeat(dir)
	if _, _, ok := HeartbeatFresh(dir, time.Minute); ok {
		t.Error("still fresh after removal")
	}
}

// A degraded worker recovers by itself once the failed step succeeds:
// here the child binary appears after startup, and the next retry leaves
// degraded mode without a restart.
func TestDegradedWorkerRecovers(t *testing.T) {
	bin := filepath.Join(worldDir(t), "later.test")
	cfg := Config{
		AllowedPeerUIDs: []uint32{uint32(os.Getuid())},
		MemoryLimit:     512 << 20, TmpLimit: 64 << 20, TmpDir: worldDir(t), Version: "test",
		ChildPath: bin, ChildArgs: []string{"-test.run=^$"}, ChildEnv: []string{"KG_SERVER_TEST_CHILD=1"},
		RetryInitial: 50 * time.Millisecond, RetryMax: 200 * time.Millisecond,
	}
	_ = os.Chmod(cfg.TmpDir, 0o1777)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s, err := New(ctx, cfg)
	if err != nil || s.Why() == "" {
		t.Fatalf("expected a degraded start: %v %q", err, s.Why())
	}
	sock := filepath.Join(worldDir(t), "worker.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve(ctx, l) }()
	e := &env{srv: s, sock: sock}
	ping := &protocol.Request{ProtocolVersion: 1, Op: protocol.OpPing, ScanID: "p"}
	if r, _ := e.controller(t, ping, -1); r == nil || r.Reason != protocol.ReasonWorkerUnavailable || r.Stats.DegradedMS < 0 {
		t.Fatalf("before: %+v", r)
	}
	// The binary appears: the next retry succeeds.
	src, err := os.ReadFile(childBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, src, 0o755); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for s.Why() != "" {
		if time.Now().After(deadline) {
			t.Fatalf("still degraded: %s", s.Why())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if r, err := e.controller(t, ping, -1); err != nil || r.Status != protocol.StatusOK {
		t.Fatalf("after recovery, ping: %+v %v", r, err)
	}
	if r, err := e.controller(t, req("recovered"), rootFD(t, alpineRoot(t, 2))); err != nil || r.Status != protocol.StatusOK {
		t.Fatalf("after recovery, scan: %+v %v", r, err)
	}
}

func TestRetryBackoff(t *testing.T) {
	d := DefaultRetryInitial
	var got []time.Duration
	for range 7 {
		got = append(got, d)
		d = nextRetry(d, DefaultRetryMax)
	}
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 10 * time.Minute, 10 * time.Minute}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("backoff %v, want %v", got, want)
		}
	}
}
