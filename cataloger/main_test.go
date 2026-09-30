package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kguardian-dev/kguardian/cataloger/internal/server"
)

// The CLI ping is the chart's liveness probe: it must pass while the
// process is alive, degraded included, and fail when nothing is there.
func TestPingCLI(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "sock", "worker.sock")
	var stderr strings.Builder

	// Nothing listening, no heartbeat: dead.
	if code := ping(sock, dir, time.Hour, &stderr); code != 1 {
		t.Errorf("no worker: exit %d", code)
	}
	// No socket but a fresh heartbeat (cannot create the socket): alive.
	if err := server.WriteHeartbeat(dir, "cannot create socket", time.Now()); err != nil {
		t.Fatal(err)
	}
	if code := ping(sock, dir, time.Hour, &stderr); code != 0 {
		t.Errorf("heartbeat: exit %d (%s)", code, stderr.String())
	}
	server.RemoveHeartbeat(dir)

	// A degraded worker answering worker_unavailable: alive.
	s := server.Unavailable(server.Config{AllowedPeerUIDs: []uint32{uint32(os.Getuid())}}, errors.New("capability probe failed"))
	l, err := server.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Serve(ctx, l) }()
	stderr.Reset()
	if code := ping(sock, dir, time.Hour, &stderr); code != 0 || !strings.Contains(stderr.String(), "capability probe failed") {
		t.Errorf("degraded worker: exit %d (%s)", code, stderr.String())
	}
}

// Degraded for longer than the bound, ping fails so the kubelet restarts
// the container: through a worker_unavailable answer and through the
// heartbeat alike.
func TestPingCLIFailsWhenDegradedTooLong(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "sock", "worker.sock")
	var stderr strings.Builder

	if err := server.WriteHeartbeat(dir, "cannot create socket", time.Now().Add(-7*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if code := ping(sock, dir, 6*time.Hour, &stderr); code != 1 {
		t.Errorf("heartbeat degraded 7h, bound 6h: exit %d", code)
	}
	if code := ping(sock, dir, 8*time.Hour, &stderr); code != 0 {
		t.Errorf("heartbeat degraded 7h, bound 8h: exit %d", code)
	}
	server.RemoveHeartbeat(dir)

	s := server.Unavailable(server.Config{AllowedPeerUIDs: []uint32{uint32(os.Getuid())}}, errors.New("probe failed"))
	l, err := server.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Serve(ctx, l) }()
	time.Sleep(20 * time.Millisecond)
	if code := ping(sock, dir, time.Millisecond, &stderr); code != 1 {
		t.Errorf("degraded past a 1 ms bound: exit %d", code)
	}
	if code := ping(sock, dir, time.Hour, &stderr); code != 0 {
		t.Errorf("degraded within the bound: exit %d", code)
	}
	var out strings.Builder
	if code := run([]string{"ping"}, func(k string) string {
		if k == "CATALOG_MAX_DEGRADED" {
			return "soon"
		}
		return ""
	}, &out, &out); code != 2 {
		t.Errorf("a bad CATALOG_MAX_DEGRADED: exit %d", code)
	}
}

func TestConfigErrorsStayFatal(t *testing.T) {
	var stderr strings.Builder
	getenv := func(k string) string {
		if k == "CATALOG_MEMORY_LIMIT" {
			return "lots"
		}
		return ""
	}
	if code := run([]string{"serve"}, getenv, os.Stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "CATALOG_MEMORY_LIMIT") {
		t.Errorf("a broken configuration must exit: %d %s", code, stderr.String())
	}
}
