package main

import (
	"context"
	"syscall"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// signalContext returns a Context cancelled on SIGINT/SIGTERM. The
// signal-handler goroutine is hard to test reliably without
// disrupting the test runner; pin the synchronous lifecycle here
// (returned ctx must be live initially; manual cancel must drain it).

func TestSignalContext_NotInitiallyDone(t *testing.T) {
	ctx, cancel := signalContext()
	defer cancel()
	select {
	case <-ctx.Done():
		t.Fatal("ctx must NOT be done immediately on construction")
	default:
		// expected — ctx is live
	}
}

func TestSignalContext_ManualCancelDrainsContext(t *testing.T) {
	ctx, cancel := signalContext()
	cancel()
	select {
	case <-ctx.Done():
		// expected
	case <-time.After(100 * time.Millisecond):
		t.Fatal("ctx.Done() did not fire within 100ms after manual cancel")
	}
	// After cancel, Err should be context.Canceled.
	if ctx.Err() != context.Canceled {
		t.Errorf("ctx.Err() after cancel: want context.Canceled, got %v", ctx.Err())
	}
}

// Note: a SIGTERM-triggers-cancel test would race the Go runtime's
// default SIGTERM handler (which kills the process) against
// signal.Notify registration — even with a small sleep, the test is
// flaky and the failure mode is "test process killed mid-run". We
// rely on the cancel() drain test above to exercise the ctx lifecycle
// and trust that signal.Notify is correctly wired.
var _ = syscall.SIGTERM // keep the syscall import for future use

func TestEnvDuration_DefaultParseAndFloor(t *testing.T) {
	t.Setenv("ASP_TEST_DUR", "")
	if d, err := envDuration("ASP_TEST_DUR", 5*time.Minute, 30*time.Second); err != nil || d != 5*time.Minute {
		t.Errorf("unset: %v %v", d, err)
	}
	t.Setenv("ASP_TEST_DUR", " 2m ")
	if d, _ := envDuration("ASP_TEST_DUR", 5*time.Minute, 30*time.Second); d != 2*time.Minute {
		t.Errorf("2m: %v", d)
	}
	t.Setenv("ASP_TEST_DUR", "1s")
	if d, _ := envDuration("ASP_TEST_DUR", 5*time.Minute, 30*time.Second); d != 30*time.Second {
		t.Errorf("below floor must clamp: %v", d)
	}
	t.Setenv("ASP_TEST_DUR", "300")
	if _, err := envDuration("ASP_TEST_DUR", 5*time.Minute, 30*time.Second); err == nil {
		t.Error("a bare number is not a duration")
	}
}

func TestStartAppProfiles_OffByDefaultAndNeedsBrokerURL(t *testing.T) {
	t.Setenv("ASP_ENABLED", "")
	if err := startAppProfiles(context.Background(), nil, logrus.New()); err != nil {
		t.Errorf("disabled must be a no-op: %v", err)
	}
	t.Setenv("ASP_ENABLED", "true")
	t.Setenv("BROKER_URL", "")
	if err := startAppProfiles(context.Background(), nil, logrus.New()); err == nil {
		t.Error("enabled without BROKER_URL must fail loudly")
	}
}
