package main

import (
	"context"
	"syscall"
	"testing"
	"time"
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
