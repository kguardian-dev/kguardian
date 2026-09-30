package scan

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func newTestLogger(w io.Writer) *syftLogger {
	n := 0
	return &syftLogger{mu: &sync.Mutex{}, w: w, written: &n}
}

// Syft reports a failed archive copy in several shapes, at any level down
// to trace; each must mark the scan as out of temp space.
func TestLoggerSeesNoSpace(t *testing.T) {
	efbig := &os.PathError{Op: "write", Path: "/tmp/x", Err: unix.EFBIG}
	for name, emit := range map[string]func(l *syftLogger){
		"trace field": func(l *syftLogger) {
			l.WithFields("error", fmt.Errorf("copy: %w", efbig)).Trace("cataloger returned errors")
		},
		"debug arg":     func(l *syftLogger) { l.Debugf("unable to extract: %v", errors.Join(errors.New("x"), efbig)) },
		"nested field":  func(l *syftLogger) { l.Nested("error", unix.ENOSPC).Tracef("failed") },
		"short write":   func(l *syftLogger) { l.Trace(fmt.Errorf("copy: %w", io.ErrShortWrite)) },
		"warn text":     func(l *syftLogger) { l.Warnf("write %s: no space left on device", "/tmp/y") },
		"error wrapped": func(l *syftLogger) { l.Error(fmt.Errorf("a: %w", fmt.Errorf("b: %w", unix.EDQUOT))) },
	} {
		NoSpaceSeen.Store(false)
		var out strings.Builder
		emit(newTestLogger(&out))
		if !NoSpaceSeen.Load() {
			t.Errorf("%s: not detected", name)
		}
		if out.Len() == 0 {
			t.Errorf("%s: not logged", name)
		}
	}
	NoSpaceSeen.Store(false)
	var out strings.Builder
	l := newTestLogger(&out)
	l.WithFields("error", errors.New("permission denied")).Trace("x")
	l.Debugf("parsed %d files", 3)
	if NoSpaceSeen.Load() || out.Len() != 0 {
		t.Errorf("false positive: %q", out.String())
	}
}
