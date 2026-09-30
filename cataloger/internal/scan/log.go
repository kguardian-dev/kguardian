package scan

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/anchore/go-logger"
	"github.com/anchore/syft/syft"
)

// NoSpaceSeen is set when any Syft log line reports ENOSPC/EFBIG. Syft's
// catalogers log and skip an archive they could not unpack, so a full temp
// dir would otherwise silently drop packages (fat-jar contents).
var NoSpaceSeen atomic.Bool

// maxLogBytes bounds what the child writes to stderr.
const maxLogBytes = 256 * 1024

type syftLogger struct {
	mu      *sync.Mutex
	w       io.Writer
	written *int
	verbose bool
	fields  string
	// fieldHit: a WithFields value was an out-of-space error.
	fieldHit bool
}

// InstallLogger routes Syft's logs to w (warnings and errors; everything
// with verbose), bounded, and watches every line up to debug for
// out-of-space errors.
func InstallLogger(w io.Writer, verbose bool) {
	n := 0
	syft.SetLogger(&syftLogger{mu: &sync.Mutex{}, w: w, written: &n, verbose: verbose})
}

func (l *syftLogger) log(level string, show bool, msg string) {
	if l.fieldHit {
		NoSpaceSeen.Store(true)
		show = true
	}
	if strings.Contains(msg, "no space left on device") || strings.Contains(msg, "file too large") ||
		strings.Contains(msg, "disk quota exceeded") || strings.Contains(msg, "short write") {
		NoSpaceSeen.Store(true)
		show = true
	}
	if !show && !l.verbose {
		return
	}
	line := fmt.Sprintf("syft %s: %s%s\n", level, msg, l.fields)
	l.mu.Lock()
	defer l.mu.Unlock()
	if *l.written+len(line) > maxLogBytes {
		return
	}
	*l.written += len(line)
	_, _ = io.WriteString(l.w, line)
}

func (l *syftLogger) Errorf(f string, a ...any) { l.log("error", true, fmt.Sprintf(f, a...)) }
func (l *syftLogger) Error(a ...any)            { l.log("error", true, fmt.Sprint(a...)) }
func (l *syftLogger) Warnf(f string, a ...any)  { l.log("warn", true, fmt.Sprintf(f, a...)) }
func (l *syftLogger) Warn(a ...any)             { l.log("warn", true, fmt.Sprint(a...)) }
func (l *syftLogger) Infof(f string, a ...any)  { l.quiet("info", f, a) }
func (l *syftLogger) Info(a ...any)             { l.quiet("info", "", a) }
func (l *syftLogger) Debugf(f string, a ...any) { l.quiet("debug", f, a) }
func (l *syftLogger) Debug(a ...any)            { l.quiet("debug", "", a) }
func (l *syftLogger) Tracef(f string, a ...any) { l.quiet("trace", f, a) }
func (l *syftLogger) Trace(a ...any)            { l.quiet("trace", "", a) }

// quiet handles the levels not shown by default. Syft reports a failed
// archive extraction (the temp budget hit) as low as trace, so each error
// argument is checked; only a hit, or verbose mode, pays for formatting.
func (l *syftLogger) quiet(level, f string, a []any) {
	hit := l.fieldHit
	for _, v := range a {
		if err, ok := v.(error); ok && IsNoSpace(err) {
			hit = true
			break
		}
	}
	if hit {
		NoSpaceSeen.Store(true)
	} else if !l.verbose {
		return
	}
	msg := fmt.Sprint(a...)
	if f != "" {
		msg = fmt.Sprintf(f, a...)
	}
	l.log(level, hit, msg)
}

func (l *syftLogger) WithFields(fields ...any) logger.MessageLogger {
	return l.with(fields)
}

func (l *syftLogger) Nested(fields ...any) logger.Logger { return l.with(fields) }

func (l *syftLogger) with(fields []any) *syftLogger {
	c := *l
	var b strings.Builder
	b.WriteString(l.fields)
	for i := 0; i+1 < len(fields); i += 2 {
		if err, ok := fields[i+1].(error); ok && IsNoSpace(err) {
			c.fieldHit = true
		}
		fmt.Fprintf(&b, " %v=%v", fields[i], fields[i+1])
	}
	c.fields = b.String()
	return &c
}
