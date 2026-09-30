package server

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// A degraded parent that cannot even create its socket (a socket directory
// owned by another uid, say) has nothing for the chart's liveness probe
// (`kguardian-cataloger ping`) to connect to. It keeps this file fresh
// instead, so the probe can tell "alive but unusable" from "dead" and the
// container is not restarted into the same error. The Controller never
// reads it: without a usable socket it reports worker_unavailable anyway.
const heartbeatName = "kguardian-cataloger.degraded"

// HeartbeatInterval is how often a degraded parent refreshes the file;
// HeartbeatMaxAge is how old it may be and still count as alive.
const (
	HeartbeatInterval = 30 * time.Second
	HeartbeatMaxAge   = 4 * HeartbeatInterval
)

// WriteHeartbeat records since when and why the worker is degraded,
// refreshing the file's mtime.
func WriteHeartbeat(dir, why string, since time.Time) error {
	tmp, err := os.CreateTemp(dir, heartbeatName+".tmp-*")
	if err != nil {
		return err
	}
	_, werr := fmt.Fprintf(tmp, "%d\n%s\n", since.Unix(), why)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp.Name())
		if werr != nil {
			return werr
		}
		return cerr
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, heartbeatName))
}

// RemoveHeartbeat clears the file once the worker is serving.
func RemoveHeartbeat(dir string) { _ = os.Remove(filepath.Join(dir, heartbeatName)) }

// HeartbeatFresh reports whether a degraded parent refreshed the file
// within maxAge, why it is degraded and since when. The file must be a
// regular file owned by this process's effective uid: the temp dir is
// shared with the scan children (another uid), which must not be able to
// fake a live worker.
func HeartbeatFresh(dir string, maxAge time.Duration) (why string, since time.Time, ok bool) {
	p := filepath.Join(dir, heartbeatName)
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() || time.Since(fi.ModTime()) > maxAge {
		return "", time.Time{}, false
	}
	st, isStat := fi.Sys().(*syscall.Stat_t)
	if !isStat || int(st.Uid) != os.Geteuid() {
		return "", time.Time{}, false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", time.Time{}, false
	}
	first, rest, _ := strings.Cut(string(b), "\n")
	secs, err := strconv.ParseInt(strings.TrimSpace(first), 10, 64)
	if err != nil {
		return "", time.Time{}, false
	}
	return strings.TrimSpace(rest), time.Unix(secs, 0), true
}
