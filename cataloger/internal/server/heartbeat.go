package server

import (
	"os"
	"path/filepath"
	"strings"
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

// WriteHeartbeat records why the worker is degraded, refreshing the
// file's mtime.
func WriteHeartbeat(dir, why string) error {
	tmp, err := os.CreateTemp(dir, heartbeatName+".tmp-*")
	if err != nil {
		return err
	}
	_, werr := tmp.WriteString(why + "\n")
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
// within maxAge, and why it is degraded.
func HeartbeatFresh(dir string, maxAge time.Duration) (string, bool) {
	p := filepath.Join(dir, heartbeatName)
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() || time.Since(fi.ModTime()) > maxAge {
		return "", false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}
