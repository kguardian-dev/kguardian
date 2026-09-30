// kguardian-cataloger: the node SBOM worker. The Controller opens a
// running container's root filesystem and passes it here as a directory
// fd over a Unix socket (PROTOCOL.md); this turns it into a package list
// with Syft, through a resolver the kernel confines to that root.
//
// It holds no token, has no network and sees nothing of the host. The
// parent process runs as uid 0 with CAP_DAC_READ_SEARCH, CAP_SETUID and
// CAP_SETGID only, parses nothing, and starts one sandboxed child per
// scan as uid 2000000000 (README "Process model").
//
//	serve        run the worker
//	ping         exit 0 if the local worker answers a ping (exec probe)
//	request DIR  act as the Controller: send DIR (opened O_PATH) to the
//	             local worker and print the response (debugging)
//	scan-dir DIR scan a host directory in-process, unsandboxed, and print
//	             the response (debugging only)
//	version      print the worker and Syft versions
//
// scan-child, probe-caps and clean-tmp are internal: the parent starts
// them.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/kguardian-dev/kguardian/cataloger/internal/child"
	"github.com/kguardian-dev/kguardian/cataloger/internal/protocol"
	"github.com/kguardian-dev/kguardian/cataloger/internal/sandbox"
	"github.com/kguardian-dev/kguardian/cataloger/internal/scan"
	"github.com/kguardian-dev/kguardian/cataloger/internal/server"
)

var version = "dev"

const usage = `usage: kguardian-cataloger <serve|ping|request DIR|scan-dir DIR|version>
`

func main() { os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr)) }

func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "serve":
		if err := serve(getenv); err != nil {
			_, _ = fmt.Fprintf(stderr, "fatal: %v\n", err)
			return 1
		}
		return 0
	case "scan-child":
		return child.Main()
	case "probe-caps":
		return child.Probe()
	case "clean-tmp":
		return child.CleanTmp()
	case "ping":
		maxDegraded, err := time.ParseDuration(env(getenv, "CATALOG_MAX_DEGRADED", defaultMaxDegraded.String()))
		if err != nil || maxDegraded <= 0 {
			_, _ = fmt.Fprintln(stderr, "CATALOG_MAX_DEGRADED must be a positive duration")
			return 2
		}
		return ping(env(getenv, "CATALOG_SOCKET", defaultSocket), env(getenv, "CATALOG_TMP_DIR", "/tmp"), maxDegraded, stderr)
	case "request":
		if len(args) != 2 {
			_, _ = fmt.Fprint(stderr, usage)
			return 2
		}
		return request(env(getenv, "CATALOG_SOCKET", defaultSocket), args[1], stdout, stderr)
	case "scan-dir":
		if len(args) != 2 {
			_, _ = fmt.Fprint(stderr, usage)
			return 2
		}
		return scanDir(args[1], stdout, stderr)
	case "version":
		_, _ = fmt.Fprintf(stdout, "%s (syft %s)\n", version, scan.SyftVersion())
		return 0
	}
	_, _ = fmt.Fprint(stderr, usage)
	return 2
}

const defaultSocket = "/run/kguardian/catalog/worker.sock"

func env(getenv func(string) string, k, def string) string {
	if v := strings.TrimSpace(getenv(k)); v != "" {
		return v
	}
	return def
}

// parseBytes reads "1073741824", "640Mi" or "1Gi".
func parseBytes(s string) (int64, error) {
	mult := int64(1)
	for suf, m := range map[string]int64{"Ki": 1 << 10, "Mi": 1 << 20, "Gi": 1 << 30} {
		if strings.HasSuffix(s, suf) {
			s, mult = strings.TrimSuffix(s, suf), m
			break
		}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("%q is not a positive size", s)
	}
	return v * mult, nil
}

func loadConfig(getenv func(string) string) (server.Config, error) {
	c := server.Config{
		Socket:  env(getenv, "CATALOG_SOCKET", defaultSocket),
		TmpDir:  env(getenv, "CATALOG_TMP_DIR", "/tmp"),
		Version: version,
	}
	var err error
	if c.MemoryLimit, err = parseBytes(env(getenv, "CATALOG_MEMORY_LIMIT", "640Mi")); err != nil {
		return c, fmt.Errorf("CATALOG_MEMORY_LIMIT: %w", err)
	}
	if c.TmpLimit, err = parseBytes(env(getenv, "CATALOG_TMP_LIMIT", "192Mi")); err != nil {
		return c, fmt.Errorf("CATALOG_TMP_LIMIT: %w", err)
	}
	for _, f := range strings.Split(env(getenv, "CATALOG_ALLOWED_PEER_UIDS", "0"), ",") {
		u, err := strconv.ParseUint(strings.TrimSpace(f), 10, 32)
		if err != nil {
			return c, fmt.Errorf("CATALOG_ALLOWED_PEER_UIDS: %q", f)
		}
		c.AllowedPeerUIDs = append(c.AllowedPeerUIDs, uint32(u))
	}
	c.Verbose = env(getenv, "LOG_LEVEL", "info") == "debug"
	return c, nil
}

// serve runs the worker. Only a broken configuration (an unparseable
// environment, a chart bug) exits with an error. Environment problems
// found at startup (capabilities that cannot be dropped, a failing
// capability probe, a socket that cannot be created) leave the worker up
// and degraded: logged at once and hourly after, pings answered with
// worker_unavailable, scans refused, so the Controller reports
// worker_unavailable instead of its pod going NotReady on a crash loop.
func serve(getenv func(string) string) error {
	// Keep only what starting a scan child needs, before anything else.
	var capsErr error
	if os.Getuid() == 0 {
		capsErr = sandbox.LimitCaps(sandbox.ParentAllowed, sandbox.ChildModelI)
	}
	c, err := loadConfig(getenv)
	if err != nil {
		return err
	}
	log := logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})
	if lvl, err := logrus.ParseLevel(env(getenv, "LOG_LEVEL", "info")); err == nil {
		log.SetLevel(lvl)
	}
	c.Log = log
	caps, _ := sandbox.CurrentCaps()
	log.WithFields(logrus.Fields{
		"version": version, "syft": scan.SyftVersion(), "socket": c.Socket, "uid": os.Getuid(),
		"caps": sandbox.Names(caps.Effective), "memoryLimit": c.MemoryLimit, "tmpLimit": c.TmpLimit,
	}).Info("kguardian-cataloger starting")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	var srv *server.Server
	if capsErr != nil {
		// Never start a child from a parent holding more than it should:
		// the degraded server refuses every scan, and retries dropping the
		// capabilities, then the startup check, on its backoff.
		srv = server.Unavailable(c, fmt.Errorf("drop capabilities: %w", capsErr))
		srv.RetryWith(func(ctx context.Context) (server.Model, error) {
			if err := sandbox.LimitCaps(sandbox.ParentAllowed, sandbox.ChildModelI); err != nil {
				return server.Model{}, fmt.Errorf("drop capabilities: %w", err)
			}
			return srv.Startup(ctx)
		})
	} else if srv, err = server.New(ctx, c); err != nil {
		return err
	}
	l := listenOrWait(ctx, c, log)
	if l == nil {
		return nil // shut down while waiting
	}
	return srv.Serve(ctx, l)
}

// listenOrWait creates the socket, retrying every HeartbeatInterval while
// it cannot (keeping the heartbeat the liveness probe reads), until ctx
// ends (nil).
func listenOrWait(ctx context.Context, c server.Config, log *logrus.Logger) *net.UnixListener {
	lastWarn := time.Time{}
	var since time.Time
	for {
		l, err := server.Listen(c.Socket)
		if err == nil {
			server.RemoveHeartbeat(c.TmpDir)
			if !lastWarn.IsZero() {
				log.Info("socket created: worker serving")
			}
			return l
		}
		why := fmt.Sprintf("cannot create socket %s: %v", c.Socket, err)
		if since.IsZero() {
			since = time.Now()
		}
		if lastWarn.IsZero() {
			log.Error("worker unavailable: " + why + " (retrying; ping stays alive)")
			lastWarn = time.Now()
		} else if time.Since(lastWarn) >= time.Hour {
			log.Warn("worker still unavailable: " + why)
			lastWarn = time.Now()
		}
		if herr := server.WriteHeartbeat(c.TmpDir, why, since); herr != nil {
			log.WithError(herr).Warn("heartbeat")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(server.HeartbeatInterval):
		}
	}
}

// defaultMaxDegraded is how long ping tolerates a degraded worker
// (CATALOG_MAX_DEGRADED).
const defaultMaxDegraded = 6 * time.Hour

// ping is the chart's liveness probe. It exits 0 while the worker process
// is alive, including when it is degraded (it then answers
// worker_unavailable, or keeps a heartbeat because it has no socket): a
// restart would not fix an environment problem, the worker retries the
// failed step itself, and the Controller sees the degraded state through
// its own protocol-level ping. Only after maxDegraded of continuous
// degradation does it fail, so the kubelet restarts the container once in
// a while rather than never.
func ping(socket, tmpDir string, maxDegraded time.Duration, stderr io.Writer) int {
	degradedTooLong := func(why string, since time.Duration) int {
		if since > maxDegraded {
			_, _ = fmt.Fprintf(stderr, "worker unavailable for %s (over %s): %s\n", since.Round(time.Second), maxDegraded, why)
			return 1
		}
		_, _ = fmt.Fprintln(stderr, "worker alive but unavailable:", why)
		return 0
	}
	conn, err := net.DialTimeout("unix", socket, 3*time.Second)
	if err != nil {
		if why, since, ok := server.HeartbeatFresh(tmpDir, server.HeartbeatMaxAge); ok {
			return degradedTooLong(why, time.Since(since))
		}
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := &protocol.Request{ProtocolVersion: protocol.Version, Op: protocol.OpPing, ScanID: "ping"}
	if err := protocol.SendRequest(conn.(*net.UnixConn), req, -1); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	resp, err := protocol.ReadResponse(conn, protocol.MaxRequestBytes)
	switch {
	case err != nil:
		_, _ = fmt.Fprintln(stderr, "ping failed:", err)
		return 1
	case resp.Status == protocol.StatusOK:
		return 0
	case resp.Reason == protocol.ReasonWorkerUnavailable:
		return degradedTooLong(resp.Message, time.Duration(resp.Stats.DegradedMS)*time.Millisecond)
	default:
		_, _ = fmt.Fprintf(stderr, "ping failed: %s %s\n", resp.Reason, resp.Message)
		return 1
	}
}

// request sends dir to the worker the way the Controller does.
func request(socket, dir string, stdout, stderr io.Writer) int {
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	defer func() { _ = unix.Close(fd) }()
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	defer func() { _ = conn.Close() }()
	req := &protocol.Request{ProtocolVersion: protocol.Version, Op: protocol.OpScan,
		ScanID: fmt.Sprintf("request-%d", time.Now().UnixNano()), ContainerStartUnixNanos: time.Now().UnixNano()}
	if err := protocol.SendRequest(conn.(*net.UnixConn), req, fd); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	resp, err := protocol.ReadResponse(conn, protocol.MaxResponseCeiling)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
	if resp.Status != protocol.StatusOK {
		return 1
	}
	return 0
}

// scanDir runs the scan in this process with no sandbox (debugging only).
func scanDir(dir string, stdout, stderr io.Writer) int {
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	scan.InstallLogger(stderr, os.Getenv("LOG_LEVEL") == "debug")
	resp := scan.Run(context.Background(), fd, scan.Options{
		Profile: protocol.ProfileFull, Budgets: protocol.Budgets{}.Effective(), CapsModel: "none", Version: version,
	})
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
	if resp.Status != protocol.StatusOK {
		return 1
	}
	return 0
}
