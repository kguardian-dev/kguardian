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
		return ping(env(getenv, "CATALOG_SOCKET", defaultSocket), stderr)
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

func serve(getenv func(string) string) error {
	// Keep only what starting a scan child needs, before anything else.
	if os.Getuid() == 0 {
		if err := sandbox.LimitCaps(sandbox.ParentAllowed, sandbox.ChildModelI); err != nil {
			return fmt.Errorf("drop capabilities: %w", err)
		}
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
	srv, err := server.New(ctx, c)
	if err != nil {
		return err
	}
	l, err := server.Listen(c.Socket)
	if err != nil {
		return err
	}
	return srv.Serve(ctx, l)
}

func ping(socket string, stderr io.Writer) int {
	conn, err := net.DialTimeout("unix", socket, 3*time.Second)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := &protocol.Request{ProtocolVersion: protocol.Version, Op: protocol.OpPing, ScanID: "ping"}
	if err := protocol.SendRequest(conn.(*net.UnixConn), req, -1); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	resp, err := protocol.ReadResponse(conn, protocol.MaxRequestBytes)
	if err != nil || resp.Status != protocol.StatusOK {
		_, _ = fmt.Fprintln(stderr, "ping failed:", err, resp)
		return 1
	}
	return 0
}

// request sends dir to the worker the way the Controller does.
func request(socket, dir string, stdout, stderr io.Writer) int {
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	defer unix.Close(fd)
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	defer conn.Close()
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
