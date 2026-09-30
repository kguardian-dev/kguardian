// Package server is the worker parent: it listens on the Unix socket,
// receives {fd, request} from the Controller, runs each scan in a fresh
// sandboxed child, enforces the wall-clock deadline, validates the child's
// output and answers. It parses no image content and holds no token.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/kguardian-dev/kguardian/cataloger/internal/protocol"
	"github.com/kguardian-dev/kguardian/cataloger/internal/sandbox"
	"github.com/kguardian-dev/kguardian/cataloger/internal/scan"
)

var capDRS = sandbox.ChildModelI

func capNames(m uint64) string { return sandbox.Names(m) }

// Config is the worker's configuration (env, see main.go).
type Config struct {
	Socket          string
	AllowedPeerUIDs []uint32
	// MemoryLimit is the scan child's hard heap cap (GOMEMLIMIT is 85 %).
	MemoryLimit int64
	// TmpLimit caps the child's temp files (they live on a memory-backed
	// emptyDir, so they count against the container's memory too).
	TmpLimit int64
	TmpDir   string
	Version  string
	Verbose  bool
	// ChildPath/ChildArgs start a child: /proc/self/exe in production,
	// the test binary in tests. The child subcommand is appended.
	ChildPath string
	ChildArgs []string
	// RetryInitial and RetryMax: the backoff on which a degraded worker
	// retries its failed startup step (defaults 30 s doubling to 10 min).
	RetryInitial time.Duration
	RetryMax     time.Duration
	// ChildEnv is appended to the child's environment (tests).
	ChildEnv []string
	Log      *logrus.Logger
}

// cleanTmpTimeout bounds the temp cleanup after a killed child.
const cleanTmpTimeout = 5 * time.Second

// Server is the worker parent.
type Server struct {
	cfg   Config
	model Model
	busy  atomic.Bool
	log   *logrus.Logger

	mu sync.Mutex
	// why is why this worker cannot scan (an environment problem found at
	// startup), or "" when it can; since is when it became degraded.
	why   string
	since time.Time
	// retry repeats the failed startup step; nil when nothing can be
	// retried. See recoverLoop.
	retry func(context.Context) (Model, error)
}

// degradedWarnEvery is how often a degraded worker repeats its warning.
const degradedWarnEvery = time.Hour

// Recovery backoff defaults (Config.RetryInitial, Config.RetryMax).
const (
	DefaultRetryInitial = 30 * time.Second
	DefaultRetryMax     = 10 * time.Minute
)

func (c *Config) defaults() {
	if c.ChildPath == "" {
		c.ChildPath = "/proc/self/exe"
	}
	if c.Log == nil {
		c.Log = logrus.New()
		c.Log.SetOutput(io.Discard)
	}
	if c.TmpDir == "" {
		c.TmpDir = os.TempDir()
	}
	if c.RetryInitial <= 0 {
		c.RetryInitial = DefaultRetryInitial
	}
	if c.RetryMax <= 0 {
		c.RetryMax = DefaultRetryMax
	}
}

// Unavailable returns a degraded server: it stays up and answers every
// request, ping included, with status failed and reason
// worker_unavailable (the Controller then reports the node as
// worker_unavailable and claims nothing), instead of exiting into a crash
// loop that would take the Controller's pod NotReady. why is logged now
// and warned again hourly.
func Unavailable(cfg Config, why error) *Server {
	cfg.defaults()
	s := &Server{cfg: cfg, log: cfg.Log, why: why.Error(), since: time.Now()}
	s.log.WithError(why).Error("worker unavailable: serving pings with worker_unavailable and refusing scans")
	return s
}

// Why reports why the worker is unavailable ("" when it is not).
func (s *Server) Why() string {
	why, _ := s.Degraded()
	return why
}

// Degraded reports why the worker is unavailable and since when ("" and
// the zero time when it is not).
func (s *Server) Degraded() (string, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.why, s.since
}

// Model returns the capability model in use.
func (s *Server) Model() Model {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.model
}

// RetryWith sets how a degraded server retries its failed startup step
// (Serve runs the retries; see recoverLoop).
func (s *Server) RetryWith(fn func(context.Context) (Model, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retry = fn
}

// Startup is the startup check: mark inherited descriptors close-on-exec
// and probe the capability model.
func (s *Server) Startup(ctx context.Context) (Model, error) {
	if err := sandbox.CloexecInherited(); err != nil {
		return Model{}, err
	}
	m, err := s.probeModel(ctx)
	if err != nil {
		return Model{}, fmt.Errorf("capability probe: %w", err)
	}
	return m, nil
}

// nextRetry doubles the delay up to max.
func nextRetry(d, max time.Duration) time.Duration {
	return min(2*d, max)
}

// recoverLoop retries the failed startup step on a backoff (RetryInitial,
// doubling to RetryMax) until it succeeds, then leaves degraded mode.
func (s *Server) recoverLoop(ctx context.Context) {
	s.mu.Lock()
	retry := s.retry
	s.mu.Unlock()
	if retry == nil {
		return
	}
	delay := s.cfg.RetryInitial
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		m, err := retry(ctx)
		if err == nil {
			s.mu.Lock()
			s.model, s.why, s.since = m, "", time.Time{}
			s.mu.Unlock()
			s.log.WithFields(logrus.Fields{"model": m.Name}).Info("worker recovered: capability model: " + m.Why)
			return
		}
		s.mu.Lock()
		s.why = err.Error()
		s.mu.Unlock()
		s.log.WithError(err).WithField("nextRetry", nextRetry(delay, s.cfg.RetryMax).String()).Debug("worker still unavailable")
		delay = nextRetry(delay, s.cfg.RetryMax)
	}
}

// New probes the capability model and returns a server. An environment
// problem (inherited descriptors that cannot be marked close-on-exec, a
// capability probe that fails) yields a degraded server (Unavailable)
// rather than an error: the worker stays up and says why.
func New(ctx context.Context, cfg Config) (*Server, error) {
	cfg.defaults()
	s := &Server{cfg: cfg, log: cfg.Log}
	// Before any child is started: nothing this process inherited may
	// reach one (children get stdio, their root fd and socketpair only).
	m, err := s.Startup(ctx)
	if err != nil {
		d := Unavailable(cfg, err)
		d.RetryWith(d.Startup)
		return d, nil
	}
	s.model = m
	s.log.WithFields(logrus.Fields{"model": m.Name, "setuid": m.SetUID, "ambient": m.Ambient}).Info("capability model: " + m.Why)
	return s, nil
}

// warnWhileDegraded repeats the degraded warning hourly until the worker
// recovers or ctx ends.
func (s *Server) warnWhileDegraded(ctx context.Context) {
	t := time.NewTicker(degradedWarnEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			why, since := s.Degraded()
			if why == "" {
				return
			}
			s.log.WithField("degradedFor", time.Since(since).Round(time.Second).String()).Warn("worker still unavailable: " + why)
		}
	}
}

// Listen creates the socket the Controller verifies before connecting
// (PROTOCOL.md §1): its directory owned by us (uid 0 in the pod) with mode
// 0700, and the socket itself mode 0600, owned by us, with no moment at
// which either is wider. A stale socket is replaced; anything else at the
// path, or a symlinked directory, is refused.
//
// The parent has no CAP_CHOWN or CAP_FOWNER: it can tighten the mode of a
// directory it owns (kubelet creates emptyDirs owned by uid 0, mode 0777),
// but a directory owned by anyone else is an error, not something to
// take over.
func Listen(path string) (*net.UnixListener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := secureDir(dir); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket: %w", err)
		}
	}
	// bind(2) creates the socket file with 0777 &^ umask: 0600 from the
	// start. The umask is process-wide, so this runs before any child.
	old := syscall.Umask(0o177)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	l.SetUnlinkOnClose(true)
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK ||
		st.Mode&0o7777 != 0o600 || int(st.Uid) != os.Geteuid() {
		_ = l.Close()
		return nil, fmt.Errorf("socket %s is not a 0600 socket owned by uid %d (mode %o uid %d)", path, os.Geteuid(), st.Mode, st.Uid)
	}
	return l, nil
}

// secureDir makes dir mode 0700 through a no-follow fd, after checking it
// is a real directory owned by this process's uid.
func secureDir(dir string) error {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("socket directory %s: %w", dir, err)
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("socket directory %s is owned by uid %d, not %d (the worker has no CAP_CHOWN to take it over)", dir, st.Uid, os.Geteuid())
	}
	if err := unix.Fchmod(fd, 0o700); err != nil {
		return fmt.Errorf("chmod 0700 %s: %w", dir, err)
	}
	return nil
}

// Serve accepts connections until ctx ends.
func (s *Server) Serve(ctx context.Context, l *net.UnixListener) error {
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	if why, _ := s.Degraded(); why != "" {
		go s.warnWhileDegraded(ctx)
		go s.recoverLoop(ctx)
	}
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go s.Handle(ctx, c)
	}
}

func (s *Server) peerAllowed(c *net.UnixConn) (int32, bool) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, false
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || cerr != nil {
		return 0, false
	}
	for _, u := range s.cfg.AllowedPeerUIDs {
		if cred.Uid == u {
			return cred.Pid, true
		}
	}
	return cred.Pid, false
}

func (s *Server) reply(c *net.UnixConn, resp *protocol.Response) {
	_ = c.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if err := protocol.WriteJSON(c, resp); err != nil {
		s.log.WithError(err).Warn("write response")
	}
}

// Handle serves one connection: one request, one response.
func (s *Server) Handle(ctx context.Context, c *net.UnixConn) {
	defer func() { _ = c.Close() }()
	if pid, ok := s.peerAllowed(c); !ok {
		s.log.WithField("peerPid", pid).Warn("refused a connection from a peer uid not in CATALOG_ALLOWED_PEER_UIDS")
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	req, fd, err := protocol.RecvRequest(c)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		reason := protocol.ReasonBadRequest
		if errors.Is(err, protocol.ErrFDStripped) {
			reason = protocol.ReasonLSMDenied
		}
		if errors.Is(err, io.EOF) {
			return
		}
		s.reply(c, protocol.Failed(nil, reason, err.Error()))
		return
	}
	var root *os.File
	if fd >= 0 {
		root = os.NewFile(uintptr(fd), "root")
		defer func() { _ = root.Close() }()
	}
	if err := req.Validate(); err != nil {
		var re *protocol.RequestError
		reason := protocol.ReasonBadRequest
		if errors.As(err, &re) {
			reason = re.Reason
		}
		s.reply(c, protocol.Failed(req, reason, err.Error()))
		return
	}
	if why, since := s.Degraded(); why != "" {
		resp := protocol.Failed(req, protocol.ReasonWorkerUnavailable, why)
		resp.Stats.DegradedMS = time.Since(since).Milliseconds()
		resp.Scanner = s.scanner()
		resp.Stats.SyftVersion = scan.SyftVersion()
		resp.Stats.WorkerVersion = s.cfg.Version
		s.reply(c, resp)
		return
	}
	if req.Op == protocol.OpPing {
		resp := protocol.Failed(req, "", "")
		resp.Status = protocol.StatusOK
		resp.Scanner = s.scanner()
		resp.Stats.CapsModel = s.Model().Name
		resp.Stats.SyftVersion = scan.SyftVersion()
		resp.Stats.WorkerVersion = s.cfg.Version
		s.reply(c, resp)
		return
	}
	if root == nil {
		s.reply(c, protocol.Failed(req, protocol.ReasonBadRequest, "scan request without a root fd"))
		return
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(root.Fd()), &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		s.reply(c, protocol.Failed(req, protocol.ReasonBadRequest, "the fd is not a directory"))
		return
	}
	if !s.busy.CompareAndSwap(false, true) {
		s.reply(c, protocol.Failed(req, protocol.ReasonBusy, "another scan is running"))
		return
	}
	defer s.busy.Store(false)

	// Closing the connection cancels the scan.
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		var b [1]byte
		_, _ = c.Read(b[:])
		cancel()
	}()
	resp := s.Scan(sctx, req, root)
	if sctx.Err() != nil && ctx.Err() == nil && resp.Reason != protocol.ReasonTimeout {
		s.log.WithField("scanId", req.ScanID).Info("controller closed the connection: scan cancelled")
		return
	}
	s.reply(c, resp)
}

func (s *Server) scanner() protocol.Scanner {
	return protocol.Scanner{Name: "kguardian-cataloger", Vendor: "kguardian", Version: s.cfg.Version}
}

// retryable: reasons after which the os_only profile is worth one try.
func retryable(reason string) bool {
	return reason == protocol.ReasonOOM || reason == protocol.ReasonTooManyFiles || reason == protocol.ReasonTooManyComponents
}

// Scan runs the request, with the one os_only retry the design allows.
func (s *Server) Scan(ctx context.Context, req *protocol.Request, root *os.File) *protocol.Response {
	start := time.Now()
	b := req.Budgets.Effective()
	deadline := start.Add(time.Duration(b.ScanTimeoutMS) * time.Millisecond)
	dctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	profile := req.Profile
	if profile == "" {
		profile = protocol.ProfileFull
	}
	var resp *protocol.Response
	retryReason := ""
	attempts := 0
	var rss int64
	for {
		attempts++
		creq := *req
		creq.Profile = profile
		creq.Budgets = b
		r := s.run(dctx, "scan-child", s.Model(), root, &creq, int(b.MaxResponseBytes))
		rss = max(rss, maxRSS(r.state))
		resp = s.interpret(req, r, b)
		if r.payload == nil {
			// A killed child cannot remove its temp dir, and the parent
			// (uid 0 without CAP_DAC_OVERRIDE) cannot either: a short
			// child as the scan uid does.
			s.cleanTmp(dctx)
		}
		s.logAttempt(req, profile, resp, r)
		if attempts == 1 && profile == protocol.ProfileFull && retryable(resp.Reason) && dctx.Err() == nil {
			retryReason = resp.Reason
			profile = protocol.ProfileOSOnly
			continue
		}
		break
	}
	// Fields only the parent sets: a child cannot choose them.
	resp.ProtocolVersion = protocol.Version
	resp.ScanID, resp.Epoch = req.ScanID, req.Epoch
	resp.RetryReason = retryReason
	resp.Scanner = s.scanner()
	resp.Stats.Attempts = attempts
	resp.Stats.CapsModel = s.Model().Name
	resp.Stats.Budgets = b
	resp.Stats.DurationMS = time.Since(start).Milliseconds()
	resp.Stats.MaxRSSBytes = rss
	resp.Stats.WorkerVersion = s.cfg.Version
	if resp.Stats.SyftVersion == "" {
		resp.Stats.SyftVersion = scan.SyftVersion()
	}
	if resp.Status == protocol.StatusFailed && resp.Reason == protocol.ReasonTooManyFiles {
		// Only a retry reason: os_only never fails on the file budget.
		resp.Reason = protocol.ReasonError
	}
	return resp
}

// cleanTmp removes a killed child's temp dir. It belongs to the scan
// (dctx), but runs right after a timeout too, when dctx is already done:
// so it keeps dctx's values, drops its cancellation, and gets its own short
// bound. It is a directory removal on tmpfs; a few seconds is plenty, and
// a response never waits longer for it.
func (s *Server) cleanTmp(dctx context.Context) {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(dctx), cleanTmpTimeout)
	defer cancel()
	if r := s.run(cctx, "clean-tmp", s.Model(), nil, nil, 64); r.startErr != nil {
		s.log.WithError(r.startErr).Warn("temp cleanup")
	}
}

func (s *Server) logAttempt(req *protocol.Request, profile string, resp *protocol.Response, r childResult) {
	f := logrus.Fields{"scanId": req.ScanID, "profile": profile, "status": resp.Status, "reason": resp.Reason,
		"components": len(resp.Components), "completeness": resp.Completeness}
	if resp.Status != protocol.StatusOK && r.stderr != "" {
		f["childStderr"] = lastLines(r.stderr, 20)
	}
	s.log.WithFields(f).Info("scan attempt")
}

// crashLine is the Go runtime's headline for a crash ("panic: ...",
// "fatal error: ..."), else the last stderr line.
func crashLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "panic: ") || strings.HasPrefix(l, "fatal error: ") {
			if i+1 < len(lines) && strings.TrimSpace(lines[i+1]) != "" && !strings.HasPrefix(lines[i+1], "goroutine ") {
				return l + " " + strings.TrimSpace(lines[i+1])
			}
			return l
		}
	}
	return lastLines(s, 1)
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// interpret turns one child run into a response.
func (s *Server) interpret(req *protocol.Request, r childResult, b protocol.Budgets) *protocol.Response {
	switch {
	case r.startErr != nil:
		return protocol.Failed(req, protocol.ReasonError, "start scan child: "+r.startErr.Error())
	case r.killed:
		return protocol.Failed(req, protocol.ReasonTimeout, fmt.Sprintf("scan exceeded %d ms", b.ScanTimeoutMS))
	case r.payload != nil:
		var resp protocol.Response
		if err := json.Unmarshal(r.payload, &resp); err != nil {
			return protocol.Failed(req, protocol.ReasonError, "invalid child output: "+err.Error())
		}
		if err := Validate(&resp, b); err != nil {
			return protocol.Failed(req, protocol.ReasonError, "invalid child output: "+err.Error())
		}
		return &resp
	case oomExit(r):
		return protocol.Failed(req, protocol.ReasonOOM, "scan child ran out of memory")
	default:
		msg := "scan child exited without a response"
		if r.state != nil {
			msg += ": " + r.state.String()
		}
		if l := crashLine(r.stderr); l != "" {
			msg += ": " + l
		}
		return protocol.Failed(req, protocol.ReasonError, msg)
	}
}

var knownReasons = map[string]bool{
	"": true, protocol.ReasonTimeout: true, protocol.ReasonOOM: true, protocol.ReasonTooManyComponents: true,
	protocol.ReasonNoPackagesFound: true, protocol.ReasonLSMDenied: true, protocol.ReasonKernelUnsupported: true,
	protocol.ReasonCapsUnavailable: true, protocol.ReasonError: true, protocol.ReasonBadRequest: true,
	protocol.ReasonOutputTooLarge: true, protocol.ReasonTooManyFiles: true,
}

var knownPartial = map[string]bool{
	protocol.PartialEACCES: true, protocol.PartialNoDACReadSearch: true, protocol.PartialCtimeDropped: true,
	protocol.PartialDepthLimited: true, protocol.PartialFilesTruncated: true, protocol.PartialResponseTrimmed: true,
	protocol.PartialComponentsDropped: true, protocol.PartialFileBudget: true,
}

func validPath(p string) bool { return protocol.ValidPath(p) }

// Validate checks a child's response against the protocol's limits. A
// compromised child can still lie within them; it cannot exceed them.
// (json.Unmarshal already replaced invalid UTF-8.)
func Validate(r *protocol.Response, b protocol.Budgets) error {
	switch r.Status {
	case protocol.StatusOK:
		if r.Reason != "" {
			return errors.New("ok with a reason")
		}
		switch r.Completeness {
		case protocol.CompletenessFull, protocol.CompletenessPartial, protocol.CompletenessOSOnly:
		default:
			return fmt.Errorf("completeness %q", r.Completeness)
		}
	case protocol.StatusFailed:
		if len(r.Components) != 0 {
			return errors.New("failed with components")
		}
		if !knownReasons[r.Reason] || r.Reason == "" {
			return fmt.Errorf("reason %q", r.Reason)
		}
		// Only no_packages_found carries a completeness when failed
		// (PROTOCOL.md §4.4), and only one of the known values.
		switch r.Completeness {
		case "":
		case protocol.CompletenessFull, protocol.CompletenessPartial, protocol.CompletenessOSOnly:
			if r.Reason != protocol.ReasonNoPackagesFound {
				return fmt.Errorf("completeness on a %s failure", r.Reason)
			}
		default:
			return fmt.Errorf("completeness %q", r.Completeness)
		}
	default:
		return fmt.Errorf("status %q", r.Status)
	}
	if len(r.Message) > protocol.MaxMessageLen {
		return errors.New("message too long")
	}
	if len(r.PartialReasons) > len(knownPartial) {
		return errors.New("too many partial reasons")
	}
	for _, p := range r.PartialReasons {
		if !knownPartial[p] {
			return fmt.Errorf("partial reason %q", p)
		}
	}
	if len(r.Stats.CtimeDroppedSample) > protocol.MaxDriftSample {
		return errors.New("drift sample too long")
	}
	for _, p := range r.Stats.CtimeDroppedSample {
		if !protocol.ValidSamplePath(p) {
			return fmt.Errorf("drift sample path %q", protocol.Truncate(p, 64))
		}
	}
	if int64(len(r.Components)) > b.MaxComponents {
		return fmt.Errorf("%d components over the budget", len(r.Components))
	}
	if r.OS != nil && (len(r.OS.Family) > protocol.MaxOSLen || len(r.OS.Name) > protocol.MaxOSLen ||
		protocol.HasControl(r.OS.Family+r.OS.Name)) {
		return errors.New("os fields too long")
	}
	for i, c := range r.Components {
		switch {
		case c.Name == "" || len(c.Name) > protocol.MaxNameLen:
			return fmt.Errorf("component %d: name", i)
		case len(c.Version) > protocol.MaxVersionLen, len(c.SrcVersion) > protocol.MaxVersionLen:
			return fmt.Errorf("component %d: version", i)
		case len(c.PURL) > protocol.MaxPURLLen, len(c.Type) > protocol.MaxShortLen, len(c.SrcName) > protocol.MaxNameLen,
			protocol.HasControl(c.Name + c.Version + c.PURL + c.Type + c.SrcName + c.SrcVersion):
			return fmt.Errorf("component %d: field too long", i)
		case c.Class != "" && c.Class != "os-pkgs" && c.Class != "lang-pkgs":
			return fmt.Errorf("component %d: class %q", i, c.Class)
		case len(c.Licenses) > protocol.MaxLicenses:
			return fmt.Errorf("component %d: licenses", i)
		case int64(len(c.FilePaths)) > b.MaxPathsPerPackage:
			return fmt.Errorf("component %d: %d file paths", i, len(c.FilePaths))
		}
		for _, l := range c.Licenses {
			if len(l) > protocol.MaxLicenseLen || protocol.HasControl(l) {
				return fmt.Errorf("component %d: license too long", i)
			}
		}
		for _, p := range c.FilePaths {
			if !validPath(p) {
				return fmt.Errorf("component %d: path %q", i, protocol.Truncate(p, 64))
			}
		}
	}
	return nil
}
