package appprofile

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	v1alpha1 "github.com/kguardian-dev/kguardian/evaluator/pkg/v1alpha1"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

// leak is what a broker, or a proxy in front of it, might put in an error
// body: an internal URL, address and a secret-looking word.
const leak = "upstream http://10.1.2.3:8080/workloads failed via broker.kguardian.svc:9090 token=secret"

// assertUserSafe fails when text carries anything from the HTTP client's
// or the broker's error text: a URL, an address, a port, the path.
func assertUserSafe(t *testing.T, what, text string) {
	t.Helper()
	for _, bad := range []string{"http", "://", "10.1.2.3", "127.0.0.1", "localhost", "kguardian.svc", "dial tcp", `get "`, "/workloads", "secret", "upstream", "broker returned"} {
		if strings.Contains(strings.ToLower(text), bad) {
			t.Errorf("%s: %q contains %q", what, text, bad)
		}
	}
	// host:port with a dotted host or an IP (a timestamp's 12:35:00 is
	// not one).
	if hostPort.MatchString(text) {
		t.Errorf("%s: %q contains a host:port", what, text)
	}
}

var hostPort = regexp.MustCompile(`[A-Za-z0-9-]+\.[A-Za-z0-9.-]+:[0-9]{1,5}\b|\[[0-9a-fA-F:]+\]:[0-9]{1,5}\b`)

// dialErr is what net/http returns when the broker's port is closed.
func dialErr() error {
	return &url.Error{Op: "Get", URL: "http://broker.kguardian.svc:9090/workloads/payments/Deployment/refunds/profile", Err: &net.OpError{
		Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(10, 1, 2, 3), Port: 9090}, Err: errors.New("connect: connection refused"),
	}}
}

// statusTexts is every user-readable message computeStatus writes.
func statusTexts(st v1alpha1.ApplicationSecurityProfileStatus) map[string]string {
	out := map[string]string{}
	for _, c := range st.Conditions {
		out["condition "+c.Type] = c.Message
	}
	if st.Posture != nil {
		for _, r := range st.Posture.Reasons {
			out["posture reason "+r.Dimension] = r.Message
		}
	}
	if st.Dimensions != nil {
		out["dimension network"] = st.Dimensions.Network.Message
	}
	if st.Deviation != nil {
		out["deviation"] = st.Deviation.Message
	}
	return out
}

// realErrors returns errors from the real BrokerClient: a closed port and
// a broker (or proxy) answering with its internal address in the body.
func realErrors(t *testing.T) map[string]struct {
	err   error
	cause string
} {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("case") {
		case "500":
			http.Error(w, leak, http.StatusInternalServerError)
		case "400":
			http.Error(w, leak, http.StatusBadRequest)
		case "400json":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"bad_request","message":"` + leak + `"}`))
		case "418":
			http.Error(w, leak, http.StatusTeapot)
		case "401":
			http.Error(w, leak, http.StatusUnauthorized)
		case "nonjson":
			_, _ = w.Write([]byte("<html>" + leak + "</html>"))
		case "slow":
			time.Sleep(300 * time.Millisecond)
		}
	}))
	t.Cleanup(srv.Close)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	_ = ln.Close()

	get := func(base, c string, timeout time.Duration) error {
		cl, err := NewBrokerClient(base, "t0ken", timeout)
		if err != nil {
			t.Fatal(err)
		}
		// The case rides in the query so the real client builds the path.
		cl.base = base
		err = cl.get(context.Background(), "/workloads/payments/Deployment/refunds/profile?case="+c, &Profile{})
		if err == nil {
			t.Fatalf("case %s: want an error", c)
		}
		return err
	}
	out := map[string]struct {
		err   error
		cause string
	}{}
	add := func(name string, err error, cause string) {
		out[name] = struct {
			err   error
			cause string
		}{err, cause}
	}
	add("closed port", get("http://"+closed, "", 2*time.Second), "connection failed")
	add("leaky 500", get(srv.URL, "500", 2*time.Second), "status 500")
	add("leaky 400", get(srv.URL, "400", 2*time.Second), "status 400")
	add("leaky 400 json", get(srv.URL, "400json", 2*time.Second), "status 400")
	add("leaky 418", get(srv.URL, "418", 2*time.Second), "status 418")
	add("leaky 401", get(srv.URL, "401", 2*time.Second), "status 401")
	add("non-JSON 200", get(srv.URL, "nonjson", 2*time.Second), "invalid response")
	add("timeout", get(srv.URL, "slow", 50*time.Millisecond), "timed out")
	add("dial error with URL", dialErr(), "connection failed")
	return out
}

// Every error path that writes status (profile read fresh and stale,
// accepted revision read, latest revision read) carries a coarse cause
// and nothing from the error text.
func TestStatusHidesBrokerText(t *testing.T) {
	for name, tc := range realErrors(t) {
		// The raw error really does carry the internals, or the test
		// proves nothing.
		if raw := tc.err.Error(); !strings.Contains(raw, "127.0.0.1") && !strings.Contains(raw, leak) && !strings.Contains(raw, "kguardian.svc") && !strings.Contains(raw, "http://") && !strings.Contains(raw, "/workloads") {
			t.Fatalf("%s: raw error %q carries nothing to hide", name, raw)
		}
		code := statusCode(tc.err)
		wantCause := tc.cause
		if code == http.StatusBadRequest {
			wantCause = "(status 400)"
		}
		if code == http.StatusUnauthorized {
			wantCause = "(status 401)"
		}
		scenarios := map[string]struct {
			b   Broker
			asp *v1alpha1.ApplicationSecurityProfile
		}{
			"profile, fresh data": {&fakeBroker{profileErr: tc.err}, staleFixture(time.Second)},
			"profile, stale data": {&fakeBroker{profileErr: tc.err}, staleFixture(testStaleAfter + time.Second)},
			"profile, never read": {&fakeBroker{profileErr: tc.err}, aspFixture(nil)},
			"accepted revision":   {&fakeBroker{profile: profileFixture(), versionErr: tc.err}, aspFixture(ptr(int64(2)))},
			"latest revision": {&splitBroker{fakeBroker: fakeBroker{profile: profileFixture(), versions: map[int64]*Version{
				2: {Revision: 2, ContentHash: "fnv1a64:rev2"},
			}}, failRev: 3, err: tc.err}, aspFixture(ptr(int64(2)))},
		}
		for sname, sc := range scenarios {
			st, _ := computeStatus(context.Background(), sc.b, sc.asp, now, testStaleAfter)
			found := false
			for what, text := range statusTexts(st) {
				assertUserSafe(t, name+" / "+sname+" / "+what, text)
				if strings.Contains(text, wantCause) {
					found = true
				}
			}
			if !found {
				t.Errorf("%s / %s: no status message names the cause %q: %v", name, sname, wantCause, statusTexts(st))
			}
		}
	}
}

// splitBroker fails only the read of one revision.
type splitBroker struct {
	fakeBroker
	failRev int64
	err     error
}

func (s *splitBroker) Version(ctx context.Context, ns, kind, name string, rev int64) (*Version, error) {
	if rev == s.failRev {
		return nil, s.err
	}
	return s.fakeBroker.Version(ctx, ns, kind, name, rev)
}

// A failure that is not retried early is still logged in full: status
// has only the cause, so the log is where an operator finds the rest.
func TestReconcileLogsTheFullError(t *testing.T) {
	be := &BrokerError{StatusCode: http.StatusTeapot, Message: leak}
	c, patches, _ := newTestController(t, &fakeBroker{profileErr: be}, aspObject("refunds", "Deployment", "refunds", now, nil))
	logger, hook := logtest.NewNullLogger()
	c.log = logger
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	syncInformer(t, ctx, c)
	if err := c.reconcile(ctx, "payments/refunds"); err != nil {
		t.Fatalf("a non-transient read failure is reported in status, not retried: %v", err)
	}
	if len(*patches) != 1 {
		t.Fatalf("status not applied: %d patches", len(*patches))
	}
	var logged bool
	for _, e := range hook.AllEntries() {
		if err, ok := e.Data[logrus.ErrorKey].(error); ok && e.Level == logrus.WarnLevel && strings.Contains(err.Error(), leak) {
			logged = true
		}
	}
	if !logged {
		t.Errorf("full broker error not logged; entries: %v", hook.AllEntries())
	}
}
