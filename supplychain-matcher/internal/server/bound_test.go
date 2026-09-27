package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain-matcher/internal/wire"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

// fixedEngine answers every match with vulns.
type fixedEngine struct{ vulns []wire.Vulnerability }

func (f fixedEngine) Match(context.Context, []wire.Component) ([]wire.Vulnerability, error) {
	return f.vulns, nil
}
func (fixedEngine) DB() wire.DB  { return wire.DB{Loaded: true, Scanner: "grype v0.119.0"} }
func (fixedEngine) Loaded() bool { return true }

// findings returns n findings that all share one list of files paths.
func findings(n, files int) []wire.Vulnerability {
	paths := make([]string, files)
	for i := range paths {
		paths[i] = fmt.Sprintf("usr/include/linux/header-%05d.h", i)
	}
	out := make([]wire.Vulnerability, n)
	for i := range out {
		out[i] = wire.Vulnerability{ID: fmt.Sprintf("CVE-2024-%05d", i), Severity: "HIGH",
			Package: wire.Package{Name: "linux-libc-dev", Version: "6.1.180-1"}, FilePaths: paths}
	}
	return out
}

func serve(t *testing.T, s *Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: s.Handler()}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "http://" + ln.Addr().String()
}

func post(t *testing.T, base string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+"/match",
		strings.NewReader(string(gz(t, map[string]any{"image": map[string]string{"digest": "sha256:fan"}, "components": []map[string]string{{"name": "linux-libc-dev"}}}))))
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestMatchResponseIsTheSameJSON(t *testing.T) {
	vulns := findings(2128, wire.MaxFilePaths)
	resp := post(t, serve(t, &Server{Engine: fixedEngine{vulns}, Log: logrus.New()}))
	defer func() { _ = resp.Body.Close() }()
	var got wire.MatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(wire.MatchResponse{DB: fixedEngine{}.DB(), Vulnerabilities: vulns})
	have, _ := json.Marshal(got)
	if resp.StatusCode != http.StatusOK || string(have) != string(want) {
		t.Errorf("status %d; streamed body differs from the encoded response", resp.StatusCode)
	}
	empty := post(t, serve(t, &Server{Engine: fixedEngine{nil}, Log: logrus.New()}))
	b, _ := io.ReadAll(empty.Body)
	if !strings.Contains(string(b), `"vulnerabilities":[]`) {
		t.Errorf("no findings: %s", b)
	}
}

// Streaming holds one finding at a time: even a response the size of the
// uncapped kernel-headers fan-out (~90 MiB) never sits in memory.
func TestMatchResponseStreamsWithBoundedHeap(t *testing.T) {
	base := serve(t, &Server{Engine: fixedEngine{findings(2128, 1520)}, Log: logrus.New()})
	runtime.GC()
	var peak atomic.Uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var ms runtime.MemStats
		for {
			select {
			case <-stop:
				return
			default:
			}
			runtime.ReadMemStats(&ms)
			if ms.HeapInuse > peak.Load() {
				peak.Store(ms.HeapInuse)
			}
			time.Sleep(time.Millisecond)
		}
	}()
	resp := post(t, base)
	n, _ := io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	close(stop)
	<-done
	if n < 64<<20 {
		t.Fatalf("fixture too small: %d bytes", n)
	}
	// Encoding the whole body first (the old writeJSON) peaked at ~2x the
	// body, well over 150 MiB here.
	if peak.Load() > 48<<20 {
		t.Errorf("peak heap %d MiB while streaming %d MiB", peak.Load()>>20, n>>20)
	}
	t.Logf("streamed %.1f MiB with peak heap %.1f MiB", float64(n)/(1<<20), float64(peak.Load())/(1<<20))
}

func TestTooManyFindingsIs413(t *testing.T) {
	log, hook := test.NewNullLogger()
	resp := post(t, serve(t, &Server{Engine: fixedEngine{findings(wire.MaxFindings+1, 1)}, Log: log}))
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge || !strings.Contains(string(b), "too many findings: 20001 (max 20000)") {
		t.Errorf("%d %s", resp.StatusCode, b)
	}
	e := hook.LastEntry()
	if e == nil || e.Level != logrus.WarnLevel || e.Data["digest"] != "sha256:fan" || e.Data["findings"] != wire.MaxFindings+1 {
		t.Errorf("log: %+v", e)
	}
}

func TestClientGoneIsLogged(t *testing.T) {
	log, hook := test.NewNullLogger()
	resp := post(t, serve(t, &Server{Engine: fixedEngine{findings(2128, 1520)}, Log: log}))
	buf := make([]byte, 1<<10)
	_, _ = io.ReadFull(resp.Body, buf)
	_ = resp.Body.Close() // gone after 1 KiB, as a client at its size cap would be
	for i := 0; i < 500; i++ {
		for _, e := range hook.AllEntries() {
			if strings.HasPrefix(e.Message, "match response not delivered: client closed after ") && e.Data["digest"] == "sha256:fan" {
				if w, _ := e.Data["written"].(int64); w <= 0 || w >= 64<<20 {
					t.Errorf("written %v", e.Data["written"])
				}
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no write-error log: %+v", hook.AllEntries())
}

// A finding that cannot be encoded is our failure, logged as such, never
// as a client that went away.
func TestEncodeFailureIsLoggedApart(t *testing.T) {
	log, hook := test.NewNullLogger()
	vulns := findings(3, 2)
	nan := math.NaN()
	vulns[1].Score = &nan // json: unsupported value: NaN
	resp := post(t, serve(t, &Server{Engine: fixedEngine{vulns}, Log: log}))
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	// Nothing had reached the client: an explicit 500, not an empty 200.
	if resp.StatusCode != http.StatusInternalServerError || !strings.Contains(string(body), "encoding match response") {
		t.Fatalf("status %d, body %q", resp.StatusCode, body)
	}
	for i := 0; i < 500; i++ {
		for _, e := range hook.AllEntries() {
			if strings.HasPrefix(e.Message, "match response not delivered: client closed") {
				t.Fatalf("encode failure logged as a client close: %+v", e)
			}
			if e.Message == "match response not delivered: encoding failed" {
				if e.Level != logrus.ErrorLevel || e.Data["digest"] != "sha256:fan" ||
					!strings.Contains(e.Data[logrus.ErrorKey].(error).Error(), "finding 1 (CVE-2024-00001)") {
					t.Fatalf("%+v", e)
				}
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no encode-failure log: %+v", hook.AllEntries())
}

// Past the first 64 KiB the status is already sent: the body is cut short
// (the client reports it truncated) and the failure is still logged.
func TestEncodeFailureAfterBytesSentTruncates(t *testing.T) {
	log, hook := test.NewNullLogger()
	vulns := findings(400, 16)
	nan := math.NaN()
	vulns[350].Score = &nan
	resp := post(t, serve(t, &Server{Engine: fixedEngine{vulns}, Log: log}))
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(body) < 64<<10 || json.Valid(body) {
		t.Fatalf("status %d, %d bytes, valid %v", resp.StatusCode, len(body), json.Valid(body))
	}
	for i := 0; i < 500; i++ {
		for _, e := range hook.AllEntries() {
			if e.Message == "match response not delivered: encoding failed" {
				if w, _ := e.Data["written"].(int64); w <= 0 {
					t.Fatalf("written %v", e.Data["written"])
				}
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no encode-failure log: %+v", hook.AllEntries())
}
