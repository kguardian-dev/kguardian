package match

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
)

// streamFindings serves a /match body of n findings that all carry the
// same files list, written one at a time so the test server itself stays
// small. n=2128, files=1520 is the kernel-headers fan-out that an
// unfixed matcher sent for ghcr.io/open-webui/open-webui:0.11.3.
func streamFindings(n, files int) http.HandlerFunc {
	paths := make([]string, files)
	for i := range paths {
		paths[i] = fmt.Sprintf("usr/include/linux/header-%05d.h", i)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/db" {
			_, _ = w.Write([]byte(`{"loaded":true}`))
			return
		}
		bw := bufio.NewWriter(w)
		_, _ = bw.WriteString(`{"db":{"loaded":true,"scanner":"grype v0.119.0"},"vulnerabilities":[`)
		for i := 0; i < n; i++ {
			if i > 0 {
				_ = bw.WriteByte(',')
			}
			b, _ := json.Marshal(types.Vulnerability{ID: fmt.Sprintf("CVE-2024-%05d", i), Severity: "HIGH",
				Package: types.Package{Name: "linux-libc-dev", Version: "6.1.180-1"}, FilePaths: paths})
			if _, err := bw.Write(b); err != nil {
				return
			}
		}
		_, _ = bw.WriteString("]}\n")
		_ = bw.Flush()
	}
}

func sbomFor(d string) *types.ImageSBOM {
	return &types.ImageSBOM{Image: types.ImageRef{Digest: d}, Components: []types.Component{{Name: "linux-libc-dev"}}}
}

func matcherFor(t *testing.T, h http.Handler) *HTTPMatcher {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	m, err := NewHTTPMatcher(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// The response that OOMKilled supplychain: ~108 MiB, over the 64 MiB cap.
// It must end as ErrTooLarge (never a bare "unexpected EOF") without
// buffering the body: the old decoder peaked at ~225 MiB here.
func TestOOMShapedResponseIsTooLargeWithBoundedHeap(t *testing.T) {
	m := matcherFor(t, streamFindings(2128, 1520))
	runtime.GC()
	var peak atomic.Uint64
	stop, done := make(chan struct{}), make(chan struct{})
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
	vs, err := m.Match(context.Background(), sbomFor("sha256:2349f3f7"))
	close(stop)
	<-done
	if !errors.Is(err, ErrTooLarge) || !strings.Contains(err.Error(), "exceeds 64 MiB") || vs != nil {
		t.Fatalf("got %d, %v", len(vs), err)
	}
	if peak.Load() > 48<<20 {
		t.Errorf("peak heap %d MiB", peak.Load()>>20)
	}
	t.Logf("%v; peak heap %.1f MiB", err, float64(peak.Load())/(1<<20))
}

func TestMatcher413IsTooLarge(t *testing.T) {
	m := matcherFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "too many findings: 20001 (max 20000)", http.StatusRequestEntityTooLarge)
	}))
	_, err := m.Match(context.Background(), sbomFor("sha256:x"))
	if !errors.Is(err, ErrTooLarge) || !strings.Contains(err.Error(), "413") || !strings.Contains(err.Error(), "too many findings") {
		t.Fatal(err)
	}
}

func TestTooManyFindingsInAResponseIsTooLarge(t *testing.T) {
	m := matcherFor(t, streamFindings(types.MaxFindings+1, 0))
	if _, err := m.Match(context.Background(), sbomFor("sha256:x")); !errors.Is(err, ErrTooLarge) ||
		!strings.Contains(err.Error(), "more than 20000 findings") {
		t.Fatal(err)
	}
}

// A body that ends early is named as such, with how far it got.
func TestTruncatedResponseIsNamed(t *testing.T) {
	m := matcherFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100000")
		_, _ = w.Write([]byte(`{"db":{"loaded":true},"vulnerabilities":[{"id":"CVE-1","package":{"name":"a"},"severity":"HIGH"},{"id":"CVE-`))
		conn, _, _ := w.(http.Hijacker).Hijack()
		_ = conn.Close()
	}))
	_, err := m.Match(context.Background(), sbomFor("sha256:x"))
	if !errors.Is(err, ErrTruncated) || errors.Is(err, ErrTooLarge) || !strings.Contains(err.Error(), "connection closed") {
		t.Fatal(err)
	}
}

// An older matcher still sends every path: kept to the broker's 16, in
// copies that do not pin the long list.
func TestFilePathsAreCapped(t *testing.T) {
	m := matcherFor(t, streamFindings(3, 1520))
	vs, err := m.Match(context.Background(), sbomFor("sha256:x"))
	if err != nil || len(vs) != 3 {
		t.Fatal(len(vs), err)
	}
	for _, v := range vs {
		if len(v.FilePaths) != types.MaxFindingFilePaths || cap(v.FilePaths) != types.MaxFindingFilePaths {
			t.Errorf("%s: %d paths (cap %d)", v.ID, len(v.FilePaths), cap(v.FilePaths))
		}
	}
	empty := matcherFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"db":{"loaded":true},"vulnerabilities":null,"extra":{"x":[1,2]}}`))
	}))
	if vs, err := empty.Match(context.Background(), sbomFor("sha256:x")); err != nil || len(vs) != 0 {
		t.Fatal(vs, err)
	}
}

// A matcher that cannot be reached, or that says it is not ready, is
// unavailable, never a failure of the SBOM.
func TestUnreachableOrNotReadyIsUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // refused from now on
	m, _ := NewHTTPMatcher(url)
	if _, err := m.Match(context.Background(), sbomFor("sha256:x")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("refused: %v", err)
	}
	for _, code := range []int{http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusGatewayTimeout} {
		m := matcherFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "vulnerability database not loaded", code)
		}))
		if _, err := m.Match(context.Background(), sbomFor("sha256:x")); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrTooLarge) {
			t.Errorf("%d: %v", code, err)
		}
	}
	m500 := matcherFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "match failed: boom", http.StatusInternalServerError)
	}))
	if _, err := m500.Match(context.Background(), sbomFor("sha256:x")); err == nil || errors.Is(err, ErrUnavailable) {
		t.Errorf("500 is a failure of this match: %v", err)
	}
}
