package broker

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
	"github.com/sirupsen/logrus"
)

const testDigest = "sha256:53a13cd1588391888c5a8ac4cef13d3ee6d229cd904038936731af7131d193a9"

type captured struct {
	path, auth, ct, ce string
	body               []byte // decompressed
	compressed         int
}

func recorder(t *testing.T, status int) (*httptest.Server, func() []captured) {
	t.Helper()
	var mu sync.Mutex
	var got []captured
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		c := captured{path: r.URL.EscapedPath(), auth: r.Header.Get("Authorization"),
			ct: r.Header.Get("Content-Type"), ce: r.Header.Get("Content-Encoding"), compressed: len(raw)}
		if zr, err := gzip.NewReader(strings.NewReader(string(raw))); err == nil {
			c.body, _ = io.ReadAll(zr)
		}
		mu.Lock()
		got = append(got, c)
		mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []captured { mu.Lock(); defer mu.Unlock(); return append([]captured(nil), got...) }
}

func TestHTTPClientSendsGzipBearerJSON(t *testing.T) {
	srv, got := recorder(t, http.StatusAccepted)
	c, err := NewHTTPClient(srv.URL+"/", " scoped-token\n")
	if err != nil {
		t.Fatal(err)
	}
	p := &types.ImageVulnerabilities{SchemaVersion: 1, Image: types.ImageRef{Digest: testDigest}, Source: types.SourceTrivyOperator}
	if err := c.SubmitVulnerabilities(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	r := got()[0]
	if r.auth != "Bearer scoped-token" || r.ct != "application/json" || r.ce != "gzip" {
		t.Errorf("headers: %+v", r)
	}
	if !strings.HasPrefix(r.path, "/images/sha256:53a1") || !strings.HasSuffix(r.path, "/vulnerabilities") {
		t.Errorf("path = %q", r.path)
	}
	var back types.ImageVulnerabilities
	if err := json.Unmarshal(r.body, &back); err != nil || back.Image.Digest != testDigest {
		t.Errorf("body did not round-trip through gzip: %v %+v", err, back)
	}
}

func TestHTTPClientNoTokenNoHeader(t *testing.T) {
	srv, got := recorder(t, http.StatusOK)
	c, _ := NewHTTPClient(srv.URL, "")
	if err := c.SubmitSBOM(context.Background(), &types.ImageSBOM{Image: types.ImageRef{Digest: testDigest}}); err != nil {
		t.Fatal(err)
	}
	if got()[0].auth != "" {
		t.Error("sent an Authorization header with no token configured")
	}
}

func TestHTTPClientStatusErrorClassification(t *testing.T) {
	cases := map[int]bool{400: false, 401: false, 403: false, 404: false, 413: false, 422: false,
		408: true, 429: true, 500: true, 502: true, 503: true}
	for code, retry := range cases {
		srv, _ := recorder(t, code)
		c, _ := NewHTTPClient(srv.URL, "t")
		err := c.SubmitSBOM(context.Background(), &types.ImageSBOM{Image: types.ImageRef{Digest: testDigest}})
		var se *StatusError
		if !errors.As(err, &se) || se.StatusCode != code {
			t.Fatalf("%d: err = %v", code, err)
		}
		if Retryable(err) != retry {
			t.Errorf("%d: Retryable = %v, want %v", code, !retry, retry)
		}
		if Reason(err) != fmt.Sprintf("http_%d", code) {
			t.Errorf("%d: reason %q", code, Reason(err))
		}
	}
	if !Retryable(errors.New("dial tcp: connection refused")) || Reason(errors.New("x")) != "network" {
		t.Error("network errors must be retryable")
	}
	if Retryable(fmt.Errorf("wrap: %w", ErrPayloadTooLarge)) {
		t.Error("oversized payloads must not be retried")
	}
}

func TestNewHTTPClientRejectsBadURL(t *testing.T) {
	for _, u := range []string{"", "broker:9090", "://x"} {
		if _, err := NewHTTPClient(u, ""); err == nil {
			t.Errorf("NewHTTPClient(%q) accepted", u)
		}
	}
}

// randomComponents are deliberately incompressible-ish so small limits
// force paging.
func randomComponents(n int) []types.Component {
	r := rand.New(rand.NewSource(1))
	out := make([]types.Component, n)
	for i := range out {
		b := make([]byte, 64)
		for j := range b {
			b[j] = byte('a' + r.Intn(26))
		}
		out[i] = types.Component{Name: string(b), Version: fmt.Sprint(i), PURL: "pkg:generic/" + string(b)}
	}
	return out
}

func TestSBOMPagingStaysUnderLimitAndReassembles(t *testing.T) {
	srv, got := recorder(t, http.StatusOK)
	c, _ := NewHTTPClient(srv.URL, "")
	c.MaxBytes = 16 << 10
	c.PageComponents = 1000
	p := &types.ImageSBOM{SchemaVersion: 1, Image: types.ImageRef{Digest: testDigest}, Format: "CycloneDX",
		Components: randomComponents(3000)}
	if err := c.SubmitSBOM(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	reqs := got()
	if len(reqs) < 2 {
		t.Fatalf("expected paging, got %d request(s)", len(reqs))
	}
	var all []types.Component
	var setID string
	for i, r := range reqs {
		if r.compressed > c.MaxBytes {
			t.Errorf("page %d is %d bytes compressed (limit %d)", i, r.compressed, c.MaxBytes)
		}
		var page types.ImageSBOM
		if err := json.Unmarshal(r.body, &page); err != nil {
			t.Fatal(err)
		}
		if page.Page == nil || page.Page.Index != i || page.Page.Total != len(reqs) {
			t.Fatalf("page %d header: %+v", i, page.Page)
		}
		if setID == "" {
			setID = page.Page.SetID
		} else if page.Page.SetID != setID {
			t.Errorf("set id changed across pages")
		}
		if page.Image.Digest != testDigest || page.Format != "CycloneDX" {
			t.Errorf("page %d lost its header", i)
		}
		all = append(all, page.Components...)
	}
	if len(all) != 3000 || all[0].Version != "0" || all[2999].Version != "2999" {
		t.Errorf("reassembled %d components, order broken", len(all))
	}
}

func TestSBOMSmallIsOnePageWithoutPageField(t *testing.T) {
	c, _ := NewHTTPClient("http://broker:9090", "")
	pages, err := c.PageSBOM(&types.ImageSBOM{Components: randomComponents(10)})
	if err != nil || len(pages) != 1 {
		t.Fatalf("pages=%d err=%v", len(pages), err)
	}
	if strings.Contains(string(mustGunzip(t, pages[0])), `"page"`) {
		t.Error("single-request SBOM must not carry a page field")
	}
}

func TestOversizedSingleComponentIsPermanent(t *testing.T) {
	// Unroutable on purpose: nothing may be sent.
	c, _ := NewHTTPClient("http://127.0.0.1:1", "")
	c.MaxBytes = 80
	_, err := c.PageSBOM(&types.ImageSBOM{Components: randomComponents(4)})
	if !errors.Is(err, ErrPayloadTooLarge) || Retryable(err) {
		t.Fatalf("err = %v", err)
	}
	err = c.SubmitVulnerabilities(context.Background(), &types.ImageVulnerabilities{
		Vulnerabilities: []types.Vulnerability{{ID: randomComponents(40)[39].Name + randomComponents(40)[7].Name}}})
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("vulns err = %v", err)
	}
}

func mustGunzip(t *testing.T, b []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(zr)
	return out
}

func TestLoggingClientNeverFails(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)
	c := LoggingClient{Log: log}
	if err := c.SubmitVulnerabilities(context.Background(), &types.ImageVulnerabilities{}); err != nil {
		t.Fatal(err)
	}
	if err := c.SubmitSBOM(context.Background(), &types.ImageSBOM{}); err != nil {
		t.Fatal(err)
	}
}
