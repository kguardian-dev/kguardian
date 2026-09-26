package match

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
)

// HTTPMatcher is the Matcher backed by the supplychain-matcher sidecar
// (a separate image embedding Grype) on loopback in the same pod. The
// wire format is documented in supplychain-matcher/internal/wire: the
// request is an ImageSBOM subset and the response's vulnerabilities use
// the same JSON field names as types.Vulnerability.
type HTTPMatcher struct {
	base string
	http *http.Client

	mu      sync.Mutex
	db      DBInfo
	scanner types.Scanner
}

// maxMatchResponse bounds one /match response.
const maxMatchResponse = 64 << 20

// NewHTTPMatcher returns a matcher for the sidecar at baseURL, which must
// be a loopback http URL.
func NewHTTPMatcher(baseURL string) (*HTTPMatcher, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || u.Scheme != "http" {
		return nil, fmt.Errorf("matcher URL %q must be http://127.0.0.1:<port>", baseURL)
	}
	h := u.Hostname()
	if h != "127.0.0.1" && h != "::1" && h != "localhost" {
		return nil, fmt.Errorf("matcher URL %q must be loopback: the matcher runs in the same pod", baseURL)
	}
	return &HTTPMatcher{
		base:    strings.TrimRight(u.String(), "/"),
		http:    &http.Client{Timeout: 5 * time.Minute},
		scanner: types.Scanner{Name: "grype", Vendor: "Anchore"},
	}, nil
}

type wireDB struct {
	Built         *time.Time `json:"built"`
	SchemaVersion string     `json:"schema_version"`
	Loaded        bool       `json:"loaded"`
	Scanner       string     `json:"scanner"`
}

func (m *HTTPMatcher) record(d wireDB) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if d.Loaded && d.Built != nil {
		m.db = DBInfo{Built: d.Built.UTC(), SchemaVersion: d.SchemaVersion}
	}
	if v, ok := strings.CutPrefix(d.Scanner, "grype "); ok {
		m.scanner.Version = v
	}
}

// DB asks the sidecar for its database status; on error it returns the
// last known value (zero before the first success).
func (m *HTTPMatcher) DB() DBInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, m.base+"/db", nil)
	if resp, err := m.http.Do(req); err == nil {
		var d wireDB
		if resp.StatusCode == http.StatusOK && json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d) == nil {
			m.record(d)
		}
		_ = resp.Body.Close()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.db
}

// Scanner identifies the matcher.
func (m *HTTPMatcher) Scanner() types.Scanner {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.scanner
}

// Match posts the SBOM's components to the sidecar.
func (m *HTTPMatcher) Match(ctx context.Context, s *types.ImageSBOM) ([]types.Vulnerability, error) {
	body := struct {
		Image struct {
			Digest string `json:"digest"`
		} `json:"image"`
		Components []types.Component `json:"components"`
	}{Components: s.Components}
	body.Image.Digest = s.Image.Digest
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(body); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.base+"/match", &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := m.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("matcher: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("matcher returned %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	var out struct {
		DB              wireDB                `json:"db"`
		Vulnerabilities []types.Vulnerability `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxMatchResponse)).Decode(&out); err != nil {
		return nil, fmt.Errorf("matcher response: %w", err)
	}
	m.record(out.DB)
	return out.Vulnerabilities, nil
}
