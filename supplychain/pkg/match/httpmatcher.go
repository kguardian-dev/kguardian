package match

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
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

// maxMatchResponse bounds one /match response. With findings capped at
// types.MaxFindings and their file paths at types.MaxFindingFilePaths a
// real response stays well under it.
const maxMatchResponse = 64 << 20

// Why a match produced no result. Both are logged and counted by the
// coordinator; neither is ever a bare JSON error.
var (
	// ErrTooLarge: the result for this SBOM is over a limit (the
	// matcher's 413, the response byte cap, or the findings cap). The
	// same SBOM against the same database will fail the same way.
	ErrTooLarge = errors.New("match result too large")
	// ErrTruncated: the response ended before it was complete (the
	// matcher went away mid-body).
	ErrTruncated = errors.New("matcher response truncated")
	// ErrUnavailable: the matcher could not be asked (connection failed,
	// or it answered 502/503/504, e.g. restarting or loading its
	// database). Says nothing about the SBOM.
	ErrUnavailable = errors.New("matcher unavailable")
)

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
		if ctx.Err() != nil {
			return nil, fmt.Errorf("matcher: %w", err)
		}
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		err := fmt.Errorf("matcher returned %s: %s", resp.Status, strings.TrimSpace(string(msg)))
		switch resp.StatusCode {
		case http.StatusRequestEntityTooLarge:
			err = fmt.Errorf("%w: %w", ErrTooLarge, err)
		case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			err = fmt.Errorf("%w: %w", ErrUnavailable, err)
		}
		return nil, err
	}
	db, vulns, err := decodeMatch(resp.Body, maxMatchResponse, types.MaxFindings)
	if err != nil {
		return nil, err
	}
	m.record(db)
	return vulns, nil
}

// decodeMatch reads a /match response one finding at a time, so memory is
// bounded by the findings kept, not by the body. Each finding keeps at
// most types.MaxFindingFilePaths paths. Over maxBytes, or more than
// maxFindings findings, is ErrTooLarge; a body that ends early is
// ErrTruncated.
func decodeMatch(r io.Reader, maxBytes int64, maxFindings int) (wireDB, []types.Vulnerability, error) {
	var db wireDB
	var out []types.Vulnerability
	cr := &capReader{r: r, left: maxBytes}
	dec := json.NewDecoder(cr)
	fail := func(err error) error {
		switch {
		case cr.over:
			return fmt.Errorf("%w: matcher response exceeds %d MiB", ErrTooLarge, maxBytes>>20)
		case errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF):
			return fmt.Errorf("%w after %d bytes: connection closed", ErrTruncated, cr.n)
		}
		return fmt.Errorf("matcher response: %w", err)
	}
	delim := func(want json.Delim) error {
		tok, err := dec.Token()
		if err != nil {
			return fail(err)
		}
		if d, ok := tok.(json.Delim); !ok || d != want {
			return fmt.Errorf("matcher response: expected %q, got %v", want, tok)
		}
		return nil
	}
	if err := delim('{'); err != nil {
		return db, nil, err
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return db, nil, fail(err)
		}
		switch tok {
		case "db":
			if err := dec.Decode(&db); err != nil {
				return db, nil, fail(err)
			}
		case "vulnerabilities":
			tok, err := dec.Token()
			if err != nil {
				return db, nil, fail(err)
			}
			if tok == nil {
				continue // null: no findings
			}
			if d, ok := tok.(json.Delim); !ok || d != '[' {
				return db, nil, fmt.Errorf("matcher response: vulnerabilities is %v", tok)
			}
			for dec.More() {
				if len(out) >= maxFindings {
					return db, nil, fmt.Errorf("%w: more than %d findings", ErrTooLarge, maxFindings)
				}
				var v types.Vulnerability
				if err := dec.Decode(&v); err != nil {
					return db, nil, fail(err)
				}
				v.FilePaths = types.CapFilePaths(v.FilePaths)
				out = append(out, v)
			}
			if err := delim(']'); err != nil {
				return db, nil, err
			}
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return db, nil, fail(err)
			}
		}
	}
	if err := delim('}'); err != nil {
		return db, nil, err
	}
	return db, out, nil
}

// capReader passes at most left bytes through and notices a byte past
// them: the difference between a body over the cap (over) and one that
// ended (EOF).
type capReader struct {
	r    io.Reader
	left int64
	n    int64
	over bool
}

var errOverCap = errors.New("over the response cap")

func (c *capReader) Read(p []byte) (int, error) {
	if c.over {
		return 0, errOverCap
	}
	if int64(len(p)) > c.left+1 {
		p = p[:c.left+1]
	}
	n, err := c.r.Read(p)
	if int64(n) > c.left {
		n = int(c.left)
		c.over = true
		err = errOverCap
	}
	c.left -= int64(n)
	c.n += int64(n)
	return n, err
}
