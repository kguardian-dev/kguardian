package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
)

// ErrNoNodeCatalog means the broker predates the node catalog: its
// catalog routes answer 404.
var ErrNoNodeCatalog = errors.New("broker has no node catalog")

// ErrNodeSBOMTooLarge means a node SBOM has more components than the
// caller's limit; nothing of it is returned.
var ErrNodeSBOMTooLarge = errors.New("node SBOM exceeds the component limit")

// ErrNodeSBOMChanged means the node SBOM was replaced while its pages were
// being read; the pages do not belong to one document.
var ErrNodeSBOMChanged = errors.New("node SBOM changed while it was being read")

// nodeCatalogProbeNode is the node name the availability probe asks
// about. Any valid name works: an unknown node gets an empty status.
const nodeCatalogProbeNode = "kguardian-supplychain-probe"

// nodeSBOMPageLimit is the page size asked for (the broker's maximum).
const nodeSBOMPageLimit = 500

// A page answered 503 (the broker's read budget shedding load) is asked
// again after its Retry-After, at most maxPageRetries times per page and
// never waiting longer than maxRetryAfter at a time.
const (
	maxPageRetries = 3
	maxRetryAfter  = 30 * time.Second
)

// NodeCatalogAvailable reports whether the broker has the node catalog,
// with one cheap read (GET /catalog/status, read scope). It returns
// ErrNoNodeCatalog on a 404 and a *StatusError for any other refusal
// (401 and 403 included). A 503 (catalog token not configured) still
// counts as available: node SBOMs stored earlier can be read.
func (c *ReadClient) NodeCatalogAvailable(ctx context.Context) error {
	resp, err := c.get(ctx, "/catalog/status?"+url.Values{"node": {nodeCatalogProbeNode}}.Encode())
	if err != nil {
		return err
	}
	switch {
	case resp.status == http.StatusNotFound:
		return ErrNoNodeCatalog
	case resp.status/100 == 2, resp.status == http.StatusServiceUnavailable:
		return nil
	}
	return &StatusError{Path: "/catalog/status", StatusCode: resp.status, Body: errorBody(resp.body)}
}

// NodeSBOM is a node catalog SBOM as the broker serves it, components
// only.
type NodeSBOM struct {
	Digest    string
	Format    string
	Trust     string
	ScannedAt string
	// Components carry no file paths: the broker cuts them to 16 on this
	// route, and matching does not use them.
	Components []types.Component
}

// nodeSBOMReport is the part of a report (broker/src/supplychain_read.rs
// Report) read here.
type nodeSBOMReport struct {
	Source       string `json:"source"`
	ReportDigest string `json:"reportDigest"`
	ScannedAt    string `json:"scannedAt"`
	ReceivedAt   string `json:"receivedAt"`
	ItemCount    int    `json:"itemCount"`
	SBOMFormat   string `json:"sbomFormat"`
	SBOMTrust    string `json:"sbomTrust"`
}

type nodeSBOMComponent struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	PURL        string   `json:"purl"`
	Type        string   `json:"type"`
	Class       string   `json:"class"`
	SrcName     string   `json:"srcName"`
	SrcVersion  string   `json:"srcVersion"`
	Licenses    []string `json:"licenses"`
	LayerDigest string   `json:"layerDigest"`
}

type nodeSBOMPage struct {
	Report    *nodeSBOMReport     `json:"report"`
	Items     []nodeSBOMComponent `json:"items"`
	NextAfter *int64              `json:"nextAfter"`
}

// NodeSBOM reads digest's node SBOM (GET /images/{digest}/sbom?source=node,
// read scope, paged). It returns nil, nil when there is none, and
// ErrNodeSBOMTooLarge past maxComponents (<= 0: no limit). A node SBOM is
// linked only to its own digest, so a report under another digest is
// refused. Any non-2xx answer is a *StatusError (a 404 here is not a sign
// of an old broker: this route predates the node catalog).
//
// Paging consistency: the pages are read one request at a time, so the
// SBOM can be replaced in between. Each page repeats the report header,
// and a page whose scannedAt or receivedAt differs from the first page's
// ends the read with ErrNodeSBOMChanged. A replacement the header does
// not reveal (both timestamps equal to the second) still heals itself:
// the replacement carries a new catalogedAt in GET /images, so the next
// pass reads it again whole. And a mixed read can only be wrong by adding
// or missing node packages for one pass; it cannot touch what Trivy or a
// registry SBOM contribute, since a node SBOM only ever adds to the
// union.
func (c *ReadClient) NodeSBOM(ctx context.Context, digest string, maxComponents int) (*NodeSBOM, error) {
	path := "/images/" + url.PathEscape(digest) + "/sbom"
	var out *NodeSBOM
	var first *nodeSBOMReport
	after := int64(0)
	for {
		q := url.Values{"source": {types.SourceNode}, "limit": {strconv.Itoa(nodeSBOMPageLimit)}}
		if after > 0 {
			q.Set("after", strconv.FormatInt(after, 10))
		}
		resp, err := c.getRetrying(ctx, path+"?"+q.Encode())
		if err != nil {
			return nil, err
		}
		if resp.status/100 != 2 {
			return nil, &StatusError{Path: path, StatusCode: resp.status, Body: errorBody(resp.body)}
		}
		var p nodeSBOMPage
		if err := json.Unmarshal(resp.body, &p); err != nil {
			return nil, fmt.Errorf("GET %s: %w", path, err)
		}
		if p.Report == nil {
			if first != nil {
				return nil, ErrNodeSBOMChanged // deleted mid-read
			}
			return nil, nil
		}
		if p.Report.Source != types.SourceNode || p.Report.ReportDigest != digest {
			return nil, fmt.Errorf("GET %s: got the %s SBOM of %s, want the node SBOM of this digest", path, p.Report.Source, p.Report.ReportDigest)
		}
		if first == nil {
			first = p.Report
			if maxComponents > 0 && first.ItemCount > maxComponents {
				return nil, fmt.Errorf("%s: %d components (limit %d): %w", digest, first.ItemCount, maxComponents, ErrNodeSBOMTooLarge)
			}
			out = &NodeSBOM{Digest: digest, Format: first.SBOMFormat, Trust: first.SBOMTrust, ScannedAt: first.ScannedAt,
				Components: make([]types.Component, 0, max(first.ItemCount, 0))}
		} else if p.Report.ReceivedAt != first.ReceivedAt || p.Report.ScannedAt != first.ScannedAt {
			return nil, ErrNodeSBOMChanged
		}
		for _, it := range p.Items {
			out.Components = append(out.Components, types.Component{
				Name: it.Name, Version: it.Version, PURL: it.PURL, Type: it.Type, Class: it.Class,
				SrcName: it.SrcName, SrcVersion: it.SrcVersion, Licenses: it.Licenses, LayerDigest: it.LayerDigest,
			})
		}
		if maxComponents > 0 && len(out.Components) > maxComponents {
			return nil, fmt.Errorf("%s: more than %d components: %w", digest, maxComponents, ErrNodeSBOMTooLarge)
		}
		if p.NextAfter == nil || *p.NextAfter <= after {
			return out, nil
		}
		after = *p.NextAfter
	}
}

type getResult struct {
	status     int
	body       []byte
	retryAfter string
}

// getRetrying is get, asking again after a 503's Retry-After (bounded; see
// maxPageRetries). A 503 without Retry-After, or still 503 after the
// retries, is returned as it is.
func (c *ReadClient) getRetrying(ctx context.Context, pathAndQuery string) (getResult, error) {
	for attempt := 0; ; attempt++ {
		resp, err := c.get(ctx, pathAndQuery)
		if err != nil || resp.status != http.StatusServiceUnavailable || attempt == maxPageRetries {
			return resp, err
		}
		wait, ok := parseRetryAfter(resp.retryAfter)
		if !ok {
			return resp, nil
		}
		sleep := c.sleep
		if sleep == nil {
			sleep = sleepCtx
		}
		if err := sleep(ctx, min(wait, maxRetryAfter)); err != nil {
			return resp, err
		}
	}
}

// parseRetryAfter reads Retry-After in seconds (the form the broker
// sends); an HTTP date is also accepted.
func parseRetryAfter(v string) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return time.Duration(n) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(time.Until(t), 0), true
	}
	return 0, false
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// get performs one authorised GET and returns the status, a body of at
// most maxPageBytes and any Retry-After.
func (c *ReadClient) get(ctx context.Context, pathAndQuery string) (getResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+pathAndQuery, nil)
	if err != nil {
		return getResult{}, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	path := pathAndQuery
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return getResult{}, fmt.Errorf("GET %s: %w", path, err)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPageBytes+1))
	_ = resp.Body.Close()
	if err != nil {
		return getResult{}, fmt.Errorf("GET %s: %w", path, err)
	}
	if len(body) > maxPageBytes {
		return getResult{}, fmt.Errorf("GET %s: response exceeds %d bytes", path, maxPageBytes)
	}
	return getResult{status: resp.StatusCode, body: body, retryAfter: resp.Header.Get("Retry-After")}, nil
}

func errorBody(b []byte) string {
	return strings.TrimSpace(string(b[:min(len(b), maxErrorBody)]))
}
