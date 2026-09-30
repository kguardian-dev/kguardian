package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// nodeSBOMServer serves GET /images/{digest}/sbom?source=node in the shape
// of broker/src/supplychain_read.rs (camelCase, file paths cut to 16 with
// filePathsTotal), n components in pages of the requested limit.
func nodeSBOMServer(t *testing.T, digest string, n int, mutate func(page int, body map[string]interface{})) *httptest.Server {
	t.Helper()
	page := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/images/"+digest+"/sbom" || r.URL.Query().Get("source") != "node" {
			http.Error(w, "bad request", 400)
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		after, _ := strconv.Atoi(r.URL.Query().Get("after"))
		var items []map[string]interface{}
		for id := after + 1; id <= n && len(items) < limit; id++ {
			paths := []string{}
			for p := 0; p < 16; p++ {
				paths = append(paths, fmt.Sprintf("/usr/lib/p%d/%d", id, p))
			}
			items = append(items, map[string]interface{}{"id": id, "name": fmt.Sprintf("pkg%d", id), "version": "1.0",
				"purl": fmt.Sprintf("pkg:deb/debian/pkg%d@1.0?arch=arm64", id), "type": "deb", "srcName": "src", "srcVersion": "1.0",
				"licenses": []string{"MIT"}, "filePaths": paths, "filePathsTotal": 40})
		}
		var next interface{}
		if len(items) == limit && after+limit < n {
			next = after + limit
		}
		body := map[string]interface{}{
			"digest": digest,
			"report": map[string]interface{}{"source": "node", "reportDigest": digest, "join": "image_id", "digestKind": "unknown",
				"scannedAt": "2026-09-30T10:00:00.123456", "receivedAt": "2026-09-30T10:00:01", "itemCount": n,
				"sbomFormat": "CycloneDX", "sbomTrust": "scanned"},
			"items":     items,
			"nextAfter": next,
		}
		if mutate != nil {
			mutate(page, body)
		}
		page++
		_ = json.NewEncoder(w).Encode(body)
	}))
}

func TestNodeSBOMPagesWithoutFilePaths(t *testing.T) {
	const d = "sha256:aa"
	srv := nodeSBOMServer(t, d, 1203, nil)
	defer srv.Close()
	c, _ := NewReadClient(srv.URL, "t")
	doc, err := c.NodeSBOM(context.Background(), d, 50000)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 1203 || doc.Format != "CycloneDX" || doc.Trust != "scanned" || doc.ScannedAt != "2026-09-30T10:00:00.123456" {
		t.Fatalf("doc: %d components, %+v", len(doc.Components), doc.Format)
	}
	c0 := doc.Components[0]
	if c0.Name != "pkg1" || c0.PURL != "pkg:deb/debian/pkg1@1.0?arch=arm64" || c0.SrcName != "src" || c0.Type != "deb" || len(c0.Licenses) != 1 {
		t.Errorf("component %+v", c0)
	}
	for _, comp := range doc.Components {
		if comp.FilePaths != nil {
			t.Fatalf("file paths kept: %+v", comp)
		}
	}
}

func TestNodeSBOMOutcomes(t *testing.T) {
	const d = "sha256:aa"
	cases := []struct {
		name   string
		n      int
		max    int
		mutate func(int, map[string]interface{})
		want   error
		none   bool
	}{
		{name: "none", mutate: func(_ int, b map[string]interface{}) { b["report"] = nil }, none: true},
		{name: "too large by count", n: 20, max: 10, want: ErrNodeSBOMTooLarge},
		{name: "replaced mid-read", n: 1200, max: 50000, want: ErrNodeSBOMChanged, mutate: func(p int, b map[string]interface{}) {
			if p == 1 {
				b["report"].(map[string]interface{})["receivedAt"] = "2026-09-30T11:00:00"
			}
		}},
		{name: "deleted mid-read", n: 1200, max: 50000, want: ErrNodeSBOMChanged, mutate: func(p int, b map[string]interface{}) {
			if p == 1 {
				b["report"] = nil
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := nodeSBOMServer(t, d, tc.n, tc.mutate)
			defer srv.Close()
			c, _ := NewReadClient(srv.URL, "t")
			doc, err := c.NodeSBOM(context.Background(), d, tc.max)
			if tc.none {
				if err != nil || doc != nil {
					t.Fatalf("want none, got %v %v", doc, err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err %v, want %v", err, tc.want)
			}
		})
	}
}

// Another source's report, or one under another digest, is never taken
// for this digest's node SBOM.
func TestNodeSBOMRefusesAnotherReport(t *testing.T) {
	const d = "sha256:aa"
	for _, m := range []func(int, map[string]interface{}){
		func(_ int, b map[string]interface{}) { b["report"].(map[string]interface{})["source"] = "trivy-operator" },
		func(_ int, b map[string]interface{}) { b["report"].(map[string]interface{})["reportDigest"] = "sha256:bb" },
	} {
		srv := nodeSBOMServer(t, d, 3, m)
		c, _ := NewReadClient(srv.URL, "t")
		if doc, err := c.NodeSBOM(context.Background(), d, 0); err == nil {
			t.Errorf("accepted %+v", doc)
		}
		srv.Close()
	}
}

func TestNodeCatalogAvailable(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   error
		other  bool
	}{
		{status: 200},
		{status: 503}, // catalog token not configured: stored SBOMs still readable
		{status: 404, want: ErrNoNodeCatalog},
		{status: 500, other: true},
		{status: 403, other: true},
	} {
		var path, auth string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path, auth = r.URL.RequestURI(), r.Header.Get("Authorization")
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte("{}"))
		}))
		c, _ := NewReadClient(srv.URL, "sc")
		err := c.NodeCatalogAvailable(context.Background())
		srv.Close()
		if path != "/catalog/status?node=kguardian-supplychain-probe" || auth != "Bearer sc" {
			t.Errorf("probe %q auth %q", path, auth)
		}
		switch {
		case tc.other:
			if err == nil || errors.Is(err, ErrNoNodeCatalog) {
				t.Errorf("%d: err %v", tc.status, err)
			}
		case !errors.Is(err, tc.want) && err != tc.want:
			t.Errorf("%d: err %v, want %v", tc.status, err, tc.want)
		}
	}
	// An old broker also has no node SBOM route semantics: a 404 there
	// means the same.
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	c, _ := NewReadClient(srv.URL, "")
	if _, err := c.NodeSBOM(context.Background(), "sha256:aa", 0); !errors.Is(err, ErrNoNodeCatalog) {
		t.Errorf("404 sbom: %v", err)
	}
}

// The new image fields decode, and an old broker's items (without them)
// still do.
func TestImageNodeCatalogFields(t *testing.T) {
	var p imagePage
	body := `{"items":[
	 {"digest":"sha256:aa","repository":"docker.io/library/nginx","tags":["1"],"digestKind":"repo","runningContainers":2,
	  "sbomSources":["node","trivy-operator"],
	  "nodeCatalog":{"state":"done","platform":"linux/arm64","completeness":"full","catalogedAt":"2026-09-30T10:00:00Z"}},
	 {"digest":"sha256:bb","repository":"x","tags":[],"digestKind":"repo","runningContainers":1}],"nextAfter":null}`
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatal(err)
	}
	a, b := p.Items[0], p.Items[1]
	if !a.HasSBOM("node") || a.NodeCatalog == nil || a.NodeCatalog.Platform != "linux/arm64" || a.NodeCatalog.CatalogedAt != "2026-09-30T10:00:00Z" {
		t.Errorf("new fields: %+v", a)
	}
	if b.HasSBOM("node") || b.NodeCatalog != nil {
		t.Errorf("old item: %+v", b)
	}
}
