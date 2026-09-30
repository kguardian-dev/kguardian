package nodesource

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/broker"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/match"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/trivy"
	"github.com/sirupsen/logrus"
)

type captureSink struct {
	mu sync.Mutex
	es []trivy.Emission
}

func (s *captureSink) Enqueue(e trivy.Emission) { s.mu.Lock(); s.es = append(s.es, e); s.mu.Unlock() }

// End to end against a real matcher sidecar: a node SBOM served by a fake
// broker in the shape of GET /images and GET /images/{digest}/sbom goes
// through this source, the match coordinator and the HTTP matcher, and
// comes out as a grype payload with a known CVE.
//
// Like supplychain-matcher's TestMatchRealDB it needs the vulnerability
// database, so it is skipped unless GRYPE_MATCHER_TEST_URL points at a
// running supplychain-matcher (loopback) with a database loaded, e.g.
//
//	LISTEN_ADDR=127.0.0.1:18090 GRYPE_DB_DIR=/tmp/grypedb supplychain-matcher serve
//	GRYPE_MATCHER_TEST_URL=http://127.0.0.1:18090 go test ./pkg/nodesource -run E2E
//
// Run locally on 2026-09-30 against the v6.1.9 DB built 2026-09-29.
func TestE2ENodeSBOMYieldsKnownCVE(t *testing.T) {
	url := os.Getenv("GRYPE_MATCHER_TEST_URL")
	if url == "" {
		t.Skip("GRYPE_MATCHER_TEST_URL not set")
	}
	const digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	// libc6 from Debian 12 before 2.36-9+deb12u3, the fix for
	// CVE-2023-4911 ("Looney Tunables"), as a node catalog SBOM lists it:
	// Syft's PURL (arch, distro, upstream) plus the source package.
	sbomPage := map[string]interface{}{
		"digest": digest,
		"report": map[string]interface{}{"source": "node", "reportDigest": digest, "join": "image_id", "digestKind": "unknown",
			"scannedAt": "2026-09-30T10:00:00", "receivedAt": "2026-09-30T10:00:01", "itemCount": 2,
			"sbomFormat": "CycloneDX", "sbomTrust": "scanned"},
		"items": []map[string]interface{}{
			{"id": 1, "name": "debian", "version": "12", "type": "operating-system", "licenses": []string{}, "filePaths": []string{}},
			{"id": 2, "name": "libc6", "version": "2.36-9+deb12u1", "type": "deb",
				"purl":    "pkg:deb/debian/libc6@2.36-9%2Bdeb12u1?arch=arm64&distro=debian-12&upstream=glibc",
				"srcName": "glibc", "srcVersion": "2.36-9+deb12u1", "licenses": []string{"LGPL-2.1"},
				"filePaths": []string{"/usr/lib/aarch64-linux-gnu/libc.so.6"}},
		},
		"nextAfter": nil,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/catalog/status":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"node": r.URL.Query().Get("node"), "claims": []string{}})
		case "/images":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"items": []map[string]interface{}{{
				"digest": digest, "repository": "docker.io/library/debian", "tags": []string{"12"}, "digestKind": "repo",
				"runningContainers": 1, "sbomSources": []string{"node"},
				"nodeCatalog": map[string]interface{}{"state": "done", "platform": "linux/arm64", "completeness": "full",
					"catalogedAt": "2026-09-30T10:00:01Z"},
			}}, "nextAfter": nil})
		case "/images/" + digest + "/sbom":
			_ = json.NewEncoder(w).Encode(sbomPage)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	log := logrus.New()
	log.SetOutput(io.Discard)
	hm, err := match.NewHTTPMatcher(url)
	if err != nil {
		t.Fatal(err)
	}
	out := &captureSink{}
	coord := &match.Coordinator{Matcher: hm, Sink: out, Log: log}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go coord.Run(ctx, 200*time.Millisecond)

	rc, err := broker.NewReadClient(srv.URL, "sc")
	if err != nil {
		t.Fatal(err)
	}
	src := &Source{Broker: rc, Matcher: coord, Log: log}
	src.Pass(ctx)
	if coord.Held() != 1 {
		t.Fatalf("coordinator holds %d digests, want the node SBOM", coord.Held())
	}

	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		out.mu.Lock()
		es := append([]trivy.Emission(nil), out.es...)
		out.mu.Unlock()
		for _, e := range es {
			if e.Kind != trivy.KindVulnerabilities || e.Digest != digest {
				continue
			}
			v := e.Vulns
			if v.Source != "grype" || len(v.SBOMSources) != 1 || v.SBOMSources[0] != "node" || v.SBOMTrust != "scanned" {
				t.Fatalf("payload header: %+v", v)
			}
			if !e.PinPlatform || e.Platform != "linux/arm64" || v.Image.PlatformManifests != nil {
				t.Errorf("payload not pinned to the node's platform: %+v", e)
			}
			for _, f := range v.Vulnerabilities {
				if f.ID == "CVE-2023-4911" && f.Package.Name == "libc6" {
					t.Logf("%d findings; CVE-2023-4911 %s, fixed in %s", len(v.Vulnerabilities), f.Severity, f.FixedVersion)
					return
				}
			}
			t.Fatalf("CVE-2023-4911 not among %d findings for libc6 2.36-9+deb12u1", len(v.Vulnerabilities))
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("no grype payload within 3m")
}
