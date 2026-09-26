package attest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/registry"
	"github.com/sigstore/sigstore-go/pkg/root"
)

// Recorded fixtures: real, public signature artifacts copied byte for
// byte from their registries (ATTEST_RECORD=1 go test -run TestRecord),
// replayed into an in-memory registry so CI never touches the network.
// Only manifests and signature/attestation blobs are recorded, never image
// layers.

type recManifest struct {
	Ref       string `json:"ref"` // tag or digest
	MediaType string `json:"media_type"`
	Body      []byte `json:"body"`
}

type recBlob struct {
	Digest string `json:"digest"`
	Body   []byte `json:"body"`
}

type recording struct {
	Source     string        `json:"source"` // where it came from, and when
	Repository string        `json:"repository"`
	Digest     string        `json:"digest"`
	Manifests  []recManifest `json:"manifests"`
	Blobs      []recBlob     `json:"blobs"`
}

type recordTarget struct{ file, repo, digest, note string }

var recordTargets = []recordTarget{
	{"cosign-v3.1.3", "ghcr.io/sigstore/cosign/cosign", "sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8", "cosign v3 bundles as referrers (tag fallback on GHCR): one keyless, one key-signed"},
	{"pause-3.10", "registry.k8s.io/pause", "sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a", "legacy cosign .sig, keyless (Kubernetes release identity)"},
	{"actions-runner", "ghcr.io/actions/actions-runner", "sha256:e5496277be5d09bc968b3d64911b74e219ac4a3f2edce956a3ecf9271bea1ef4", "GitHub artifact attestation: SLSA provenance bundle, no image signature"},
	{"chainguard-static", "cgr.dev/chainguard/static", "sha256:41e17ed83c594a64a9396b6ab96dd26d5ddc290dacf4c177464712ff21ad534f", "legacy .sig and .att (SLSA v1, SPDX SBOM)"},
	{"kguardian-controller-v1.15.1", "ghcr.io/kguardian-dev/kguardian/controller", "sha256:f6ab986a3a713f127b0f03c6f5319756883249bbf58cebbee9911d80eb7fa1f8", "kguardian's own controller before image signing: unsigned"},
}

// localRecordTargets were signed by cosign v3.0.5 with the key pair whose
// public half is testdata/cosign.pub (tlog upload off), in a throwaway
// local registry: "crane registry serve --address 127.0.0.1:5557", then
// "cosign sign --key cosign.key --tlog-upload=false --use-signing-config=false
// --allow-http-registry [--new-bundle-format=false] <repo>@<digest>". The
// private key was discarded. Re-record with ATTEST_RECORD_LOCAL=1 while
// that registry serves them.
var localRecordTargets = []recordTarget{
	{"key-legacy", "127.0.0.1:5557/fixture/key-legacy", "sha256:94be8ca1be31f007a2a31fd67a3830ee9dbde9cc971a699f35d419b5f51b242b", "cosign v3.0.5 key signature, legacy .sig tag, no tlog"},
	{"key-bundle", "127.0.0.1:5557/fixture/key-bundle", "sha256:3de3b7e5f8062f772ceab50833cbd54cb09688ca0e7a0f70bd79895ab54cd95d", "cosign v3.0.5 key signature, Sigstore bundle referrer (tag fallback), no tlog"},
}

func TestRecord(t *testing.T) {
	local := os.Getenv("ATTEST_RECORD_LOCAL") == "1"
	if os.Getenv("ATTEST_RECORD") != "1" && !local {
		t.Skip("set ATTEST_RECORD=1 to re-record fixtures from the live registries (ATTEST_RECORD_LOCAL=1 for the key-signed ones)")
	}
	ctx := context.Background()
	rt := RateLimit(registry.Guard{}.Transport(20*time.Second), 3, 5)
	targets := recordTargets
	var nameOpts []name.Option
	if local {
		rt, targets, nameOpts = http.DefaultTransport, localRecordTargets, []name.Option{name.Insecure}
	}
	opts := []remote.Option{remote.WithAuth(authn.Anonymous), remote.WithContext(ctx), remote.WithTransport(rt)}
	for _, tg := range targets {
		repo, err := name.NewRepository(tg.repo, nameOpts...)
		if err != nil {
			t.Fatal(err)
		}
		dig := tg.digest
		rec := recording{
			Source:     fmt.Sprintf("%s@%s, recorded %s: %s", tg.repo, dig, time.Now().UTC().Format("2006-01-02"), tg.note),
			Repository: tg.repo,
			Digest:     dig,
		}
		addManifest := func(ref name.Reference, key string) *remote.Descriptor {
			d, err := remote.Get(ref, opts...)
			if err != nil {
				return nil
			}
			rec.Manifests = append(rec.Manifests, recManifest{Ref: key, MediaType: string(d.MediaType), Body: d.Manifest})
			return d
		}
		addBlob := func(desc v1.Descriptor) {
			l, err := remote.Layer(repo.Digest(desc.Digest.String()), opts...)
			if err != nil {
				t.Fatal(err)
			}
			rc, err := l.Compressed()
			if err != nil {
				t.Fatal(err)
			}
			b, err := io.ReadAll(rc)
			_ = rc.Close()
			if err != nil {
				t.Fatal(err)
			}
			rec.Blobs = append(rec.Blobs, recBlob{Digest: desc.Digest.String(), Body: b})
		}
		subj := addManifest(repo.Digest(dig), dig)
		if subj == nil {
			t.Fatalf("%s: subject not found", tg.repo)
		}
		if subj.MediaType.IsIndex() {
			im, err := v1.ParseIndexManifest(bytes.NewReader(subj.Manifest))
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range im.Manifests {
				addManifest(repo.Digest(m.Digest.String()), m.Digest.String())
			}
		}
		for _, suffix := range []string{"sig", "att"} {
			tag := tagFor(repo, dig, suffix)
			if d := addManifest(tag, tag.TagStr()); d != nil {
				m, err := v1.ParseManifest(bytes.NewReader(d.Manifest))
				if err != nil {
					t.Fatal(err)
				}
				for _, l := range m.Layers {
					addBlob(l)
				}
			}
		}
		fb := tagFor(repo, dig, "")
		if d := addManifest(fb, fb.TagStr()); d != nil {
			im, err := v1.ParseIndexManifest(bytes.NewReader(d.Manifest))
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range im.Manifests {
				rd := addManifest(repo.Digest(r.Digest.String()), r.Digest.String())
				m, err := v1.ParseManifest(bytes.NewReader(rd.Manifest))
				if err != nil {
					t.Fatal(err)
				}
				for _, l := range m.Layers {
					addBlob(l)
				}
			}
		}
		b, err := json.MarshalIndent(rec, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join("testdata", "registry", tg.file+".json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: %d manifests, %d blobs", tg.file, len(rec.Manifests), len(rec.Blobs))
	}
	if local {
		return
	}
	// Snapshot the public-good trusted root so replay verifies offline.
	tr := &TUFTrustRoot{Transport: rt}
	raw, err := tr.fetchRaw(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("testdata", "trusted_root.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// --- Replay ---

func loadRecording(t *testing.T, file string) recording {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "registry", file+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var r recording
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// repoPath strips the registry host: "ghcr.io/a/b" -> "a/b".
func repoPath(repository string) string {
	_, p, _ := strings.Cut(repository, "/")
	return p
}

// fixtureRegistry is an in-memory OCI registry on loopback.
type fixtureRegistry struct {
	t    *testing.T
	srv  *httptest.Server
	host string
}

func newFixtureRegistry(t *testing.T, referrersAPI bool) *fixtureRegistry {
	t.Helper()
	h := ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(referrersAPI))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return &fixtureRegistry{t: t, srv: srv, host: u.Host}
}

func (f *fixtureRegistry) do(method, path, contentType string, body []byte) {
	f.t.Helper()
	req, err := http.NewRequest(method, f.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		f.t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		f.t.Fatalf("%s %s: %d %s", method, path, resp.StatusCode, b)
	}
}

func (f *fixtureRegistry) putBlob(repo string, digest string, body []byte) {
	f.do(http.MethodPost, "/v2/"+repo+"/blobs/uploads/?digest="+url.QueryEscape(digest), "application/octet-stream", body)
}

func (f *fixtureRegistry) putManifest(repo, ref, mediaType string, body []byte) {
	f.do(http.MethodPut, "/v2/"+repo+"/manifests/"+ref, mediaType, body)
}

// load pushes a recording under repo (default: its own path). Image
// manifests go first, so indexes find their children.
func (f *fixtureRegistry) load(r recording, repo string) Target {
	if repo == "" {
		repo = repoPath(r.Repository)
	}
	for _, b := range r.Blobs {
		f.putBlob(repo, b.Digest, b.Body)
	}
	ms := append([]recManifest(nil), r.Manifests...)
	sort.SliceStable(ms, func(i, j int) bool {
		return !v1MediaIsIndex(ms[i].MediaType) && v1MediaIsIndex(ms[j].MediaType)
	})
	for _, m := range ms {
		f.putManifest(repo, m.Ref, m.MediaType, m.Body)
	}
	return Target{Repository: f.host + "/" + repo, Digest: r.Digest, DigestKind: "repo"}
}

func v1MediaIsIndex(mt string) bool {
	return strings.Contains(mt, "index") || strings.Contains(mt, "manifest.list")
}

func fixtureTrustRoot(t *testing.T) TrustRoot {
	t.Helper()
	return &FileTrustRoot{Path: filepath.Join("testdata", "trusted_root.json")}
}

func newFixtureVerifier(t *testing.T) *Verifier {
	t.Helper()
	v, err := New(Options{
		TrustRoot:     fixtureTrustRoot(t),
		Insecure:      true,
		transport:     http.DefaultTransport,
		skipHostCheck: true,
		RegistryRPS:   1000,
		RegistryBurst: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// sanity: the fixture trusted root parses.
func TestFixtureTrustedRootParses(t *testing.T) {
	if _, err := root.NewTrustedRootFromPath(filepath.Join("testdata", "trusted_root.json")); err != nil {
		t.Fatal(err)
	}
}
