package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
)

type counting struct {
	h        http.Handler
	requests atomic.Int32
	sawAuth  atomic.Bool
	deny     bool
}

func (c *counting) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.requests.Add(1)
	if r.Header.Get("Authorization") != "" {
		c.sawAuth.Store(true)
	}
	if c.deny && r.URL.Path != "/v2/" {
		w.Header().Set("WWW-Authenticate", `Basic realm="private"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	c.h.ServeHTTP(w, r)
}

func setup(t *testing.T) (*counting, string, v1.Hash, v1.Hash, map[string]string) {
	t.Helper()
	c := &counting{h: ggcrregistry.New()}
	srv := httptest.NewServer(c)
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")

	amd, _ := random.Image(64, 1)
	arm, _ := random.Image(64, 1)
	idx := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: amd, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}},
		mutate.IndexAddendum{Add: arm, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}}},
	)
	ref, _ := name.ParseReference(host+"/example/api:multi", name.Insecure)
	if err := remote.WriteIndex(ref, idx); err != nil {
		t.Fatal(err)
	}
	single, _ := random.Image(64, 1)
	sref, _ := name.ParseReference(host+"/example/api:single", name.Insecure)
	if err := remote.Write(sref, single); err != nil {
		t.Fatal(err)
	}
	idxDigest, _ := idx.Digest()
	singleDigest, _ := single.Digest()
	amdD, _ := amd.Digest()
	armD, _ := arm.Digest()
	c.requests.Store(0)
	return c, host, idxDigest, singleDigest, map[string]string{"linux/amd64": amdD.String(), "linux/arm64/v8": armD.String()}
}

func TestInspectIndexAndManifest(t *testing.T) {
	c, host, idx, single, want := setup(t)
	in := New()
	in.Insecure = true

	r := in.Inspect(context.Background(), host, "example/api", idx.String())
	if r.Kind != types.DigestKindIndex || len(r.PlatformManifests) != 2 ||
		r.PlatformManifests["linux/amd64"] != want["linux/amd64"] || r.PlatformManifests["linux/arm64/v8"] != want["linux/arm64/v8"] {
		t.Fatalf("index: %+v, want %v", r, want)
	}
	if r := in.Inspect(context.Background(), host, "example/api", single.String()); r.Kind != types.DigestKindManifest || r.PlatformManifests != nil {
		t.Fatalf("manifest: %+v", r)
	}
	before := c.requests.Load()
	in.Inspect(context.Background(), host, "example/api", idx.String())
	if c.requests.Load() != before {
		t.Error("definitive result not cached")
	}
	if c.sawAuth.Load() {
		t.Error("sent credentials; lookups must be anonymous")
	}

	img := types.ImageRef{Registry: host, Repository: "example/api", Digest: idx.String()}
	in.Enrich(context.Background(), &img)
	if img.DigestKind != types.DigestKindIndex || len(img.PlatformManifests) != 2 {
		t.Errorf("enrich: %+v", img)
	}
}

// A private registry (401) leaves the kind unknown, sends no credentials,
// and is not asked again until the failure TTL expires.
func TestInspectPrivateIsUnknownAndBackedOff(t *testing.T) {
	c, host, idx, _, _ := setup(t)
	c.deny = true
	in := New()
	in.Insecure = true
	now := time.Unix(1000, 0)
	in.now = func() time.Time { return now }

	if r := in.Inspect(context.Background(), host, "example/api", idx.String()); r.Kind != types.DigestKindUnknown {
		t.Fatalf("private: %+v", r)
	}
	if c.sawAuth.Load() {
		t.Error("sent credentials to a private registry")
	}
	n := c.requests.Load()
	in.Inspect(context.Background(), host, "example/api", idx.String())
	if c.requests.Load() != n {
		t.Error("failure not cached")
	}
	now = now.Add(2 * time.Hour)
	in.Inspect(context.Background(), host, "example/api", idx.String())
	if c.requests.Load() == n {
		t.Error("failure cached past its TTL")
	}
}

func TestInspectDegenerateInputs(t *testing.T) {
	in := New()
	for _, c := range [][3]string{{"", "", "sha256:x"}, {"r", "repo", ""}, {"r", "Bad Repo", "sha256:nothex"}} {
		if r := in.Inspect(context.Background(), c[0], c[1], c[2]); r.Kind != types.DigestKindUnknown {
			t.Errorf("%v: %+v", c, r)
		}
	}
	if normaliseRegistry("docker.io") != "index.docker.io" || normaliseRegistry("ghcr.io") != "ghcr.io" {
		t.Error("registry normalisation")
	}
}
