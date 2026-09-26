package attest

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/registry"
)

// liveTargets are public, anonymously readable images. The live test
// reaches the real registries and the Sigstore TUF CDN, so it only runs
// with ATTEST_LIVE=1. ATTEST_LIVE_IMAGES adds "repo@digest" entries
// (comma separated), e.g. a signed kguardian release.
var liveTargets = []Target{
	// cosign v3 bundle signature, referrers tag fallback on GHCR.
	{Repository: "ghcr.io/sigstore/cosign/cosign", Digest: "sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8", DigestKind: "repo"},
	// Legacy cosign .sig.
	{Repository: "registry.k8s.io/pause", Digest: "sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a", DigestKind: "repo"},
	// GitHub artifact attestation (SLSA provenance bundle), no signature.
	{Repository: "ghcr.io/actions/actions-runner", Digest: "sha256:e5496277be5d09bc968b3d64911b74e219ac4a3f2edce956a3ecf9271bea1ef4", DigestKind: "repo"},
	// Unsigned: kguardian's own controller before image signing (v1.15.1).
	{Repository: "ghcr.io/kguardian-dev/kguardian/controller", Digest: "", DigestKind: "repo", Tags: []string{"1.15.1"}},
}

func TestLive(t *testing.T) {
	if os.Getenv("ATTEST_LIVE") != "1" {
		t.Skip("set ATTEST_LIVE=1 to verify real public images")
	}
	g := registry.Guard{}
	tr := &TUFTrustRoot{Transport: RateLimit(g.Transport(10*time.Second), 2, 4)}
	v, err := New(Options{Guard: g, TrustRoot: tr})
	if err != nil {
		t.Fatal(err)
	}
	targets := append([]Target(nil), liveTargets...)
	for _, e := range strings.Split(os.Getenv("ATTEST_LIVE_IMAGES"), ",") {
		if repo, dig, ok := strings.Cut(strings.TrimSpace(e), "@"); ok {
			targets = append(targets, Target{Repository: repo, Digest: dig, DigestKind: "repo"})
		}
	}
	for _, tg := range targets {
		if tg.Digest == "" {
			continue
		}
		r := v.Verify(context.Background(), tg)
		b, _ := json.MarshalIndent(r, "", "  ")
		t.Logf("%s@%s:\n%s", tg.Repository, tg.Digest, b)
	}
}
