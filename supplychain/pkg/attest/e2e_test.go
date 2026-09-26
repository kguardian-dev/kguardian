package attest

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

// TestBrokerE2E posts the acceptance fixtures' results to a real broker
// and reads them back. Needs a broker with scoped auth whose images table
// holds the four fixture digests: ATTEST_E2E_BROKER=http://host:port,
// ATTEST_E2E_TOKEN (supplychain scope; it includes read).
func TestBrokerE2E(t *testing.T) {
	url := os.Getenv("ATTEST_E2E_BROKER")
	if url == "" {
		t.Skip("set ATTEST_E2E_BROKER (and ATTEST_E2E_TOKEN) to run against a broker")
	}
	bc, err := NewBrokerClient(url, os.Getenv("ATTEST_E2E_TOKEN"))
	if err != nil {
		t.Fatal(err)
	}
	reg := newFixtureRegistry(t, false)
	targets := map[string]Target{
		"keyless":  reg.load(loadRecording(t, "pause-3.10"), ""),
		"key":      reg.load(loadRecording(t, "key-legacy"), ""),
		"unsigned": reg.load(loadRecording(t, "kguardian-controller-v1.15.1"), ""),
		"tampered": reg.load(tamperKeylessSig(t), "tampered/pause"),
	}
	ctx := context.Background()
	inv, err := bc.RunningImages(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("broker inventory: %d running digests", len(inv))
	v := newKeyVerifier(t, fixtureKey(t))
	want := map[string]string{"keyless": VerdictVerified, "key": VerdictVerified, "unsigned": VerdictUnsigned, "tampered": VerdictInvalid}
	for name, tg := range targets {
		r := v.Verify(ctx, tg)
		if r.Verdict != want[name] {
			t.Fatalf("%s: verdict %s", name, r.Verdict)
		}
		if err := bc.Post(ctx, r); err != nil {
			t.Fatalf("%s: post: %v", name, err)
		}
		// Posting the same result again is a no-op, not a conflict.
		if err := bc.Post(ctx, r); err != nil {
			t.Fatalf("%s: repost: %v", name, err)
		}
		raw, err := bc.do(ctx, http.MethodGet, "/images/"+r.Digest+"/attestation", nil)
		if err != nil {
			t.Fatalf("%s: get: %v", name, err)
		}
		var got struct {
			Verdict    string           `json:"verdict"`
			Signatures []map[string]any `json:"signatures"`
		}
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		if got.Verdict != r.Verdict {
			t.Fatalf("%s: stored verdict %s, want %s", name, got.Verdict, r.Verdict)
		}
		t.Logf("%s %s: verdict=%s signatures=%s", name, r.Digest[:19], got.Verdict, compact(got.Signatures))
	}
	raw, err := bc.do(ctx, http.MethodGet, "/attestations?limit=10", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("GET /attestations: %s", raw)
}

func compact(v any) string {
	b, _ := json.Marshal(v)
	s := string(b)
	if len(s) > 400 {
		s = s[:400] + "..."
	}
	return strings.TrimSpace(s)
}
