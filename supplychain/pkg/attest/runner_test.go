package attest

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeBroker serves GET /images from a fixed list and records posts.
type fakeBroker struct {
	mu        sync.Mutex
	images    []InventoryImage
	posts     map[string][]Result
	postCode  int
	auth      string
	pageLimit int
}

func (f *fakeBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = r.Header.Get("Authorization")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/images":
		after := r.URL.Query().Get("after")
		var page inventoryPage
		for _, it := range f.images {
			if after != "" && it.Digest <= after {
				continue
			}
			if len(page.Items) == f.pageLimit {
				last := page.Items[len(page.Items)-1].Digest
				page.NextAfter = &last
				break
			}
			page.Items = append(page.Items, it)
		}
		_ = json.NewEncoder(w).Encode(page)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/attestation"):
		var body io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, _ := gzip.NewReader(r.Body)
			body = gz
		}
		var res Result
		if err := json.NewDecoder(body).Decode(&res); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if f.posts == nil {
			f.posts = map[string][]Result{}
		}
		f.posts[res.Digest] = append(f.posts[res.Digest], res)
		if f.postCode != 0 {
			w.WriteHeader(f.postCode)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func TestRunnerPostsRunningDigestsOnce(t *testing.T) {
	reg := newFixtureRegistry(t, false)
	signed := reg.load(loadRecording(t, "pause-3.10"), "")
	unsigned := reg.load(loadRecording(t, "kguardian-controller-v1.15.1"), "")
	repo := func(s string) *string { return &s }
	fb := &fakeBroker{pageLimit: 1, images: []InventoryImage{
		{Digest: signed.Digest, Repository: repo(signed.Repository), DigestKind: "repo", RunningContainers: 2},
		{Digest: "sha256:" + strings.Repeat("0", 64), Repository: repo(signed.Repository), DigestKind: "repo", RunningContainers: 0}, // not running
		{Digest: unsigned.Digest, Repository: repo(unsigned.Repository), DigestKind: "repo", RunningContainers: 1},
		{Digest: "sha256:" + strings.Repeat("f", 64), DigestKind: "config", RunningContainers: 1},
	}}
	srv := httptest.NewServer(fb)
	defer srv.Close()
	bc, err := NewBrokerClient(srv.URL, "sc-token")
	if err != nil {
		t.Fatal(err)
	}
	var posts []string
	r := &Runner{Verifier: newFixtureVerifier(t), Inventory: bc, Sink: bc, OnPost: func(o string) { posts = append(posts, o) }}
	r.Pass(context.Background())
	r.Pass(context.Background()) // cached: nothing new to post
	if !r.Ready() {
		t.Fatal("not ready after a pass")
	}
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if fb.auth != "Bearer sc-token" {
		t.Fatalf("auth = %q", fb.auth)
	}
	if len(fb.posts) != 3 || len(posts) != 3 {
		t.Fatalf("posts = %v (%v)", fb.posts, posts)
	}
	for d, want := range map[string]string{signed.Digest: VerdictVerified, unsigned.Digest: VerdictUnsigned, "sha256:" + strings.Repeat("f", 64): VerdictUnknown} {
		got := fb.posts[d]
		if len(got) != 1 || got[0].Verdict != want {
			t.Fatalf("%s: posts %+v, want one %s", d, got, want)
		}
	}
}

func TestRunnerRetriesOnlyRetryableFailures(t *testing.T) {
	for _, tc := range []struct {
		code  int
		posts int
	}{{http.StatusServiceUnavailable, 2}, {http.StatusNotFound, 1}} {
		fb := &fakeBroker{pageLimit: 10, postCode: tc.code, images: []InventoryImage{
			{Digest: "sha256:" + strings.Repeat("1", 64), DigestKind: "config", RunningContainers: 1},
		}}
		srv := httptest.NewServer(fb)
		bc, _ := NewBrokerClient(srv.URL, "")
		r := &Runner{Verifier: newFixtureVerifier(t), Inventory: bc, Sink: bc}
		r.Pass(context.Background())
		r.Pass(context.Background())
		srv.Close()
		if n := len(fb.posts["sha256:"+strings.Repeat("1", 64)]); n != tc.posts {
			t.Fatalf("code %d: %d posts, want %d", tc.code, n, tc.posts)
		}
	}
}

func TestEncodeBounded(t *testing.T) {
	r := Result{Digest: "sha256:" + strings.Repeat("a", 64)}
	for i := 0; i < 100; i++ {
		r.Signatures = append(r.Signatures, Signature{Detail: strings.Repeat("x", 256)})
		r.Attestations = append(r.Attestations, Attestation{PredicateType: strings.Repeat("p", 4000), Detail: strings.Repeat("y", 256)})
	}
	b, err := encodeBounded(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > MaxPostBytes {
		t.Fatalf("%d bytes", len(b))
	}
	var back Result
	if err := json.Unmarshal(b, &back); err != nil || len(back.Signatures) != maxSignatures || len(back.Attestations) > maxAttestation {
		t.Fatalf("decoded %d sigs %d atts err %v", len(back.Signatures), len(back.Attestations), err)
	}
}
