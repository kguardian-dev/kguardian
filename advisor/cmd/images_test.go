package cmd

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
)

// `kguardian images list/get` read GET /images and GET /images/{digest}.
// These tests drive the real HTTP client against an httptest broker so the
// query string, the auth header and the 404 mapping are all exercised.

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

const imagesPageJSON = `{"items":[{"digest":"` + testDigest + `","repository":"docker.io/library/nginx","tags":["1.27","latest"],"digestKind":"repo","firstSeen":"2026-09-20T10:00:00","lastSeen":"2026-09-26T09:00:00","runningContainers":3,"futureField":"kept"}],"nextAfter":"` + testDigest + `"}`

const imageDetailJSON = `{"digest":"` + testDigest + `","repository":null,"tags":[],"digestKind":"config","firstSeen":"2026-09-20T10:00:00","lastSeen":"2026-09-26T09:00:00","workloads":[{"clusterId":"primary","namespace":"shop","workloadKind":"Deployment","workloadName":"checkout","containerName":"app","containerKind":"regular","imageRef":"nginx:1.27","firstSeen":"2026-09-20T10:00:00","lastSeen":"2026-09-26T09:00:00","state":"waiting","stateReason":"ImagePullBackOff","ranAsInit":false,"running":false}],"truncated":true}`

// fakeBroker serves routes keyed by path and records the last request.
type fakeBroker struct {
	routes  map[string]string
	lastReq *http.Request
}

func startFakeBroker(t *testing.T, routes map[string]string) *fakeBroker {
	t.Helper()
	fb := &fakeBroker{routes: routes}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fb.lastReq = r
		body, ok := fb.routes[r.URL.EscapedPath()]
		if !ok {
			http.Error(w, "No data found", http.StatusNotFound)
			return
		}
		// "404:<body>" / "400:<body>" answer with that status.
		status := http.StatusOK
		if len(body) > 4 && body[3] == ':' {
			if code, err := strconv.Atoi(body[:3]); err == nil {
				status, body = code, body[4:]
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	origURL, origTok := api.BrokerBaseURL, api.BrokerAuthToken
	api.BrokerBaseURL = srv.URL
	api.BrokerAuthToken = "read-token"
	t.Cleanup(func() {
		srv.Close()
		api.BrokerBaseURL, api.BrokerAuthToken = origURL, origTok
	})
	return fb
}

func TestImagesList_TableAndCursor(t *testing.T) {
	fb := startFakeBroker(t, map[string]string{"/images": imagesPageJSON})
	var out, errOut bytes.Buffer
	err := fetchAndRenderImages(api.ImageListOptions{Namespace: "shop", Repository: "docker.io/library/nginx", Limit: 50}, "table", &out, &errOut)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	q := fb.lastReq.URL.Query()
	if q.Get("namespace") != "shop" || q.Get("repository") != "docker.io/library/nginx" || q.Get("limit") != "50" || q.Has("after") {
		t.Errorf("query wrong: %s", fb.lastReq.URL.RawQuery)
	}
	if got := fb.lastReq.Header.Get("Authorization"); got != "Bearer read-token" {
		t.Errorf("auth header = %q", got)
	}
	s := out.String()
	for _, want := range []string{"DIGEST", "RUNNING", "sha256:0123456789ab", "docker.io/library/nginx", "1.27,latest"} {
		if !strings.Contains(s, want) {
			t.Errorf("table missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, testDigest) {
		t.Errorf("table should shorten the digest:\n%s", s)
	}
	if !strings.Contains(errOut.String(), "--after "+testDigest) {
		t.Errorf("cursor notice missing: %q", errOut.String())
	}
}

func TestImagesList_JSONPassesThroughUnknownFields(t *testing.T) {
	startFakeBroker(t, map[string]string{"/images": imagesPageJSON})
	var out, errOut bytes.Buffer
	if err := fetchAndRenderImages(api.ImageListOptions{}, "json", &out, &errOut); err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out.String(), `"futureField": "kept"`) {
		t.Errorf("json must pass broker fields through:\n%s", out.String())
	}
}

func TestImagesList_YAML(t *testing.T) {
	startFakeBroker(t, map[string]string{"/images": imagesPageJSON})
	var out, errOut bytes.Buffer
	if err := fetchAndRenderImages(api.ImageListOptions{}, "yaml", &out, &errOut); err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out.String(), "runningContainers: 3") {
		t.Errorf("yaml output wrong:\n%s", out.String())
	}
}

func TestImagesList_Empty(t *testing.T) {
	startFakeBroker(t, map[string]string{"/images": `{"items":[],"nextAfter":null}`})
	var out, errOut bytes.Buffer
	if err := fetchAndRenderImages(api.ImageListOptions{}, "table", &out, &errOut); err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out.String(), "No images") || errOut.Len() != 0 {
		t.Errorf("empty page: out=%q err=%q", out.String(), errOut.String())
	}
}

func TestImagesGet_TableShowsUnknownRepositoryAndState(t *testing.T) {
	fb := startFakeBroker(t, map[string]string{"/images/" + testDigest: imageDetailJSON})
	var out bytes.Buffer
	if err := fetchAndRenderImage(testDigest, "table", &out); err != nil {
		t.Fatalf("get: %v", err)
	}
	if fb.lastReq.URL.Path != "/images/"+testDigest {
		t.Errorf("path = %s", fb.lastReq.URL.Path)
	}
	s := out.String()
	for _, want := range []string{"Repository:  -", "Deployment/checkout", "waiting (ImagePullBackOff)", "More workload containers"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q:\n%s", want, s)
		}
	}
}

func TestImagesGet_NotFound(t *testing.T) {
	startFakeBroker(t, map[string]string{})
	var out bytes.Buffer
	err := fetchAndRenderImage(testDigest, "table", &out)
	if err == nil || !strings.Contains(err.Error(), "not in the inventory") {
		t.Fatalf("want not-in-inventory error, got %v", err)
	}
}

func TestImagesGet_AuthErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	origURL, origTok := api.BrokerBaseURL, api.BrokerAuthToken
	api.BrokerBaseURL, api.BrokerAuthToken = srv.URL, ""
	defer func() { api.BrokerBaseURL, api.BrokerAuthToken = origURL, origTok }()
	var out bytes.Buffer
	err := fetchAndRenderImage(testDigest, "table", &out)
	if err == nil || !strings.Contains(err.Error(), "KGUARDIAN_BROKER_TOKEN") {
		t.Fatalf("want auth guidance, got %v", err)
	}
	if !strings.Contains(err.Error(), "hint: this needs a broker token with the read scope") || !strings.Contains(err.Error(), "--broker-token-file") {
		t.Errorf("want the read-scope hint, got %v", err)
	}
}

// A 403 (token set, wrong scope) on every new read command gets the hint;
// other errors do not.
func TestBrokerReadErr_HintOnlyForAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	origURL, origTok := api.BrokerBaseURL, api.BrokerAuthToken
	api.BrokerBaseURL, api.BrokerAuthToken = srv.URL, "ingest-only"
	defer func() { api.BrokerBaseURL, api.BrokerAuthToken = origURL, origTok }()
	var out, errOut bytes.Buffer
	checks := map[string]error{
		"images list":    fetchAndRenderImages(api.ImageListOptions{}, "table", &out, &errOut),
		"profile get":    fetchAndRenderProfile(checkoutRef, "table", &out),
		"profile list":   fetchAndRenderProfiles(api.ProfileListOptions{}, "table", &out, &errOut),
		"profile diff":   fetchAndRenderProfileDiff(checkoutRef, 0, 0, "table", &out),
		"profile export": exportPSSPatch(checkoutRef, &out, &errOut),
	}
	for name, err := range checks {
		if err == nil || !strings.Contains(err.Error(), "HTTP 403") || !strings.Contains(err.Error(), "read scope") {
			t.Errorf("%s: want 403 with read-scope hint, got %v", name, err)
		}
	}
	if e := brokerReadErr("x", errors.New("boom")); strings.Contains(e.Error(), "hint") {
		t.Errorf("non-auth error must not carry the hint: %v", e)
	}
}

func TestParseOutput(t *testing.T) {
	if o, err := parseOutput(" JSON ", "table", "json"); err != nil || o != "json" {
		t.Errorf("got %q %v", o, err)
	}
	if _, err := parseOutput("xml", "table", "json"); err == nil {
		t.Error("xml must be rejected")
	}
}
