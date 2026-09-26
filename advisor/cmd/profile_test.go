package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
)

// `kguardian profile get/list/diff/export` against an httptest broker that
// serves the shared contract fixtures (test/fixtures/posture, also replayed
// by the llm-bridge tool tests). The rules under test: unknown is printed as
// unknown and never as 0 or a pass, -o json/yaml pass the broker body
// through, and export prints the broker's recommendation verbatim with its
// caveats on stderr.

func postureFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "test", "fixtures", "posture", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return string(b)
}

var checkoutRef = workloadRef{"payments", "Deployment", "checkout"}

const checkoutProfilePath = "/workloads/payments/Deployment/checkout/profile"

func TestParseWorkloadRef(t *testing.T) {
	got, err := parseWorkloadRef(" payments/Deployment/checkout ")
	if err != nil || got != checkoutRef {
		t.Fatalf("got %+v %v", got, err)
	}
	for _, bad := range []string{"checkout", "payments/checkout", "a/b/c/d", "/Deployment/x", "ns//x", "ns/Deployment/"} {
		if _, err := parseWorkloadRef(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestProfileGet_Table(t *testing.T) {
	fb := startFakeBroker(t, map[string]string{checkoutProfilePath: postureFixture(t, "profile_full.json")})
	var out bytes.Buffer
	if err := fetchAndRenderProfile(checkoutRef, "table", &out); err != nil {
		t.Fatalf("get: %v", err)
	}
	if fb.lastReq.URL.Path != checkoutProfilePath || fb.lastReq.Header.Get("Authorization") != "Bearer read-token" {
		t.Errorf("request wrong: %s auth=%q", fb.lastReq.URL.Path, fb.lastReq.Header.Get("Authorization"))
	}
	s := out.String()
	for _, want := range []string{
		"Posture:    warn  score 71  coverage 41%  grade -",
		"Not scored: network, images (unknown or unscored; excluded from the score)",
		"Revision:   3",
		"PSS level:  at most baseline (9 checks not visible to kguardian)",
		"DIMENSION", "podSecurity", "not scored",
		"syscalls.no_enforcing_profile",
		"noWouldDeny24h", "unknown",
		"profile export payments/Deployment/checkout --format pss",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
}

func TestProfileGet_AllUnknownNeverRendersAsZeroOrPass(t *testing.T) {
	startFakeBroker(t, map[string]string{"/workloads/batch/CronJob/nightly-report/profile": postureFixture(t, "profile_unknown.json")})
	var out bytes.Buffer
	if err := fetchAndRenderProfile(workloadRef{"batch", "CronJob", "nightly-report"}, "table", &out); err != nil {
		t.Fatalf("get: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "score unknown") || !strings.Contains(s, "PSS level:  unknown") || !strings.Contains(s, "none stored yet") {
		t.Errorf("unknown not rendered as unknown:\n%s", s)
	}
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && (f[0] == "network" || f[0] == "syscalls" || f[0] == "podSecurity" || f[0] == "images" || f[0] == "compute") {
			if f[1] != "unknown" || f[2] != "unknown" {
				t.Errorf("dimension row must be unknown/unknown: %q", line)
			}
		}
		if strings.Contains(line, "trafficObserved24h") && !strings.Contains(line, "unknown") {
			t.Errorf("readiness null must render unknown: %q", line)
		}
	}
	if strings.Contains(s, "score 0") {
		t.Errorf("null score rendered as 0:\n%s", s)
	}
}

func TestProfileGet_JSONAndYAMLPassThrough(t *testing.T) {
	body := postureFixture(t, "profile_full.json")
	startFakeBroker(t, map[string]string{checkoutProfilePath: body})
	var js bytes.Buffer
	if err := fetchAndRenderProfile(checkoutRef, "json", &js); err != nil {
		t.Fatalf("json: %v", err)
	}
	var want, got any
	_ = json.Unmarshal([]byte(body), &want)
	if err := json.Unmarshal(js.Bytes(), &got); err != nil {
		t.Fatalf("json output is not JSON: %v", err)
	}
	wb, _ := json.Marshal(want)
	gb, _ := json.Marshal(got)
	if !bytes.Equal(wb, gb) {
		t.Error("-o json must be the broker body unchanged")
	}
	var y bytes.Buffer
	if err := fetchAndRenderProfile(checkoutRef, "yaml", &y); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	if !strings.Contains(y.String(), "levelConfidence: upper_bound") || !strings.Contains(y.String(), "vulnerabilities: null") {
		t.Errorf("yaml output wrong:\n%s", y.String())
	}
}

func TestProfileGet_NotFound(t *testing.T) {
	startFakeBroker(t, map[string]string{})
	var out bytes.Buffer
	err := fetchAndRenderProfile(checkoutRef, "table", &out)
	if err == nil || !strings.Contains(err.Error(), "no data for payments/Deployment/checkout") {
		t.Fatalf("want no-data error, got %v", err)
	}
}

func TestProfileList_TableQueryAndCursor(t *testing.T) {
	fb := startFakeBroker(t, map[string]string{"/workloads": postureFixture(t, "profiles_page.json")})
	var out, errOut bytes.Buffer
	opts := api.ProfileListOptions{Namespace: "payments", Kind: "Deployment", Status: "risk", Limit: 20}
	if err := fetchAndRenderProfiles(opts, "table", &out, &errOut); err != nil {
		t.Fatalf("list: %v", err)
	}
	q := fb.lastReq.URL.Query()
	if q.Get("namespace") != "payments" || q.Get("kind") != "Deployment" || q.Get("status") != "risk" || q.Get("limit") != "20" {
		t.Errorf("query wrong: %s", fb.lastReq.URL.RawQuery)
	}
	rows := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(rows) != 3 {
		t.Fatalf("want header + 2 rows:\n%s", out.String())
	}
	if f := strings.Fields(rows[1]); strings.Join(f, " ") != "payments Deployment checkout warn 71 41% - 0/0/1 3" {
		t.Errorf("row 1: %v", f)
	}
	if f := strings.Fields(rows[2]); f[3] != "unknown" || f[4] != "unknown" || f[5] != "0%" {
		t.Errorf("unknown row must render unknown, got %v", f)
	}
	if !strings.Contains(errOut.String(), "--after payments/StatefulSet/ledger-db") {
		t.Errorf("cursor notice: %q", errOut.String())
	}
}

func TestProfileDiff_Table(t *testing.T) {
	fb := startFakeBroker(t, map[string]string{checkoutProfilePath + "/diff": postureFixture(t, "profile_diff.json")})
	var out bytes.Buffer
	if err := fetchAndRenderProfileDiff(checkoutRef, 2, 3, "table", &out); err != nil {
		t.Fatalf("diff: %v", err)
	}
	if q := fb.lastReq.URL.Query(); q.Get("from") != "2" || q.Get("to") != "3" {
		t.Errorf("query: %s", fb.lastReq.URL.RawQuery)
	}
	s := out.String()
	for _, want := range []string{
		"From:     2 (2026-09-22T09:00:00Z)",
		"podSecurity: changed",
		"level: baseline -> restricted",
		"securityContext.seccompProfileType: unset -> RuntimeDefault",
		"\n      fields:\n        allowPrivilegeEscalation: unset -> false\n",
		"\n  pod:\n    securityContext.seccompProfileType: unset -> RuntimeDefault\n",
		"+ sha256:9f2c0d1e",
		"- sha256:0c3d",
		"+ io_uring_setup",
		"+ egress TCP/443 external:203.0.113.10",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if strings.Contains(s, "captureLevel") || strings.Contains(s, "audited") {
		t.Errorf("null (unchanged) scalars must not be printed:\n%s", s)
	}
}

func TestProfileDiff_DefaultsAndErrors(t *testing.T) {
	fb := startFakeBroker(t, map[string]string{})
	var out bytes.Buffer
	err := fetchAndRenderProfileDiff(checkoutRef, 0, 0, "table", &out)
	if fb.lastReq.URL.RawQuery != "" {
		t.Errorf("defaults must send no from/to: %q", fb.lastReq.URL.RawQuery)
	}
	if err == nil || !strings.Contains(err.Error(), "no stored profile revisions") {
		t.Errorf("want no-revisions error, got %v", err)
	}
	fb.routes[checkoutProfilePath+"/diff"] = `404:{"error":"revision_not_found","message":"revision 9 does not exist"}`
	err = fetchAndRenderProfileDiff(checkoutRef, 0, 9, "table", &out)
	if err == nil || !strings.Contains(err.Error(), "revision 9 does not exist") {
		t.Errorf("want the broker's revision message, got %v", err)
	}
	fb.routes[checkoutProfilePath+"/diff"] = `400:{"error":"bad_request","message":"from must be < to"}`
	err = fetchAndRenderProfileDiff(checkoutRef, 0, 9, "table", &out)
	if err == nil || !strings.Contains(err.Error(), "HTTP 400: from must be < to") {
		t.Errorf("want the broker's 400 message, got %v", err)
	}
}

func TestProfileExport_PrintsRecommendationVerbatim(t *testing.T) {
	body := postureFixture(t, "profile_full.json")
	startFakeBroker(t, map[string]string{checkoutProfilePath: body})
	var out, errOut bytes.Buffer
	if err := exportPSSPatch(checkoutRef, &out, &errOut); err != nil {
		t.Fatalf("export: %v", err)
	}
	var p struct {
		Dimensions struct {
			PodSecurity struct {
				Recommendation struct {
					YAML string `json:"yaml"`
				} `json:"recommendation"`
			} `json:"podSecurity"`
		} `json:"dimensions"`
	}
	_ = json.Unmarshal([]byte(body), &p)
	if out.String() != p.Dimensions.PodSecurity.Recommendation.YAML {
		t.Errorf("stdout must be the broker's patch verbatim:\n%q", out.String())
	}
	if !strings.Contains(out.String(), "not applied") {
		t.Error("patch must carry its not-applied header")
	}
	e := errOut.String()
	if !strings.Contains(e, "caveat: Checks kguardian cannot see") || !strings.Contains(e, "has not applied it") {
		t.Errorf("stderr: %q", e)
	}
}

func TestProfileExport_NothingToRecommendAndUnknown(t *testing.T) {
	var full map[string]any
	_ = json.Unmarshal([]byte(postureFixture(t, "profile_full.json")), &full)
	full["dimensions"].(map[string]any)["podSecurity"].(map[string]any)["recommendation"] = nil
	passing, _ := json.Marshal(full)
	startFakeBroker(t, map[string]string{
		checkoutProfilePath: string(passing),
		"/workloads/batch/CronJob/nightly-report/profile": postureFixture(t, "profile_unknown.json"),
	})
	var out, errOut bytes.Buffer
	if err := exportPSSPatch(checkoutRef, &out, &errOut); err != nil {
		t.Fatalf("export: %v", err)
	}
	if out.Len() != 0 || !strings.Contains(errOut.String(), "nothing to recommend") {
		t.Errorf("out=%q err=%q", out.String(), errOut.String())
	}
	err := exportPSSPatch(workloadRef{"batch", "CronJob", "nightly-report"}, &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), "unknown, not compliant") {
		t.Errorf("unknown podSecurity must be an error, got %v", err)
	}
}

// The broker's own sample response (profile API PR, contract v1.1) must
// decode and render, including pod-level failing checks.
func TestProfileGet_BrokerSampleRenders(t *testing.T) {
	startFakeBroker(t, map[string]string{checkoutProfilePath: postureFixture(t, "profile_broker_sample.json")})
	var out bytes.Buffer
	if err := fetchAndRenderProfile(checkoutRef, "table", &out); err != nil {
		t.Fatalf("get: %v", err)
	}
	s := out.String()
	for _, want := range []string{"Posture:    warn  score 63  coverage 41%", "podSecurity", "syscalls", "Needs attention:"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	var patch, errOut bytes.Buffer
	if err := exportPSSPatch(checkoutRef, &patch, &errOut); err != nil {
		t.Fatalf("export: %v", err)
	}
	if !strings.Contains(patch.String(), "securityContext") {
		t.Errorf("sample export has no patch:\n%s", patch.String())
	}
}

// Diffing revision 1 with no --from: the broker sends from=null.
func TestProfileDiff_Revision1FromNull(t *testing.T) {
	startFakeBroker(t, map[string]string{checkoutProfilePath + "/diff": postureFixture(t, "profile_diff_rev1.json")})
	var out bytes.Buffer
	if err := fetchAndRenderProfileDiff(checkoutRef, 0, 1, "table", &out); err != nil {
		t.Fatalf("diff: %v", err)
	}
	s := out.String()
	for _, want := range []string{"From:     (none)", "To:       1", "level: unknown -> baseline", "captureLevel: unknown -> full", "audited: unknown -> false", "+ read"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
}
