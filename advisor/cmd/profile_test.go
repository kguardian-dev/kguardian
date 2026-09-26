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
// serves real broker output (test/fixtures/posture: contract v1.2 captures
// from the profile API PR, also replayed by the llm-bridge tool tests). The
// rules under test: there is no score anywhere; unknown prints as unknown
// and readiness null as "can't tell", never as a pass; -o json/yaml pass
// the broker body through; export prints the broker's recommendation
// verbatim with its caveats on stderr, and a null recommendation is not a
// pass.

func postureFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "test", "fixtures", "posture", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return string(b)
}

var (
	checkoutRef     = workloadRef{"payments", "Deployment", "checkout"}
	otelRef         = workloadRef{"observability", "Deployment", "otel-collector"}
	nodeExporterRef = workloadRef{"observability", "DaemonSet", "node-exporter"}
	ledgerRef       = workloadRef{"payments", "Deployment", "ledger"}
)

const checkoutProfilePath = "/workloads/payments/Deployment/checkout/profile"

func profileRoutes(t *testing.T) map[string]string {
	return map[string]string{
		checkoutProfilePath: postureFixture(t, "profile_warn.json"),
		"/workloads/observability/Deployment/otel-collector/profile": postureFixture(t, "profile_unknown.json"),
		"/workloads/observability/DaemonSet/node-exporter/profile":   postureFixture(t, "profile_risk.json"),
		"/workloads/payments/Deployment/ledger/profile":              postureFixture(t, "profile_stale.json"),
	}
}

func mustContain(t *testing.T, s string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(s, w) {
			t.Errorf("missing %q in:\n%s", w, s)
		}
	}
}

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

func TestProfileGet_TableWarn(t *testing.T) {
	fb := startFakeBroker(t, profileRoutes(t))
	var out bytes.Buffer
	if err := fetchAndRenderProfile(checkoutRef, "table", &out); err != nil {
		t.Fatalf("get: %v", err)
	}
	if fb.lastReq.URL.Path != checkoutProfilePath || fb.lastReq.Header.Get("Authorization") != "Bearer read-token" {
		t.Errorf("request wrong: %s auth=%q", fb.lastReq.URL.Path, fb.lastReq.Header.Get("Authorization"))
	}
	s := out.String()
	mustContain(t, s,
		"Posture:    warn  coverage 50% (known core dimensions)",
		"Unknown:    network, podSecurity (no data; not counted as ok or risk)",
		"  syscalls warn: No SeccompProfile CR enforces the observed syscall set",
		"Revision:   4",
		"PSS level:  at most restricted (unconfirmed: 9 checks not visible to kguardian)",
		"DIMENSION    STATUS   COVERAGE  REASON",
		"syscalls.no_enforcing_profile",
		"podSecurityRestricted   can't tell",
		"syscallCaptureComplete  no",
	)
	if strings.Contains(strings.ToLower(s), "score") || strings.Contains(s, "grade") {
		t.Errorf("v1.2 has no score or grade:\n%s", s)
	}
	if strings.Contains(s, "profile export") {
		t.Errorf("no recommendation hint when recommendation is null:\n%s", s)
	}
}

func TestProfileGet_UnknownNeverRendersAsPass(t *testing.T) {
	startFakeBroker(t, profileRoutes(t))
	var out bytes.Buffer
	if err := fetchAndRenderProfile(otelRef, "table", &out); err != nil {
		t.Fatalf("get: %v", err)
	}
	s := out.String()
	mustContain(t, s, "Posture:    unknown  coverage 0%", "PSS level:  unknown", "imageSigned             can't tell")
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if strings.HasPrefix(line, " ") {
			// posture reason lines ("  network unknown: ...") and readiness rows
			if len(f) >= 2 && f[1] == "yes" {
				t.Errorf("nothing is a pass on an all-unknown workload: %q", line)
			}
			continue
		}
		if len(f) >= 2 && (f[0] == "network" || f[0] == "syscalls" || f[0] == "podSecurity" || f[0] == "images") && f[1] != "unknown" {
			t.Errorf("dimension row must be unknown: %q", line)
		}
		if len(f) >= 2 && f[1] == "yes" {
			t.Errorf("nothing is a pass on an all-unknown workload: %q", line)
		}
	}
}

func TestProfileGet_RiskAndStale(t *testing.T) {
	startFakeBroker(t, profileRoutes(t))
	var out bytes.Buffer
	if err := fetchAndRenderProfile(nodeExporterRef, "table", &out); err != nil {
		t.Fatalf("get: %v", err)
	}
	mustContain(t, out.String(),
		"Posture:    risk  coverage 75%",
		"podSecurity risk: Privileged under PSS",
		"PSS level:  privileged",
		"podSecurity.hostPID",
		"profile export observability/DaemonSet/node-exporter --format pss",
	)
	out.Reset()
	if err := fetchAndRenderProfile(ledgerRef, "table", &out); err != nil {
		t.Fatalf("get: %v", err)
	}
	mustContain(t, out.String(), "Stale:      legacy-proxy (regular, last seen 2026-09-24T02:04:20.420873Z) is no longer in the spec and is excluded")
}

func TestProfileGet_JSONAndYAMLPassThrough(t *testing.T) {
	body := postureFixture(t, "profile_warn.json")
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
	mustContain(t, y.String(), "levelConfidence: upper_bound", "vulnerabilities: null", "recommendation: null")
}

func TestProfileGet_NotFound(t *testing.T) {
	startFakeBroker(t, map[string]string{
		checkoutProfilePath: `404:{"error":"workload_not_found","message":"the broker has no inventory, syscall aggregate, live pod or stored profile for this workload"}`,
	})
	var out bytes.Buffer
	err := fetchAndRenderProfile(checkoutRef, "table", &out)
	if err == nil || !strings.Contains(err.Error(), "no data for payments/Deployment/checkout") {
		t.Fatalf("want no-data error, got %v", err)
	}
}

func TestProfileList_TableQueryAndCursor(t *testing.T) {
	page := postureFixture(t, "profiles_page.json")
	fb := startFakeBroker(t, map[string]string{"/workloads": page})
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
	if h := strings.Join(strings.Fields(rows[0]), " "); h != "NAMESPACE KIND NAME STATUS COVERAGE UNKNOWN FINDINGS (C/H/M) REV" {
		t.Errorf("header: %q", h)
	}
	if f := strings.Join(strings.Fields(rows[1]), " "); f != "payments Deployment checkout warn 50% network,podSecurity 0/0/1 4" {
		t.Errorf("row 1: %q", f)
	}
	if errOut.Len() != 0 {
		t.Errorf("last page must print no cursor: %q", errOut.String())
	}

	var m map[string]any
	_ = json.Unmarshal([]byte(page), &m)
	m["nextAfter"] = "payments/Deployment/ledger"
	more, _ := json.Marshal(m)
	fb.routes["/workloads"] = string(more)
	out.Reset()
	if err := fetchAndRenderProfiles(api.ProfileListOptions{}, "table", &out, &errOut); err != nil {
		t.Fatal(err)
	}
	mustContain(t, errOut.String(), "--after payments/Deployment/ledger")
}

func TestProfileDiff_Table(t *testing.T) {
	fb := startFakeBroker(t, map[string]string{checkoutProfilePath + "/diff": postureFixture(t, "profile_diff.json")})
	var out bytes.Buffer
	if err := fetchAndRenderProfileDiff(checkoutRef, 2, 4, "table", &out); err != nil {
		t.Fatalf("diff: %v", err)
	}
	if q := fb.lastReq.URL.Query(); q.Get("from") != "2" || q.Get("to") != "4" {
		t.Errorf("query: %s", fb.lastReq.URL.RawQuery)
	}
	s := out.String()
	mustContain(t, s,
		"From:     2 (2026-09-26T02:05:41.141561Z)",
		"podSecurity: changed",
		"level: baseline -> restricted",
		"\n      fields:\n        securityContext.allowPrivilegeEscalation: unset -> false\n",
		`securityContext.capabilitiesDrop: unset -> ["ALL"]`,
		"+ egress TCP/443 external:198.51.100.20",
		"syscalls: unchanged",
		"images: unchanged",
	)
	if strings.Contains(s, "captureLevel") || strings.Contains(s, "Note:") {
		t.Errorf("null (unchanged) scalars and the trimmed note must not print:\n%s", s)
	}
}

func TestProfileDiff_TrimmedPredecessor(t *testing.T) {
	startFakeBroker(t, map[string]string{checkoutProfilePath + "/diff": postureFixture(t, "profile_diff_trimmed.json")})
	var out bytes.Buffer
	if err := fetchAndRenderProfileDiff(checkoutRef, 0, 2, "table", &out); err != nil {
		t.Fatalf("diff: %v", err)
	}
	mustContain(t, out.String(), "From:     (none)", "Note:     the revision before --to was trimmed by retention", "(none, so everything shows as added)")
}

// A null derived value is unknown, a null spec field is unset.
func TestProfileDiff_Revision1NullsAreUnknown(t *testing.T) {
	startFakeBroker(t, map[string]string{checkoutProfilePath + "/diff": postureFixture(t, "profile_diff_rev1.json")})
	var out bytes.Buffer
	if err := fetchAndRenderProfileDiff(checkoutRef, 0, 1, "table", &out); err != nil {
		t.Fatalf("diff: %v", err)
	}
	mustContain(t, out.String(), "From:     (none)", "To:       1", "level: unknown -> baseline", "captureLevel: unknown -> full", "+ read")
	if strings.Contains(out.String(), "level: unset") {
		t.Errorf("a null level must print unknown:\n%s", out.String())
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
	// Real broker error bodies (profile API captures).
	fb.routes[checkoutProfilePath+"/diff"] = `404:{"error":"revision_not_found","message":"no stored profile version with that revision"}`
	err = fetchAndRenderProfileDiff(checkoutRef, 1, 3, "table", &out)
	if err == nil || !strings.Contains(err.Error(), "no stored profile version with that revision") {
		t.Errorf("want the broker's revision message, got %v", err)
	}
	fb.routes[checkoutProfilePath+"/diff"] = `400:{"error":"bad_request","message":"from must be lower than to"}`
	err = fetchAndRenderProfileDiff(checkoutRef, 0, 9, "table", &out)
	if err == nil || !strings.Contains(err.Error(), "HTTP 400: from must be lower than to") {
		t.Errorf("want the broker's 400 message, got %v", err)
	}
}

func TestProfileExport_PrintsRecommendationVerbatim(t *testing.T) {
	body := postureFixture(t, "profile_risk.json")
	startFakeBroker(t, profileRoutes(t))
	var out, errOut bytes.Buffer
	if err := exportPSSPatch(nodeExporterRef, &out, &errOut); err != nil {
		t.Fatalf("export: %v", err)
	}
	var p struct {
		Dimensions struct {
			PodSecurity struct {
				Recommendation struct {
					YAML    string   `json:"yaml"`
					Caveats []string `json:"caveats"`
				} `json:"recommendation"`
			} `json:"podSecurity"`
		} `json:"dimensions"`
	}
	_ = json.Unmarshal([]byte(body), &p)
	want := p.Dimensions.PodSecurity.Recommendation.YAML
	if !strings.HasSuffix(want, "\n") {
		want += "\n"
	}
	if out.String() != want {
		t.Errorf("stdout must be the broker's patch verbatim:\n%q", out.String())
	}
	mustContain(t, out.String(), "not applied", "hostPID: false")
	for _, c := range p.Dimensions.PodSecurity.Recommendation.Caveats {
		mustContain(t, errOut.String(), "caveat: "+c)
	}
	mustContain(t, errOut.String(), "has not applied it")
}

func TestProfileExport_NullRecommendationIsNotAPass(t *testing.T) {
	startFakeBroker(t, profileRoutes(t))
	var out, errOut bytes.Buffer
	if err := exportPSSPatch(checkoutRef, &out, &errOut); err != nil {
		t.Fatalf("export: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("no patch means empty stdout, got %q", out.String())
	}
	mustContain(t, errOut.String(), "no securityContext patch to recommend (level restricted). This is not a pass", "reason: Every evaluated check passes restricted")

	out.Reset()
	errOut.Reset()
	err := exportPSSPatch(otelRef, &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), "unknown, not compliant") {
		t.Errorf("unknown podSecurity must be an error, got %v", err)
	}
}
