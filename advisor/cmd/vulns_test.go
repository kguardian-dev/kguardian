package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
)

// `kguardian images vulns|sbom` and `kguardian vulns list|exposure` against
// an httptest broker serving real responses captured from a local broker
// built from the vulnerability API PR (test/fixtures/vulns; neutral names,
// fake CVE-2099-* ids). The rules under test: unknown prints as unknown
// (no data, KEV, exposed), the --fail-on gate exits 1 / 3 / 0 correctly
// and looks at every page, and -o json/yaml/cyclonedx pass the broker's
// bytes through.

const (
	storefrontDigest = "sha256:00000000000000000000000000000000000000000000000000000000000000a2"
	ledgerDigest     = "sha256:00000000000000000000000000000000000000000000000000000000000000b1"
	unscannedDigest  = "sha256:00000000000000000000000000000000000000000000000000000000000000c1"
)

type vulnCapture struct {
	Request string          `json:"request"`
	Status  int             `json:"status"`
	Body    json.RawMessage `json:"body"`
}

// vulnRoute reads a capture and returns (path, route body) for
// startFakeBroker; a non-200 capture is encoded as "NNN:<body>".
func vulnRoute(t *testing.T, name string) (string, string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "test", "fixtures", "vulns", name+".json"))
	if err != nil {
		t.Fatalf("reading capture %s: %v", name, err)
	}
	var c vulnCapture
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("decoding capture %s: %v", name, err)
	}
	p := strings.SplitN(strings.TrimPrefix(c.Request, "GET "), "?", 2)[0]
	body := string(c.Body)
	if c.Status != 200 {
		body = fmt.Sprintf("%d:%s", c.Status, body)
	}
	return p, body
}

func vulnRoutes(t *testing.T, names ...string) map[string]string {
	r := map[string]string{}
	for _, n := range names {
		p, b := vulnRoute(t, n)
		r[p] = b
	}
	return r
}

func TestParseSeverityListAndFailOn(t *testing.T) {
	if s, err := parseSeverityList(" high, critical ,HIGH"); err != nil || s != "HIGH,CRITICAL" {
		t.Errorf("got %q %v", s, err)
	}
	if _, err := parseSeverityList("severe"); err == nil {
		t.Error("severe must be rejected")
	}
	if s, _ := failOnSeverities("high"); s != "CRITICAL,HIGH,UNKNOWN" {
		t.Errorf("fail-on high = %q", s)
	}
	if s, _ := failOnSeverities("LOW"); s != "CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN" {
		t.Errorf("fail-on low = %q", s)
	}
	for _, bad := range []string{"none", "unknown", "urgent"} {
		if _, err := failOnSeverities(bad); err == nil {
			t.Errorf("--fail-on %s must be rejected", bad)
		}
	}
}

func TestImagesVulns_Table(t *testing.T) {
	fb := startFakeBroker(t, vulnRoutes(t, "image-vulns-storefront"))
	var out, errOut bytes.Buffer
	if err := fetchAndRenderImageVulns(storefrontDigest, api.ImageVulnsOptions{Severity: "CRITICAL,HIGH", Limit: 50}, "", "", "table", &out, &errOut); err != nil {
		t.Fatal(err)
	}
	q := fb.lastReq.URL.Query()
	if fb.lastReq.URL.Path != "/images/"+storefrontDigest+"/vulnerabilities" || q.Get("severity") != "CRITICAL,HIGH" || q.Get("limit") != "50" {
		t.Errorf("request: %s", fb.lastReq.URL.String())
	}
	s := out.String()
	mustContain(t, s,
		"SOURCE", "grype", "trivy-operator", "platform_manifest", "unverified", "scanned",
		"CRITICAL  CVE-2099-10001",
		"fastparse", "2.1.10 or 2.1.4", "yes", "grype,trivy-operator",
		"TIER", "IN USE", "never as unused", "a KEV finding\nthere is P0",
	)
	// This capture predates tiers: TIER prints "-", IN USE "unknown".
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, "CVE-2099-10001") && (!strings.HasPrefix(line, "-") || !strings.Contains(line, "unknown")) {
			t.Errorf("no tier = '-', no in-use = unknown: %q", line)
		}
	}
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, "CVE-2099-10002") && !strings.Contains(line, "unknown") {
			t.Errorf("KEV null must print unknown: %q", line)
		}
	}
}

func TestImagesVulns_UnscannedIsUnknown(t *testing.T) {
	startFakeBroker(t, vulnRoutes(t, "image-vulns-unscanned"))
	var out, errOut bytes.Buffer
	if err := fetchAndRenderImageVulns(unscannedDigest, api.ImageVulnsOptions{}, "", "", "table", &out, &errOut); err != nil {
		t.Fatal(err)
	}
	mustContain(t, out.String(), "No vulnerability data", "unknown, not clean")
}

func gateCode(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var ge *gateError
	if !errors.As(err, &ge) {
		t.Fatalf("want a gate result, got %v", err)
	}
	return ge.code
}

func TestImagesVulns_FailOnGate(t *testing.T) {
	// storefront has a CRITICAL: --fail-on high fails with exit 1.
	fb := startFakeBroker(t, vulnRoutes(t, "image-vulns-storefront", "image-vulns-unscanned"))
	var out, errOut bytes.Buffer
	gate, _ := failOnSeverities("high")
	err := fetchAndRenderImageVulns(storefrontDigest, api.ImageVulnsOptions{}, gate, "HIGH", "table", &out, &errOut)
	if gateCode(t, err) != exitGateFindings {
		t.Fatalf("want exit %d, got %v", exitGateFindings, err)
	}
	// The gate runs its own query with the threshold severities, limit 1,
	// so it is not fooled by the page shown.
	if q := fb.lastReq.URL.Query(); q.Get("severity") != "CRITICAL,HIGH,UNKNOWN" || q.Get("limit") != "1" {
		t.Errorf("gate query: %s", fb.lastReq.URL.RawQuery)
	}
	mustContain(t, err.Error(), "CVE-2099-10001")

	// No data at all is exit 3, never a pass.
	err = fetchAndRenderImageVulns(unscannedDigest, api.ImageVulnsOptions{}, gate, "HIGH", "table", &out, &errOut)
	if gateCode(t, err) != exitGateUnknown {
		t.Fatalf("want exit %d, got %v", exitGateUnknown, err)
	}
	mustContain(t, err.Error(), "unknown is not a pass")
}

func TestImagesVulns_FailOnPasses(t *testing.T) {
	// ledger has nothing CRITICAL. The display page is the real capture;
	// the gate query (threshold severities, limit 1) answers with no items,
	// as the broker does when nothing is at or above the threshold.
	p, body := vulnRoute(t, "image-vulns-ledger")
	startFakeBroker(t, map[string]string{p: body})
	var out, errOut bytes.Buffer
	gate, _ := failOnSeverities("critical")
	orig := api.GetImageVulnsFunc
	calls := 0
	api.GetImageVulnsFunc = func(d string, o api.ImageVulnsOptions) (*api.ImageVulnsPage, []byte, error) {
		calls++
		if o.Limit == 1 {
			empty := &api.ImageVulnsPage{Digest: d, Reports: []api.VulnReport{{Source: "trivy-operator"}}}
			return empty, []byte(`{}`), nil
		}
		return orig(d, o)
	}
	t.Cleanup(func() { api.GetImageVulnsFunc = orig })
	err := fetchAndRenderImageVulns(ledgerDigest, api.ImageVulnsOptions{}, gate, "CRITICAL", "table", &out, &errOut)
	if err != nil || calls != 2 {
		t.Fatalf("want pass after 2 calls, got %v (%d calls)", err, calls)
	}
	mustContain(t, errOut.String(), "gate: no findings at or above CRITICAL")
}

func TestImagesVulns_JSONPassThrough(t *testing.T) {
	p, body := vulnRoute(t, "image-vulns-storefront")
	startFakeBroker(t, map[string]string{p: body})
	var out, errOut bytes.Buffer
	if err := fetchAndRenderImageVulns(storefrontDigest, api.ImageVulnsOptions{}, "", "", "json", &out, &errOut); err != nil {
		t.Fatal(err)
	}
	var want, got any
	_ = json.Unmarshal([]byte(body), &want)
	_ = json.Unmarshal(out.Bytes(), &got)
	wb, _ := json.Marshal(want)
	gb, _ := json.Marshal(got)
	if !bytes.Equal(wb, gb) {
		t.Error("-o json must be the broker body unchanged")
	}
}

func TestImagesVulns_BrokerErrors(t *testing.T) {
	startFakeBroker(t, vulnRoutes(t, "image-vulns-bad-severity"))
	var out, errOut bytes.Buffer
	err := fetchAndRenderImageVulns(ledgerDigest, api.ImageVulnsOptions{Severity: "SEVERE"}, "", "", "table", &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), "HTTP 400") {
		t.Errorf("want the broker's 400, got %v", err)
	}
}

func TestImagesSbom_TableAndTrust(t *testing.T) {
	fb := startFakeBroker(t, vulnRoutes(t, "sbom-storefront"))
	var out, errOut bytes.Buffer
	if err := fetchAndRenderSbom(storefrontDigest, "", 50, 0, "table", &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if fb.lastReq.URL.Query().Get("limit") != "50" {
		t.Errorf("query: %s", fb.lastReq.URL.RawQuery)
	}
	s := out.String()
	mustContain(t, s, "SOURCE", "TRUST", "SIGNED", "Components from trivy-operator (trust scanned)", "fastparse", "pkg:npm/fastparse@2.1.0")
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && (f[0] == "registry" || f[0] == "trivy-operator") && f[3] != "no" {
			t.Errorf("only verified is signed: %q", line)
		}
	}
}

func TestImagesSbom_NoSbomIsUnknown(t *testing.T) {
	startFakeBroker(t, vulnRoutes(t, "sbom-unscanned"))
	var out, errOut bytes.Buffer
	if err := fetchAndRenderSbom(unscannedDigest, "", 0, 0, "table", &out, &errOut); err != nil {
		t.Fatal(err)
	}
	mustContain(t, out.String(), "No SBOM for", "contents are unknown")
}

func TestImagesSbom_CycloneDXPassThrough(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "test", "fixtures", "vulns", "sbom-storefront.cdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	fb := startFakeBroker(t, map[string]string{"/images/" + storefrontDigest + "/sbom/cyclonedx": string(doc)})
	var out, errOut bytes.Buffer
	if err := fetchAndRenderSbom(storefrontDigest, "registry", 0, 0, "cyclonedx", &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if fb.lastReq.URL.Query().Get("source") != "registry" {
		t.Errorf("source not forwarded: %s", fb.lastReq.URL.RawQuery)
	}
	if !bytes.Equal(bytes.TrimRight(out.Bytes(), "\n"), bytes.TrimRight(doc, "\n")) {
		t.Error("cyclonedx output must be the broker's document byte for byte")
	}
	mustContain(t, out.String(), `"bomFormat":"CycloneDX"`, "kguardian:sbomTrust")

	fb.routes["/images/"+storefrontDigest+"/sbom/cyclonedx"] = "404:No SBOM for this image"
	out.Reset()
	err = fetchAndRenderSbom(storefrontDigest, "", 0, 0, "cyclonedx", &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), "contents are unknown") || out.Len() != 0 {
		t.Errorf("want unknown error and no output, got %v / %q", err, out.String())
	}
}

func TestVulnsList_TableAndFreshness(t *testing.T) {
	fb := startFakeBroker(t, vulnRoutes(t, "vulns-list"))
	var out, errOut bytes.Buffer
	fixable := true
	opts := api.VulnsListOptions{Namespace: "billing", Severity: "HIGH", Fixable: &fixable, Running: true, Limit: 10}
	if err := fetchAndRenderVulns(opts, "table", &out, &errOut); err != nil {
		t.Fatal(err)
	}
	q := fb.lastReq.URL.Query()
	if q.Get("namespace") != "billing" || q.Get("severity") != "HIGH" || q.Get("fixable") != "true" || q.Get("running") != "true" || q.Get("limit") != "10" {
		t.Errorf("query: %s", fb.lastReq.URL.RawQuery)
	}
	mustContain(t, out.String(), "SEVERITY", "CVE-2099-10001", "CVE-2099-10003", "platform_manifest", "image_id")
	mustContain(t, errOut.String(), "Summary computed at")
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.Contains(line, "CVE-2099-10003") && !strings.Contains(line, "unknown") {
			t.Errorf("KEV null must print unknown: %q", line)
		}
	}
}

func TestVulnsList_SummaryNotBuiltIsUnknown(t *testing.T) {
	startFakeBroker(t, map[string]string{"/vulnerabilities": `{"items":[],"nextAfter":null,"computedAt":null,"staleSeconds":null}`})
	var out, errOut bytes.Buffer
	if err := fetchAndRenderVulns(api.VulnsListOptions{}, "table", &out, &errOut); err != nil {
		t.Fatal(err)
	}
	mustContain(t, errOut.String(), "not been built yet", "unknown, not clean")
	mustContain(t, out.String(), "Images no source has scanned are unknown")
}

func TestVulnsExposure_TableTrueFalseUnknown(t *testing.T) {
	fb := startFakeBroker(t, vulnRoutes(t, "exposure-shared"))
	var out bytes.Buffer
	if err := fetchAndRenderExposure("CVE-2099-10003", 72, "table", &out); err != nil {
		t.Fatal(err)
	}
	if fb.lastReq.URL.Query().Get("window_hours") != "72" {
		t.Errorf("query: %s", fb.lastReq.URL.RawQuery)
	}
	s := out.String()
	mustContain(t, s, "CVE-2099-10003  HIGH, no fix available", "libexample", "In use: unknown", "IN USE", "INGRESS FLOWS", "egress alone does not count")
	// catalog-sync had egress but no ingress: unknown, never "no".
	want := map[string][3]string{
		"Deployment/storefront":   {"yes", "other_namespace,unattributed,public_ip", "2"},
		"Deployment/ledger":       {"no", "-", "1"},
		"Deployment/catalog-sync": {"unknown", "-", "0"},
	}
	for wl, exp := range want {
		found := false
		for _, line := range strings.Split(s, "\n") {
			f := strings.Fields(line)
			if len(f) >= 8 && f[1] == wl {
				found = true
				if f[4] != "unknown" {
					t.Errorf("%s: in use = %s, want unknown (capture predates in-use)", wl, f[4])
				}
				if f[5] != exp[0] || f[6] != exp[1] || f[7] != exp[2] {
					t.Errorf("%s: exposed/via/ingress = %s %s %s, want %v", wl, f[5], f[6], f[7], exp)
				}
			}
		}
		if !found {
			t.Errorf("no row for %s in:\n%s", wl, s)
		}
	}
}

func TestVulnsExposure_NotFoundIsNotProofOfAbsence(t *testing.T) {
	startFakeBroker(t, vulnRoutes(t, "exposure-not-found"))
	var out bytes.Buffer
	err := fetchAndRenderExposure("CVE-2099-99999", 0, "table", &out)
	if err == nil || !strings.Contains(err.Error(), "not proof the cluster is unaffected") {
		t.Errorf("got %v", err)
	}
}

func TestImagesVulns_GateCouldNotCheckIsExit2(t *testing.T) {
	gate, _ := failOnSeverities("high")
	var out, errOut bytes.Buffer

	// Broker refuses the token: exit 2 with the token hint, not 1.
	startFakeBroker(t, vulnRoutes(t, "image-vulns-noauth"))
	err := fetchAndRenderImageVulns(ledgerDigest, api.ImageVulnsOptions{}, gate, "HIGH", "table", &out, &errOut)
	if gateCode(t, err) != exitGateNoCheck {
		t.Fatalf("401 with a gate: want exit %d, got %v", exitGateNoCheck, err)
	}
	mustContain(t, err.Error(), "gate: could not check (exit 2)", "read scope")

	// Broker unreachable: exit 2.
	origURL := api.BrokerBaseURL
	api.BrokerBaseURL = "http://127.0.0.1:1"
	err = fetchAndRenderImageVulns(ledgerDigest, api.ImageVulnsOptions{}, gate, "HIGH", "table", &out, &errOut)
	api.BrokerBaseURL = origURL
	if gateCode(t, err) != exitGateNoCheck {
		t.Fatalf("unreachable broker with a gate: want exit %d, got %v", exitGateNoCheck, err)
	}

	// The display page works but the gate's own query fails: still 2.
	p, body := vulnRoute(t, "image-vulns-storefront")
	startFakeBroker(t, map[string]string{p: body})
	orig := api.GetImageVulnsFunc
	api.GetImageVulnsFunc = func(d string, o api.ImageVulnsOptions) (*api.ImageVulnsPage, []byte, error) {
		if o.Limit == 1 {
			return nil, nil, fmt.Errorf("GetImageVulns: broker returned HTTP 503: shed")
		}
		return orig(d, o)
	}
	t.Cleanup(func() { api.GetImageVulnsFunc = orig })
	err = fetchAndRenderImageVulns(storefrontDigest, api.ImageVulnsOptions{}, gate, "HIGH", "table", &out, &errOut)
	if gateCode(t, err) != exitGateNoCheck {
		t.Fatalf("gate query failure: want exit %d, got %v", exitGateNoCheck, err)
	}

	// Without a gate, an error stays an ordinary error.
	api.GetImageVulnsFunc = orig
	api.BrokerBaseURL = "http://127.0.0.1:1"
	err = fetchAndRenderImageVulns(ledgerDigest, api.ImageVulnsOptions{}, "", "", "table", &out, &errOut)
	api.BrokerBaseURL = origURL
	var ge *gateError
	if err == nil || errors.As(err, &ge) {
		t.Errorf("no gate: want a plain error, got %v", err)
	}
}

// The process exit codes, through Execute: re-run this test binary as the
// CLI. A kubeconfig pointing at a closed port makes the broker port-forward
// fail (exit 2 with --fail-on), and a bad --fail-on value is exit 2 too;
// neither touches a real cluster.
func TestImagesVulns_ProcessExitCodes(t *testing.T) {
	if os.Getenv("KG_EXEC_CLI") == "1" {
		os.Args = append([]string{"kguardian"}, strings.Fields(os.Getenv("KG_ARGS"))...)
		Execute()
		os.Exit(0)
	}
	kubeconfig := filepath.Join(t.TempDir(), "config")
	cfg := "apiVersion: v1\nkind: Config\nclusters:\n- name: none\n  cluster:\n    server: https://127.0.0.1:1\ncontexts:\n- name: none\n  context:\n    cluster: none\n    user: none\n    namespace: default\nusers:\n- name: none\n  user:\n    token: x\ncurrent-context: none\n"
	if err := os.WriteFile(kubeconfig, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(args string) (int, string) {
		c := exec.Command(os.Args[0], "-test.run=^TestImagesVulns_ProcessExitCodes$")
		c.Env = append(os.Environ(), "KG_EXEC_CLI=1", "KG_ARGS="+args, "KUBECONFIG="+kubeconfig)
		out, err := c.CombinedOutput()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), string(out)
		}
		if err != nil {
			t.Fatalf("running CLI: %v", err)
		}
		return 0, string(out)
	}
	if code, out := run("images vulns " + storefrontDigest + " --fail-on high"); code != exitGateNoCheck || !strings.Contains(out, "gate: could not check") {
		t.Errorf("port-forward failure with --fail-on: exit %d, want %d\n%s", code, exitGateNoCheck, out)
	}
	if code, out := run("images vulns " + storefrontDigest + " --fail-on urgent"); code != exitGateNoCheck || !strings.Contains(out, "invalid --fail-on") {
		t.Errorf("bad --fail-on: exit %d, want %d\n%s", code, exitGateNoCheck, out)
	}
	if code, _ := run("images vulns " + storefrontDigest); code != 1 {
		t.Errorf("port-forward failure without a gate: exit %d, want 1", code)
	}
}

// --- tiers and in-use (#1533 P1-5) ------------------------------------------

// A finding as the in-use broker serialises it (supplychain_read.rs
// Finding); not a capture, the id is fake.
const tieredFinding = `{"id":"CVE-2099-30001","package":{"name":"libfoo1","type":"debian","purl":null},
 "installedVersion":"1.2.3-1","fixedVersions":["1.2.4"],"fixable":true,"severity":"HIGH","score":7.5,
 "kev":true,"epss":0.31,"sources":["trivy-operator"],"inUse":true,"inUseState":"loaded",
 "inUseDetail":{"state":"loaded","reason":null,"observedSince":null,"windowHours":24,"containers":1,"coverage":"file"},
 "tier":"P0","tierFactors":["in_use:loaded","kev","severity:high","exposure:unknown"]}`

func tieredPage(items string) string {
	return `{"digest":"` + storefrontDigest + `","reports":[{"source":"trivy-operator","reportDigest":"x","join":"image_id",
 "digestKind":"manifest","scannedAt":"2026-09-20T08:00:00","itemCount":1}],"items":[` + items + `],"nextAfter":null}`
}

func TestFailOnGateAndRiskFlagParsing(t *testing.T) {
	for in, want := range map[string]string{"p0": "tier:P0", "P1": "tier:P0,P1", "p2": "tier:P0,P1,P2", "high": "CRITICAL,HIGH,UNKNOWN"} {
		if got, err := failOnGate(in); err != nil || got != want {
			t.Errorf("failOnGate(%q) = %q %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"background", "p3", "none"} {
		if _, err := failOnGate(bad); err == nil {
			t.Errorf("--fail-on %s must be rejected", bad)
		}
	}
	if s, err := parseTierList("p1, background,P1"); err != nil || s != "P1,Background" {
		t.Errorf("tiers: %q %v", s, err)
	}
	if _, err := parseTierList("urgent"); err == nil {
		t.Error("an unknown tier must be rejected")
	}
	if s, err := parseInUseList("Loaded,unknown"); err != nil || s != "loaded,unknown" {
		t.Errorf("in-use: %q %v", s, err)
	}
	if _, err := parseInUseList("maybe"); err == nil {
		t.Error("an unknown in-use state must be rejected")
	}
}

func TestImagesVulns_TiersFiltersAndInUse(t *testing.T) {
	fb := startFakeBroker(t, map[string]string{"/images/" + storefrontDigest + "/vulnerabilities": tieredPage(tieredFinding)})
	var out, errOut bytes.Buffer
	kev, epss := true, 0.1
	opts := api.ImageVulnsOptions{Kev: &kev, EpssMin: &epss, InUse: "loaded,unknown", Tier: "P0,P1"}
	if err := fetchAndRenderImageVulns(storefrontDigest, opts, "", "", "table", &out, &errOut); err != nil {
		t.Fatal(err)
	}
	q := fb.lastReq.URL.Query()
	if q.Get("kev") != "true" || q.Get("epss_min") != "0.1" || q.Get("in_use") != "loaded,unknown" || q.Get("tier") != "P0,P1" {
		t.Errorf("query: %s", fb.lastReq.URL.RawQuery)
	}
	var row string
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.Contains(line, "CVE-2099-30001") {
			row = line
		}
	}
	if f := strings.Fields(row); len(f) < 9 || f[0] != "P0" || f[8] != "loaded" {
		t.Errorf("row: %q", row)
	}
}

func TestImagesVulns_FailOnTier(t *testing.T) {
	fb := startFakeBroker(t, map[string]string{"/images/" + storefrontDigest + "/vulnerabilities": tieredPage(tieredFinding)})
	var out, errOut bytes.Buffer
	gate, _ := failOnGate("p0")
	err := fetchAndRenderImageVulns(storefrontDigest, api.ImageVulnsOptions{}, gate, "P0", "table", &out, &errOut)
	if gateCode(t, err) != exitGateFindings {
		t.Fatalf("want exit %d, got %v", exitGateFindings, err)
	}
	if q := fb.lastReq.URL.Query(); q.Get("tier") != "P0" || q.Get("severity") != "" || q.Get("limit") != "1" {
		t.Errorf("gate query: %s", fb.lastReq.URL.RawQuery)
	}
	mustContain(t, err.Error(), "P0 HIGH CVE-2099-30001")

	// A broker without tiers ignores the filter and returns any finding:
	// that is "could not check" (2), never a result.
	startFakeBroker(t, vulnRoutes(t, "image-vulns-storefront"))
	err = fetchAndRenderImageVulns(storefrontDigest, api.ImageVulnsOptions{}, gate, "P0", "table", &out, &errOut)
	if gateCode(t, err) != exitGateNoCheck {
		t.Fatalf("want exit %d, got %v", exitGateNoCheck, err)
	}
	mustContain(t, err.Error(), "does not report risk tiers")
}

func TestVulnsList_TierColumnsAndFilters(t *testing.T) {
	body := `{"items":[{"id":"CVE-2099-30001","severity":"HIGH","maxScore":7.5,"fixable":true,"kev":true,"maxEpss":0.31,
 "packages":["libfoo1"],"sources":["trivy-operator"],"images":1,"workloads":2,"runningWorkloads":2,"namespaces":1,
 "weakestJoin":"image_id","tier":"P0","executedWorkloads":0,"loadedWorkloads":1,"unknownWorkloads":1,
 "notObservedWorkloads":0,"exposedWorkloads":1,"inUse":true,"inUseState":"loaded"}],
 "nextAfter":null,"computedAt":"2026-09-26T03:00:00","staleSeconds":5}`
	fb := startFakeBroker(t, map[string]string{"/vulnerabilities": body})
	var out, errOut bytes.Buffer
	if err := fetchAndRenderVulns(api.VulnsListOptions{Tier: "P0", InUse: "loaded"}, "table", &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if q := fb.lastReq.URL.Query(); q.Get("tier") != "P0" || q.Get("in_use") != "loaded" {
		t.Errorf("query: %s", fb.lastReq.URL.RawQuery)
	}
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.Contains(line, "CVE-2099-30001") {
			// TIER SEVERITY ID SCORE FIXABLE KEV IN-USE IMAGES WORKLOADS RUNNING EXPOSED
			if f := strings.Fields(line); len(f) < 11 || f[0] != "P0" || f[6] != "loaded" || f[10] != "1" {
				t.Errorf("row: %q", line)
			}
		}
	}
}
