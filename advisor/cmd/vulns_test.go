package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
		"In use: unknown",
	)
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
	mustContain(t, s, "CVE-2099-10003  HIGH, no fix available", "libexample", "In use: unknown", "INGRESS FLOWS", "egress alone does not count")
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
			if len(f) >= 7 && f[1] == wl {
				found = true
				if f[4] != exp[0] || f[5] != exp[1] || f[6] != exp[2] {
					t.Errorf("%s: exposed/via/ingress = %s %s %s, want %v", wl, f[4], f[5], f[6], exp)
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
