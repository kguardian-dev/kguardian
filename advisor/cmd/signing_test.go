package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
)

// `kguardian images signers|trust` against an httptest broker serving
// responses captured from a local broker (test/fixtures/signing: real
// sigstore-go verifications of the supplychain fixtures over SQL-seeded
// workloads, and the real evaluator's ImageTrustPolicy results from an
// envtest API server; see its README.md). The
// rules under test: verified is never called trusted, unknown is never a
// pass, and --fail-on exits 1 / 2 / 3 like `images vulns`.

var signDigest = map[string]string{
	"storefront": "sha256:41e17ed83c594a64a9396b6ab96dd26d5ddc290dacf4c177464712ff21ad534f",
	"checkout":   "sha256:94be8ca1be31f007a2a31fd67a3830ee9dbde9cc971a699f35d419b5f51b242b",
	"search":     "sha256:3de3b7e5f8062f772ceab50833cbd54cb09688ca0e7a0f70bd79895ab54cd95d",
	"cart":       "sha256:f6ab986a3a713f127b0f03c6f5319756883249bbf58cebbee9911d80eb7fa1f8",
	"ledger":     "sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a",
	"payments":   "sha256:" + strings.Repeat("a", 64),
	"recs":       "sha256:" + strings.Repeat("d", 64),
}

// signRoutes serves the signing captures at their request paths.
func signRoutes(t *testing.T, names ...string) map[string]string {
	t.Helper()
	r := map[string]string{}
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join("..", "..", "test", "fixtures", "signing", n+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var c vulnCapture
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatal(err)
		}
		p := strings.SplitN(strings.TrimPrefix(c.Request, "GET "), "?", 2)[0]
		body := string(c.Body)
		if c.Status != 200 {
			body = fmt.Sprintf("%d:%s", c.Status, body)
		}
		r[p] = body
	}
	return r
}

func allSigners(t *testing.T) map[string]string {
	return signRoutes(t, "attestation-storefront", "attestation-checkout", "attestation-search",
		"attestation-cart", "attestation-ledger", "attestation-payments", "attestation-recs")
}

func TestImagesSigners_TableVerifiedIsNotTrusted(t *testing.T) {
	fb := startFakeBroker(t, allSigners(t))
	var out, errOut bytes.Buffer
	if err := fetchAndRenderSigners(signDigest["storefront"], "", "table", &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if fb.lastReq.URL.Path != "/images/"+signDigest["storefront"]+"/attestation" {
		t.Errorf("request: %s", fb.lastReq.URL)
	}
	if got := fb.lastReq.Header.Get("Authorization"); got != "Bearer read-token" {
		t.Errorf("auth header %q", got)
	}
	s := out.String()
	mustContain(t, s,
		"VERDICT     verified (a signature verified for the signer(s) below; valid, not trusted: see 'images trust')",
		"https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main via https://token.actions.githubusercontent.com",
		"ATTESTATIONS", "https://slsa.dev/provenance/v1", "https://spdx.dev/Document",
		"builder https://github.com/chainguard-dev/terraform-provider-apko",
	)

	out.Reset()
	if err := fetchAndRenderSigners(signDigest["checkout"], "", "table", &out, &errOut); err != nil {
		t.Fatal(err)
	}
	mustContain(t, out.String(), "yes       key   fixture (sha256 e2312c28209f4778…)")
}

func TestImagesSigners_UnverifiedShowsNoSigner(t *testing.T) {
	startFakeBroker(t, allSigners(t))
	for _, w := range []string{"search", "ledger"} {
		var out, errOut bytes.Buffer
		if err := fetchAndRenderSigners(signDigest[w], "", "table", &out, &errOut); err != nil {
			t.Fatal(err)
		}
		rows := 0
		for _, line := range strings.Split(out.String(), "\n") {
			if f := strings.Fields(line); len(f) > 3 && f[0] == "no" {
				rows++
				if f[1] != "-" || f[2] != "-" {
					t.Errorf("%s: an unverified signature shows a signer: %q", w, line)
				}
			}
		}
		if rows != 1 {
			t.Errorf("%s: want 1 unverified row, got %d:\n%s", w, rows, out.String())
		}
	}
}

func TestImagesSigners_FailOnGate(t *testing.T) {
	startFakeBroker(t, allSigners(t))
	cases := []struct {
		workload, level string
		code            int
	}{
		// The ruled matrix (invalid / unsigned / unverified).
		// storefront verified keyless, checkout verified key: 0/0/0
		{"storefront", "invalid", 0}, {"storefront", "unsigned", 0}, {"storefront", "unverified", 0},
		{"checkout", "invalid", 0}, {"checkout", "unsigned", 0}, {"checkout", "unverified", 0},
		// search key_signed: 3/3/1, never a pass
		{"search", "invalid", exitGateUnknown}, {"search", "unsigned", exitGateUnknown}, {"search", "unverified", exitGateFindings},
		// cart unsigned: 0/1/1
		{"cart", "invalid", 0}, {"cart", "unsigned", exitGateFindings}, {"cart", "unverified", exitGateFindings},
		// ledger invalid: 1/1/1
		{"ledger", "invalid", exitGateFindings}, {"ledger", "unsigned", exitGateFindings}, {"ledger", "unverified", exitGateFindings},
		// payments unknown (registry_auth) and recs never checked: 3/3/3
		{"payments", "invalid", exitGateUnknown}, {"payments", "unsigned", exitGateUnknown}, {"payments", "unverified", exitGateUnknown},
		{"recs", "invalid", exitGateUnknown}, {"recs", "unsigned", exitGateUnknown}, {"recs", "unverified", exitGateUnknown},
	}
	for _, c := range cases {
		var out, errOut bytes.Buffer
		err := fetchAndRenderSigners(signDigest[c.workload], c.level, "table", &out, &errOut)
		got := 0
		if err != nil {
			got = gateCode(t, err)
		}
		if got != c.code {
			t.Errorf("%s --fail-on %s: exit %d, want %d (%v)", c.workload, c.level, got, c.code, err)
		}
		if got == 0 {
			mustContain(t, errOut.String(), "gate: ", "which passes", "valid is not trusted")
		}
	}
}

func TestImagesSigners_NotCheckedIsUnknown(t *testing.T) {
	startFakeBroker(t, allSigners(t))
	var out, errOut bytes.Buffer
	if err := fetchAndRenderSigners(signDigest["recs"], "", "table", &out, &errOut); err != nil {
		t.Fatal(err)
	}
	mustContain(t, out.String(), "has not been checked", "This is unknown, not unsigned.")
	out.Reset()
	if err := fetchAndRenderSigners(signDigest["recs"], "", "json", &out, &errOut); err != nil {
		t.Fatal(err)
	}
	mustContain(t, out.String(), `"verdict": null`)
}

func TestImagesSigners_CouldNotCheckIsExit2(t *testing.T) {
	orig := api.BrokerBaseURL
	api.BrokerBaseURL = "http://127.0.0.1:1"
	t.Cleanup(func() { api.BrokerBaseURL = orig })
	var out, errOut bytes.Buffer
	err := asGateResult(fetchAndRenderSigners(signDigest["cart"], "unsigned", "table", &out, &errOut))
	if gateCode(t, err) != exitGateNoCheck {
		t.Fatalf("unreachable broker: want exit %d, got %v", exitGateNoCheck, err)
	}
}

func TestImagesSigners_JSONPassThrough(t *testing.T) {
	startFakeBroker(t, allSigners(t))
	var out, errOut bytes.Buffer
	if err := fetchAndRenderSigners(signDigest["checkout"], "", "json", &out, &errOut); err != nil {
		t.Fatal(err)
	}
	mustContain(t, out.String(), `"keyPem"`, `"keyFingerprint": "e2312c28209f4778ffc6c0ca2786638bb86d6027ee8092aba67c5d94d268ee30"`)
}

func TestTermSafe(t *testing.T) {
	in := "evil\x1b[31m\u202eowned\u200b\u2028"
	if got := termSafe(in); strings.ContainsAny(got, "\x1b\u202e\u200b\u2028") || got != "evil?[31m?owned??" {
		t.Errorf("termSafe = %q", got)
	}
}

func TestImagesTrust_TableCountsAndOrder(t *testing.T) {
	fb := startFakeBroker(t, signRoutes(t, "image-trust-all"))
	var out, errOut bytes.Buffer
	opts := api.ImageTrustOptions{Namespace: "shop", WorkloadKind: "Deployment", WorkloadName: "search", Limit: 50}
	if err := fetchAndRenderTrust(opts, false, "table", &out, &errOut); err != nil {
		t.Fatal(err)
	}
	q := fb.lastReq.URL.Query()
	if q.Get("namespace") != "shop" || q.Get("workload_kind") != "Deployment" || q.Get("workload_name") != "search" || q.Get("limit") != "50" || q.Has("verdict") {
		t.Errorf("query: %s", fb.lastReq.URL.RawQuery)
	}
	s := out.String()
	mustContain(t, s, "VERDICT    REASON", "WouldDeny  key-not-verified", "Unknown    registry_auth", "Trusted    -")
	if strings.Index(s, "WouldDeny") > strings.Index(s, "Unknown") || strings.Index(s, "Unknown") > strings.Index(s, "Trusted ") {
		t.Errorf("order is WouldDeny, Unknown, Trusted:\n%s", s)
	}
	mustContain(t, errOut.String(), "5 would deny, 2 unknown, 3 trusted (10 results, 2 policies)")
}

func TestImagesTrust_TruncatedSaysSo(t *testing.T) {
	startFakeBroker(t, signRoutes(t, "image-trust-woulddeny-limit2"))
	var out, errOut bytes.Buffer
	if err := fetchAndRenderTrust(api.ImageTrustOptions{Verdict: "WouldDeny", Limit: 2}, false, "table", &out, &errOut); err != nil {
		t.Fatal(err)
	}
	mustContain(t, errOut.String(), "Showing 2 of 5 results")
}

// trustServer answers /image-trust with body.
func trustServer(t *testing.T, body string) {
	t.Helper()
	startFakeBroker(t, map[string]string{"/image-trust": body})
}

func TestImagesTrust_FailOnGate(t *testing.T) {
	all := signRoutes(t, "image-trust-all")["/image-trust"]
	var a map[string]any
	_ = json.Unmarshal([]byte(all), &a)
	with := func(mut func(m map[string]any)) string {
		b, _ := json.Marshal(a)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		mut(m)
		out, _ := json.Marshal(m)
		return string(out)
	}
	cases := []struct {
		name, body string
		code       int
		msg        string
	}{
		{"would deny", all, exitGateFindings, "5 container result(s) would be denied"},
		{"unknown only", with(func(m map[string]any) { m["wouldDeny"] = 0 }), exitGateUnknown, "2 container result(s) are Unknown"},
		{"all trusted", with(func(m map[string]any) { m["wouldDeny"], m["unknown"], m["total"] = 0, 0, 3 }), 0, ""},
		{"no policy", with(func(m map[string]any) { m["wouldDeny"], m["unknown"], m["trusted"], m["total"] = 0, 0, 0, 0 }), exitGateUnknown, "no ImageTrustPolicy selects"},
		{"not evaluated", with(func(m map[string]any) { m["evaluatedAt"] = nil }), exitGateUnknown, "has not finished a pass"},
		{"unrecognised verdict", with(func(m map[string]any) {
			// An older broker counted only the three known verdicts: a
			// "Maybe" is in total and in no count.
			m["wouldDeny"], m["unknown"], m["trusted"], m["total"] = 0, 0, 1, 2
			m["results"] = []map[string]any{{"verdict": "Maybe", "policy": "p", "namespace": "shop", "workload": "Deployment/b", "container": "app", "digest": "sha256:aa"},
				{"verdict": "Trusted", "policy": "p", "namespace": "shop", "workload": "Deployment/a", "container": "app", "digest": "sha256:bb"}}
		}), exitGateUnknown, "1 of 2 container result(s) are not Trusted"},
		{"unavailable", `{"available":false,"reason":"image trust evaluation is off in the evaluator","evaluatedAt":null,"total":0,"wouldDeny":0,"unknown":0,"trusted":0,"policies":[],"results":[],"truncated":false}`, exitGateNoCheck, "could not check (exit 2): image trust evaluation is off"},
	}
	for _, c := range cases {
		trustServer(t, c.body)
		var out, errOut bytes.Buffer
		err := fetchAndRenderTrust(api.ImageTrustOptions{}, true, "table", &out, &errOut)
		got := 0
		if err != nil {
			got = gateCode(t, err)
			mustContain(t, err.Error(), c.msg)
		} else {
			mustContain(t, errOut.String(), "gate: all 3 container result(s) are Trusted")
		}
		if got != c.code {
			t.Errorf("%s: exit %d, want %d (%v)", c.name, got, c.code, err)
		}
	}
}

func TestImagesTrust_UnavailableTable(t *testing.T) {
	trustServer(t, `{"available":false,"reason":"no evaluator is configured (EVALUATOR_URL): ImageTrustPolicy results are not available","evaluatedAt":null,"total":0,"wouldDeny":0,"unknown":0,"trusted":0,"policies":[],"results":[],"truncated":false}`)
	var out, errOut bytes.Buffer
	if err := fetchAndRenderTrust(api.ImageTrustOptions{}, false, "table", &out, &errOut); err != nil {
		t.Fatal(err)
	}
	mustContain(t, out.String(), "not available: no evaluator is configured", "Whether anything would be denied is unknown.")
}

func TestParseTrustFlags(t *testing.T) {
	for in, want := range map[string]string{"would-deny": "WouldDeny", "UNKNOWN": "Unknown", "trusted": "Trusted", "": ""} {
		if got, err := parseTrustVerdictFlag(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	if _, err := parseTrustVerdictFlag("denied"); err == nil {
		t.Error("denied must be rejected")
	}
	for _, bad := range []string{"verified", "key_signed", "p0"} {
		if _, err := parseSignerFailOn(bad); err == nil {
			t.Errorf("--fail-on %s must be rejected", bad)
		}
	}
}

func TestDirectBrokerURL(t *testing.T) {
	for in, want := range map[string]string{"": "", " http://127.0.0.1:56310/ ": "http://127.0.0.1:56310", "https://broker.example.com/kg": "https://broker.example.com/kg"} {
		if got, err := directBrokerURL(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"127.0.0.1:9090", "ftp://x", "http://", "http://u:p@host", "http://h/?a=1", "http://h/#x"} {
		if _, err := directBrokerURL(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

// Through Execute with KGUARDIAN_BROKER_URL: no port-forward, exit codes
// reach the process.
func TestImagesSignersTrust_ProcessExitCodes(t *testing.T) {
	if os.Getenv("KG_EXEC_CLI") == "1" {
		os.Args = append([]string{"kguardian"}, strings.Fields(os.Getenv("KG_ARGS"))...)
		Execute()
		os.Exit(0)
	}
	routes := allSigners(t)
	for k, v := range signRoutes(t, "image-trust-all") {
		routes[k] = v
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer file-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body, ok := routes[r.URL.EscapedPath()]
		if !ok || strings.HasPrefix(body, "404:") {
			http.Error(w, "No data found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	kubeconfig := filepath.Join(dir, "config")
	cfg := "apiVersion: v1\nkind: Config\nclusters:\n- name: none\n  cluster:\n    server: https://127.0.0.1:1\ncontexts:\n- name: none\n  context:\n    cluster: none\n    user: none\n    namespace: default\nusers:\n- name: none\n  user:\n    token: x\ncurrent-context: none\n"
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(kubeconfig, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenFile, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(brokerURL, args string) (int, string) {
		c := exec.Command(os.Args[0], "-test.run=^TestImagesSignersTrust_ProcessExitCodes$")
		c.Env = append(os.Environ(), "KG_EXEC_CLI=1", "KG_ARGS="+args+" --broker-token-file "+tokenFile, "KUBECONFIG="+kubeconfig, brokerURLEnv+"="+brokerURL)
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
	for _, c := range []struct {
		args string
		code int
		want string
	}{
		{"images signers " + signDigest["storefront"] + " --fail-on unverified", 0, "which passes --fail-on unverified"},
		{"images signers " + signDigest["cart"] + " --fail-on unsigned", exitGateFindings, "is unsigned, which fails --fail-on unsigned"},
		{"images signers " + signDigest["recs"] + " --fail-on invalid", exitGateUnknown, "unknown is not a pass"},
		{"images signers " + signDigest["search"] + " --fail-on unsigned", exitGateUnknown, "could not be verified; that is not a pass"},
		{"images signers " + signDigest["cart"] + " --fail-on sometimes", exitGateNoCheck, "invalid --fail-on"},
		{"images trust -n shop --fail-on would-deny", exitGateFindings, "would be denied"},
		{"images trust --fail-on would-deny --verdict Trusted", exitGateNoCheck, "cannot be combined"},
	} {
		code, out := run(srv.URL, c.args)
		if code != c.code || !strings.Contains(out, c.want) {
			t.Errorf("%s: exit %d, want %d; output:\n%s", c.args, code, c.code, out)
		}
	}
	if code, out := run("not-a-url", "images signers "+signDigest["cart"]+" --fail-on unsigned"); code != exitGateNoCheck || !strings.Contains(out, brokerURLEnv) {
		t.Errorf("bad %s: exit %d\n%s", brokerURLEnv, code, out)
	}
}

func TestPlainHTTPTokenWarning(t *testing.T) {
	for _, c := range []struct {
		url, token string
		warn       bool
	}{
		{"http://127.0.0.1:9090", "t", false},
		{"http://localhost:9090", "t", false},
		{"http://[::1]:9090", "t", false},
		{"https://broker.example.com", "t", false},
		{"http://broker.example.com", "", false},
		{"http://broker.example.com", "t", true},
		{"http://10.0.0.5:9090", "t", true},
	} {
		if got := plainHTTPTokenWarning(c.url, c.token) != ""; got != c.warn {
			t.Errorf("%s token=%q: warn=%v, want %v", c.url, c.token, got, c.warn)
		}
	}
}

// A "verified" result whose signatures name no signer (stored before the
// broker's ingest rule) is unknown: exit 3 at every level, and the table
// says so.
func TestImagesSigners_VerifiedWithoutASignerIdentityIsUnknown(t *testing.T) {
	d := signDigest["storefront"]
	for name, sig := range map[string]string{
		"no kind":         `{"format":"cosign-bundle","source":"referrers","verified":true}`,
		"kind only":       `{"format":"cosign-bundle","source":"referrers","verified":true,"signerKind":"keyless"}`,
		"issuer only":     `{"format":"cosign-bundle","source":"referrers","verified":true,"signerKind":"keyless","issuer":"https://token.actions.githubusercontent.com"}`,
		"key without fp":  `{"format":"cosign-legacy","source":"sig-tag","verified":true,"signerKind":"key","keyName":"release"}`,
		"blank san":       `{"format":"cosign-bundle","source":"referrers","verified":true,"signerKind":"keyless","issuer":"https://token.actions.githubusercontent.com","san":"   "}`,
		"blank issuer":    `{"format":"cosign-bundle","source":"referrers","verified":true,"signerKind":"keyless","issuer":" ","san":"https://github.com/example/app"}`,
		"blank fp":        `{"format":"cosign-legacy","source":"sig-tag","verified":true,"signerKind":"key","keyName":"release","keyFingerprint":"  "}`,
		"fp without kind": `{"format":"cosign-legacy","source":"sig-tag","verified":true,"keyName":"release","keyFingerprint":"e2312c28"}`,
	} {
		body := `{"digest":"` + d + `","repository":"ghcr.io/example/app","verdict":"verified","reason":null,"trustRoot":"public-good",` +
			`"signedVia":"self","signedDigest":"` + d + `","signatures":[` + sig + `],"attestations":[],"checkedAt":"2026-09-27T00:00:00","receivedAt":"2026-09-27T00:00:01"}`
		startFakeBroker(t, map[string]string{"/images/" + d + "/attestation": body})
		for _, level := range []string{"invalid", "unsigned", "unverified"} {
			var out, errOut bytes.Buffer
			err := fetchAndRenderSigners(d, level, "table", &out, &errOut)
			if code := gateCode(t, err); code != exitGateUnknown {
				t.Errorf("%s --fail-on %s: exit %d, want %d", name, level, code, exitGateUnknown)
			}
			mustContain(t, err.Error(), "no_signer_identity")
			mustContain(t, out.String(), "no signature names its signer", "- (no signer identity)")
		}
	}
}
