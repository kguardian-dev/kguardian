package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

// emitPromoted is the deterministic core of `kguardian audit promote`:
// it converts an AuditNetworkPolicy into the equivalent enforced
// networking.k8s.io/v1.NetworkPolicy ready for kubectl apply.
// Bug here = operator promotes a policy that doesn't enforce what they
// audited, with potential blast radius up to "all pods in namespace".

func newAuditPolicy(t *testing.T, namespace, name string, spec map[string]any, opts ...func(*unstructured.Unstructured)) *unstructured.Unstructured {
	t.Helper()
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "kguardian.dev/v1alpha1",
		"kind":       "AuditNetworkPolicy",
		"metadata": map[string]any{
			"namespace":       namespace,
			"name":            name,
			"uid":             "test-uid-1234",
			"resourceVersion": "9999",
		},
		"spec": spec,
	}}
	for _, opt := range opts {
		opt(u)
	}
	return u
}

func decodeYAML(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var got map[string]any
	if err := yaml.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode emitted YAML: %v", err)
	}
	return got
}

func TestEmitPromoted_RewritesApiVersionAndKind(t *testing.T) {
	// The whole point of promote: an AuditNetworkPolicy becomes a
	// NetworkPolicy. Apply via kubectl would fail noisily if the
	// emitted kind were left at AuditNetworkPolicy, but a wrong
	// apiVersion (e.g. networking.k8s.io/v1beta1) on a 1.20+ cluster
	// would either fail or silently target the wrong type. Pin both.
	u := newAuditPolicy(t, "prod", "web-deny", map[string]any{
		"podSelector": map[string]any{
			"matchLabels": map[string]any{"app": "web"},
		},
	})
	var buf bytes.Buffer
	if err := emitPromoted(u, &buf); err != nil {
		t.Fatalf("emitPromoted: %v", err)
	}
	got := decodeYAML(t, buf.Bytes())
	if got["apiVersion"] != "networking.k8s.io/v1" {
		t.Errorf("apiVersion: want networking.k8s.io/v1, got %v", got["apiVersion"])
	}
	if got["kind"] != "NetworkPolicy" {
		t.Errorf("kind: want NetworkPolicy, got %v", got["kind"])
	}
}

func TestEmitPromoted_StripsServerSideMetadata(t *testing.T) {
	// uid / resourceVersion / status are server-side state — they
	// must not be copied into the promoted YAML or `kubectl apply`
	// will reject as immutable.
	u := newAuditPolicy(t, "prod", "web-deny", map[string]any{
		"podSelector": map[string]any{},
	})
	u.Object["status"] = map[string]any{
		"observedGeneration": int64(7),
		"evaluation": map[string]any{
			"flowsWouldDeny": int64(42),
		},
	}
	var buf bytes.Buffer
	if err := emitPromoted(u, &buf); err != nil {
		t.Fatalf("emitPromoted: %v", err)
	}
	got := decodeYAML(t, buf.Bytes())
	meta := got["metadata"].(map[string]any)
	if _, ok := meta["uid"]; ok {
		t.Error("uid must be stripped from emitted metadata")
	}
	if _, ok := meta["resourceVersion"]; ok {
		t.Error("resourceVersion must be stripped from emitted metadata")
	}
	if _, ok := got["status"]; ok {
		t.Error("status must be absent from emitted YAML — its audit-side state, not enforcement state")
	}
}

func TestEmitPromoted_PreservesUserLabelsAndAnnotations(t *testing.T) {
	// GitOps tooling (Argo, Flux) keys off labels/annotations. Losing
	// them on promote would orphan the resource in the operators
	// reconciliation logic.
	u := newAuditPolicy(t, "prod", "web-deny", map[string]any{
		"podSelector": map[string]any{},
	})
	u.SetLabels(map[string]string{
		"app.kubernetes.io/managed-by": "argocd",
		"team":                         "platform",
	})
	u.SetAnnotations(map[string]string{
		"argocd.argoproj.io/sync-wave":                     "5",
		"kubectl.kubernetes.io/last-applied-configuration": `{"...stale prior apply..."}`,
	})
	var buf bytes.Buffer
	if err := emitPromoted(u, &buf); err != nil {
		t.Fatalf("emitPromoted: %v", err)
	}
	got := decodeYAML(t, buf.Bytes())
	meta := got["metadata"].(map[string]any)

	labels := meta["labels"].(map[string]any)
	if labels["team"] != "platform" {
		t.Errorf("user label team must survive promote, got %v", labels["team"])
	}
	if labels["app.kubernetes.io/managed-by"] != "argocd" {
		t.Errorf("argocd managed-by label must survive promote")
	}

	anns, _ := meta["annotations"].(map[string]any)
	if anns == nil {
		t.Fatal("annotations should be present after promote")
	}
	if anns["argocd.argoproj.io/sync-wave"] != "5" {
		t.Errorf("user annotation must survive promote")
	}
	if _, ok := anns["kubectl.kubernetes.io/last-applied-configuration"]; ok {
		t.Error("kubectl last-applied-configuration must be stripped — it refers to the audit kind and would mislead future kubectl applies of the new kind")
	}
}

func TestEmitPromoted_PreservesSpecVerbatim(t *testing.T) {
	// The spec is the load-bearing part of the promotion. Any
	// silent transformation (e.g. dropping policyTypes, missing
	// ipBlock fields) would change semantics.
	u := newAuditPolicy(t, "prod", "complex", map[string]any{
		"podSelector": map[string]any{
			"matchLabels": map[string]any{"app": "web"},
		},
		"policyTypes": []any{"Ingress", "Egress"},
		"ingress": []any{
			map[string]any{
				"from": []any{
					map[string]any{
						"ipBlock": map[string]any{
							"cidr":   "10.0.0.0/8",
							"except": []any{"10.10.0.0/16"},
						},
					},
				},
				"ports": []any{
					map[string]any{
						"protocol": "TCP",
						"port":     int64(8080),
					},
				},
			},
		},
		"egress": []any{
			map[string]any{
				"to": []any{
					map[string]any{
						"namespaceSelector": map[string]any{
							"matchLabels": map[string]any{"team": "data"},
						},
					},
				},
			},
		},
	})
	var buf bytes.Buffer
	if err := emitPromoted(u, &buf); err != nil {
		t.Fatalf("emitPromoted: %v", err)
	}
	got := decodeYAML(t, buf.Bytes())
	spec := got["spec"].(map[string]any)

	if got, want := spec["policyTypes"], []any{"Ingress", "Egress"}; !equalSlices(got, want) {
		t.Errorf("policyTypes: want %v, got %v", want, got)
	}

	ingress := spec["ingress"].([]any)
	if len(ingress) != 1 {
		t.Fatalf("ingress: want 1 rule, got %d", len(ingress))
	}
	rule := ingress[0].(map[string]any)
	from := rule["from"].([]any)
	ipBlock := from[0].(map[string]any)["ipBlock"].(map[string]any)
	if ipBlock["cidr"] != "10.0.0.0/8" {
		t.Errorf("cidr lost on promote: got %v", ipBlock["cidr"])
	}
	if exc := ipBlock["except"].([]any); len(exc) != 1 || exc[0] != "10.10.0.0/16" {
		t.Errorf("except entries lost on promote: got %v", exc)
	}
}

func TestEmitPromoted_ErrorsWhenSpecMissing(t *testing.T) {
	// A malformed Unstructured with no spec must produce a clear
	// error — silently emitting a NetworkPolicy with no spec would
	// be a no-op policy that doesn't enforce anything (worst case:
	// operator thinks they have enforcement when they don't).
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "kguardian.dev/v1alpha1",
		"kind":       "AuditNetworkPolicy",
		"metadata": map[string]any{
			"namespace": "prod",
			"name":      "no-spec",
		},
		// no spec
	}}
	err := emitPromoted(u, &bytes.Buffer{})
	if err == nil {
		t.Fatal("missing spec must error")
	}
	if !strings.Contains(err.Error(), "no spec") {
		t.Errorf("error should explain the missing spec; got %v", err)
	}
}

func TestEmitPromoted_DeleteFlagAppendsHelperComment(t *testing.T) {
	// --delete prints a follow-up `kubectl delete` instruction so
	// the operator can pipe through `sh` once theyve applied. The
	// comment must include the namespace AND name to be safe to copy
	// into a busy terminal — the operator might have other audit
	// policies open.
	prev := promoteDelete
	t.Cleanup(func() { promoteDelete = prev })
	promoteDelete = true

	u := newAuditPolicy(t, "prod", "web-deny", map[string]any{"podSelector": map[string]any{}})
	var buf bytes.Buffer
	if err := emitPromoted(u, &buf); err != nil {
		t.Fatalf("emitPromoted: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "kubectl delete auditnetworkpolicy web-deny") {
		t.Errorf("delete-helper comment must reference the audit policy name; got:\n%s", out)
	}
	if !strings.Contains(out, "-n prod") {
		t.Errorf("delete-helper comment must reference the namespace; got:\n%s", out)
	}
	// The trailing line is a `#`-prefixed comment so piping the
	// whole output to kubectl apply doesn't mistake it for a YAML doc.
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.HasPrefix(line, "kubectl") {
			t.Errorf("kubectl-delete instruction must be commented out (#-prefixed) so the YAML stays apply-able; got bare line: %q", line)
		}
	}
}

func TestEmitPromoted_DeleteFlagOffByDefault(t *testing.T) {
	// Counterpart: without --delete, the helper comment must NOT
	// appear. A surprise instruction tells the operator to delete
	// something they may not yet have applied successfully.
	prev := promoteDelete
	t.Cleanup(func() { promoteDelete = prev })
	promoteDelete = false

	u := newAuditPolicy(t, "prod", "web-deny", map[string]any{"podSelector": map[string]any{}})
	var buf bytes.Buffer
	if err := emitPromoted(u, &buf); err != nil {
		t.Fatalf("emitPromoted: %v", err)
	}
	if strings.Contains(buf.String(), "kubectl delete") {
		t.Error("delete-helper must NOT appear when promoteDelete=false; output:\n" + buf.String())
	}
}

func TestPromoteListItem_FileOutputPathNamingAndContent(t *testing.T) {
	// File-output mode: each promoted policy lands at
	// <outputDir>/<namespace>-<name>.yaml. The naming pattern matters
	// because operators use it to spot which file goes where on a
	// `kubectl apply -f <dir>` run, and a collision would silently
	// overwrite. Pin the pattern AND that the file actually contains
	// the promoted YAML (not e.g. an empty file from a botched defer).
	dir := t.TempDir()
	prev := promoteOutputDir
	t.Cleanup(func() { promoteOutputDir = prev })
	promoteOutputDir = dir

	u := newAuditPolicy(t, "prod", "web-deny", map[string]any{
		"podSelector": map[string]any{"matchLabels": map[string]any{"app": "web"}},
	})

	if err := promoteListItem(u, 0, 1); err != nil {
		t.Fatalf("promoteListItem: %v", err)
	}

	wantPath := dir + "/prod-web-deny.yaml"
	raw, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("expected file %s; got %v", wantPath, err)
	}
	got := decodeYAML(t, raw)
	if got["kind"] != "NetworkPolicy" {
		t.Errorf("file content: want kind=NetworkPolicy, got %v", got["kind"])
	}
	meta := got["metadata"].(map[string]any)
	if meta["namespace"] != "prod" || meta["name"] != "web-deny" {
		t.Errorf("file content: want metadata={prod,web-deny}, got %v", meta)
	}
}

func TestPromoteListItem_FailsLoudlyOnUncreatableFile(t *testing.T) {
	// Output-dir is read-only: os.Create must surface the EPERM/EROFS
	// from the OS rather than silently dropping the policy. Operators
	// rely on the exit code from a `--all --output-dir=...` run; a
	// silent skip would ship an incomplete policy bundle.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skipf("cant chmod tempdir on this fs: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	prev := promoteOutputDir
	t.Cleanup(func() { promoteOutputDir = prev })
	promoteOutputDir = dir

	u := newAuditPolicy(t, "prod", "x", map[string]any{"podSelector": map[string]any{}})
	err := promoteListItem(u, 0, 1)
	if err == nil {
		t.Fatal("readonly output dir should produce an error so the CLI exits non-zero")
	}
	if !strings.Contains(err.Error(), "opening") {
		t.Errorf("error should name the operation that failed for debuggability; got %v", err)
	}
}

func equalSlices(a, b any) bool {
	as, ok := a.([]any)
	if !ok {
		return false
	}
	bs, ok := b.([]any)
	if !ok {
		return false
	}
	if len(as) != len(bs) {
		return false
	}
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}
