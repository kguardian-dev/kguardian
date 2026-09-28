package network

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
	"sigs.k8s.io/yaml"
)

// The cilium.io/v2 CiliumNetworkPolicy CRD (Cilium 1.17; mirrored by the
// datree CRDs-catalog as cilium.io/ciliumnetworkpolicy_v2.json) constrains
// spec with anyOf over these four keys, so a spec carrying none of them is
// rejected by the API server ("must validate at least one schema (anyOf)").
var ciliumSpecAnyOf = []string{"ingress", "ingressDeny", "egress", "egressDeny"}

const datreeSchemaLocation = "https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json"

type ciliumCRDCase struct {
	name    string
	detail  *api.PodDetail
	traffic []api.PodTraffic
	// Sections the spec must carry; every other anyOf key must be absent.
	ingress, egress bool
	denyAll         bool
}

func ciliumCRDCases() []ciliumCRDCase {
	web := fixturePodDetail("web", "prod", "10.0.0.1", map[string]string{"app": "web"})
	idle := fixturePodDetail("idle", "prod", "10.0.0.2", map[string]string{"app": "idle"})
	in := api.PodTraffic{TrafficType: "INGRESS", SrcIP: "10.0.0.1", SrcPodPort: "8080", DstIP: "10.0.0.7", Protocol: "TCP"}
	out := api.PodTraffic{TrafficType: "EGRESS", SrcIP: "10.0.0.1", DstIP: "10.96.0.10", DstPort: "5432", Protocol: "TCP"}
	self := api.PodTraffic{TrafficType: "INGRESS", SrcIP: "10.0.0.2", SrcPodPort: "8080", DstIP: "10.0.0.2", Protocol: "TCP"}
	return []ciliumCRDCase{
		{name: "deny-all without traffic", detail: idle, denyAll: true, ingress: true, egress: true},
		{name: "deny-all when every rule is dropped", detail: idle, traffic: []api.PodTraffic{self}, denyAll: true, ingress: true, egress: true},
		{name: "ingress only", detail: web, traffic: []api.PodTraffic{in}, ingress: true},
		{name: "egress only", detail: web, traffic: []api.PodTraffic{out}, egress: true},
		{name: "egress only after every ingress peer is dropped", detail: web, traffic: []api.PodTraffic{{TrafficType: "INGRESS", SrcIP: "10.0.0.1", SrcPodPort: "8080", DstIP: "10.0.0.1", Protocol: "TCP"}, out}, egress: true},
		{name: "both directions", detail: web, traffic: []api.PodTraffic{in, out}, ingress: true, egress: true},
	}
}

func (c ciliumCRDCase) render(t *testing.T) ([]byte, map[string]any) {
	t.Helper()
	gen := NewCiliumPolicyGenerator()
	gen.setBrokerData(stubBrokerData{})
	policy, comments, err := gen.GenerateWithComments(c.detail.Name, c.traffic, c.detail)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	doc, err := MarshalPolicyYAML(policy, comments)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var parsed struct {
		Spec map[string]any `json:"spec"`
	}
	if err := yaml.Unmarshal(doc, &parsed); err != nil {
		t.Fatalf("parse rendered YAML: %v\n%s", err, doc)
	}
	return doc, parsed.Spec
}

func TestCiliumPolicy_SpecSatisfiesCRDAnyOf(t *testing.T) {
	for _, c := range ciliumCRDCases() {
		t.Run(c.name, func(t *testing.T) {
			doc, spec := c.render(t)
			present := 0
			for _, k := range ciliumSpecAnyOf {
				if _, ok := spec[k]; ok {
					present++
				}
			}
			if present == 0 {
				t.Fatalf("spec has none of %v; the CRD rejects it:\n%s", ciliumSpecAnyOf, doc)
			}
			want := map[string]bool{"ingress": c.ingress, "egress": c.egress}
			for _, k := range ciliumSpecAnyOf {
				if _, ok := spec[k]; ok != want[k] {
					t.Errorf("spec.%s present=%v, want %v:\n%s", k, ok, want[k], doc)
				}
			}
			_, hasDefaultDeny := spec["enableDefaultDeny"]
			if hasDefaultDeny != c.denyAll {
				t.Errorf("spec.enableDefaultDeny present=%v, want %v:\n%s", hasDefaultDeny, c.denyAll, doc)
			}
			if c.denyAll {
				// Cilium's deny form: one empty rule per denied direction.
				for _, k := range []string{"ingress", "egress"} {
					rules, _ := spec[k].([]any)
					if len(rules) != 1 || len(rules[0].(map[string]any)) != 0 {
						t.Errorf("spec.%s = %v, want [{}]", k, spec[k])
					}
				}
			}
		})
	}
}

// Validates every generated Cilium document and every committed cilium_*
// golden against the full CRD schema with kubeconform. Skipped when the binary
// is not installed (KUBECONFORM names it; KUBECONFORM_SCHEMA_LOCATION overrides
// the datree catalog, e.g. with a local mirror).
func TestCiliumPolicy_ValidatesAgainstCRDWithKubeconform(t *testing.T) {
	bin := os.Getenv("KUBECONFORM")
	if bin == "" {
		bin = "kubeconform"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		t.Skipf("kubeconform not installed (%v); install it or set KUBECONFORM", err)
	}
	dir := t.TempDir()
	var files []string
	for _, c := range ciliumCRDCases() {
		doc, _ := c.render(t)
		f := filepath.Join(dir, strings.ReplaceAll(c.name, " ", "_")+".yaml")
		if err := os.WriteFile(f, doc, 0o644); err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	goldens, err := filepath.Glob(filepath.Join("..", "..", "..", "test", "fixtures", "generators", "networkpolicy", "cilium_*.golden.yaml"))
	if err != nil || len(goldens) == 0 {
		t.Fatalf("cilium goldens: %v (%d found)", err, len(goldens))
	}
	files = append(files, goldens...)

	location := os.Getenv("KUBECONFORM_SCHEMA_LOCATION")
	if location == "" {
		location = datreeSchemaLocation
	}
	cache := filepath.Join(os.TempDir(), "kguardian-kubeconform-cache")
	if err := os.MkdirAll(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"-strict", "-summary", "-cache", cache, "-schema-location", location}, files...)
	out, err := exec.Command(path, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("kubeconform: %v\n%s", err, out)
	}
	t.Logf("%s", strings.TrimSpace(string(out)))
}
