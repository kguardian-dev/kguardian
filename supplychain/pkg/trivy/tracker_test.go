package trivy

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
)

var ctx = context.Background()

func kinds(es []Emission) []Kind {
	out := make([]Kind, 0, len(es))
	for _, e := range es {
		out = append(out, e.Kind)
	}
	return out
}

func findVuln(p *types.ImageVulnerabilities, id string) *types.Vulnerability {
	for i := range p.Vulnerabilities {
		if p.Vulnerabilities[i].ID == id {
			return &p.Vulnerabilities[i]
		}
	}
	return nil
}

// A tag-only VulnerabilityReport is held back (never sent keyed by a tag)
// until the SbomReport for the same container supplies the digest.
func TestTrackerTagOnlyHeldUntilSBOMResolves(t *testing.T) {
	tr := NewTracker(nil)
	if es := tr.UpsertVulnerabilityReport(ctx, loadVuln(t, "vulnerabilityreport-apiserver-tagonly.yaml")); len(es) != 0 {
		t.Fatalf("unresolved report emitted: %+v", es)
	}
	if s := tr.Stats(); s.UnresolvedVulns != 1 || s.VulnDigests != 0 {
		t.Fatalf("stats: %+v", s)
	}

	es := tr.UpsertSbomReport(ctx, loadSBOM(t, "sbomreport-docs.yaml"))
	if !reflect.DeepEqual(kinds(es), []Kind{KindSBOM, KindVulnerabilities}) {
		t.Fatalf("emissions: %v", kinds(es))
	}
	for _, e := range es {
		if e.Digest != apiserverDigest {
			t.Errorf("%s keyed by %q", e.Kind, e.Digest)
		}
	}
	v := es[1].Vulns
	if v.Image.Digest != apiserverDigest {
		t.Errorf("payload digest %q", v.Image.Digest)
	}
	if s := tr.Stats(); s.UnresolvedVulns != 0 || s.VulnDigests != 1 || s.SBOMDigests != 1 {
		t.Errorf("stats after resolve: %+v", s)
	}
}

// The reverse order: SBOM first, then the tag-only vulnerability report.
func TestTrackerTagOnlyResolvedFromExistingSBOM(t *testing.T) {
	tr := NewTracker(nil)
	tr.UpsertSbomReport(ctx, loadSBOM(t, "sbomreport-docs.yaml"))
	es := tr.UpsertVulnerabilityReport(ctx, loadVuln(t, "vulnerabilityreport-apiserver-tagonly.yaml"))
	if len(es) != 1 || es[0].Kind != KindVulnerabilities || es[0].Digest != apiserverDigest {
		t.Fatalf("emissions: %+v", es)
	}
}

// Correlation must match the workload container, not just the tag: a
// different workload running the same tag may be on a different digest.
func TestTrackerCorrelationRequiresSameContainer(t *testing.T) {
	tr := NewTracker(nil)
	tr.UpsertSbomReport(ctx, loadSBOM(t, "sbomreport-docs.yaml"))
	r := loadVuln(t, "vulnerabilityreport-apiserver-tagonly.yaml")
	r.Metadata.UID = "other"
	r.Metadata.Labels[LabelResourceName] = "some-other-pod"
	if es := tr.UpsertVulnerabilityReport(ctx, r); len(es) != 0 {
		t.Fatalf("correlated across workloads: %+v", es)
	}
}

func TestTrackerSBOMJoinAddsFilePaths(t *testing.T) {
	tr := NewTracker(nil)
	es := tr.UpsertVulnerabilityReport(ctx, loadVuln(t, "vulnerabilityreport-api-digest.yaml"))
	if len(es) != 1 {
		t.Fatalf("emissions: %+v", es)
	}
	if v := findVuln(es[0].Vulns, "CVE-2099-1002"); v == nil || v.FilePaths != nil {
		t.Fatalf("express before SBOM: %+v", v)
	}

	es = tr.UpsertSbomReport(ctx, loadSBOM(t, "sbomreport-api-digest.yaml"))
	if !reflect.DeepEqual(kinds(es), []Kind{KindSBOM, KindVulnerabilities}) {
		t.Fatalf("emissions: %v", kinds(es))
	}
	v := findVuln(es[1].Vulns, "CVE-2099-1002")
	if v == nil || !reflect.DeepEqual(v.FilePaths, []string{"app/node_modules/express/package.json"}) {
		t.Fatalf("join: %+v", v)
	}
	// Deleting the SBOM drops the joined paths again.
	es = tr.DeleteSbomReport(loadSBOM(t, "sbomreport-api-digest.yaml"))
	if len(es) != 1 || es[0].Kind != KindVulnerabilities {
		t.Fatalf("after sbom delete: %v", kinds(es))
	}
	if v := findVuln(es[0].Vulns, "CVE-2099-1002"); v.FilePaths != nil {
		t.Errorf("stale join: %v", v.FilePaths)
	}
}

// Many workloads running one image produce one payload.
func TestTrackerDedupAcrossWorkloads(t *testing.T) {
	tr := NewTracker(nil)
	if es := tr.UpsertVulnerabilityReport(ctx, loadVuln(t, "vulnerabilityreport-api-digest.yaml")); len(es) != 1 {
		t.Fatalf("first: %d", len(es))
	}
	for i, name := range []string{"api-2", "api-3", "worker"} {
		r := loadVuln(t, "vulnerabilityreport-api-digest.yaml")
		r.Metadata.UID = name
		r.Metadata.Labels[LabelResourceName] = name
		if es := tr.UpsertVulnerabilityReport(ctx, r); len(es) != 0 {
			t.Fatalf("replica %d re-emitted identical content", i)
		}
	}
	if s := tr.Stats(); s.VulnDigests != 1 {
		t.Errorf("digests: %d", s.VulnDigests)
	}
}

// An informer resync redelivers every object unchanged: no re-send.
func TestTrackerResyncIsQuiet(t *testing.T) {
	tr := NewTracker(nil)
	tr.UpsertVulnerabilityReport(ctx, loadVuln(t, "vulnerabilityreport-api-digest.yaml"))
	tr.UpsertSbomReport(ctx, loadSBOM(t, "sbomreport-api-digest.yaml"))
	if es := tr.UpsertVulnerabilityReport(ctx, loadVuln(t, "vulnerabilityreport-api-digest.yaml")); len(es) != 0 {
		t.Errorf("vuln resync emitted %v", kinds(es))
	}
	if es := tr.UpsertSbomReport(ctx, loadSBOM(t, "sbomreport-api-digest.yaml")); len(es) != 0 {
		t.Errorf("sbom resync emitted %v", kinds(es))
	}
}

func TestTrackerNewerScanWinsOlderIgnored(t *testing.T) {
	tr := NewTracker(nil)
	tr.UpsertVulnerabilityReport(ctx, loadVuln(t, "vulnerabilityreport-api-digest.yaml"))

	// A second workload's report for the same digest, scanned EARLIER with
	// different results (older DB): must not overwrite the newer scan.
	old := loadVuln(t, "vulnerabilityreport-api-digest.yaml")
	old.Metadata.UID = "older"
	old.Metadata.Labels[LabelResourceName] = "api-old"
	old.Report.UpdateTimestamp = "2026-09-01T00:00:00Z"
	old.Report.Vulnerabilities = old.Report.Vulnerabilities[:1]
	if es := tr.UpsertVulnerabilityReport(ctx, old); len(es) != 0 {
		t.Fatalf("older scan emitted: %+v", es)
	}

	// A rescan with a new finding and a newer timestamp is sent.
	newer := loadVuln(t, "vulnerabilityreport-api-digest.yaml")
	newer.Report.UpdateTimestamp = "2026-09-21T08:00:00Z"
	extra := newer.Report.Vulnerabilities[0]
	extra.VulnerabilityID = "CVE-2099-1003"
	newer.Report.Vulnerabilities = append(newer.Report.Vulnerabilities, extra)
	es := tr.UpsertVulnerabilityReport(ctx, newer)
	if len(es) != 1 || findVuln(es[0].Vulns, "CVE-2099-1003") == nil {
		t.Fatalf("newer scan not sent: %+v", es)
	}
	if got := len(es[0].Vulns.ObservedIn); got != 2 {
		t.Errorf("observed_in should list both workloads, got %d", got)
	}
}

func TestTrackerDeleteThenReaddResends(t *testing.T) {
	tr := NewTracker(nil)
	r := loadVuln(t, "vulnerabilityreport-api-digest.yaml")
	tr.UpsertVulnerabilityReport(ctx, r)
	if es := tr.DeleteVulnerabilityReport(r); len(es) != 0 {
		t.Fatalf("delete emitted: %+v", es)
	}
	if s := tr.Stats(); s.VulnDigests != 0 {
		t.Fatalf("digest still tracked after last report deleted: %+v", s)
	}
	if es := tr.UpsertVulnerabilityReport(ctx, r); len(es) != 1 {
		t.Fatalf("re-add after delete must resend, got %d", len(es))
	}
	// Deleting an unknown object is a no-op.
	unknown := loadVuln(t, "vulnerabilityreport-docs-basic.yaml")
	if es := tr.DeleteVulnerabilityReport(unknown); es != nil {
		t.Errorf("unknown delete: %+v", es)
	}
}

// A report whose image changed (same object, new digest) moves between keys.
func TestTrackerReportChangesDigest(t *testing.T) {
	tr := NewTracker(nil)
	r := loadVuln(t, "vulnerabilityreport-api-digest.yaml")
	tr.UpsertVulnerabilityReport(ctx, r)
	r2 := loadVuln(t, "vulnerabilityreport-api-digest.yaml")
	r2.Report.Artifact.Digest = apiserverDigest
	es := tr.UpsertVulnerabilityReport(ctx, r2)
	if len(es) != 1 || es[0].Digest != apiserverDigest {
		t.Fatalf("emissions: %+v", es)
	}
	if s := tr.Stats(); s.VulnDigests != 1 {
		t.Errorf("old digest still tracked: %+v", s)
	}
}

type fakeResolver struct {
	digest string
	err    error
	calls  []types.WorkloadRef
}

func (f *fakeResolver) ResolveDigest(_ context.Context, w types.WorkloadRef, _ string) (string, error) {
	f.calls = append(f.calls, w)
	return f.digest, f.err
}

func TestTrackerExternalResolver(t *testing.T) {
	res := &fakeResolver{digest: "docker.io/library/nginx@" + apiDigest}
	tr := NewTracker(res)
	es := tr.UpsertVulnerabilityReport(ctx, loadVuln(t, "vulnerabilityreport-docs-basic.yaml"))
	if len(es) != 1 || es[0].Digest != apiDigest {
		t.Fatalf("emissions: %+v", es)
	}
	want := types.WorkloadRef{Namespace: "default", Kind: "ReplicaSet", Name: "nginx-6d4cf56db6", Container: "nginx"}
	if len(res.calls) != 1 || res.calls[0] != want {
		t.Errorf("resolver called with %+v", res.calls)
	}

	// A failing resolver leaves the report held back.
	tr2 := NewTracker(&fakeResolver{err: errors.New("broker down")})
	if es := tr2.UpsertVulnerabilityReport(ctx, loadVuln(t, "vulnerabilityreport-docs-basic.yaml")); len(es) != 0 {
		t.Fatalf("emitted despite resolver error: %+v", es)
	}
	if tr2.Stats().UnresolvedVulns != 1 {
		t.Error("report not held")
	}
}

// Emitted payloads must be independent copies: the SBOM join must not
// write into the tracker's stored state.
func TestTrackerEmissionsDoNotAliasState(t *testing.T) {
	tr := NewTracker(nil)
	tr.UpsertSbomReport(ctx, loadSBOM(t, "sbomreport-api-digest.yaml"))
	es := tr.UpsertVulnerabilityReport(ctx, loadVuln(t, "vulnerabilityreport-api-digest.yaml"))
	es[0].Vulns.Vulnerabilities[0].ID = "mutated"
	es[0].Vulns.ObservedIn = nil
	if es := tr.UpsertVulnerabilityReport(ctx, loadVuln(t, "vulnerabilityreport-api-digest.yaml")); len(es) != 0 {
		t.Errorf("mutating an emission changed tracker state: %+v", es)
	}
}
