package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
	"github.com/spf13/cobra"
)

// profileCmd groups the read-only workload security profile views. Nothing
// under `profile` applies anything: `export` prints a recommendation for a
// human to review.
var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Show workload security profiles (posture, findings, PSS level)",
	Long: `Read-only views over the broker's workload security profiles. A profile is
keyed by workload (namespace/kind/name), not by pod, and joins what kguardian
observed: Pod Security Standards checks on the reported securityContext,
network peers, syscalls and SeccompProfile CRs, running image digests and
compute settings.

  get      one workload's posture, findings and per-dimension status
  list     posture summaries for many workloads
  diff     what changed between two stored profile revisions
  export   print a recommendation (--format pss: securityContext patch)

"unknown" means kguardian has no data for that dimension, or the source is not
configured. It is never a pass. The posture score only covers known
dimensions; read the coverage next to it.`,
}

var (
	profileGetOutput    string
	profileListKind     string
	profileListStatus   string
	profileListLimit    int
	profileListAfter    string
	profileListOutput   string
	profileDiffFrom     int
	profileDiffTo       int
	profileDiffOutput   string
	profileExportFormat string
)

var profileGetCmd = &cobra.Command{
	Use:   "get <namespace>/<kind>/<name>",
	Short: "Show one workload's security profile",
	Long: `Show one workload's security profile, computed live by the broker.

The kind is case-sensitive and is the owning workload's kind (Deployment,
StatefulSet, DaemonSet, CronJob, Job, or Pod for a pod with no owner).

Examples:
  kubectl kguardian profile get payments/Deployment/checkout
  kubectl kguardian profile get payments/Deployment/checkout -o yaml`,
	Args: cobra.ExactArgs(1),
	RunE: runProfileGet,
}

var profileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List workloads with their posture summary",
	Long: `List workloads with their posture summary, ordered by namespace, kind, name.
Rows come from the broker's snapshot read model, refreshed every few minutes.

Examples:
  kubectl kguardian profile list
  kubectl kguardian profile list -n payments --status risk
  kubectl kguardian profile list --kind Deployment -o json`,
	Args: cobra.NoArgs,
	RunE: runProfileList,
}

var profileDiffCmd = &cobra.Command{
	Use:   "diff <namespace>/<kind>/<name>",
	Short: "Show what changed between two profile revisions",
	Long: `Compare two stored revisions of a workload's profile. A revision is stored
whenever the observed, policy-relevant behaviour changes (securityContext,
running digests, syscalls, network rules). It records what kguardian observed,
not what is applied in the cluster.

Without flags the latest revision is compared with the one before it.

Examples:
  kubectl kguardian profile diff payments/Deployment/checkout
  kubectl kguardian profile diff payments/Deployment/checkout --from 2 --to 5`,
	Args: cobra.ExactArgs(1),
	RunE: runProfileDiff,
}

var profileExportCmd = &cobra.Command{
	Use:   "export <namespace>/<kind>/<name>",
	Short: "Print a recommendation for a workload (review before applying)",
	Long: `Print a recommendation derived from the workload's profile. kguardian never
applies it; review it and apply it yourself.

  --format pss   the recommended securityContext as a strategic-merge patch
                 that moves the workload toward Pod Security Standards
                 restricted. Only fields that fail an evaluated check are
                 set. Caveats go to stderr.

When every evaluated check already passes restricted there is nothing to
recommend; the command says so on stderr and prints nothing.

Examples:
  kubectl kguardian profile export payments/Deployment/checkout --format pss > patch.yaml
  kubectl patch deployment checkout -n payments --patch-file patch.yaml   # after review`,
	Args: cobra.ExactArgs(1),
	RunE: runProfileExport,
}

func init() {
	rootCmd.AddCommand(profileCmd)
	profileCmd.AddCommand(profileGetCmd, profileListCmd, profileDiffCmd, profileExportCmd)
	profileGetCmd.Flags().StringVarP(&profileGetOutput, "output", "o", "table", "Output format: table, json or yaml")
	profileListCmd.Flags().StringVar(&profileListKind, "kind", "", "Only this workload kind (case-sensitive)")
	profileListCmd.Flags().StringVar(&profileListStatus, "status", "", "Only this posture status: ok, warn, risk or unknown")
	profileListCmd.Flags().IntVar(&profileListLimit, "limit", 100, "Page size (the broker caps it at 500)")
	profileListCmd.Flags().StringVar(&profileListAfter, "after", "", "Cursor printed by the previous page")
	profileListCmd.Flags().StringVarP(&profileListOutput, "output", "o", "table", "Output format: table, json or yaml")
	profileDiffCmd.Flags().IntVar(&profileDiffFrom, "from", 0, "Older revision (default: the one before --to)")
	profileDiffCmd.Flags().IntVar(&profileDiffTo, "to", 0, "Newer revision (default: the latest)")
	profileDiffCmd.Flags().StringVarP(&profileDiffOutput, "output", "o", "table", "Output format: table, json or yaml")
	profileExportCmd.Flags().StringVar(&profileExportFormat, "format", "pss", "Export format: pss")
}

// workloadRef is the (namespace, kind, name) profile key.
type workloadRef struct{ Namespace, Kind, Name string }

func (w workloadRef) String() string { return w.Namespace + "/" + w.Kind + "/" + w.Name }

// parseWorkloadRef parses <namespace>/<kind>/<name>.
func parseWorkloadRef(s string) (workloadRef, error) {
	parts := strings.Split(strings.TrimSpace(s), "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return workloadRef{}, fmt.Errorf("workload must be <namespace>/<kind>/<name>, e.g. payments/Deployment/checkout; got %q", s)
	}
	return workloadRef{parts[0], parts[1], parts[2]}, nil
}

// profileNotFound turns a broker 404 into an operator-facing error.
func profileNotFound(ref workloadRef, err error) error {
	var nf *api.NotFoundError
	if errors.As(err, &nf) && nf.Code == "revision_not_found" {
		return fmt.Errorf("%s: %s", ref, nf.Error())
	}
	return fmt.Errorf("kguardian has no data for %s (check the kind is the owning workload's, e.g. Deployment, and is capitalised)", ref)
}

func runProfileGet(cmd *cobra.Command, args []string) error {
	output, err := parseOutput(profileGetOutput, "table", "json", "yaml")
	if err != nil {
		return err
	}
	ref, err := parseWorkloadRef(args[0])
	if err != nil {
		return err
	}
	closeFn, err := connectBroker(cmd)
	if err != nil {
		return err
	}
	defer closeFn()
	return fetchAndRenderProfile(ref, output, os.Stdout)
}

func runProfileList(cmd *cobra.Command, _ []string) error {
	output, err := parseOutput(profileListOutput, "table", "json", "yaml")
	if err != nil {
		return err
	}
	status := strings.ToLower(strings.TrimSpace(profileListStatus))
	switch status {
	case "", "ok", "warn", "risk", "unknown":
	default:
		return fmt.Errorf("invalid --status %q: must be ok, warn, risk or unknown", profileListStatus)
	}
	closeFn, err := connectBroker(cmd)
	if err != nil {
		return err
	}
	defer closeFn()
	opts := api.ProfileListOptions{
		Namespace: explicitNamespace(cmd),
		Kind:      profileListKind,
		Status:    status,
		Limit:     profileListLimit,
		After:     profileListAfter,
	}
	return fetchAndRenderProfiles(opts, output, os.Stdout, os.Stderr)
}

func runProfileDiff(cmd *cobra.Command, args []string) error {
	output, err := parseOutput(profileDiffOutput, "table", "json", "yaml")
	if err != nil {
		return err
	}
	ref, err := parseWorkloadRef(args[0])
	if err != nil {
		return err
	}
	if profileDiffFrom < 0 || profileDiffTo < 0 {
		return fmt.Errorf("--from and --to are revision numbers (1 or more)")
	}
	if profileDiffFrom > 0 && profileDiffTo > 0 && profileDiffFrom >= profileDiffTo {
		return fmt.Errorf("--from (%d) must be older than --to (%d)", profileDiffFrom, profileDiffTo)
	}
	closeFn, err := connectBroker(cmd)
	if err != nil {
		return err
	}
	defer closeFn()
	return fetchAndRenderProfileDiff(ref, profileDiffFrom, profileDiffTo, output, os.Stdout)
}

func runProfileExport(cmd *cobra.Command, args []string) error {
	format := strings.ToLower(strings.TrimSpace(profileExportFormat))
	if format != "pss" {
		return fmt.Errorf("invalid --format %q: only pss is available", profileExportFormat)
	}
	ref, err := parseWorkloadRef(args[0])
	if err != nil {
		return err
	}
	closeFn, err := connectBroker(cmd)
	if err != nil {
		return err
	}
	defer closeFn()
	return exportPSSPatch(ref, os.Stdout, os.Stderr)
}

// --- rendering ---------------------------------------------------------------

// fmtScore renders a 0-100 score, "unknown" when nil.
func fmtScore(v *float64) string {
	if v == nil || math.IsNaN(*v) {
		return "unknown"
	}
	return fmt.Sprintf("%d", int(math.Round(*v)))
}

// fmtFraction renders a 0-1 fraction as a percent, "-" when nil.
func fmtFraction(v *float64) string {
	if v == nil || math.IsNaN(*v) {
		return "-"
	}
	return fmt.Sprintf("%d%%", int(math.Round(*v*100)))
}

// fmtOK renders a readiness result; nil is "unknown", never a pass.
func fmtOK(v *bool) string {
	switch {
	case v == nil:
		return "unknown"
	case *v:
		return "yes"
	default:
		return "no"
	}
}

// profileDimensionOrder is the display order; unknown extra dimensions follow.
var profileDimensionOrder = []string{"podSecurity", "network", "syscalls", "images", "compute"}

func orderedDimensions(dims map[string]json.RawMessage) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range profileDimensionOrder {
		if _, ok := dims[d]; ok {
			out = append(out, d)
			seen[d] = true
		}
	}
	var extra []string
	for d := range dims {
		if !seen[d] {
			extra = append(extra, d)
		}
	}
	sort.Strings(extra)
	return append(out, extra...)
}

// fetchAndRenderProfile is the testable core of `profile get`.
func fetchAndRenderProfile(ref workloadRef, output string, w io.Writer) error {
	p, raw, err := api.GetProfile(ref.Namespace, ref.Kind, ref.Name)
	if errors.Is(err, api.ErrNotFound) {
		return profileNotFound(ref, err)
	}
	if err != nil {
		return brokerReadErr(fmt.Sprintf("fetching profile for %s", ref), err)
	}
	if output != "table" {
		return writeRaw(w, raw, output)
	}
	return renderProfileTable(w, ref, p)
}

func renderProfileTable(dst io.Writer, ref workloadRef, p *api.Profile) error {
	// Render into memory and write once, so the only fallible write is the last.
	var out bytes.Buffer
	w := &out
	var b strings.Builder
	fmt.Fprintf(&b, "Workload:   %s\n", ref)
	if p.Workload.Pods != nil {
		fmt.Fprintf(&b, "Live pods:  %d\n", p.Workload.Pods.Live)
	}
	grade := "-"
	if p.Posture.Grade != nil {
		grade = *p.Posture.Grade
	}
	fmt.Fprintf(&b, "Posture:    %s  score %s  coverage %s  grade %s\n",
		p.Posture.Status, fmtScore(p.Posture.Score), fmtFraction(p.Posture.Coverage), grade)
	if len(p.Posture.UnknownDimensions) > 0 {
		fmt.Fprintf(&b, "Not scored: %s (unknown or unscored; excluded from the score)\n", strings.Join(p.Posture.UnknownDimensions, ", "))
	}
	if p.Version != nil {
		fmt.Fprintf(&b, "Revision:   %d (%s)", p.Version.Revision, p.Version.CreatedAt)
		if p.SnapshotPending {
			b.WriteString(", live profile differs; a new revision is pending")
		}
		b.WriteByte('\n')
	} else {
		b.WriteString("Revision:   none stored yet\n")
	}
	if ps := p.PodSecurity(); ps != nil {
		level := "unknown"
		if ps.Level != nil {
			level = *ps.Level
			if ps.LevelConfidence != nil && *ps.LevelConfidence == "upper_bound" {
				level = "at most " + level + " (" + fmt.Sprint(len(ps.UnevaluatedChecks)) + " checks not visible to kguardian)"
			}
		}
		fmt.Fprintf(&b, "PSS level:  %s\n", level)
	}
	b.WriteByte('\n')
	out.WriteString(b.String())

	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "DIMENSION\tSTATUS\tSCORE\tCOVERAGE\tREASON")
	for _, name := range orderedDimensions(p.Dimensions) {
		d, ok := p.DimensionEnvelope(name)
		if !ok {
			continue
		}
		score := fmtScore(d.Score)
		if !d.Scored && d.Status != "unknown" {
			score = "not scored"
		}
		cov := "-"
		if d.Coverage != nil {
			cov = d.Coverage.Level
		}
		reason := "-"
		if len(d.Reasons) > 0 {
			reason = cell(d.Reasons[0].Message)
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", name, d.Status, score, cov, reason)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	if len(p.Attention) > 0 {
		_, _ = fmt.Fprintln(w, "\nNeeds attention:")
		tw = tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "SEVERITY\tFINDING\tCONTAINER\tTITLE")
		for _, f := range p.Attention {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Severity, f.ID, orDash(f.Container), cell(f.Title))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if len(p.Readiness) > 0 {
		_, _ = fmt.Fprintln(w, "\nReadiness:")
		tw = tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
		for _, r := range p.Readiness {
			_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\n", r.ID, fmtOK(r.OK), cell(r.Message))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if ps := p.PodSecurity(); ps != nil && ps.Recommendation != nil {
		_, _ = fmt.Fprintf(w, "\nA securityContext recommendation is available: kubectl kguardian profile export %s --format pss\n", ref)
	}
	_, err := dst.Write(out.Bytes())
	return err
}

// fetchAndRenderProfiles is the testable core of `profile list`.
func fetchAndRenderProfiles(opts api.ProfileListOptions, output string, w, errw io.Writer) error {
	page, raw, err := api.GetProfiles(opts)
	if err != nil {
		return brokerReadErr("fetching workload profiles", err)
	}
	if output != "table" {
		return writeRaw(w, raw, output)
	}
	if len(page.Items) == 0 {
		_, err := fmt.Fprintln(w, "No workload profiles.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAMESPACE\tKIND\tNAME\tSTATUS\tSCORE\tCOVERAGE\tGRADE\tFINDINGS (C/H/M)\tREV")
	for _, it := range page.Items {
		grade := "-"
		if it.Posture.Grade != nil {
			grade = *it.Posture.Grade
		}
		rev := "-"
		if it.Revision != nil {
			rev = fmt.Sprint(*it.Revision)
		}
		counts := fmt.Sprintf("%d/%d/%d", it.FindingCounts["critical"], it.FindingCounts["high"], it.FindingCounts["medium"])
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			it.Namespace, it.Kind, it.Name, it.Posture.Status, fmtScore(it.Posture.Score),
			fmtFraction(it.Posture.Coverage), grade, counts, rev)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if page.NextAfter != nil && *page.NextAfter != "" {
		_, err := fmt.Fprintf(errw, "More workloads: pass --after %s for the next page.\n", *page.NextAfter)
		return err
	}
	return nil
}

// fetchAndRenderProfileDiff is the testable core of `profile diff`.
func fetchAndRenderProfileDiff(ref workloadRef, from, to int, output string, w io.Writer) error {
	d, raw, err := api.GetProfileDiff(ref.Namespace, ref.Kind, ref.Name, from, to)
	if errors.Is(err, api.ErrNotFound) {
		var nf *api.NotFoundError
		if errors.As(err, &nf) && nf.Code == "revision_not_found" {
			return profileNotFound(ref, err)
		}
		return fmt.Errorf("%s has no stored profile revisions yet", ref)
	}
	if err != nil {
		return brokerReadErr(fmt.Sprintf("fetching profile diff for %s", ref), err)
	}
	if output != "table" {
		return writeRaw(w, raw, output)
	}
	return renderProfileDiff(w, ref, d)
}

func fmtRev(v *api.ProfileVersion) string {
	if v == nil {
		return "(none)"
	}
	return fmt.Sprintf("%d (%s)", v.Revision, v.CreatedAt)
}

// Diff scalars whose null means "kguardian could not tell" rather than
// "not set in the spec": a derived level or state, never a pass.
var unknownWhenNull = map[string]string{
	"level":        "unknown",
	"captureLevel": "unknown",
	"audited":      "unknown",
	"cr":           "none",
}

// fmtSide renders one side of a {from,to} pair for key.
func fmtSide(key string, v any) string {
	if v == nil {
		if s, ok := unknownWhenNull[key]; ok {
			return s
		}
	}
	return fmtValue(v)
}

// fmtValue renders a diff value; null is "unset" (a spec field not set).
func fmtValue(v any) string {
	if v == nil {
		return "unset"
	}
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// fmtDiffEntry renders one list entry: a network rule, a field change, or
// anything else as compact JSON.
func fmtDiffEntry(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return fmtValue(v)
	}
	if dir, ok := m["direction"]; ok {
		port := "unknown"
		if m["port"] != nil {
			port = fmtValue(m["port"])
		}
		return fmt.Sprintf("%s %s/%s %s", fmtValue(dir), fmtValue(m["protocol"]), port, fmtValue(m["peer"]))
	}
	if f, ok := m["field"]; ok {
		return fmt.Sprintf("%s: %s -> %s", fmtValue(f), fmtValue(m["from"]), fmtValue(m["to"]))
	}
	return fmtValue(v)
}

// renderProfileDiff prints each dimension's changes. A null scalar in the
// broker's diff means unchanged and is skipped; a {from,to} pair is a change.
func renderProfileDiff(w io.Writer, ref workloadRef, d *api.ProfileDiff) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Workload: %s\nFrom:     %s\nTo:       %s\n", ref, fmtRev(d.From), fmtRev(d.To))
	if !d.Changed {
		b.WriteString("\nNo changes.\n")
		_, err := io.WriteString(w, b.String())
		return err
	}
	for _, name := range orderedDimensions(d.Dimensions) {
		var dim map[string]any
		if json.Unmarshal(d.Dimensions[name], &dim) != nil {
			continue
		}
		changed, _ := dim["changed"].(bool)
		if !changed {
			fmt.Fprintf(&b, "\n%s: unchanged\n", name)
			continue
		}
		fmt.Fprintf(&b, "\n%s: changed\n", name)
		keys := make([]string, 0, len(dim))
		for k := range dim {
			if k != "changed" {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			writeDiffField(&b, k, dim[k], "  ")
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func writeDiffField(b *strings.Builder, key string, v any, indent string) {
	switch val := v.(type) {
	case nil:
		// unchanged
	case map[string]any:
		if _, hasFrom := val["from"]; hasFrom {
			fmt.Fprintf(b, "%s%s: %s -> %s\n", indent, key, fmtSide(key, val["from"]), fmtSide(key, val["to"]))
			return
		}
		fmt.Fprintf(b, "%s%s: %s\n", indent, key, fmtValue(val))
	case []any:
		if len(val) == 0 {
			return
		}
		sign := " "
		lk := strings.ToLower(key)
		if strings.HasPrefix(lk, "added") || strings.HasSuffix(lk, "added") {
			sign = "+"
		} else if strings.HasPrefix(lk, "removed") || strings.HasSuffix(lk, "removed") {
			sign = "-"
		}
		fmt.Fprintf(b, "%s%s:\n", indent, key)
		for _, e := range val {
			// Per-container groups: {name, fields|added|removed}.
			if m, ok := e.(map[string]any); ok {
				if n, ok := m["name"].(string); ok && len(m) > 1 {
					fmt.Fprintf(b, "%s  %s\n", indent, n)
					sub := make([]string, 0, len(m))
					for k := range m {
						if k != "name" {
							sub = append(sub, k)
						}
					}
					sort.Strings(sub)
					for _, k := range sub {
						writeDiffField(b, k, m[k], indent+"    ")
					}
					continue
				}
			}
			if sign == " " {
				fmt.Fprintf(b, "%s  %s\n", indent, fmtDiffEntry(e))
			} else {
				fmt.Fprintf(b, "%s  %s %s\n", indent, sign, fmtDiffEntry(e))
			}
		}
	case bool:
		fmt.Fprintf(b, "%s%s: %t\n", indent, key, val)
	default:
		fmt.Fprintf(b, "%s%s: %s\n", indent, key, fmtValue(val))
	}
}

// exportPSSPatch prints dimensions.podSecurity.recommendation.yaml verbatim;
// caveats and the nothing-to-recommend notice go to stderr so stdout stays a
// clean patch file.
func exportPSSPatch(ref workloadRef, w, errw io.Writer) error {
	p, _, err := api.GetProfile(ref.Namespace, ref.Kind, ref.Name)
	if errors.Is(err, api.ErrNotFound) {
		return profileNotFound(ref, err)
	}
	if err != nil {
		return brokerReadErr(fmt.Sprintf("fetching profile for %s", ref), err)
	}
	ps := p.PodSecurity()
	if ps == nil || ps.Level == nil {
		return fmt.Errorf("%s: no container securityContext has been reported, so there is nothing to base a recommendation on (unknown, not compliant)", ref)
	}
	if ps.Recommendation == nil || strings.TrimSpace(ps.Recommendation.YAML) == "" {
		_, err := fmt.Fprintf(errw, "%s: every evaluated Pod Security Standards check already passes restricted; nothing to recommend. %d checks are not visible to kguardian.\n", ref, len(ps.UnevaluatedChecks))
		return err
	}
	patch := ps.Recommendation.YAML
	if !strings.HasSuffix(patch, "\n") {
		patch += "\n"
	}
	if _, err := io.WriteString(w, patch); err != nil {
		return err
	}
	for _, c := range ps.Recommendation.Caveats {
		if _, err := fmt.Fprintf(errw, "caveat: %s\n", c); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintln(errw, "This is a recommendation. kguardian has not applied it; review it before use.")
	return err
}
