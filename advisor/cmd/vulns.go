package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
	"github.com/spf13/cobra"
)

// Vulnerability and SBOM views over the broker's supply-chain reads.
// Findings come from Trivy Operator reports and, when the opt-in
// supplychain matcher is enabled, from kguardian's own Grype matcher, which
// matches SBOMs. kguardian never blocks or applies anything. `images vulns --fail-on` is the one place a
// result changes the exit code, for CI gates.

// gateError carries a CI gate result: a distinct exit code and a message,
// printed by Execute without the usual error log.
type gateError struct {
	code int
	msg  string
}

func (e *gateError) Error() string { return e.msg }

// Gate exit codes for `images vulns --fail-on`.
const (
	exitGateFindings = 1 // at least one finding at or above the threshold
	exitGateNoCheck  = 2 // the check could not run: broker, transport, auth or usage error
	exitGateUnknown  = 3 // no vulnerability data for the image (unknown)
)

// severityOrder ranks broker severities, most severe first.
var severityOrder = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}

// parseSeverityList validates a comma-separated severity list.
func parseSeverityList(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	var out []string
	seen := map[string]bool{}
	for _, p := range strings.Split(raw, ",") {
		s := strings.ToUpper(strings.TrimSpace(p))
		if s == "" || seen[s] {
			continue
		}
		if s != "UNKNOWN" && indexOf(severityOrder, s) < 0 {
			return "", fmt.Errorf("invalid severity %q: use CRITICAL, HIGH, MEDIUM, LOW, NONE or UNKNOWN", p)
		}
		seen[s] = true
		out = append(out, s)
	}
	return strings.Join(out, ","), nil
}

func indexOf(xs []string, s string) int {
	for i, x := range xs {
		if x == s {
			return i
		}
	}
	return -1
}

// failOnSeverities is the broker severity filter for a --fail-on threshold:
// the threshold and everything more severe, plus UNKNOWN (a finding whose
// severity no source knows is never assumed to be below the bar).
func failOnSeverities(threshold string) (string, error) {
	t := strings.ToUpper(strings.TrimSpace(threshold))
	i := indexOf(severityOrder, t)
	if i < 0 || t == "NONE" {
		return "", fmt.Errorf("invalid --fail-on %q: use critical, high, medium or low", threshold)
	}
	return strings.Join(append(append([]string{}, severityOrder[:i+1]...), "UNKNOWN"), ","), nil
}

// tierOrder ranks broker tiers, most urgent first.
var tierOrder = []string{"P0", "P1", "P2", "Background"}

// tierGatePrefix marks a --fail-on gate on tiers rather than severities.
const tierGatePrefix = "tier:"

// failOnGate is the gate filter for --fail-on: a severity threshold (see
// failOnSeverities) or a tier (p0, p1, p2: that tier and every more urgent
// one, as "tier:P0,P1"). Background is never a gate.
func failOnGate(threshold string) (string, error) {
	t := strings.TrimSpace(threshold)
	for i, tier := range tierOrder[:3] {
		if strings.EqualFold(t, tier) {
			return tierGatePrefix + strings.Join(tierOrder[:i+1], ","), nil
		}
	}
	g, err := failOnSeverities(t)
	if err != nil {
		return "", fmt.Errorf("invalid --fail-on %q: use critical, high, medium, low, p0, p1 or p2", threshold)
	}
	return g, nil
}

// parseTierList validates a comma-separated tier list (case-insensitive)
// into the broker's spelling.
func parseTierList(raw string) (string, error) {
	return parseEnumList(raw, tierOrder, "--tier", "P0, P1, P2 or Background")
}

var inUseStates = []string{"executed", "loaded", "unknown", "installed_not_observed"}

// parseInUseList validates a comma-separated in-use state list.
func parseInUseList(raw string) (string, error) {
	return parseEnumList(raw, inUseStates, "--in-use", strings.Join(inUseStates, ", "))
}

func parseEnumList(raw string, allowed []string, flag, want string) (string, error) {
	var out []string
	seen := map[string]bool{}
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		match := ""
		for _, a := range allowed {
			if strings.EqualFold(a, p) {
				match = a
			}
		}
		if match == "" {
			return "", fmt.Errorf("invalid %s %q: use %s", flag, p, want)
		}
		if !seen[match] {
			seen[match] = true
			out = append(out, match)
		}
	}
	return strings.Join(out, ","), nil
}

// optEpss is --epss-min when given (a probability, 0-1).
func optEpss(cmd *cobra.Command, name string, v float64) (*float64, error) {
	if !cmd.Flags().Changed(name) {
		return nil, nil
	}
	if v < 0 || v > 1 {
		return nil, fmt.Errorf("--%s must be between 0 and 1 (e.g. 0.1 for 10%%)", name)
	}
	return &v, nil
}

// riskFilters holds the flags shared by `images vulns` and `vulns list`.
type riskFilters struct {
	kev     bool
	epssMin float64
	inUse   string
	tier    string
}

func (f *riskFilters) register(cmd *cobra.Command, noun string) {
	cmd.Flags().BoolVar(&f.kev, "kev", false, "Only "+noun+" a source lists in CISA KEV (--kev=false: only those a source says are not; unknown is excluded either way)")
	cmd.Flags().Float64Var(&f.epssMin, "epss-min", 0, "Only "+noun+" with EPSS at or above this probability (0-1); unknown EPSS is excluded")
	cmd.Flags().StringVar(&f.inUse, "in-use", "", "Only these in-use states, comma-separated (executed,loaded,unknown,installed_not_observed)")
	cmd.Flags().StringVar(&f.tier, "tier", "", "Only these risk tiers, comma-separated (P0,P1,P2,Background)")
}

// resolve validates the flags into broker filter values.
func (f *riskFilters) resolve(cmd *cobra.Command) (kev *bool, epss *float64, inUse, tier string, err error) {
	kev = optBool(cmd, "kev", f.kev)
	if epss, err = optEpss(cmd, "epss-min", f.epssMin); err != nil {
		return
	}
	if inUse, err = parseInUseList(f.inUse); err != nil {
		return
	}
	tier, err = parseTierList(f.tier)
	return
}

// fmtInUse renders an in-use state; empty (a broker without in-use data)
// and unknown both print "unknown".
func fmtInUse(state string) string {
	switch state {
	case "executed", "loaded":
		return state
	case "installed_not_observed":
		return "not-observed"
	default:
		return "unknown"
	}
}

func orDashStr(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// inUseLegend explains IN USE and TIER under a table.
const inUseLegend = `
IN USE is from observed exec and shared-library capture: executed/loaded = a file the package owns ran;
unknown = no evidence either way (treat as potentially reachable, never as unused); not-observed = not seen
over a covered window, which is not proof the code can never run.
TIER: P0 = in use + (KEV or high EPSS) + exposed (no observed ingress counts as exposed, so a KEV finding
there is P0); P1 = in use + critical/high, or P0 factors without exposure; P2 = in use + medium/low, or
high with no fix and not exposed; Background = installed, not observed. "-" = not computed yet (never low risk).
`

func parseDigestArg(raw string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(raw))
	hex, ok := strings.CutPrefix(d, "sha256:")
	if !ok || len(hex) != 64 || strings.Trim(hex, "0123456789abcdef") != "" {
		return "", fmt.Errorf("digest must be sha256: followed by 64 hex characters, got %q (find it with 'kguardian images list')", raw)
	}
	return d, nil
}

func optBool(cmd *cobra.Command, name string, v bool) *bool {
	if cmd.Flags().Changed(name) {
		return &v
	}
	return nil
}

func fmtFloat(v *float64) string {
	if v == nil {
		return "-"
	}
	return strconv.FormatFloat(*v, 'f', 1, 64)
}

// fmtFixed renders every fixed version the sources give, as the broker
// lists them (source order). None is picked: text order is not version
// order. "-" when no source has a fix.
func fmtFixed(v []string) string {
	if len(v) == 0 {
		return "-"
	}
	return strings.Join(v, " or ")
}

// fmtKev renders KEV: null is unknown (Trivy never reports it), not "no".
func fmtKev(v *bool) string {
	switch {
	case v == nil:
		return "unknown"
	case *v:
		return "yes"
	default:
		return "no"
	}
}

// --- images vulns ----------------------------------------------------------

var (
	imageVulnsSeverity string
	imageVulnsFixable  bool
	imageVulnsSource   string
	imageVulnsLimit    int
	imageVulnsAfter    string
	imageVulnsFailOn   string
	imageVulnsOutput   string
	imageVulnsRisk     riskFilters
)

var imagesVulnsCmd = &cobra.Command{
	Use:   "vulns <digest>",
	Short: "List the vulnerabilities found in an image",
	Long: `List the vulnerability findings for one image digest, deduplicated across
sources, most severe first. Findings come from Trivy Operator reports and,
when the opt-in supplychain matcher is enabled, from kguardian's own Grype
matcher, which matches SBOMs.

"No vulnerability data" means no source has reported on the image. That is
unknown, not clean. KEV "unknown" means no source said either way (Trivy never
does).

IN USE comes from observed exec and shared-library capture: executed or
loaded means a file the package owns ran in some workload container; unknown
means no evidence either way and must be treated as potentially reachable;
not-observed means capture covered the container for the whole window and
nothing the package owns ran. TIER ranks findings: P0 (in use, KEV or high
EPSS, and exposed; a workload with no observed ingress counts as exposed),
P1, P2, Background. See the table legend.

CI gate: --fail-on <severity> or --fail-on <tier> (p0, p1, p2) exits
  0  no finding at or above the severity or tier
  1  at least one finding at or above it (findings of UNKNOWN severity count;
     tiers already rank unknown in-use as in use)
  2  the check could not run: broker unreachable, port-forward or token
     failure, a broker error, an invalid flag, or --fail-on <tier> against a
     broker that does not report tiers
  3  no vulnerability data for the image: unknown is never a pass
Each result is printed as a "gate:" line on stderr.

Examples:
  kubectl kguardian images vulns sha256:0123...
  kubectl kguardian images vulns sha256:0123... --severity critical,high --fixable
  kubectl kguardian images vulns sha256:0123... --tier p0,p1
  kubectl kguardian images vulns sha256:0123... --fail-on high -o json
  kubectl kguardian images vulns sha256:0123... --fail-on p0`,
	Args: cobra.ExactArgs(1),
	RunE: runImagesVulns,
}

func runImagesVulns(cmd *cobra.Command, args []string) error {
	err := imagesVulns(cmd, args)
	if strings.TrimSpace(imageVulnsFailOn) != "" {
		// With a gate, every outcome is a gate result: CI must be able to
		// tell "findings" (1) from "could not check" (2) from "no data" (3).
		err = asGateResult(err)
	}
	var ge *gateError
	if errors.As(err, &ge) {
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
	}
	return err
}

// asGateResult keeps a gate result as is and turns any other error into
// exit code 2 ("could not check").
func asGateResult(err error) error {
	if err == nil {
		return nil
	}
	var ge *gateError
	if errors.As(err, &ge) {
		return err
	}
	return &gateError{code: exitGateNoCheck, msg: fmt.Sprintf("gate: could not check (exit %d): %v", exitGateNoCheck, err)}
}

func imagesVulns(cmd *cobra.Command, args []string) error {
	output, err := parseOutput(imageVulnsOutput, "table", "json", "yaml")
	if err != nil {
		return err
	}
	digest, err := parseDigestArg(args[0])
	if err != nil {
		return err
	}
	sev, err := parseSeverityList(imageVulnsSeverity)
	if err != nil {
		return err
	}
	gate := ""
	if imageVulnsFailOn != "" {
		if gate, err = failOnGate(imageVulnsFailOn); err != nil {
			return err
		}
	}
	src, err := parseSourceFlag(imageVulnsSource)
	if err != nil {
		return err
	}
	kev, epss, inUse, tier, err := imageVulnsRisk.resolve(cmd)
	if err != nil {
		return err
	}
	closeFn, err := connectBroker(cmd)
	if err != nil {
		return err
	}
	defer closeFn()
	opts := api.ImageVulnsOptions{Severity: sev, Fixable: optBool(cmd, "fixable", imageVulnsFixable), Kev: kev, EpssMin: epss,
		InUse: inUse, Tier: tier, Source: src, Limit: imageVulnsLimit, After: imageVulnsAfter}
	return fetchAndRenderImageVulns(digest, opts, gate, strings.ToUpper(imageVulnsFailOn), output, os.Stdout, os.Stderr)
}

// fetchAndRenderImageVulns renders the page asked for, then, with a gate,
// runs its own query (threshold severities or tiers, limit 1) so the gate
// sees every page, not just the one shown.
func fetchAndRenderImageVulns(digest string, opts api.ImageVulnsOptions, gate, threshold, output string, w, errw io.Writer) error {
	err := renderAndGate(digest, opts, gate, threshold, output, w, errw)
	if gate != "" {
		return asGateResult(err)
	}
	return err
}

func renderAndGate(digest string, opts api.ImageVulnsOptions, gate, threshold, output string, w, errw io.Writer) error {
	page, raw, err := api.GetImageVulns(digest, opts)
	if err != nil {
		return brokerReadErr(fmt.Sprintf("fetching vulnerabilities for %s", digest), err)
	}
	if output != "table" {
		if err := writeRaw(w, raw, output); err != nil {
			return err
		}
	} else if err := renderImageVulnsTable(w, errw, page); err != nil {
		return err
	}
	if gate == "" {
		return nil
	}
	if len(page.Reports) == 0 {
		return &gateError{code: exitGateUnknown, msg: fmt.Sprintf("gate: no vulnerability data for %s; unknown is not a pass (exit %d)", digest, exitGateUnknown)}
	}
	gq := api.ImageVulnsOptions{Severity: gate, Source: opts.Source, Limit: 1}
	tierGate := strings.HasPrefix(gate, tierGatePrefix)
	if tierGate {
		gq = api.ImageVulnsOptions{Tier: strings.TrimPrefix(gate, tierGatePrefix), Source: opts.Source, Limit: 1}
	}
	g, _, err := api.GetImageVulns(digest, gq)
	if err != nil {
		return brokerReadErr("evaluating --fail-on", err)
	}
	if len(g.Items) > 0 {
		f := g.Items[0]
		if tierGate && f.Tier == "" {
			// A broker without tiers ignores the filter and answers with
			// any finding: that is not a result.
			return &gateError{code: exitGateNoCheck, msg: fmt.Sprintf("gate: could not check (exit %d): the broker does not report risk tiers; upgrade it or gate on a severity", exitGateNoCheck)}
		}
		level := f.Severity
		if tierGate {
			level = f.Tier + " " + f.Severity
		}
		return &gateError{code: exitGateFindings, msg: fmt.Sprintf("gate: %s has findings at or above %s (e.g. %s %s in %s) (exit %d)", digest, threshold, level, f.ID, f.Package.Name, exitGateFindings)}
	}
	_, err = fmt.Fprintf(errw, "gate: no findings at or above %s\n", threshold)
	return err
}

func renderImageVulnsTable(w, errw io.Writer, p *api.ImageVulnsPage) error {
	var out bytes.Buffer
	if len(p.Reports) == 0 {
		fmt.Fprintf(&out, "No vulnerability data for %s: no source has reported on this image. This is unknown, not clean.\n", p.Digest)
		_, err := w.Write(out.Bytes())
		return err
	}
	tw := tabwriter.NewWriter(&out, 0, 8, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SOURCE\tSCANNER\tSCANNED\tJOIN\tSBOM TRUST\tFINDINGS")
	for _, r := range p.Reports {
		scanner := orDash(r.ScannerName)
		if r.ScannerVersion != nil {
			scanner += " " + *r.ScannerVersion
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\n", r.Source, cell(scanner), r.ScannedAt, r.Join, orDash(r.SbomTrust), r.ItemCount)
	}
	_ = tw.Flush()
	out.WriteByte('\n')
	if len(p.Items) == 0 {
		out.WriteString("No findings match.\n")
	} else {
		tw = tabwriter.NewWriter(&out, 0, 8, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "TIER\tSEVERITY\tID\tPACKAGE\tINSTALLED\tFIXED\tSCORE\tKEV\tIN USE\tSOURCES")
		for _, f := range p.Items {
			fixed := fmtFixed(f.FixedVersions)
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", orDashStr(f.Tier), f.Severity, cell(f.ID), cell(f.Package.Name),
				cell(f.InstalledVersion), cell(fixed), fmtFloat(f.Score), fmtKev(f.Kev), fmtInUse(f.InUseState), strings.Join(f.Sources, ","))
		}
		_ = tw.Flush()
		out.WriteString(inUseLegend)
	}
	if _, err := w.Write(out.Bytes()); err != nil {
		return err
	}
	if p.NextAfter != nil && *p.NextAfter != "" {
		_, err := fmt.Fprintf(errw, "More findings: pass --after %s for the next page.\n", *p.NextAfter)
		return err
	}
	return nil
}

// --- images sbom -------------------------------------------------------------

var (
	imageSbomSource string
	imageSbomLimit  int
	imageSbomAfter  int64
	imageSbomOutput string
)

var imagesSbomCmd = &cobra.Command{
	Use:   "sbom <digest>",
	Short: "Show an image's SBOM (or download it as CycloneDX)",
	Long: `Show the software bill of materials the broker holds for an image.

Every source's SBOM is kept side by side and listed with its trust level,
weakest first:
  attached-unbound  a bare document attached to the image in its registry
  unverified        an in-toto statement naming the image; signature not checked
  scanned           Trivy Operator's in-cluster scan
  verified          signature verified
Only "verified" means signed. The components shown come from one SBOM: the
--source you ask for, else Trivy Operator's, else another scanner's, and a
registry SBOM only when it is the only one.

-o cyclonedx writes the broker's CycloneDX 1.5 JSON export of that SBOM to
stdout, with the source, join and trust in metadata.properties.

Examples:
  kubectl kguardian images sbom sha256:0123...
  kubectl kguardian images sbom sha256:0123... --source registry
  kubectl kguardian images sbom sha256:0123... -o cyclonedx > sbom.cdx.json`,
	Args: cobra.ExactArgs(1),
	RunE: runImagesSbom,
}

func parseSourceFlag(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch s {
	case "", "trivy-operator", "grype", "registry":
		return s, nil
	}
	return "", fmt.Errorf("invalid --source %q: use trivy-operator, grype or registry", raw)
}

func runImagesSbom(cmd *cobra.Command, args []string) error {
	output, err := parseOutput(imageSbomOutput, "table", "json", "yaml", "cyclonedx")
	if err != nil {
		return err
	}
	digest, err := parseDigestArg(args[0])
	if err != nil {
		return err
	}
	src, err := parseSourceFlag(imageSbomSource)
	if err != nil {
		return err
	}
	closeFn, err := connectBroker(cmd)
	if err != nil {
		return err
	}
	defer closeFn()
	return fetchAndRenderSbom(digest, src, imageSbomLimit, imageSbomAfter, output, os.Stdout, os.Stderr)
}

func fetchAndRenderSbom(digest, source string, limit int, after int64, output string, w, errw io.Writer) error {
	if output == "cyclonedx" {
		doc, err := api.GetSbomCycloneDX(digest, source)
		if errors.Is(err, api.ErrNotFound) {
			return fmt.Errorf("no SBOM for %s from %s: its contents are unknown", digest, orAny(source))
		}
		if err != nil {
			return brokerReadErr(fmt.Sprintf("downloading the CycloneDX SBOM for %s", digest), err)
		}
		if _, err := w.Write(doc); err != nil {
			return err
		}
		if len(doc) > 0 && doc[len(doc)-1] != '\n' {
			_, err = w.Write([]byte("\n"))
		}
		return err
	}
	page, raw, err := api.GetSbom(digest, source, limit, after)
	if err != nil {
		return brokerReadErr(fmt.Sprintf("fetching the SBOM for %s", digest), err)
	}
	if output != "table" {
		return writeRaw(w, raw, output)
	}
	var out bytes.Buffer
	if len(page.Reports) > 0 {
		tw := tabwriter.NewWriter(&out, 0, 8, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "SOURCE\tFORMAT\tTRUST\tSIGNED\tCOMPONENTS\tSCANNED")
		for _, r := range page.Reports {
			signed := "no"
			if r.SbomTrust != nil && *r.SbomTrust == "verified" {
				signed = "yes"
			}
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\n", r.Source, orDash(r.SbomFormat), orDash(r.SbomTrust), signed, r.ItemCount, r.ScannedAt)
		}
		_ = tw.Flush()
		out.WriteByte('\n')
	}
	if page.Report == nil {
		fmt.Fprintf(&out, "No SBOM for %s from %s: its contents are unknown.\n", digest, orAny(source))
		_, err := w.Write(out.Bytes())
		return err
	}
	fmt.Fprintf(&out, "Components from %s (trust %s):\n", page.Report.Source, orDash(page.Report.SbomTrust))
	tw := tabwriter.NewWriter(&out, 0, 8, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tVERSION\tTYPE\tLICENSES\tPURL")
	for _, c := range page.Items {
		lic := "-"
		if len(c.Licenses) > 0 {
			lic = strings.Join(c.Licenses, ",")
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", cell(c.Name), cell(orDash(c.Version)), cell(orDash(c.Type)), cell(lic), cell(orDash(c.Purl)))
	}
	_ = tw.Flush()
	if _, err := w.Write(out.Bytes()); err != nil {
		return err
	}
	if page.NextAfter != nil {
		_, err := fmt.Fprintf(errw, "More components: pass --after %d for the next page.\n", *page.NextAfter)
		return err
	}
	return nil
}

func orAny(source string) string {
	if source == "" {
		return "any source"
	}
	return source
}

// --- vulns list / exposure ---------------------------------------------------

var vulnsCmd = &cobra.Command{
	Use:     "vulns",
	Aliases: []string{"vulnerabilities"},
	Short:   "List vulnerabilities across the cluster and where one CVE runs",
	Long: `Read-only views over the vulnerabilities found in the images your
workloads run. Findings come from Trivy Operator reports and, when the
opt-in supplychain matcher is enabled, from kguardian's own Grype matcher,
which matches SBOMs.

  list       every vulnerability affecting an inventory image, grouped by id
  exposure   one id: affected images, the workloads running them, and their
             observed network exposure

Only images with vulnerability data are counted; images without any are
unknown and absent. IN USE and TIER come from observed exec and
shared-library capture and observed ingress (see 'images vulns --help'); an
unknown in-use state is treated as potentially reachable and ranked as in
use. kguardian reports; it never blocks or applies anything.`,
}

var (
	vulnsListSeverity string
	vulnsListFixable  bool
	vulnsListRunning  bool
	vulnsListLimit    int
	vulnsListAfter    string
	vulnsListOutput   string
	vulnsListRisk     riskFilters
	vulnsExposureWin  int
	vulnsExposureOut  string
)

var vulnsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List vulnerabilities affecting inventory images",
	Long: `List every vulnerability affecting an image in the inventory, grouped by id,
most severe first, with its risk tier (the most urgent over every affected
workload container), the strongest in-use state, and how many images,
workloads (running) and namespaces it affects. It reads a summary the broker rebuilds every few minutes; the
freshness is printed on stderr.

KEV "unknown" means no source said either way. JOIN "workload_tag" means some
matches are by tag only (the tag may have moved since the scan).

Examples:
  kubectl kguardian vulns list
  kubectl kguardian vulns list -n payments --severity critical,high --running
  kubectl kguardian vulns list --tier p0`,
	Args: cobra.NoArgs,
	RunE: runVulnsList,
}

var vulnsExposureCmd = &cobra.Command{
	Use:   "exposure <id>",
	Short: "Show where a vulnerability runs and how exposed it is",
	Long: `Show which inventory images a vulnerability affects, the workloads running
(or having run) them, and each workload's observed ingress over the window.

EXPOSED is observed traffic, not reachability analysis:
  yes      ingress seen from another namespace, an unattributed or public IP,
           or a node IP (VIA names which; node also covers kubelet probes and
           NodePort/LoadBalancer traffic)
  no       ingress was observed in the window and none of it came from
           outside; not proof that none is possible
  unknown  no ingress observed in the window, even if the workload had
           egress (inbound UDP is not captured): never "not exposed"

FIXED lists every fixed version the sources give, in source order; none is
picked because text order is not version order.

IN USE is per workload container, from observed exec and shared-library
capture: unknown is potentially reachable, and not-observed only means not
seen in the window. Never read a finding as unreachable because of it.

Examples:
  kubectl kguardian vulns exposure CVE-2024-3094
  kubectl kguardian vulns exposure CVE-2024-3094 --window-hours 24 -o json`,
	Args: cobra.ExactArgs(1),
	RunE: runVulnsExposure,
}

func init() {
	imagesCmd.AddCommand(imagesVulnsCmd, imagesSbomCmd)
	imagesVulnsCmd.Flags().StringVar(&imageVulnsSeverity, "severity", "", "Only these severities, comma-separated (critical,high,medium,low,none,unknown)")
	imagesVulnsCmd.Flags().BoolVar(&imageVulnsFixable, "fixable", false, "Only findings with a fix (--fixable=false: only without)")
	imagesVulnsCmd.Flags().StringVar(&imageVulnsSource, "source", "", "Only this source's report: trivy-operator, grype or registry")
	imagesVulnsCmd.Flags().IntVar(&imageVulnsLimit, "limit", 100, "Page size (the broker caps it at 500)")
	imagesVulnsCmd.Flags().StringVar(&imageVulnsAfter, "after", "", "Cursor printed by the previous page")
	imagesVulnsCmd.Flags().StringVar(&imageVulnsFailOn, "fail-on", "", "CI gate (critical, high, medium, low, or a tier: p0, p1, p2): exit 1 on any finding at or above it, 2 if the check could not run, 3 if the image has no vulnerability data")
	imageVulnsRisk.register(imagesVulnsCmd, "findings")
	imagesVulnsCmd.Flags().StringVarP(&imageVulnsOutput, "output", "o", "table", "Output format: table, json or yaml")

	imagesSbomCmd.Flags().StringVar(&imageSbomSource, "source", "", "Which SBOM: trivy-operator, grype or registry (default: the broker's choice)")
	imagesSbomCmd.Flags().IntVar(&imageSbomLimit, "limit", 100, "Components per page (the broker caps it at 500)")
	imagesSbomCmd.Flags().Int64Var(&imageSbomAfter, "after", 0, "Cursor printed by the previous page")
	imagesSbomCmd.Flags().StringVarP(&imageSbomOutput, "output", "o", "table", "Output format: table, json, yaml or cyclonedx")

	rootCmd.AddCommand(vulnsCmd)
	vulnsCmd.AddCommand(vulnsListCmd, vulnsExposureCmd)
	vulnsListCmd.Flags().StringVar(&vulnsListSeverity, "severity", "", "Only these severities, comma-separated")
	vulnsListCmd.Flags().BoolVar(&vulnsListFixable, "fixable", false, "Only vulnerabilities with a fix (--fixable=false: only without)")
	vulnsListCmd.Flags().BoolVar(&vulnsListRunning, "running", false, "Only vulnerabilities with at least one running workload")
	vulnsListRisk.register(vulnsListCmd, "vulnerabilities")
	vulnsListCmd.Flags().IntVar(&vulnsListLimit, "limit", 100, "Page size (the broker caps it at 500)")
	vulnsListCmd.Flags().StringVar(&vulnsListAfter, "after", "", "Cursor printed by the previous page")
	vulnsListCmd.Flags().StringVarP(&vulnsListOutput, "output", "o", "table", "Output format: table, json or yaml")
	vulnsExposureCmd.Flags().IntVar(&vulnsExposureWin, "window-hours", 0, "How far back traffic counts, in hours (default 168, max 720)")
	vulnsExposureCmd.Flags().StringVarP(&vulnsExposureOut, "output", "o", "table", "Output format: table, json or yaml")
}

func runVulnsList(cmd *cobra.Command, _ []string) error {
	output, err := parseOutput(vulnsListOutput, "table", "json", "yaml")
	if err != nil {
		return err
	}
	sev, err := parseSeverityList(vulnsListSeverity)
	if err != nil {
		return err
	}
	kev, epss, inUse, tier, err := vulnsListRisk.resolve(cmd)
	if err != nil {
		return err
	}
	closeFn, err := connectBroker(cmd)
	if err != nil {
		return err
	}
	defer closeFn()
	opts := api.VulnsListOptions{Namespace: explicitNamespace(cmd), Severity: sev, Fixable: optBool(cmd, "fixable", vulnsListFixable),
		Kev: kev, EpssMin: epss, InUse: inUse, Tier: tier, Running: vulnsListRunning, Limit: vulnsListLimit, After: vulnsListAfter}
	return fetchAndRenderVulns(opts, output, os.Stdout, os.Stderr)
}

func fetchAndRenderVulns(opts api.VulnsListOptions, output string, w, errw io.Writer) error {
	page, raw, err := api.GetVulns(opts)
	if err != nil {
		return brokerReadErr("fetching vulnerabilities", err)
	}
	if output != "table" {
		return writeRaw(w, raw, output)
	}
	if page.ComputedAt == nil {
		if _, err := fmt.Fprintln(errw, "The vulnerability summary has not been built yet since the broker started; an empty list is unknown, not clean."); err != nil {
			return err
		}
	} else if page.StaleSeconds != nil {
		if _, err := fmt.Fprintf(errw, "Summary computed at %s (%ds ago).\n", *page.ComputedAt, *page.StaleSeconds); err != nil {
			return err
		}
	}
	var out bytes.Buffer
	if len(page.Items) == 0 {
		out.WriteString("No vulnerabilities match among images with vulnerability data. Images no source has scanned are unknown and not listed.\n")
	} else {
		tw := tabwriter.NewWriter(&out, 0, 8, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "TIER\tSEVERITY\tID\tSCORE\tFIXABLE\tKEV\tIN USE\tIMAGES\tWORKLOADS\tRUNNING\tEXPOSED\tNAMESPACES\tJOIN\tPACKAGES")
		for _, v := range page.Items {
			fix := "no"
			if v.Fixable {
				fix = "yes"
			}
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%s\t%s\n", orDashStr(v.Tier), v.Severity, cell(v.ID), fmtFloat(v.MaxScore),
				fix, fmtKev(v.Kev), fmtInUse(v.InUseState), v.Images, v.Workloads, v.RunningWorkloads, v.ExposedWorkloads, v.Namespaces, v.WeakestJoin,
				cell(strings.Join(v.Packages, ",")))
		}
		_ = tw.Flush()
		out.WriteString(inUseLegend)
	}
	if _, err := w.Write(out.Bytes()); err != nil {
		return err
	}
	if page.NextAfter != nil && *page.NextAfter != "" {
		_, err := fmt.Fprintf(errw, "More vulnerabilities: pass --after %s for the next page.\n", *page.NextAfter)
		return err
	}
	return nil
}

func runVulnsExposure(cmd *cobra.Command, args []string) error {
	output, err := parseOutput(vulnsExposureOut, "table", "json", "yaml")
	if err != nil {
		return err
	}
	id := strings.TrimSpace(args[0])
	if id == "" || strings.ContainsAny(id, "/?#") || len(id) > 128 {
		return fmt.Errorf("invalid vulnerability id %q", args[0])
	}
	if strings.HasPrefix(strings.ToLower(id), "cve-") {
		id = strings.ToUpper(id)
	}
	if vulnsExposureWin < 0 || vulnsExposureWin > 720 {
		return fmt.Errorf("--window-hours must be between 1 and 720")
	}
	closeFn, err := connectBroker(cmd)
	if err != nil {
		return err
	}
	defer closeFn()
	return fetchAndRenderExposure(id, vulnsExposureWin, output, os.Stdout)
}

// fmtExposed renders network.exposed: null is unknown, never "no".
func fmtExposed(v *bool) string {
	switch {
	case v == nil:
		return "unknown"
	case *v:
		return "yes"
	default:
		return "no"
	}
}

func fetchAndRenderExposure(id string, window int, output string, w io.Writer) error {
	e, raw, err := api.GetExposure(id, window)
	if errors.Is(err, api.ErrNotFound) {
		return fmt.Errorf("no inventory image with vulnerability data lists %s; that is not proof the cluster is unaffected (images no source has scanned are unknown)", id)
	}
	if err != nil {
		return brokerReadErr(fmt.Sprintf("fetching exposure for %s", id), err)
	}
	if output != "table" {
		return writeRaw(w, raw, output)
	}
	var out bytes.Buffer
	fix := "no fix available"
	if e.Fixable {
		fix = "fixable"
	}
	fmt.Fprintf(&out, "%s  %s, %s\n\nImages:\n", e.ID, e.Severity, fix)
	tw := tabwriter.NewWriter(&out, 0, 8, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "  DIGEST\tREPOSITORY\tTAGS\tPACKAGE\tINSTALLED\tFIXED\tJOIN")
	for _, im := range e.Images {
		tags := strings.Join(im.Tags, ",")
		if tags == "" {
			tags = "-"
		}
		if len(im.Packages) == 0 {
			_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\t-\t-\t-\t%s\n", shortDigest(im.Digest), cell(orDash(im.Repository)), cell(tags), im.Join)
		}
		for _, p := range im.Packages {
			_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\n", shortDigest(im.Digest), cell(orDash(im.Repository)), cell(tags),
				cell(p.Name), cell(p.InstalledVersion), cell(fmtFixed(p.FixedVersions)), im.Join)
		}
	}
	_ = tw.Flush()
	out.WriteString("\nWorkloads:\n")
	if len(e.Workloads) == 0 {
		out.WriteString("  none recorded\n")
	} else {
		tw = tabwriter.NewWriter(&out, 0, 8, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "  NAMESPACE\tWORKLOAD\tCONTAINER\tRUNNING\tIN USE\tEXPOSED\tVIA\tINGRESS FLOWS")
		for _, wl := range e.Workloads {
			via := "-"
			if len(wl.Network.ExposedVia) > 0 {
				via = strings.Join(wl.Network.ExposedVia, ",")
			}
			_, _ = fmt.Fprintf(tw, "  %s\t%s/%s\t%s\t%t\t%s\t%s\t%s\t%d\n", wl.Namespace, wl.Kind, wl.Name, wl.Container, wl.Running,
				fmtInUse(wl.InUseState), fmtExposed(wl.Network.Exposed), via, wl.Network.IngressFlowsObserved)
		}
		_ = tw.Flush()
		if len(e.Workloads) > 0 {
			fmt.Fprintf(&out, "\nExposure window: %dh of observed traffic. unknown = no ingress observed (egress alone does not count; inbound UDP is not captured), never \"not exposed\".\n", e.Workloads[0].Network.WindowHours)
		}
	}
	fmt.Fprintf(&out, "In use: %s. IN USE is from observed exec and shared-library capture: unknown is potentially reachable, not-observed only means not seen in the window; never treat the package as unreachable.\n", fmtInUse(e.InUseState))
	if e.Truncated {
		out.WriteString("More images or workloads are affected than the broker lists (200 each).\n")
	}
	_, err = w.Write(out.Bytes())
	return err
}
