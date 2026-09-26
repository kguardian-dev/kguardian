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

// Vulnerability and SBOM views over the broker's supply-chain reads. The
// data comes from scanners the supplychain component reads (Trivy
// Operator, Grype, registry SBOMs); kguardian reports it and never scans,
// blocks or applies anything. `images vulns --fail-on` is the one place a
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

func parseDigestArg(raw string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(raw))
	if !strings.HasPrefix(d, "sha256:") && !strings.HasPrefix(d, "sha512:") {
		return "", fmt.Errorf("digest must look like sha256:<hex>, got %q (find it with 'kguardian images list')", raw)
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
)

var imagesVulnsCmd = &cobra.Command{
	Use:   "vulns <digest>",
	Short: "List the vulnerabilities scanners found in an image",
	Long: `List the vulnerability findings for one image digest, deduplicated across
sources (Trivy Operator, Grype), most severe first.

"No vulnerability data" means no source has reported on the image. That is
unknown, not clean. KEV "unknown" means no source said either way (Trivy never
does). kguardian cannot yet tell which packages a workload loads, so treat
every finding as potentially reachable.

CI gate: --fail-on <severity> exits
  0  no finding at or above the severity
  1  at least one finding at or above it (findings of UNKNOWN severity count)
  3  no vulnerability data for the image: unknown is never a pass
Other errors (broker unreachable, bad token) exit 1 with an error message.

Examples:
  kubectl kguardian images vulns sha256:0123...
  kubectl kguardian images vulns sha256:0123... --severity critical,high --fixable
  kubectl kguardian images vulns sha256:0123... --fail-on high -o json`,
	Args: cobra.ExactArgs(1),
	RunE: runImagesVulns,
}

func runImagesVulns(cmd *cobra.Command, args []string) error {
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
		if gate, err = failOnSeverities(imageVulnsFailOn); err != nil {
			return err
		}
	}
	src, err := parseSourceFlag(imageVulnsSource)
	if err != nil {
		return err
	}
	closeFn, err := connectBroker(cmd)
	if err != nil {
		return err
	}
	defer closeFn()
	opts := api.ImageVulnsOptions{Severity: sev, Fixable: optBool(cmd, "fixable", imageVulnsFixable), Source: src, Limit: imageVulnsLimit, After: imageVulnsAfter}
	err = fetchAndRenderImageVulns(digest, opts, gate, strings.ToUpper(imageVulnsFailOn), output, os.Stdout, os.Stderr)
	var ge *gateError
	if errors.As(err, &ge) {
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
	}
	return err
}

// fetchAndRenderImageVulns renders the page asked for, then, with a gate,
// runs its own query (threshold severities, limit 1) so the gate sees
// every page, not just the one shown.
func fetchAndRenderImageVulns(digest string, opts api.ImageVulnsOptions, gate, threshold, output string, w, errw io.Writer) error {
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
	g, _, err := api.GetImageVulns(digest, api.ImageVulnsOptions{Severity: gate, Source: opts.Source, Limit: 1})
	if err != nil {
		return brokerReadErr("evaluating --fail-on", err)
	}
	if len(g.Items) > 0 {
		f := g.Items[0]
		return &gateError{code: exitGateFindings, msg: fmt.Sprintf("gate: %s has findings at or above %s (e.g. %s %s in %s) (exit %d)", digest, threshold, f.Severity, f.ID, f.Package.Name, exitGateFindings)}
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
		_, _ = fmt.Fprintln(tw, "SEVERITY\tID\tPACKAGE\tINSTALLED\tFIXED\tSCORE\tKEV\tSOURCES")
		for _, f := range p.Items {
			fixed := fmtFixed(f.FixedVersions)
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", f.Severity, cell(f.ID), cell(f.Package.Name), cell(f.InstalledVersion),
				cell(fixed), fmtFloat(f.Score), fmtKev(f.Kev), strings.Join(f.Sources, ","))
		}
		_ = tw.Flush()
		out.WriteString("\nIn use: unknown. kguardian cannot yet tell which packages load; treat every finding as potentially reachable.\n")
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
	Long: `Read-only views over the vulnerabilities scanners found in the images your
workloads run.

  list       every vulnerability affecting an inventory image, grouped by id
  exposure   one id: affected images, the workloads running them, and their
             observed network exposure

Only images a source has reported on are counted; images never scanned are
unknown and absent. kguardian cannot yet tell which packages a workload
loads ("in use" is unknown), so treat every finding as potentially
reachable. kguardian reports; it never blocks or applies anything.`,
}

var (
	vulnsListSeverity string
	vulnsListFixable  bool
	vulnsListRunning  bool
	vulnsListLimit    int
	vulnsListAfter    string
	vulnsListOutput   string
	vulnsExposureWin  int
	vulnsExposureOut  string
)

var vulnsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List vulnerabilities affecting inventory images",
	Long: `List every vulnerability affecting an image in the inventory, grouped by id,
most severe first, with how many images, workloads (running) and namespaces
it affects. It reads a summary the broker rebuilds every few minutes; the
freshness is printed on stderr.

KEV "unknown" means no source said either way. JOIN "workload_tag" means some
matches are by tag only (the tag may have moved since the scan).

Examples:
  kubectl kguardian vulns list
  kubectl kguardian vulns list -n payments --severity critical,high --running`,
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

IN USE is unknown for now: never read a finding as unreachable because of it.

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
	imagesVulnsCmd.Flags().StringVar(&imageVulnsFailOn, "fail-on", "", "CI gate: exit 1 on any finding at or above this severity (critical, high, medium, low); exit 3 when the image has no vulnerability data")
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
	closeFn, err := connectBroker(cmd)
	if err != nil {
		return err
	}
	defer closeFn()
	opts := api.VulnsListOptions{Namespace: explicitNamespace(cmd), Severity: sev, Fixable: optBool(cmd, "fixable", vulnsListFixable),
		Running: vulnsListRunning, Limit: vulnsListLimit, After: vulnsListAfter}
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
		_, _ = fmt.Fprintln(tw, "SEVERITY\tID\tSCORE\tFIXABLE\tKEV\tIMAGES\tWORKLOADS\tRUNNING\tNAMESPACES\tJOIN\tPACKAGES")
		for _, v := range page.Items {
			fix := "no"
			if v.Fixable {
				fix = "yes"
			}
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%s\t%s\n", v.Severity, cell(v.ID), fmtFloat(v.MaxScore), fix, fmtKev(v.Kev),
				v.Images, v.Workloads, v.RunningWorkloads, v.Namespaces, v.WeakestJoin, cell(strings.Join(v.Packages, ",")))
		}
		_ = tw.Flush()
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
		_, _ = fmt.Fprintln(tw, "  NAMESPACE\tWORKLOAD\tCONTAINER\tRUNNING\tEXPOSED\tVIA\tINGRESS FLOWS")
		for _, wl := range e.Workloads {
			via := "-"
			if len(wl.Network.ExposedVia) > 0 {
				via = strings.Join(wl.Network.ExposedVia, ",")
			}
			_, _ = fmt.Fprintf(tw, "  %s\t%s/%s\t%s\t%t\t%s\t%s\t%d\n", wl.Namespace, wl.Kind, wl.Name, wl.Container, wl.Running,
				fmtExposed(wl.Network.Exposed), via, wl.Network.IngressFlowsObserved)
		}
		_ = tw.Flush()
		if len(e.Workloads) > 0 {
			fmt.Fprintf(&out, "\nExposure window: %dh of observed traffic. unknown = no ingress observed (egress alone does not count; inbound UDP is not captured), never \"not exposed\".\n", e.Workloads[0].Network.WindowHours)
		}
	}
	out.WriteString("In use: unknown. kguardian cannot yet tell whether the vulnerable package is loaded; do not treat it as unreachable.\n")
	if e.Truncated {
		out.WriteString("More images or workloads are affected than the broker lists (200 each).\n")
	}
	_, err = w.Write(out.Bytes())
	return err
}
