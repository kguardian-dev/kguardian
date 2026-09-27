package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
	"github.com/spf13/cobra"
)

// Signature and ImageTrustPolicy views (#1533 P2) over the broker reads
// GET /images/{digest}/attestation and GET /image-trust. Report-only:
// kguardian never admits or blocks an image. --fail-on uses the same exit
// codes as `images vulns`: 1 = fails the gate, 2 = could not check,
// 3 = unknown (never a pass).

// termSafe replaces control and invisible formatting characters (bidi
// overrides, zero-width marks) in cluster-supplied text before it reaches
// a terminal. The broker refuses them at ingest; this is the second fence.
func termSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			return '?'
		}
		return r
	}, s)
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return termSafe(s)
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// --- images signers ---------------------------------------------------------

// signerFailLevels: the verdicts each --fail-on level fails (exit 1).
// key_signed is never a pass: under invalid and unsigned it could not be
// verified (exit 3, like unknown); under unverified it fails (exit 1).
//
//	            invalid  unsigned  unverified
//	verified       0        0          0
//	key_signed     3        3          1
//	unsigned       0        1          1
//	invalid        1        1          1
//	unknown        3        3          3   (also: no result)
var signerFailLevels = map[string][]string{
	"invalid":    {"invalid"},
	"unsigned":   {"invalid", "unsigned"},
	"unverified": {"invalid", "unsigned", "key_signed"},
}

var verdictMeaning = map[string]string{
	"verified":   "a signature verified for the signer(s) below; valid, not trusted: see 'images trust'",
	"key_signed": "signed with a key kguardian was not given; the signature was NOT checked",
	"unsigned":   "no signature found, and every lookup answered",
	"invalid":    "signatures exist and none verified",
	"unknown":    "could not be checked; not the same as unsigned",
}

var (
	imageSignersFailOn string
	imageSignersOutput string
)

var imagesSignersCmd = &cobra.Command{
	Use:   "signers <digest>",
	Short: "Show who signed an image digest",
	Long: `Show the signature discovery result for one image digest: the verdict, the
verified signers (a keyless issuer and certificate identity, or a configured
public key) and every signature and attestation found. Results come from the
supplychain component's signature discovery (supplychain.signatureDiscovery).

VERDICT
  verified    a signature verified for the listed signer. Valid, not trusted:
              anyone with a Fulcio identity or a key can sign, and anyone who
              can push to the repository can attach a signature. Use
              'images trust' for what an ImageTrustPolicy accepts.
  key_signed  signed with a public key kguardian was not given: NOT checked
  unsigned    no signature, and every lookup answered
  invalid     signatures exist and none verified
  unknown     could not be checked (REASON says why); not unsigned

An unverified signature shows its error and never a signer: a claimed
identity is not a fact.

CI gate: --fail-on invalid|unsigned|unverified exits

                invalid  unsigned  unverified
  verified         0        0          0
  key_signed       3        3          1
  unsigned         0        1          1
  invalid          1        1          1
  unknown          3        3          3   (also: no result for the digest)

  0  passes; 1  fails the level
  2  the check could not run: broker unreachable, port-forward or token
     failure, a broker error or an invalid flag
  3  could not be verified: no result (never checked), verdict unknown or
     one this CLI does not know, or key_signed (a key kguardian was not
     given) below --fail-on unverified. Never a pass.
Each result is printed as a "gate:" line on stderr. A pass says nothing
about who signed: combine it with 'images trust --fail-on would-deny'.

Examples:
  kubectl kguardian images signers sha256:0123...
  kubectl kguardian images signers sha256:0123... -o json
  kubectl kguardian images signers sha256:0123... --fail-on unsigned`,
	Args: cobra.ExactArgs(1),
	RunE: runImagesSigners,
}

func runImagesSigners(cmd *cobra.Command, args []string) error {
	err := imagesSigners(cmd, args)
	if strings.TrimSpace(imageSignersFailOn) != "" {
		err = asGateResult(err)
	}
	var ge *gateError
	if errors.As(err, &ge) {
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
	}
	return err
}

func parseSignerFailOn(raw string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return "", nil
	}
	if _, ok := signerFailLevels[v]; !ok {
		return "", fmt.Errorf("invalid --fail-on %q: must be invalid, unsigned or unverified", raw)
	}
	return v, nil
}

func imagesSigners(cmd *cobra.Command, args []string) error {
	output, err := parseOutput(imageSignersOutput, "table", "json", "yaml")
	if err != nil {
		return err
	}
	digest, err := parseDigestArg(args[0])
	if err != nil {
		return err
	}
	level, err := parseSignerFailOn(imageSignersFailOn)
	if err != nil {
		return err
	}
	closeFn, err := connectBroker(cmd)
	if err != nil {
		return err
	}
	defer closeFn()
	return fetchAndRenderSigners(digest, level, output, os.Stdout, os.Stderr)
}

func fetchAndRenderSigners(digest, level, output string, w, errw io.Writer) error {
	res, raw, err := api.GetSignatureResult(digest)
	if errors.Is(err, api.ErrNotFound) {
		if output == "table" {
			_, _ = fmt.Fprintf(w, "No signature result for %s: it has not been checked (signature discovery off, the image is not running, or it has not been reached yet). This is unknown, not unsigned.\n", digest)
		} else if werr := writeRaw(w, []byte(`{"digest":"`+digest+`","verdict":null}`), output); werr != nil {
			return werr
		}
		if level == "" {
			return nil
		}
		return &gateError{code: exitGateUnknown, msg: fmt.Sprintf("gate: no signature result for %s; unknown is not a pass (exit %d)", digest, exitGateUnknown)}
	}
	if err != nil {
		return brokerReadErr(fmt.Sprintf("fetching the signature result for %s", digest), err)
	}
	if output != "table" {
		if err := writeRaw(w, raw, output); err != nil {
			return err
		}
	} else if err := renderSignersTable(w, res); err != nil {
		return err
	}
	if level == "" {
		return nil
	}
	return signerGate(res, level, errw)
}

// namesSigner: a signer identity names someone (a keyless issuer and SAN,
// or a key fingerprint). With no kind, either form counts.
func namesSigner(s api.SignerIdentity) bool {
	set := func(v string) bool { return strings.TrimSpace(v) != "" }
	keyless := set(s.Issuer) && set(s.SAN)
	switch s.SignerKind {
	case "key":
		return set(s.KeyFingerprint)
	case "":
		return keyless || set(s.KeyFingerprint)
	default:
		return keyless
	}
}

// anonymousVerified: the result says verified but no verified signature
// names its signer (an older broker stored it before the ingest rule).
// It is treated as unknown, never as signed.
func anonymousVerified(r *api.SignatureResult) bool {
	if r.Verdict != "verified" {
		return false
	}
	for _, s := range r.Signatures {
		if s.Verified && namesSigner(s.SignerIdentity) {
			return false
		}
	}
	return true
}

func signerGate(res *api.SignatureResult, level string, errw io.Writer) error {
	v := res.Verdict
	if anonymousVerified(res) {
		return &gateError{code: exitGateUnknown, msg: fmt.Sprintf("gate: %s is verified but no signature names its signer (no_signer_identity); unknown is not a pass (exit %d)", res.Digest, exitGateUnknown)}
	}
	if _, known := verdictMeaning[v]; !known || v == "unknown" {
		why := derefStr(res.Reason)
		if why == "" {
			why = "no reason given"
		}
		return &gateError{code: exitGateUnknown, msg: fmt.Sprintf("gate: %s could not be checked (verdict %s, %s); unknown is not a pass (exit %d)", res.Digest, termSafe(v), termSafe(why), exitGateUnknown)}
	}
	for _, bad := range signerFailLevels[level] {
		if v == bad {
			return &gateError{code: exitGateFindings, msg: fmt.Sprintf("gate: %s is %s, which fails --fail-on %s (exit %d)", res.Digest, v, level, exitGateFindings)}
		}
	}
	if v == "key_signed" {
		return &gateError{code: exitGateUnknown, msg: fmt.Sprintf("gate: %s is signed with a key kguardian was not given, so the signature could not be verified; that is not a pass (exit %d)", res.Digest, exitGateUnknown)}
	}
	_, err := fmt.Fprintf(errw, "gate: %s is %s, which passes --fail-on %s (valid is not trusted: see 'images trust')\n", res.Digest, v, level)
	return err
}

func signerLabel(s api.SignerIdentity) string {
	if !namesSigner(s) {
		return "- (no signer identity)"
	}
	if s.SignerKind == "key" {
		name := dashIfEmpty(s.KeyName)
		if s.KeyFingerprint != "" {
			fp := s.KeyFingerprint
			if len(fp) > 16 {
				fp = fp[:16] + "…"
			}
			name += " (sha256 " + termSafe(fp) + ")"
		}
		return name
	}
	return dashIfEmpty(s.SAN) + " via " + dashIfEmpty(s.Issuer)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func renderSignersTable(w io.Writer, r *api.SignatureResult) error {
	var out bytes.Buffer
	tw := tabwriter.NewWriter(&out, 0, 8, 2, ' ', 0)
	meaning := verdictMeaning[r.Verdict]
	if meaning == "" {
		meaning = "not a verdict this CLI knows: treat as unknown"
	}
	if anonymousVerified(r) {
		meaning = "but no signature names its signer (no_signer_identity): treat as unknown, not signed"
	}
	_, _ = fmt.Fprintf(tw, "DIGEST\t%s\n", termSafe(r.Digest))
	_, _ = fmt.Fprintf(tw, "REPOSITORY\t%s\n", dashIfEmpty(r.Repository))
	_, _ = fmt.Fprintf(tw, "VERDICT\t%s (%s)\n", termSafe(r.Verdict), meaning)
	_, _ = fmt.Fprintf(tw, "REASON\t%s\n", dashIfEmpty(derefStr(r.Reason)))
	_, _ = fmt.Fprintf(tw, "TRUST ROOT\t%s\n", dashIfEmpty(derefStr(r.TrustRoot)))
	via := dashIfEmpty(derefStr(r.SignedVia))
	if derefStr(r.SignedVia) == "index" && r.SignedDigest != nil {
		via += " (" + termSafe(*r.SignedDigest) + ")"
	}
	_, _ = fmt.Fprintf(tw, "SIGNED VIA\t%s\n", via)
	_, _ = fmt.Fprintf(tw, "CHECKED\t%s\n", dashIfEmpty(r.CheckedAt))
	if err := tw.Flush(); err != nil {
		return err
	}

	if len(r.Signatures) > 0 {
		out.WriteString("\nSIGNATURES\n")
		tw = tabwriter.NewWriter(&out, 0, 8, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "VERIFIED\tKIND\tSIGNER\tFORMAT\tSOURCE\tERROR")
		for _, pass := range []bool{true, false} {
			for _, s := range r.Signatures {
				if s.Verified != pass {
					continue
				}
				signer, kind := "-", "-"
				if s.Verified {
					signer, kind = signerLabel(s.SignerIdentity), dashIfEmpty(s.SignerKind)
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", yesNo(s.Verified), kind, signer,
					dashIfEmpty(s.Format), dashIfEmpty(s.Source), dashIfEmpty(s.Error))
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if len(r.Attestations) > 0 {
		out.WriteString("\nATTESTATIONS\n")
		tw = tabwriter.NewWriter(&out, 0, 8, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "VERIFIED\tPREDICATE\tSIGNER\tPROVENANCE\tERROR")
		for _, pass := range []bool{true, false} {
			for _, a := range r.Attestations {
				if a.Verified != pass {
					continue
				}
				signer, prov := "-", "-"
				if a.Verified {
					signer = signerLabel(a.SignerIdentity)
					if p := a.Provenance; p != nil && p.SourceRepo != "" {
						prov = termSafe(p.SourceRepo)
						if p.SourceCommit != "" {
							c := p.SourceCommit
							if len(c) > 12 {
								c = c[:12]
							}
							prov += "@" + termSafe(c)
						}
					} else if p != nil && p.BuilderID != "" {
						prov = "builder " + termSafe(p.BuilderID)
					}
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", yesNo(a.Verified), dashIfEmpty(a.PredicateType), signer, prov, dashIfEmpty(a.Error))
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if len(r.Signatures) == 0 && len(r.Attestations) == 0 {
		out.WriteString("\nNo signatures or attestations were found.\n")
	}
	_, err := w.Write(out.Bytes())
	return err
}

// --- images trust -------------------------------------------------------------

var (
	imageTrustKind    string
	imageTrustName    string
	imageTrustVerdict string
	imageTrustLimit   int
	imageTrustFailOn  string
	imageTrustOutput  string
)

var imagesTrustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Show which ImageTrustPolicies would deny which workloads",
	Long: `Show the evaluator's ImageTrustPolicy and ClusterImageTrustPolicy results:
for every policy and running workload container it selects, Trusted,
WouldDeny or Unknown, with the reason. WouldDeny first. Report-only: WouldDeny
means an admission controller enforcing the policy would reject the image;
kguardian never blocks anything.

REASON
  unsigned             the image has no signature
  invalid              its signatures did not verify
  untrusted-signer     signed, but not by an identity or key the policy trusts
  key-not-verified     key-signed with a key kguardian was not given, and the
                       policy trusts a key: give supplychain the key
  attestation-missing  a required attestation is missing or not signed by a
                       trusted signer
  not-checked          no signature result yet (Unknown)
  namespace-unknown    the namespace's labels could not be read (Unknown)
  broker-unavailable, broker-unauthorized
                       the evaluator could not read signature results (Unknown)
Unknown can also carry a discovery reason (registry_auth, timeout, ...).

The counts cover every matching result; the list is cut at --limit.

CI gate: --fail-on would-deny exits
  0  every selected container is Trusted
  1  at least one WouldDeny
  2  the check could not run: broker unreachable, port-forward or token
     failure, an invalid flag, or the broker has no image trust results
     (no evaluator, image trust off, or the evaluator refused the token)
  3  unknown: at least one Unknown result and no WouldDeny, no pass has
     finished yet, or no policy selects the workloads. Unknown is never a
     pass.
Each result is printed as a "gate:" line on stderr.

Examples:
  kubectl kguardian images trust
  kubectl kguardian images trust -n payments --verdict WouldDeny
  kubectl kguardian images trust -n payments --kind Deployment --name checkout
  kubectl kguardian images trust -n payments --fail-on would-deny`,
	Args: cobra.NoArgs,
	RunE: runImagesTrust,
}

var trustVerdicts = []string{"Trusted", "WouldDeny", "Unknown"}

func parseTrustVerdictFlag(raw string) (string, error) {
	v := strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "").Replace(strings.TrimSpace(raw)))
	if v == "" {
		return "", nil
	}
	for _, t := range trustVerdicts {
		if strings.ToLower(t) == v {
			return t, nil
		}
	}
	return "", fmt.Errorf("invalid --verdict %q: must be Trusted, WouldDeny or Unknown", raw)
}

func runImagesTrust(cmd *cobra.Command, _ []string) error {
	err := imagesTrust(cmd)
	if strings.TrimSpace(imageTrustFailOn) != "" {
		err = asGateResult(err)
	}
	var ge *gateError
	if errors.As(err, &ge) {
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
	}
	return err
}

func imagesTrust(cmd *cobra.Command) error {
	output, err := parseOutput(imageTrustOutput, "table", "json", "yaml")
	if err != nil {
		return err
	}
	verdict, err := parseTrustVerdictFlag(imageTrustVerdict)
	if err != nil {
		return err
	}
	gate := strings.ToLower(strings.TrimSpace(imageTrustFailOn))
	if gate != "" && gate != "would-deny" {
		return fmt.Errorf("invalid --fail-on %q: must be would-deny", imageTrustFailOn)
	}
	if gate != "" && verdict != "" {
		return fmt.Errorf("--fail-on cannot be combined with --verdict: the gate needs every result")
	}
	closeFn, err := connectBroker(cmd)
	if err != nil {
		return err
	}
	defer closeFn()
	opts := api.ImageTrustOptions{
		Namespace: explicitNamespace(cmd), WorkloadKind: strings.TrimSpace(imageTrustKind),
		WorkloadName: strings.TrimSpace(imageTrustName), Verdict: verdict, Limit: imageTrustLimit,
	}
	return fetchAndRenderTrust(opts, gate != "", output, os.Stdout, os.Stderr)
}

func fetchAndRenderTrust(opts api.ImageTrustOptions, gate bool, output string, w, errw io.Writer) error {
	a, raw, err := api.GetImageTrust(opts)
	if err != nil {
		return brokerReadErr("fetching image trust results", err)
	}
	if output != "table" {
		if err := writeRaw(w, raw, output); err != nil {
			return err
		}
	} else if err := renderTrustTable(w, errw, a); err != nil {
		return err
	}
	if !gate {
		return nil
	}
	return trustGate(a, errw)
}

func trustGate(a *api.ImageTrustAnswer, errw io.Writer) error {
	switch {
	case !a.Available:
		return &gateError{code: exitGateNoCheck, msg: fmt.Sprintf("gate: could not check (exit %d): %s", exitGateNoCheck, termSafe(a.Reason))}
	case a.EvaluatedAt == nil:
		return &gateError{code: exitGateUnknown, msg: fmt.Sprintf("gate: the evaluator has not finished a pass yet; unknown is not a pass (exit %d)", exitGateUnknown)}
	case a.WouldDeny > 0:
		return &gateError{code: exitGateFindings, msg: fmt.Sprintf("gate: %d container result(s) would be denied (exit %d)", a.WouldDeny, exitGateFindings)}
	case a.Unknown > 0:
		return &gateError{code: exitGateUnknown, msg: fmt.Sprintf("gate: %d container result(s) are Unknown; unknown is not a pass (exit %d)", a.Unknown, exitGateUnknown)}
	case a.Total == 0:
		return &gateError{code: exitGateUnknown, msg: fmt.Sprintf("gate: no ImageTrustPolicy selects these workloads; nothing was checked (exit %d)", exitGateUnknown)}
	case a.Trusted != a.Total:
		// A verdict this CLI or the broker does not know (a newer
		// evaluator) is in total and in no count: unknown, never a pass.
		return &gateError{code: exitGateUnknown, msg: fmt.Sprintf("gate: %d of %d container result(s) are not Trusted and not a verdict this CLI knows; unknown is not a pass (exit %d)", a.Total-a.Trusted, a.Total, exitGateUnknown)}
	}
	_, err := fmt.Fprintf(errw, "gate: all %d container result(s) are Trusted\n", a.Trusted)
	return err
}

func renderTrustTable(w, errw io.Writer, a *api.ImageTrustAnswer) error {
	var out bytes.Buffer
	if !a.Available {
		fmt.Fprintf(&out, "Image trust results are not available: %s\nWhether anything would be denied is unknown.\n", termSafe(a.Reason))
		_, err := w.Write(out.Bytes())
		return err
	}
	if a.EvaluatedAt == nil {
		out.WriteString("The evaluator has not finished a pass yet: results are unknown.\n")
		_, err := w.Write(out.Bytes())
		return err
	}
	if a.Total == 0 {
		out.WriteString("No ImageTrustPolicy selects the matching workloads.\n")
	} else {
		tw := tabwriter.NewWriter(&out, 0, 8, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "VERDICT\tREASON\tNAMESPACE\tWORKLOAD\tCONTAINER\tPOLICY\tIMAGE")
		for _, r := range a.Results {
			img := r.Image
			if img == "" {
				img = r.Digest
			}
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", termSafe(r.Verdict), dashIfEmpty(r.Reason),
				termSafe(r.Namespace), termSafe(r.Workload), termSafe(r.Container), termSafe(r.Policy), termSafe(img))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if _, err := w.Write(out.Bytes()); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(errw, "Evaluated %s: %d would deny, %d unknown, %d trusted (%d results, %d policies).\n",
		termSafe(*a.EvaluatedAt), a.WouldDeny, a.Unknown, a.Trusted, a.Total, len(a.Policies))
	if a.Truncated {
		_, _ = fmt.Fprintf(errw, "Showing %d of %d results; raise --limit or narrow with -n, --kind/--name or --verdict.\n", len(a.Results), a.Total)
	}
	return nil
}

func init() {
	imagesCmd.AddCommand(imagesSignersCmd, imagesTrustCmd)
	imagesSignersCmd.Flags().StringVar(&imageSignersFailOn, "fail-on", "", "CI gate (invalid, unsigned or unverified): exit 1 if the verdict fails it, 2 if the check could not run, 3 if it could not be verified (unknown, no result, or key_signed below unverified)")
	imagesSignersCmd.Flags().StringVarP(&imageSignersOutput, "output", "o", "table", "Output format: table, json or yaml")

	imagesTrustCmd.Flags().StringVar(&imageTrustKind, "kind", "", "Only this workload kind, e.g. Deployment")
	imagesTrustCmd.Flags().StringVar(&imageTrustName, "name", "", "Only this workload name")
	imagesTrustCmd.Flags().StringVar(&imageTrustVerdict, "verdict", "", "Only this verdict: Trusted, WouldDeny or Unknown")
	imagesTrustCmd.Flags().IntVar(&imageTrustLimit, "limit", 200, "Results to show (the broker caps it at 2000); counts always cover every result")
	imagesTrustCmd.Flags().StringVar(&imageTrustFailOn, "fail-on", "", "CI gate (would-deny): exit 1 on any WouldDeny, 2 if the check could not run, 3 if anything is unknown")
	imagesTrustCmd.Flags().StringVarP(&imageTrustOutput, "output", "o", "table", "Output format: table, json or yaml")
}
