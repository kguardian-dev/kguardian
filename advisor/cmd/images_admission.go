package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
	"github.com/spf13/cobra"
)

var (
	admissionFormat string
	admissionMode   string
	admissionAck    bool
	admissionFile   string
)

var imagesAdmissionCmd = &cobra.Command{
	Use:   "admission-policy",
	Short: "Generate an image signature admission policy from observed signers",
	Long: `Generate an image admission policy from the signers kguardian verified on the
images your workloads run (supplychain.signatureDiscovery must be on).

Formats:
  kyverno            Kyverno ImageValidatingPolicy (policies.kyverno.io/v1beta1)
  policy-controller  Sigstore policy-controller ClusterImagePolicy (policy.sigstore.dev/v1beta1)
  kguardian          kguardian ImageTrustPolicy, reported by the kguardian evaluator

The default mode is audit: Kyverno validationActions [Audit] (and no digest
mutation), policy-controller mode warn (it has no audit-only mode). Use
--mode enforce for Deny / enforce; it is refused while a running image is
not covered unless --acknowledge-partial.

A repository is covered only when every running digest of it verified.
Unsigned, invalid, unchecked and key-signed-with-an-unknown-key images are
listed in the header as not covered: kguardian never invents a signer.
kguardian applies nothing; review the output and apply it yourself.

Examples:
  kubectl kguardian images admission-policy > kyverno-images.yaml
  kubectl kguardian images admission-policy --format policy-controller -n payments
  kubectl kguardian images admission-policy --format kguardian -n payments -f itp.yaml`,
	Args: cobra.NoArgs,
	RunE: runImagesAdmission,
}

func init() {
	imagesCmd.AddCommand(imagesAdmissionCmd)
	imagesAdmissionCmd.Flags().StringVar(&admissionFormat, "format", "kyverno", "kyverno, policy-controller or kguardian")
	imagesAdmissionCmd.Flags().StringVar(&admissionMode, "mode", "audit", "audit or enforce")
	imagesAdmissionCmd.Flags().BoolVar(&admissionAck, "acknowledge-partial", false, "With --mode enforce: generate although some running images are not covered")
	imagesAdmissionCmd.Flags().StringVarP(&admissionFile, "file", "f", "", "Write to this file instead of stdout")
}

func admissionOptions(cmd *cobra.Command) (api.AdmissionPolicyOptions, error) {
	o := api.AdmissionPolicyOptions{
		Format:             strings.ToLower(strings.TrimSpace(admissionFormat)),
		Mode:               strings.ToLower(strings.TrimSpace(admissionMode)),
		Namespace:          explicitNamespace(cmd),
		AcknowledgePartial: admissionAck,
	}
	switch o.Format {
	case "kyverno", "policy-controller", "kguardian":
	default:
		return o, fmt.Errorf("invalid --format %q: must be kyverno, policy-controller or kguardian", admissionFormat)
	}
	switch o.Mode {
	case "audit", "enforce":
	default:
		return o, fmt.Errorf("invalid --mode %q: must be audit or enforce", admissionMode)
	}
	if o.Mode == "enforce" && o.Format == "kguardian" {
		return o, fmt.Errorf("the kguardian format is report-only; use --format kyverno or policy-controller with --mode enforce")
	}
	return o, nil
}

func runImagesAdmission(cmd *cobra.Command, _ []string) error {
	o, err := admissionOptions(cmd)
	if err != nil {
		return err
	}
	closeFn, err := connectBroker(cmd)
	if err != nil {
		return err
	}
	defer closeFn()
	w := io.Writer(os.Stdout)
	if admissionFile != "" {
		f, err := os.Create(admissionFile)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		w = f
	}
	return fetchAdmissionPolicy(o, w)
}

// fetchAdmissionPolicy is the testable core of images admission-policy.
func fetchAdmissionPolicy(o api.AdmissionPolicyOptions, w io.Writer) error {
	body, err := api.GetAdmissionPolicy(o)
	if err != nil {
		return brokerReadErr("generating the admission policy", err)
	}
	_, err = w.Write(body)
	return err
}
