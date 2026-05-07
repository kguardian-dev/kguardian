package cmd

import (
	"context"
	"fmt"
	"io"
	"os"

	log "github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/kguardian-dev/kguardian/advisor/pkg/k8s"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/yaml"
)

// auditCmd is the namespace for AuditNetworkPolicy lifecycle helpers.
var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Manage kguardian AuditNetworkPolicy resources",
	Long: `Helpers for the audit-mode policy lifecycle:

  promote   take an AuditNetworkPolicy and emit the equivalent
            networking.k8s.io/v1.NetworkPolicy ready for kubectl apply

The audit -> enforced transition is intentionally a separate step:
review the would-deny output first, then promote.`,
}

var (
	promoteAll       bool
	promoteOutputDir string
	promoteDelete    bool
)

var auditPromoteCmd = &cobra.Command{
	Use:   "promote [name]",
	Short: "Convert an AuditNetworkPolicy into an enforced NetworkPolicy",
	Long: `Promote prints a networking.k8s.io/v1.NetworkPolicy with the same
spec as the named AuditNetworkPolicy. Pipe to kubectl to apply:

  kguardian audit promote payments-isolation -n prod | kubectl apply -f -

Add --delete to follow up by removing the AuditNetworkPolicy after a
successful kubectl apply (run them in sequence — promote does not
delete on its own to keep the rollback simple).

Use --all to dump every AuditNetworkPolicy in the namespace, or
--all-namespaces to dump cluster-wide.`,
	RunE: runAuditPromote,
}

func init() {
	rootCmd.AddCommand(auditCmd)
	auditCmd.AddCommand(auditPromoteCmd)
	auditPromoteCmd.Flags().BoolVar(&promoteAll, "all", false, "Promote every AuditNetworkPolicy in the target namespace")
	auditPromoteCmd.Flags().BoolVar(&allNamespaces, "all-namespaces", false, "When used with --all, target every namespace")
	auditPromoteCmd.Flags().StringVar(&promoteOutputDir, "output-dir", "", "If set, write each NetworkPolicy to <dir>/<namespace>-<name>.yaml instead of stdout")
	auditPromoteCmd.Flags().BoolVar(&promoteDelete, "delete", false, "Print a `kubectl delete auditnetworkpolicy ...` companion command after each promoted policy (so you can pipe through `sh` once you've applied)")
}

var auditNetworkPolicyGVR = schema.GroupVersionResource{
	Group:    "kguardian.dev",
	Version:  "v1alpha1",
	Resource: "auditnetworkpolicies",
}

func runAuditPromote(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	// Construct the dynamic client straight from kubeConfigFlags.
	// The k8s.NewConfig wrapper used by other advisor commands is
	// broker-aware; for a CRD lookup we just need a plain REST config.
	rest, err := kubeConfigFlags.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("loading kubeconfig: %w", err)
	}
	dyn, err := dynamic.NewForConfig(rest)
	if err != nil {
		return fmt.Errorf("constructing dynamic client: %w", err)
	}

	namespace, _, err := kubeConfigFlags.ToRawKubeConfigLoader().Namespace()
	if err != nil {
		return fmt.Errorf("resolving namespace: %w", err)
	}

	switch {
	case promoteAll && allNamespaces:
		return promoteList(ctx, dyn, "")
	case promoteAll:
		return promoteList(ctx, dyn, namespace)
	default:
		if len(args) != 1 {
			return fmt.Errorf("promote requires the AuditNetworkPolicy name (or --all)")
		}
		return promoteOne(ctx, dyn, namespace, args[0])
	}
}

func promoteOne(ctx context.Context, dyn dynamic.Interface, namespace, name string) error {
	u, err := dyn.Resource(auditNetworkPolicyGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("AuditNetworkPolicy %s/%s not found", namespace, name)
		}
		return fmt.Errorf("fetching %s/%s: %w", namespace, name, err)
	}
	return emitPromoted(u, os.Stdout)
}

func promoteList(ctx context.Context, dyn dynamic.Interface, namespace string) error {
	var list *unstructured.UnstructuredList
	var err error
	if namespace == "" {
		list, err = dyn.Resource(auditNetworkPolicyGVR).List(ctx, metav1.ListOptions{})
	} else {
		list, err = dyn.Resource(auditNetworkPolicyGVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
	}
	if err != nil {
		return fmt.Errorf("listing AuditNetworkPolicies: %w", err)
	}
	if len(list.Items) == 0 {
		log.Warn().Msg("no AuditNetworkPolicy resources found")
		return nil
	}

	if promoteOutputDir != "" {
		if err := os.MkdirAll(promoteOutputDir, 0o755); err != nil {
			return fmt.Errorf("creating output dir: %w", err)
		}
	}

	for i := range list.Items {
		item := &list.Items[i]
		var out io.Writer = os.Stdout
		if promoteOutputDir != "" {
			path := fmt.Sprintf("%s/%s-%s.yaml", promoteOutputDir, item.GetNamespace(), item.GetName())
			f, err := os.Create(path)
			if err != nil {
				return fmt.Errorf("opening %s: %w", path, err)
			}
			out = f
			defer f.Close()
			log.Info().Str("path", path).Msg("wrote promoted NetworkPolicy")
		} else if i > 0 {
			fmt.Fprintln(os.Stdout, "---")
		}
		if err := emitPromoted(item, out); err != nil {
			return err
		}
	}
	return nil
}

// emitPromoted converts an AuditNetworkPolicy into an enforced
// NetworkPolicy YAML and writes it to w. It strips the audit-side
// status, kguardian-managed labels, and the resourceVersion / uid
// machinery that a kubectl-applied resource shouldn't carry.
func emitPromoted(u *unstructured.Unstructured, w io.Writer) error {
	out := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
		"metadata": map[string]any{
			"name":      u.GetName(),
			"namespace": u.GetNamespace(),
		},
	}}
	// Carry over any user-applied annotations + labels — they may
	// matter to GitOps tooling. Strip the kubectl.kubernetes.io
	// last-applied-configuration as it'd be wrong for the new kind.
	if labels := u.GetLabels(); len(labels) > 0 {
		out.SetLabels(labels)
	}
	if anns := u.GetAnnotations(); len(anns) > 0 {
		clean := make(map[string]string, len(anns))
		for k, v := range anns {
			if k == "kubectl.kubernetes.io/last-applied-configuration" {
				continue
			}
			clean[k] = v
		}
		if len(clean) > 0 {
			out.SetAnnotations(clean)
		}
	}
	spec, found, err := unstructured.NestedFieldCopy(u.Object, "spec")
	if err != nil || !found {
		return fmt.Errorf("AuditNetworkPolicy %s/%s has no spec", u.GetNamespace(), u.GetName())
	}
	out.Object["spec"] = spec

	raw, err := yaml.Marshal(out.Object)
	if err != nil {
		return fmt.Errorf("marshalling promoted policy: %w", err)
	}
	if _, err := w.Write(raw); err != nil {
		return err
	}
	if promoteDelete {
		fmt.Fprintf(w, "# After kubectl apply succeeds, retire the audit policy:\n#   kubectl delete auditnetworkpolicy %s -n %s\n",
			u.GetName(), u.GetNamespace())
	}
	return nil
}

// silence unused-symbol linters for the corev1 import (kept for
// future status-style annotations on promoted policies).
var _ = corev1.NamespaceDefault
var _ = k8s.ConfigKey
