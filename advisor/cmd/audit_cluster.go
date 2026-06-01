package cmd

import (
	"context"
	"fmt"
	"os"

	log "github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// audit promote-cluster — the cluster-scoped sibling of `audit promote`.
// AuditClusterNetworkPolicy promotes to one or more namespaced
// networking.k8s.io/v1.NetworkPolicies (since native NetworkPolicy is
// per-namespace). Two paths:
//
//   - default: discover namespaces matching spec.namespaceSelector and
//     emit one NetworkPolicy per match
//   - --target-namespace=foo (repeatable): override the discovery and
//     emit only for the named namespace(s)

var auditPromoteClusterCmd = &cobra.Command{
	Use:   "promote-cluster [name]",
	Short: "Convert an AuditClusterNetworkPolicy into one NetworkPolicy per matching namespace",
	Long: `Promote-cluster prints one networking.k8s.io/v1.NetworkPolicy per
namespace selected by the AuditClusterNetworkPolicy's namespaceSelector
(or per --target-namespace, if provided). Pipe to kubectl to apply:

  kguardian audit promote-cluster baseline-deny | kubectl apply -f -

Each emitted NetworkPolicy carries the same podSelector, policyTypes,
ingress, and egress as the source — only the metadata.namespace field
varies. The cluster-scope namespaceSelector is dropped (NetworkPolicy
has no equivalent).

Use --target-namespace foo --target-namespace bar to skip the namespace
discovery step and emit only for the explicit list. Useful when promoting
to a subset of currently-matching namespaces.`,
	RunE: runAuditPromoteCluster,
}

var (
	promoteClusterTargetNamespaces []string
)

func init() {
	auditCmd.AddCommand(auditPromoteClusterCmd)
	auditPromoteClusterCmd.Flags().StringSliceVar(&promoteClusterTargetNamespaces, "target-namespace", nil,
		"Emit only for these namespaces; skip the namespaceSelector discovery. Repeat or comma-separate.")
	auditPromoteClusterCmd.Flags().StringVar(&promoteOutputDir, "output-dir", "",
		"If set, write each NetworkPolicy to <dir>/<namespace>-<name>.yaml instead of stdout")
	auditPromoteClusterCmd.Flags().BoolVar(&promoteDelete, "delete", false,
		"Print a `kubectl delete auditclusternetworkpolicy ...` companion comment after each policy")
}

var auditClusterNetworkPolicyGVR = schema.GroupVersionResource{
	Group:    "kguardian.dev",
	Version:  "v1alpha1",
	Resource: "auditclusternetworkpolicies",
}

var corev1NamespaceGVR = schema.GroupVersionResource{
	Group:    "",
	Version:  "v1",
	Resource: "namespaces",
}

func runAuditPromoteCluster(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("promote-cluster requires the AuditClusterNetworkPolicy name")
	}
	ctx := cmd.Context()
	rest, err := kubeConfigFlags.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("loading kubeconfig: %w", err)
	}
	dyn, err := dynamic.NewForConfig(rest)
	if err != nil {
		return fmt.Errorf("constructing dynamic client: %w", err)
	}

	cluster, err := dyn.Resource(auditClusterNetworkPolicyGVR).Get(ctx, args[0], metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("AuditClusterNetworkPolicy %s not found", args[0])
		}
		return fmt.Errorf("fetching %s: %w", args[0], err)
	}

	targetNamespaces := promoteClusterTargetNamespaces
	if len(targetNamespaces) == 0 {
		discovered, err := discoverNamespacesForClusterPolicy(ctx, dyn, cluster)
		if err != nil {
			return fmt.Errorf("discovering target namespaces: %w", err)
		}
		if len(discovered) == 0 {
			log.Warn().Msgf("no namespaces match the namespaceSelector of %s — nothing to promote", args[0])
			return nil
		}
		targetNamespaces = discovered
	}

	expanded, err := expandClusterPolicyToNamespaced(cluster, targetNamespaces)
	if err != nil {
		return err
	}
	return emitExpanded(expanded, len(targetNamespaces))
}

// discoverNamespacesForClusterPolicy lists every namespace whose labels
// match the cluster policy's spec.namespaceSelector. A nil or empty
// selector matches all namespaces.
func discoverNamespacesForClusterPolicy(ctx context.Context, dyn dynamic.Interface, cluster *unstructured.Unstructured) ([]string, error) {
	sel, found, err := unstructured.NestedFieldCopy(cluster.Object, "spec", "namespaceSelector")
	if err != nil {
		return nil, fmt.Errorf("reading spec.namespaceSelector: %w", err)
	}
	listOpts := metav1.ListOptions{}
	// Convert the selector map to a label selector string for server-side filtering
	// when possible; fall back to client-side filtering for matchExpressions.
	var clientFilter labels.Selector
	if found && sel != nil {
		nsSel, ok := sel.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("spec.namespaceSelector is not an object: %T", sel)
		}
		converted := unstructuredToLabelSelector(nsSel)
		s, err := metav1.LabelSelectorAsSelector(converted)
		if err != nil {
			return nil, fmt.Errorf("compiling namespaceSelector: %w", err)
		}
		clientFilter = s
		listOpts.LabelSelector = s.String()
	}

	list, err := dyn.Resource(corev1NamespaceGVR).List(ctx, listOpts)
	if err != nil {
		return nil, fmt.Errorf("listing namespaces: %w", err)
	}

	var out []string
	for _, item := range list.Items {
		// Server-side filter is best-effort; double-check client-side
		// in case the server applied a stale label index or the
		// selector contained matchExpressions the server-side filter
		// can't fully express. Belt-and-braces: emitting a NetworkPolicy
		// to a namespace that doesn't match is a real footgun.
		if clientFilter != nil && !clientFilter.Matches(labels.Set(item.GetLabels())) {
			continue
		}
		out = append(out, item.GetName())
	}
	return out, nil
}

// unstructuredToLabelSelector converts the nested map form (as
// returned by unstructured.NestedFieldCopy) into a typed
// metav1.LabelSelector. Only matchLabels + matchExpressions are
// honoured (the only valid fields per upstream schema).
func unstructuredToLabelSelector(in map[string]any) *metav1.LabelSelector {
	out := &metav1.LabelSelector{}
	if ml, ok := in["matchLabels"].(map[string]any); ok {
		out.MatchLabels = make(map[string]string, len(ml))
		for k, v := range ml {
			if s, ok := v.(string); ok {
				out.MatchLabels[k] = s
			}
		}
	}
	if me, ok := in["matchExpressions"].([]any); ok {
		for _, raw := range me {
			expr, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			req := metav1.LabelSelectorRequirement{}
			if k, ok := expr["key"].(string); ok {
				req.Key = k
			}
			if op, ok := expr["operator"].(string); ok {
				req.Operator = metav1.LabelSelectorOperator(op)
			}
			if vals, ok := expr["values"].([]any); ok {
				for _, v := range vals {
					if s, ok := v.(string); ok {
						req.Values = append(req.Values, s)
					}
				}
			}
			out.MatchExpressions = append(out.MatchExpressions, req)
		}
	}
	return out
}

// expandClusterPolicyToNamespaced builds one synthetic
// AuditNetworkPolicy-shaped Unstructured per target namespace, with
// the cluster-scope namespaceSelector dropped from the spec. The
// resulting items are suitable for emitPromoted to convert to a
// NetworkPolicy.
//
// Pure transform — no I/O, no global state — so this is the heart of
// what's worth unit-testing. Bug here = wrong namespace gets a policy
// it didnt audit, blast radius "all pods in that namespace".
func expandClusterPolicyToNamespaced(cluster *unstructured.Unstructured, namespaces []string) ([]*unstructured.Unstructured, error) {
	spec, found, err := unstructured.NestedMap(cluster.Object, "spec")
	if err != nil || !found {
		return nil, fmt.Errorf("AuditClusterNetworkPolicy %s has no spec", cluster.GetName())
	}
	// Drop namespaceSelector — networking.k8s.io/v1.NetworkPolicy has no
	// equivalent, and leaving it in would produce a YAML the API server
	// rejects with a "unknown field" error on strict-decoding clusters.
	delete(spec, "namespaceSelector")
	// Carry over user labels/annotations once so each item inherits them.
	labels := cluster.GetLabels()
	anns := cluster.GetAnnotations()

	out := make([]*unstructured.Unstructured, 0, len(namespaces))
	for _, ns := range namespaces {
		// Deep-copy spec per item — emitPromoted reads via NestedFieldCopy
		// so wed actually be safe sharing, but a future refactor that
		// mutates spec would cross-pollute. Cheap insurance.
		specCopy, err := deepCopyMap(spec)
		if err != nil {
			return nil, fmt.Errorf("copying spec for %s: %w", ns, err)
		}
		item := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "kguardian.dev/v1alpha1",
			"kind":       "AuditNetworkPolicy", // synthetic — emitPromoted only reads spec + metadata
			"metadata": map[string]any{
				"namespace": ns,
				"name":      cluster.GetName(),
			},
			"spec": specCopy,
		}}
		if len(labels) > 0 {
			item.SetLabels(labels)
		}
		if len(anns) > 0 {
			clean := make(map[string]string, len(anns))
			for k, v := range anns {
				if k == "kubectl.kubernetes.io/last-applied-configuration" {
					continue
				}
				clean[k] = v
			}
			if len(clean) > 0 {
				item.SetAnnotations(clean)
			}
		}
		out = append(out, item)
	}
	return out, nil
}

func deepCopyMap(in map[string]any) (map[string]any, error) {
	u := &unstructured.Unstructured{Object: in}
	c := u.DeepCopy()
	return c.Object, nil
}

func emitExpanded(items []*unstructured.Unstructured, total int) error {
	if promoteOutputDir != "" {
		if err := os.MkdirAll(promoteOutputDir, 0o755); err != nil {
			return fmt.Errorf("creating output dir: %w", err)
		}
	}
	for i, item := range items {
		if err := promoteListItem(item, i, total); err != nil {
			return err
		}
	}
	return nil
}
