// Command evaluator-standin serves the evaluator's GET /image-trust for the
// attestation captures, with no cluster.
//
// It is the evaluator's own image trust code (evaluator/pkg/imagetrust):
// the real Runner evaluates real v1alpha1 ImageTrustPolicy and
// ClusterImageTrustPolicy objects against the real Broker's
// /attestations/running (the evaluator's BrokerFeed), and the real Handler
// serves the result behind the READ token. Only the Kubernetes API is
// replaced, by the in-memory fake dynamic client the evaluator's own tests
// use (k8s.io/client-go/dynamic/fake): no envtest, no cluster. So the JSON,
// the verdicts and the reasons are the evaluator's, never hand-written.
//
//	./build.sh /tmp/evaluator-standin && /tmp/evaluator-standin -listen 127.0.0.1:<port> -broker http://127.0.0.1:<broker port> -token <read token>
package main

import (
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"os"
	"time"

	"github.com/kguardian-dev/kguardian/evaluator/pkg/imagetrust"
	v1alpha1 "github.com/kguardian-dev/kguardian/evaluator/pkg/v1alpha1"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

// The GitHub Actions OIDC issuer and the ledger's configured key, as the
// signature seed in ../capture.py reports them.
const (
	gha      = "https://token.actions.githubusercontent.com"
	ledgerFP = "d4d97426189ec7a3bc8a16cc81bfc8ec314b179c4dad1123ff4e167026fc2c41"
)

func object(obj runtime.Object, kind string) *unstructured.Unstructured {
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		panic(err)
	}
	u := &unstructured.Unstructured{Object: m}
	u.SetAPIVersion(v1alpha1.GroupName + "/" + v1alpha1.Version)
	u.SetKind(kind)
	return u
}

// policies: one namespaced policy for payments that trusts the checkout
// release workflow and the ledger key, one cluster policy over example-org
// that trusts the release workflow only and wants SLSA provenance, and one
// cluster policy over the monitoring and platform images.
func policies() []runtime.Object {
	payments := &v1alpha1.ImageTrustPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "payments-release-signers", Namespace: "payments", Generation: 1},
		Spec: v1alpha1.ImageTrustPolicySpec{
			Images: []string{"ghcr.io/example/**"},
			Authorities: []v1alpha1.Authority{
				{Name: "release-workflow", Keyless: &v1alpha1.KeylessAuthority{Issuer: gha, SubjectRegExp: `^https://github\.com/example-org/checkout/\.github/workflows/release\.yaml@refs/tags/.+$`}},
				{Name: "payments-release-key", Key: &v1alpha1.KeyAuthority{Fingerprint: ledgerFP}},
			},
		},
	}
	org := &v1alpha1.ClusterImageTrustPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "example-org-releases", Generation: 1},
		Spec: v1alpha1.ClusterImageTrustPolicySpec{ImageTrustPolicySpec: v1alpha1.ImageTrustPolicySpec{
			Images:       []string{"ghcr.io/example/checkout", "ghcr.io/example/ledger"},
			Authorities:  []v1alpha1.Authority{{Name: "release-workflow", Keyless: &v1alpha1.KeylessAuthority{Issuer: gha, SubjectRegExp: `^https://github\.com/example-org/.+/\.github/workflows/release\.yaml@refs/tags/.+$`}}},
			Attestations: []v1alpha1.AttestationRequirement{{PredicateType: "https://slsa.dev/provenance/v1"}},
		}},
	}
	monitoring := &v1alpha1.ClusterImageTrustPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "monitoring-signed", Generation: 1},
		Spec: v1alpha1.ClusterImageTrustPolicySpec{ImageTrustPolicySpec: v1alpha1.ImageTrustPolicySpec{
			Images:      []string{"docker.io/grafana/**", "quay.io/prometheus/**", "ghcr.io/fluxcd/**", "registry.k8s.io/ingress-nginx/**"},
			Authorities: []v1alpha1.Authority{{Name: "upstream-releases", Keyless: &v1alpha1.KeylessAuthority{Issuer: gha, SubjectRegExp: `^https://github\.com/(grafana|prometheus|fluxcd|kubernetes)/.+$`}}},
		}},
	}
	return []runtime.Object{
		object(payments, "ImageTrustPolicy"),
		object(org, "ClusterImageTrustPolicy"),
		object(monitoring, "ClusterImageTrustPolicy"),
	}
}

func main() {
	listen := flag.String("listen", "127.0.0.1:56430", "address to serve GET /image-trust on")
	broker := flag.String("broker", "http://127.0.0.1:56421", "Broker base URL (its /attestations/running is the feed)")
	token := flag.String("token", "", "Broker READ token (the feed's and this endpoint's)")
	flag.Parse()

	dc := dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		imagetrust.PolicyGVR:  "ImageTrustPolicyList",
		imagetrust.ClusterGVR: "ClusterImageTrustPolicyList",
	}, policies()...)
	// The fake client does not implement server-side apply; accept the
	// runner's status writes into the tracker, as the evaluator's tests do.
	dc.PrependReactor("patch", "*", func(a k8stesting.Action) (bool, runtime.Object, error) {
		pa := a.(k8stesting.PatchAction)
		obj, err := dc.Tracker().Get(a.GetResource(), pa.GetNamespace(), pa.GetName())
		if err != nil {
			return true, nil, err
		}
		var u map[string]any
		if err := json.Unmarshal(pa.GetPatch(), &u); err != nil {
			return true, nil, err
		}
		uo := obj.(*unstructured.Unstructured).DeepCopy()
		uo.Object["status"] = u["status"]
		return true, uo, dc.Tracker().Update(a.GetResource(), uo, pa.GetNamespace())
	})

	log := logrus.New()
	log.SetOutput(os.Stderr)
	known := map[string]bool{"payments": true, "observability": true, "flux-system": true, "ingress-nginx": true}
	r := &imagetrust.Runner{
		Dynamic:  dc,
		Feed:     &imagetrust.BrokerFeed{BaseURL: *broker, Token: *token, HTTP: &http.Client{Timeout: 10 * time.Second}},
		Log:      log,
		Interval: 30 * time.Second,
		Namespaces: func(ns string) map[string]string {
			if !known[ns] {
				return nil
			}
			return map[string]string{"kubernetes.io/metadata.name": ns}
		},
	}
	ctx := context.Background()
	if err := r.Pass(ctx); err != nil {
		log.WithError(err).Fatal("first image trust pass failed")
	}
	go r.Run(ctx)
	mux := http.NewServeMux()
	mux.Handle("/image-trust", r.Handler(*token))
	log.WithField("listen", *listen).Info("evaluator stand-in serving /image-trust")
	if err := http.ListenAndServe(*listen, mux); err != nil {
		log.Fatal(err)
	}
}
