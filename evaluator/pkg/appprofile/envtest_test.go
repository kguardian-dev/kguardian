package appprofile

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1alpha1 "github.com/kguardian-dev/kguardian/evaluator/pkg/v1alpha1"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// TestStatusHidesBrokerAddressOnARealAPIServer applies status for a
// broker the evaluator cannot reach and reads the stored object back from
// a real kube-apiserver (envtest, as CI's test-evaluator job runs it):
// what users see with kubectl carries the cause, not the broker's URL.
func TestStatusHidesBrokerAddressOnARealAPIServer(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		if os.Getenv("CI") == "true" || os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatal("KUBEBUILDER_ASSETS is not set in CI: the envtest install step did not run or failed")
		}
		t.Skip("set KUBEBUILDER_ASSETS (setup-envtest) to run against a real API server")
	}
	env := &envtest.Environment{
		// The chart installs this CRD from files/ (behind a values flag), not crds/.
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "..", "charts", "kguardian", "files", "kguardian.dev_applicationsecurityprofiles.yaml")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	ctx := context.Background()
	dc := dynamic.NewForConfigOrDie(cfg)
	res := dc.Resource(GVR).Namespace("default")

	u := aspObject("refunds", "Deployment", "refunds", time.Now(), ptr(int64(2)))
	u.SetNamespace("default")
	delete(u.Object["metadata"].(map[string]any), "creationTimestamp")
	delete(u.Object["metadata"].(map[string]any), "generation")
	if _, err := res.Create(ctx, u, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	read := func() *v1alpha1.ApplicationSecurityProfile {
		t.Helper()
		got, err := res.Get(ctx, "refunds", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		asp, err := fromUnstructured(got)
		if err != nil {
			t.Fatal(err)
		}
		return asp
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	_ = ln.Close()
	client, err := NewBrokerClient("http://"+closed, "t0ken", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	log := logrus.New()
	c := &Controller{dyn: dc, log: log}

	asp := read()
	st, rerr := computeStatus(ctx, client, asp, time.Now(), testStaleAfter)
	if rerr == nil || !strings.Contains(rerr.Error(), closed) {
		t.Fatalf("the returned error (logged by processNext) must keep the full detail, got %v", rerr)
	}
	if err := c.apply(ctx, asp, st); err != nil {
		t.Fatal(err)
	}

	stored := read().Status
	pa := meta.FindStatusCondition(stored.Conditions, v1alpha1.ConditionProfileAvailable)
	if pa == nil || pa.Reason != v1alpha1.ReasonBrokerUnavailable ||
		!strings.Contains(pa.Message, "Could not read the profile from the broker (connection failed)") {
		t.Fatalf("stored ProfileAvailable = %+v", pa)
	}
	if stored.Posture == nil || stored.Posture.Status != "unknown" {
		t.Fatalf("stored posture = %+v, want unknown", stored.Posture)
	}
	texts := statusTexts(stored)
	if len(texts) < 4 {
		t.Fatalf("expected condition, posture, dimension and deviation messages, got %v", texts)
	}
	for what, text := range texts {
		assertUserSafe(t, "stored "+what, text)
		if strings.Contains(text, closed) {
			t.Errorf("stored %s: %q names the broker address %s", what, text, closed)
		}
	}
}
