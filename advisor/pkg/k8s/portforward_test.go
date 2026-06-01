package k8s

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// IsPodReady is the gate that decides which broker pod the
// port-forwarder targets. The pre-fix inline check defaulted to
// "ready" and only flipped on an explicit Ready=False — so a
// freshly-created pod whose status.conditions slice was still empty
// got picked, and `kguardian gen networkpolicy` failed with a
// connection-refused error instead of waiting for the pod to come
// up.

func TestIsPodReady_NilReturnsFalse(t *testing.T) {
	assert.False(t, IsPodReady(nil))
}

func TestIsPodReady_NoConditionsReturnsFalse(t *testing.T) {
	// The bug case: a brand-new pod with no conditions populated.
	// Pre-fix returned true; must return false.
	assert.False(t, IsPodReady(&corev1.Pod{}),
		"a pod with NO Ready condition is not ready — it just hasn't been scheduled yet")
}

func TestIsPodReady_ReadyTrue(t *testing.T) {
	pod := &corev1.Pod{
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionTrue},
			},
		},
	}
	assert.True(t, IsPodReady(pod))
}

func TestIsPodReady_ReadyFalse(t *testing.T) {
	pod := &corev1.Pod{
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionFalse, Message: "readiness probe failed"},
			},
		},
	}
	assert.False(t, IsPodReady(pod))
}

func TestIsPodReady_ReadyUnknownReturnsFalse(t *testing.T) {
	// Ready=Unknown happens during a node partition — treat as
	// not-ready. The pod might be running but we can't reach it.
	pod := &corev1.Pod{
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionUnknown},
			},
		},
	}
	assert.False(t, IsPodReady(pod))
}

func TestIsPodReady_OtherConditionsDontImplyReady(t *testing.T) {
	// PodScheduled / Initialized / ContainersReady are NOT the same
	// as Ready. The function must specifically check Type=Ready.
	pod := &corev1.Pod{
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodScheduled, Status: corev1.ConditionTrue},
				{Type: corev1.PodInitialized, Status: corev1.ConditionTrue},
				{Type: corev1.ContainersReady, Status: corev1.ConditionTrue},
				// No PodReady condition!
			},
		},
	}
	assert.False(t, IsPodReady(pod),
		"PodScheduled / Initialized / ContainersReady do NOT imply Ready")
}

func TestIsPodReady_FindsReadyAmongOtherConditions(t *testing.T) {
	pod := &corev1.Pod{
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodScheduled, Status: corev1.ConditionTrue},
				{Type: corev1.PodInitialized, Status: corev1.ConditionTrue},
				{Type: corev1.ContainersReady, Status: corev1.ConditionTrue},
				{Type: corev1.PodReady, Status: corev1.ConditionTrue},
			},
		},
	}
	assert.True(t, IsPodReady(pod))
}

func TestPortForward(t *testing.T) {
	// Test basic validation failures
	// Test nil config
	stopChan, errChan, done := PortForward(nil, "", "")
	select {
	case err := <-errChan:
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil Kubernetes configuration")
	case <-time.After(time.Second):
		t.Fatal("Expected error but none received")
	}
	<-done          // Wait for done signal
	close(stopChan) // Clean up

	// Test nil clientset
	nilClientConfig := &Config{
		Clientset: nil,
		Config:    &rest.Config{},
	}
	stopChan, errChan, done = PortForward(nilClientConfig, "", "")
	select {
	case err := <-errChan:
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil Kubernetes clientset")
	case <-time.After(time.Second):
		t.Fatal("Expected error but none received")
	}
	<-done          // Wait for done signal
	close(stopChan) // Clean up

	// Test nil REST config
	nilRestConfig := &Config{
		Clientset: &kubernetes.Clientset{},
		Config:    nil,
	}
	stopChan, errChan, done = PortForward(nilRestConfig, "", "")
	select {
	case err := <-errChan:
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil REST configuration")
	case <-time.After(time.Second):
		t.Fatal("Expected error but none received")
	}
	<-done          // Wait for done signal
	close(stopChan) // Clean up
}

func TestWriterFunc(t *testing.T) {
	// Test the writerFunc adapter
	var called bool
	var capturedData []byte

	// Create a writerFunc that captures the data
	w := writerFunc(func(p []byte) (int, error) {
		called = true
		capturedData = make([]byte, len(p))
		copy(capturedData, p)
		return len(p), nil
	})

	testData := []byte("test data")
	n, err := w.Write(testData)

	assert.NoError(t, err)
	assert.Equal(t, len(testData), n)
	assert.True(t, called)
	assert.Equal(t, testData, capturedData)
}
