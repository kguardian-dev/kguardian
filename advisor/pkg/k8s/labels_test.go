package k8s

import (
	"testing"

	"github.com/stretchr/testify/assert"
	api "github.com/xentra-ai/advisor/pkg/api"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func TestDetectSelectorLabels(t *testing.T) {
	clientset := &kubernetes.Clientset{}
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"app": "test-app",
			},
		},
	}
	podDetail := &api.PodDetail{
		Pod: v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					"app": "test-app",
				},
			},
		},
	}
	serviceDetail := &api.SvcDetail{
		Service: v1.Service{
			Spec: v1.ServiceSpec{
				Selector: map[string]string{
					"app": "test-app",
				},
			},
		},
	}

	labels1, err1 := DetectSelectorLabels(clientset, pod)
	assert.NoError(t, err1)
	assert.Equal(t, map[string]string{"app": "test-app"}, labels1)

	labels2, err2 := DetectSelectorLabels(clientset, podDetail)
	assert.NoError(t, err2)
	assert.Equal(t, map[string]string{"app": "test-app"}, labels2)

	labels3, err3 := DetectSelectorLabels(clientset, serviceDetail)
	assert.NoError(t, err3)
	assert.Equal(t, map[string]string{"app": "test-app"}, labels3)

	_, err4 := DetectSelectorLabels(clientset, "unknown type")
	assert.Error(t, err4)
}
