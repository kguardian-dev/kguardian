package k8s

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	api "github.com/xentra-ai/advisor/pkg/api"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
)

// The old mock API functions (apiGetPodTraffic, apiGetPodSpec, etc.) have been replaced
// with function variables in the api package (api.GetPodTrafficFunc, api.GetPodSpecFunc, etc.)

func TestGenerateNetworkPolicy(t *testing.T) {
	// Save original functions
	origFetchSinglePod := fetchSinglePodInNamespaceFunc
	origFetchAllPodsInNs := fetchAllPodsInNamespaceFunc
	origFetchAllPodsInAllNs := fetchAllPodsInAllNamespacesFunc
	origGetPodTrafficFunc := api.GetPodTrafficFunc
	origGetPodSpecFunc := api.GetPodSpecFunc
	origGetSvcSpecFunc := api.GetSvcSpecFunc

	// Restore original functions when test completes
	defer func() {
		fetchSinglePodInNamespaceFunc = origFetchSinglePod
		fetchAllPodsInNamespaceFunc = origFetchAllPodsInNs
		fetchAllPodsInAllNamespacesFunc = origFetchAllPodsInAllNs
		api.GetPodTrafficFunc = origGetPodTrafficFunc
		api.GetPodSpecFunc = origGetPodSpecFunc
		api.GetSvcSpecFunc = origGetSvcSpecFunc
	}()

	// Mock the fetch functions to return test data
	fetchSinglePodInNamespaceFunc = func(podName, namespace string, config *Config) (*corev1.Pod, error) {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
				Labels: map[string]string{
					"app": "test-pod",
				},
			},
		}, nil
	}

	fetchAllPodsInNamespaceFunc = func(namespace string, config *Config) ([]corev1.Pod, error) {
		return []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
					Labels: map[string]string{
						"app": "test-pod",
					},
				},
			},
		}, nil
	}

	fetchAllPodsInAllNamespacesFunc = func(config *Config) ([]corev1.Pod, error) {
		return []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
					Labels: map[string]string{
						"app": "test-pod",
					},
				},
			},
		}, nil
	}

	// Mock API GetPodTraffic to return test data
	api.GetPodTrafficFunc = func(podName string) ([]api.PodTraffic, error) {
		return []api.PodTraffic{
			{
				SrcIP:       "10.0.0.1",
				TrafficType: "INGRESS",
				SrcPodPort:  "80",
				Protocol:    corev1.ProtocolTCP,
			},
		}, nil
	}

	// Mock API GetPodSpec to return test data
	api.GetPodSpecFunc = func(podIP string) (*api.PodDetail, error) {
		return &api.PodDetail{
			Name:      "test-pod",
			Namespace: "default",
			Pod: corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
					Labels: map[string]string{
						"app": "test-pod",
					},
				},
			},
		}, nil
	}

	// Mock API GetSvcSpec to return test data
	api.GetSvcSpecFunc = func(svcIP string) (*api.SvcDetail, error) {
		return &api.SvcDetail{
			SvcName:      "test-svc",
			SvcNamespace: "default",
			Service: corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-svc",
					Namespace: "default",
				},
				Spec: corev1.ServiceSpec{
					Selector: map[string]string{
						"app": "test-svc",
					},
				},
			},
		}, nil
	}

	// Mock detectSelectorLabels
	originalDetectSelectorLabels := detectSelectorLabelsFunc
	defer func() { detectSelectorLabelsFunc = originalDetectSelectorLabels }()

	detectSelectorLabelsFunc = func(clientset *kubernetes.Clientset, origin interface{}) (map[string]string, error) {
		return map[string]string{"app": "test-pod"}, nil
	}

	// Test with nil config
	GenerateNetworkPolicy(GenerateOptions{}, nil)

	// Test with output directory
	config := &Config{
		DryRun:    true,
		OutputDir: t.TempDir(), // Use temporary directory for test
	}
	GenerateNetworkPolicy(GenerateOptions{}, config)

	// Test with dry run mode
	config.DryRun = true
	config.OutputDir = ""
	GenerateNetworkPolicy(GenerateOptions{}, config)

	// Create a config with clientset
	config = &Config{
		Clientset: &kubernetes.Clientset{},
		DryRun:    false,
	}

	// Test with GetPodTraffic error
	api.GetPodTrafficFunc = func(podName string) ([]api.PodTraffic, error) {
		return nil, assert.AnError
	}
	GenerateNetworkPolicy(GenerateOptions{}, config)

	// Test with successful API calls
	api.GetPodTrafficFunc = func(podName string) ([]api.PodTraffic, error) {
		return []api.PodTraffic{
			{
				SrcIP:       "10.0.0.1",
				TrafficType: "INGRESS",
				SrcPodPort:  "80",
				Protocol:    corev1.ProtocolTCP,
			},
		}, nil
	}

	// Test with GetPodSpec error
	api.GetPodSpecFunc = func(podIP string) (*api.PodDetail, error) {
		return nil, assert.AnError
	}
	GenerateNetworkPolicy(GenerateOptions{}, config)

	// Test with successful GetPodSpec
	api.GetPodSpecFunc = func(podIP string) (*api.PodDetail, error) {
		return &api.PodDetail{
			Name:      "test-pod",
			Namespace: "default",
			Pod: corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
					Labels: map[string]string{
						"app": "test-pod",
					},
				},
			},
		}, nil
	}

	// Test with all successful cases
	GenerateNetworkPolicy(GenerateOptions{}, config)
}

func TestTransformToNetworkPolicy(t *testing.T) {
	// Save original API functions
	origGetPodSpecFunc := api.GetPodSpecFunc
	origGetSvcSpecFunc := api.GetSvcSpecFunc

	// Restore original functions when test completes
	defer func() {
		api.GetPodSpecFunc = origGetPodSpecFunc
		api.GetSvcSpecFunc = origGetSvcSpecFunc
	}()

	// Mock API functions
	api.GetPodSpecFunc = func(podIP string) (*api.PodDetail, error) {
		return &api.PodDetail{
			Name:      "test-pod",
			Namespace: "default",
			Pod: corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
					Labels: map[string]string{
						"app": "test-pod",
					},
				},
			},
		}, nil
	}

	api.GetSvcSpecFunc = func(svcIP string) (*api.SvcDetail, error) {
		return &api.SvcDetail{
			SvcName:      "test-svc",
			SvcNamespace: "default",
			Service: corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-svc",
					Namespace: "default",
				},
				Spec: corev1.ServiceSpec{
					Selector: map[string]string{
						"app": "test-svc",
					},
				},
			},
		}, nil
	}

	// Create test data
	podTraffic := []api.PodTraffic{
		{
			SrcIP:       "10.0.0.1",
			DstIP:       "10.0.0.2",
			SrcPodPort:  "80",
			DstPort:     "8080",
			TrafficType: "INGRESS",
			Protocol:    corev1.ProtocolTCP,
		},
		{
			SrcIP:       "10.0.0.1",
			DstIP:       "10.0.0.3",
			SrcPodPort:  "80",
			DstPort:     "443",
			TrafficType: "EGRESS",
			Protocol:    corev1.ProtocolTCP,
		},
	}

	podDetail := &api.PodDetail{
		Name:      "test-pod",
		Namespace: "default",
		Pod: corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
				Labels: map[string]string{
					"app": "test-pod",
				},
			},
		},
	}

	config := &Config{
		Clientset: &kubernetes.Clientset{},
	}

	// Mock the underlying functions
	originalProcessIngressRules := processIngressRulesFunc
	originalProcessEgressRules := processEgressRulesFunc
	originalDetectSelectorLabels := detectSelectorLabelsFunc
	defer func() {
		processIngressRulesFunc = originalProcessIngressRules
		processEgressRulesFunc = originalProcessEgressRules
		detectSelectorLabelsFunc = originalDetectSelectorLabels
	}()

	// Test with process rules error
	processIngressRulesFunc = func(podTraffic []api.PodTraffic, config *Config) ([]networkingv1.NetworkPolicyIngressRule, error) {
		return nil, assert.AnError
	}

	policy, err := transformToNetworkPolicy(podTraffic, podDetail, config)
	assert.Error(t, err)
	assert.Nil(t, policy)

	// Fix ingress, break egress
	processIngressRulesFunc = func(podTraffic []api.PodTraffic, config *Config) ([]networkingv1.NetworkPolicyIngressRule, error) {
		return []networkingv1.NetworkPolicyIngressRule{}, nil
	}

	processEgressRulesFunc = func(podTraffic []api.PodTraffic, config *Config) ([]networkingv1.NetworkPolicyEgressRule, error) {
		return nil, assert.AnError
	}

	policy, err = transformToNetworkPolicy(podTraffic, podDetail, config)
	assert.Error(t, err)
	assert.Nil(t, policy)

	// Fix both, break detectSelectorLabels
	processEgressRulesFunc = func(podTraffic []api.PodTraffic, config *Config) ([]networkingv1.NetworkPolicyEgressRule, error) {
		return []networkingv1.NetworkPolicyEgressRule{}, nil
	}

	detectSelectorLabelsFunc = func(clientset *kubernetes.Clientset, origin interface{}) (map[string]string, error) {
		return nil, assert.AnError
	}

	policy, err = transformToNetworkPolicy(podTraffic, podDetail, config)
	assert.Error(t, err)
	assert.Nil(t, policy)

	// Fix all
	detectSelectorLabelsFunc = func(clientset *kubernetes.Clientset, origin interface{}) (map[string]string, error) {
		return map[string]string{"app": "test-pod"}, nil
	}

	policy, err = transformToNetworkPolicy(podTraffic, podDetail, config)
	assert.NoError(t, err)
	assert.NotNil(t, policy)
	assert.Equal(t, "test-pod", policy.Name)
	assert.Equal(t, "default", policy.Namespace)
	assert.Equal(t, map[string]string{"app": "test-pod"}, policy.Spec.PodSelector.MatchLabels)
	assert.Len(t, policy.Spec.PolicyTypes, 2)
}

func TestProcessIngressRules(t *testing.T) {
	// Save original functions
	origGetPodSpecFunc := api.GetPodSpecFunc
	origGetSvcSpecFunc := api.GetSvcSpecFunc

	// Restore original functions when test completes
	defer func() {
		api.GetPodSpecFunc = origGetPodSpecFunc
		api.GetSvcSpecFunc = origGetSvcSpecFunc
	}()

	// Create test data
	podTraffic := []api.PodTraffic{
		{
			SrcIP:       "10.0.0.1",
			DstIP:       "10.0.0.2",
			SrcPodPort:  "80",
			DstPort:     "8080",
			TrafficType: "INGRESS",
			Protocol:    corev1.ProtocolTCP,
		},
		{
			SrcIP:       "10.0.0.1",
			DstIP:       "10.0.0.3",
			SrcPodPort:  "443",
			DstPort:     "8443",
			TrafficType: "EGRESS", // This one should be skipped
			Protocol:    corev1.ProtocolTCP,
		},
	}

	config := &Config{
		Clientset: &kubernetes.Clientset{},
	}

	// Test with error in determinePeerForTraffic
	originalDeterminePeerForTraffic := determinePeerForTrafficFunc
	defer func() { determinePeerForTrafficFunc = originalDeterminePeerForTraffic }()

	determinePeerForTrafficFunc = func(traffic api.PodTraffic, config *Config) (*networkingv1.NetworkPolicyPeer, error) {
		return nil, assert.AnError
	}

	rules, err := processIngressRules(podTraffic, config)
	assert.Error(t, err)
	assert.Nil(t, rules)

	// Test with successful peer determination
	determinePeerForTrafficFunc = func(traffic api.PodTraffic, config *Config) (*networkingv1.NetworkPolicyPeer, error) {
		return &networkingv1.NetworkPolicyPeer{
			PodSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "test-pod"},
			},
			NamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"kubernetes.io/metadata.name": "default"},
			},
		}, nil
	}

	rules, err = processIngressRules(podTraffic, config)
	assert.NoError(t, err)
	assert.NotNil(t, rules)
	assert.Len(t, rules, 1)
	assert.Equal(t, podTraffic[0].Protocol, *rules[0].Ports[0].Protocol)
}

func TestProcessEgressRules(t *testing.T) {
	// Save original functions
	origGetPodSpecFunc := api.GetPodSpecFunc
	origGetSvcSpecFunc := api.GetSvcSpecFunc

	// Restore original functions when test completes
	defer func() {
		api.GetPodSpecFunc = origGetPodSpecFunc
		api.GetSvcSpecFunc = origGetSvcSpecFunc
	}()

	// Create test data
	podTraffic := []api.PodTraffic{
		{
			SrcIP:       "10.0.0.1",
			DstIP:       "10.0.0.2",
			SrcPodPort:  "80",
			DstPort:     "8080",
			TrafficType: "INGRESS", // This one should be skipped
			Protocol:    corev1.ProtocolTCP,
		},
		{
			SrcIP:       "10.0.0.1",
			DstIP:       "10.0.0.3",
			SrcPodPort:  "443",
			DstPort:     "8443",
			TrafficType: "EGRESS",
			Protocol:    corev1.ProtocolTCP,
		},
	}

	config := &Config{
		Clientset: &kubernetes.Clientset{},
	}

	// Test with error in determinePeerForTraffic
	originalDeterminePeerForTraffic := determinePeerForTrafficFunc
	defer func() { determinePeerForTrafficFunc = originalDeterminePeerForTraffic }()

	determinePeerForTrafficFunc = func(traffic api.PodTraffic, config *Config) (*networkingv1.NetworkPolicyPeer, error) {
		return nil, assert.AnError
	}

	rules, err := processEgressRules(podTraffic, config)
	assert.Error(t, err)
	assert.Nil(t, rules)

	// Test with successful peer determination
	determinePeerForTrafficFunc = func(traffic api.PodTraffic, config *Config) (*networkingv1.NetworkPolicyPeer, error) {
		return &networkingv1.NetworkPolicyPeer{
			PodSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "test-pod"},
			},
			NamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"kubernetes.io/metadata.name": "default"},
			},
		}, nil
	}

	rules, err = processEgressRules(podTraffic, config)
	assert.NoError(t, err)
	assert.NotNil(t, rules)
	assert.Len(t, rules, 1)
	assert.Equal(t, podTraffic[1].Protocol, *rules[0].Ports[0].Protocol)
}

func TestDeterminePeerForTraffic(t *testing.T) {
	// Save original functions
	origGetPodSpecFunc := api.GetPodSpecFunc
	origGetSvcSpecFunc := api.GetSvcSpecFunc

	// Restore original functions when test completes
	defer func() {
		api.GetPodSpecFunc = origGetPodSpecFunc
		api.GetSvcSpecFunc = origGetSvcSpecFunc
	}()

	// Mock the detectSelectorLabels function
	originalDetectSelectorLabels := detectSelectorLabelsFunc
	defer func() { detectSelectorLabelsFunc = originalDetectSelectorLabels }()

	detectSelectorLabelsFunc = func(clientset *kubernetes.Clientset, origin interface{}) (map[string]string, error) {
		return map[string]string{"app": "test-pod"}, nil
	}

	// Create test traffic
	traffic := api.PodTraffic{
		SrcIP:       "10.0.0.1",
		DstIP:       "10.0.0.2",
		SrcPodPort:  "80",
		DstPort:     "443",
		TrafficType: "INGRESS",
		Protocol:    corev1.ProtocolTCP,
	}

	config := &Config{
		Clientset: &kubernetes.Clientset{},
	}

	// Test GetPodSpec error
	api.GetPodSpecFunc = func(podIP string) (*api.PodDetail, error) {
		return nil, assert.AnError
	}

	peer, err := determinePeerForTraffic(traffic, config)
	assert.Error(t, err)
	assert.Nil(t, peer)

	// Test pod with hostNetwork
	api.GetPodSpecFunc = func(podIP string) (*api.PodDetail, error) {
		return &api.PodDetail{
			PodIP: "10.0.0.2",
			Pod: corev1.Pod{
				Spec: corev1.PodSpec{
					HostNetwork: true,
				},
			},
		}, nil
	}

	peer, err = determinePeerForTraffic(traffic, config)
	assert.NoError(t, err)
	assert.NotNil(t, peer)
	assert.NotNil(t, peer.IPBlock)
	assert.Equal(t, "10.0.0.2/32", peer.IPBlock.CIDR)

	// Test normal pod
	api.GetPodSpecFunc = func(podIP string) (*api.PodDetail, error) {
		return &api.PodDetail{
			PodIP:     "10.0.0.2",
			Name:      "test-pod",
			Namespace: "default",
			Pod: corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
					Labels: map[string]string{
						"app": "test-pod",
					},
				},
				Spec: corev1.PodSpec{
					HostNetwork: false,
				},
			},
		}, nil
	}

	peer, err = determinePeerForTraffic(traffic, config)
	assert.NoError(t, err)
	assert.NotNil(t, peer)
	assert.NotNil(t, peer.PodSelector)
	assert.Equal(t, map[string]string{"app": "test-pod"}, peer.PodSelector.MatchLabels)

	// Test service
	api.GetPodSpecFunc = func(podIP string) (*api.PodDetail, error) {
		return nil, nil
	}

	api.GetSvcSpecFunc = func(svcIP string) (*api.SvcDetail, error) {
		return &api.SvcDetail{
			Service: corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-svc",
					Namespace: "default",
				},
				Spec: corev1.ServiceSpec{
					Selector: map[string]string{
						"app": "test-svc",
					},
				},
			},
		}, nil
	}

	peer, err = determinePeerForTraffic(traffic, config)
	assert.NoError(t, err)
	assert.NotNil(t, peer)
	assert.NotNil(t, peer.PodSelector)
	assert.Equal(t, map[string]string{"app": "test-pod"}, peer.PodSelector.MatchLabels)

	// Test external IP (no pod or service)
	api.GetSvcSpecFunc = func(svcIP string) (*api.SvcDetail, error) {
		return nil, nil
	}

	peer, err = determinePeerForTraffic(traffic, config)
	assert.NoError(t, err)
	assert.NotNil(t, peer)
	assert.NotNil(t, peer.IPBlock)
	assert.Equal(t, "10.0.0.2/32", peer.IPBlock.CIDR)
}

func TestDeduplicateRules(t *testing.T) {
	// Create test data for ingress rules
	ingressRules := []networkingv1.NetworkPolicyIngressRule{
		{
			Ports: []networkingv1.NetworkPolicyPort{
				{
					Port: &intstr.IntOrString{
						Type:   intstr.String,
						StrVal: "80",
					},
					Protocol: &[]corev1.Protocol{corev1.ProtocolTCP}[0],
				},
			},
			From: []networkingv1.NetworkPolicyPeer{
				{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "test",
						},
					},
				},
			},
		},
		{
			Ports: []networkingv1.NetworkPolicyPort{
				{
					Port: &intstr.IntOrString{
						Type:   intstr.String,
						StrVal: "80",
					},
					Protocol: &[]corev1.Protocol{corev1.ProtocolTCP}[0],
				},
			},
			From: []networkingv1.NetworkPolicyPeer{
				{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "test",
						},
					},
				},
			},
		},
		{
			Ports: []networkingv1.NetworkPolicyPort{
				{
					Port: &intstr.IntOrString{
						Type:   intstr.String,
						StrVal: "443",
					},
					Protocol: &[]corev1.Protocol{corev1.ProtocolTCP}[0],
				},
			},
			From: []networkingv1.NetworkPolicyPeer{
				{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "test",
						},
					},
				},
			},
		},
	}

	deduplicatedRules := deduplicateRules(ingressRules)
	assert.Len(t, deduplicatedRules, 2) // Should deduplicate to 2 rules
}

func TestNetworkPolicyFileOutput(t *testing.T) {
	// Save original functions
	origFetchSinglePod := fetchSinglePodInNamespaceFunc
	origGetPodTrafficFunc := api.GetPodTrafficFunc
	origGetPodSpecFunc := api.GetPodSpecFunc
	origDetectSelectorLabels := detectSelectorLabelsFunc

	// Restore original functions when test completes
	defer func() {
		fetchSinglePodInNamespaceFunc = origFetchSinglePod
		api.GetPodTrafficFunc = origGetPodTrafficFunc
		api.GetPodSpecFunc = origGetPodSpecFunc
		detectSelectorLabelsFunc = origDetectSelectorLabels
	}()

	// Create a temporary directory for the test
	tempDir := t.TempDir()

	// Set up a test pod
	testPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			Labels: map[string]string{
				"app": "test-pod",
			},
		},
	}

	// Mock the functions
	fetchSinglePodInNamespaceFunc = func(podName, namespace string, config *Config) (*corev1.Pod, error) {
		return testPod, nil
	}

	api.GetPodTrafficFunc = func(podName string) ([]api.PodTraffic, error) {
		return []api.PodTraffic{
			{
				SrcIP:       "10.0.0.1",
				TrafficType: "INGRESS",
				SrcPodPort:  "80",
				Protocol:    corev1.ProtocolTCP,
			},
		}, nil
	}

	api.GetPodSpecFunc = func(podIP string) (*api.PodDetail, error) {
		return &api.PodDetail{
			Name:      "test-pod",
			Namespace: "default",
			Pod:       *testPod,
		}, nil
	}

	detectSelectorLabelsFunc = func(clientset *kubernetes.Clientset, origin interface{}) (map[string]string, error) {
		return map[string]string{"app": "test-pod"}, nil
	}

	// Create a config with output directory
	config := &Config{
		Clientset: &kubernetes.Clientset{},
		DryRun:    true,
		OutputDir: tempDir,
	}

	// Define options
	options := GenerateOptions{
		Mode:      SinglePod,
		PodName:   "test-pod",
		Namespace: "default",
	}

	// Call the function
	GenerateNetworkPolicy(options, config)

	// Check if the file was created
	expectedFilePath := filepath.Join(tempDir, "default-test-pod-networkpolicy.yaml")
	_, err := os.Stat(expectedFilePath)
	assert.NoError(t, err, "File should exist")

	// Verify file content
	content, err := os.ReadFile(expectedFilePath)
	assert.NoError(t, err, "Should be able to read file")

	// Basic checks on content
	assert.Contains(t, string(content), "kind: NetworkPolicy", "File should contain NetworkPolicy resource")
	assert.Contains(t, string(content), "name: test-pod", "File should reference the pod name")
	assert.Contains(t, string(content), "namespace: default", "File should reference the namespace")
}

// Create a test config
