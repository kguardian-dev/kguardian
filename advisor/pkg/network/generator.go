package network

import (
	"errors"
	"fmt"

	log "github.com/rs/zerolog/log"
	api "github.com/xentra-ai/advisor/pkg/api"
	"github.com/xentra-ai/advisor/pkg/common"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

// PolicyService handles network policy generation and management
type PolicyService struct {
	config      ConfigProvider
	generators  map[PolicyType]PolicyGenerator
	defaultType PolicyType
}

// NewPolicyService creates a new PolicyService
func NewPolicyService(config ConfigProvider, defaultType PolicyType) *PolicyService {
	return &PolicyService{
		config:      config,
		generators:  make(map[PolicyType]PolicyGenerator),
		defaultType: defaultType,
	}
}

// RegisterGenerator registers a policy generator for a specific policy type
func (s *PolicyService) RegisterGenerator(generator PolicyGenerator) {
	s.generators[generator.GetType()] = generator
}

// GeneratePolicy generates a network policy for a pod
func (s *PolicyService) GeneratePolicy(pod *corev1.Pod, policyType PolicyType) (*PolicyOutput, error) {
	if pod == nil {
		return nil, fmt.Errorf("pod reference is nil")
	}

	// Get the pod traffic data
	podTraffic, err := api.GetPodTraffic(pod.Name)
	if err != nil {
		if errors.Is(err, api.ErrNoPodTraffic) {
			log.Info().Msgf("No traffic data available for pod %s; generating baseline policy", pod.Name)
			podTraffic = nil
		} else {
			log.Debug().Err(err).Msgf("Error retrieving %s pod traffic", pod.Name)
			return nil, err
		}
	}

	var lookupIP string
	if len(podTraffic) > 0 {
		if podTraffic[0].SrcIP != "" {
			lookupIP = podTraffic[0].SrcIP
		} else if podTraffic[0].DstIP != "" {
			lookupIP = podTraffic[0].DstIP
		}
	}

	if lookupIP == "" {
		lookupIP = pod.Status.PodIP
	}

	// Get the pod details
	var podDetail *api.PodDetail
	if lookupIP != "" {
		var detailErr error
		podDetail, detailErr = api.GetPodSpec(lookupIP)
		if detailErr != nil {
			log.Debug().Err(detailErr).Msgf("Falling back to live pod metadata for %s", pod.Name)
		}
	} else {
		log.Debug().Msgf("No lookup IP available for pod %s; using live pod metadata", pod.Name)
	}

	if podDetail == nil {
		if pod.Status.PodIP == "" {
			return nil, fmt.Errorf("pod details unavailable for %s and pod IP is empty", pod.Name)
		}
		podDetail = &api.PodDetail{
			UUID:      string(pod.UID),
			PodIP:     pod.Status.PodIP,
			Name:      pod.Name,
			Namespace: pod.Namespace,
			Pod:       *pod,
		}
	}

	// Select the appropriate generator
	generator, exists := s.generators[policyType]
	if !exists {
		// Fall back to the default generator
		generator, exists = s.generators[s.defaultType]
		if !exists {
			return nil, fmt.Errorf("no generator available for policy type %s", policyType)
		}
		log.Warn().Msgf("No generator found for policy type %s, using default type %s", policyType, s.defaultType)
	}

	// Generate the policy
	policy, err := generator.Generate(pod.Name, podTraffic, podDetail)
	if err != nil {
		log.Error().Err(err).Msgf("Error generating %s policy for pod %s", policyType, pod.Name)
		return nil, err
	}

	// Convert to YAML
	policyYAML, err := yaml.Marshal(policy)
	if err != nil {
		log.Error().Err(err).Msgf("Error converting %s policy to YAML", policyType)
		return nil, err
	}

	return &PolicyOutput{
		Policy:    policy,
		YAML:      policyYAML,
		PodName:   podDetail.Name,
		Namespace: podDetail.Namespace,
		Type:      generator.GetType(),
	}, nil
}

// HandlePolicyOutput handles the output of a generated policy
func (s *PolicyService) HandlePolicyOutput(output *PolicyOutput) error {
	resourceType := fmt.Sprintf("%s-networkpolicy", output.Type)

	// Save to file if output directory is specified
	if s.config.GetOutputDir() != "" {
		filename, err := common.SaveToFile(
			s.config.GetOutputDir(),
			resourceType,
			output.Namespace,
			output.PodName,
			output.YAML,
		)
		if err != nil {
			return err
		}

		log.Info().Msgf("Generated %s network policy for pod %s saved to %s",
			output.Type, output.PodName, filename)
	}

	// Print dry run message if in dry run mode
	if s.config.IsDryRun() {
		common.PrintDryRunMessage(resourceType, output.PodName, output.YAML, s.config.GetOutputDir())
	} else {
		// Apply the policy to the cluster
		log.Info().Msgf("Applying %s network policy for pod %s", output.Type, output.PodName)

		// TODO: Implement applying the policy to the cluster
		log.Warn().Msg("Applying network policies is not yet implemented - only saving to files")
	}

	return nil
}

// InitOutputDirectory initializes the output directory
func (s *PolicyService) InitOutputDirectory() error {
	if s.config.IsDryRun() {
		log.Info().Msg("Dry run: Output directory checks will be performed, but policies won't be applied.")
	}

	return common.HandleOutputDir(s.config.GetOutputDir(), "Network policies")
}

// GenerateAndHandlePolicy generates and handles a policy in a single call
func (s *PolicyService) GenerateAndHandlePolicy(pod *corev1.Pod, policyType PolicyType) error {
	output, err := s.GeneratePolicy(pod, policyType)
	if err != nil {
		return err
	}
	if output == nil { // Handle case where policy generation results in nil output (e.g., no traffic)
		log.Info().Msgf("No policy generated for pod %s (policy type: %s), likely due to no traffic data or other issue.", pod.Name, policyType)
		return nil
	}

	return s.HandlePolicyOutput(output)
}

// BatchGenerateAndHandlePolicies generates and handles policies for multiple pods
func (s *PolicyService) BatchGenerateAndHandlePolicies(pods []corev1.Pod, policyType PolicyType) error {
	var firstError error // Store the first error encountered

	for i := range pods {
		if err := s.GenerateAndHandlePolicy(&pods[i], policyType); err != nil {
			log.Error().Err(err).Msgf("Error generating and handling policy for pod %s", pods[i].Name)
			// Store the first error but continue processing other pods
			if firstError == nil {
				firstError = err
			}
			continue
		}
	}

	return firstError // Return the first error encountered, if any
}
