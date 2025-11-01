package network

import (
	"fmt"

	log "github.com/rs/zerolog/log"
	api "github.com/kguardian-dev/kguardian/advisor/pkg/api"
	"github.com/kguardian-dev/kguardian/advisor/pkg/common"
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
func (s *PolicyService) GeneratePolicy(podName string, policyType PolicyType) (*PolicyOutput, error) {
	// Get the pod traffic data
	podTraffic, err := api.GetPodTraffic(podName)
	if err != nil {
		log.Debug().Err(err).Msgf("Error retrieving %s pod traffic", podName)
		return nil, err
	}

	if len(podTraffic) == 0 {
		return nil, fmt.Errorf("no traffic data found for pod %s", podName)
	}

	// Use the first traffic record's source IP to get pod details.
	// This assumes all traffic records for a pod will have the same relevant source/dest IP for spec lookup.
	lookupIP := ""
	if len(podTraffic) > 0 {
		if podTraffic[0].SrcIP != "" {
			lookupIP = podTraffic[0].SrcIP
		} else if podTraffic[0].DstIP != "" { // Fallback if SrcIP is empty for some reason
			lookupIP = podTraffic[0].DstIP
		}
	}
	if lookupIP == "" {
		return nil, fmt.Errorf("could not determine IP for pod spec lookup for pod %s", podName)
	}

	// Get the pod details
	podDetail, err := api.GetPodSpec(lookupIP)
	if err != nil {
		log.Error().Err(err).Msgf("Error retrieving pod spec using IP %s for pod %s", lookupIP, podName)
		return nil, err
	}

	if podDetail == nil {
		return nil, fmt.Errorf("pod details not found using IP %s for pod %s", lookupIP, podName)
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
	policy, err := generator.Generate(podName, podTraffic, podDetail)
	if err != nil {
		log.Error().Err(err).Msgf("Error generating %s policy for pod %s", policyType, podName)
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
func (s *PolicyService) GenerateAndHandlePolicy(podName string, policyType PolicyType) error {
	output, err := s.GeneratePolicy(podName, policyType)
	if err != nil {
		return err
	}
	if output == nil { // Handle case where policy generation results in nil output (e.g., no traffic)
		log.Info().Msgf("No policy generated for pod %s (policy type: %s), likely due to no traffic data or other issue.", podName, policyType)
		return nil
	}

	return s.HandlePolicyOutput(output)
}

// BatchGenerateAndHandlePolicies generates and handles policies for multiple pods
func (s *PolicyService) BatchGenerateAndHandlePolicies(podNames []string, policyType PolicyType) error {
	var firstError error // Store the first error encountered

	for _, podName := range podNames {
		if err := s.GenerateAndHandlePolicy(podName, policyType); err != nil {
			log.Error().Err(err).Msgf("Error generating and handling policy for pod %s", podName)
			// Store the first error but continue processing other pods
			if firstError == nil {
				firstError = err
			}
			continue
		}
	}

	return firstError // Return the first error encountered, if any
}
