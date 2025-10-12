package k8s

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/rs/zerolog/log"
	api "github.com/xentra-ai/advisor/pkg/api"
)

// SeccompProfile represents the structure of a seccomp security profile
type SeccompProfile struct {
	DefaultAction string   `json:"defaultAction"`
	Architectures []string `json:"architectures"`
	Syscalls      []Rule   `json:"syscalls"`
}

// Rule represents a seccomp rule with action and syscalls
type Rule struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
}

func GenerateSeccompProfile(options GenerateOptions, config *Config) {

	var architectures = map[string][]string{
		"x86_64": {"SCMP_ARCH_X86_64"},
		"arm64":  {"SCMP_ARCH_ARM64"},
	}

	defaultAction := options.DefaultAction
	if defaultAction == "" {
		defaultAction = "SCMP_ACT_ERRNO"
	}

	outputDir := options.OutputDir
	if outputDir == "" && config != nil {
		outputDir = config.OutputDir
	}
	if outputDir == "" {
		outputDir = "seccomp-profiles"
	}
	if config != nil {
		config.OutputDir = outputDir
	}

	// Fetch pods based on options
	pods := GetResource(options, config)

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatal().Err(err).Msgf("failed to create output directory")
	}

	// Generate seccompprofile for each pod in pods
	for _, pod := range pods {
		podSysCalls, err := api.GetPodSysCall(pod.Name)
		if err != nil {
			log.Debug().Err(err).Msgf("Error retrieving %s pod syscall", pod.Name)
			continue
		}

		archKey := strings.ToLower(podSysCalls.Arch)
		archList, ok := architectures[archKey]
		if !ok || len(archList) == 0 {
			log.Warn().Msgf("Unknown architecture %q for pod %s, defaulting to SCMP_ARCH_X86_64", podSysCalls.Arch, pod.Name)
			archList = []string{"SCMP_ARCH_X86_64"}
		}

		profile := SeccompProfile{
			DefaultAction: defaultAction,
			Architectures: archList,
			Syscalls: []Rule{
				{
					Names:  podSysCalls.Syscalls,
					Action: "SCMP_ACT_ALLOW",
				},
			},
		}

		if err := ValidateProfile(profile); err != nil {
			log.Error().Err(err).Msgf("Generated profile for pod %s failed validation", pod.Name)
			continue
		}

		// Generate profile JSON
		profileJSON, err := json.MarshalIndent(profile, "", "    ")
		if err != nil {
			log.Error().Err(err).Msgf("Failed to marshal profile for pod %s", pod.Name)
			continue
		}

		// Write profile to file
		filename := filepath.Join(outputDir, fmt.Sprintf("%s-seccomp.json", pod.Name))
		if err := os.WriteFile(filename, profileJSON, 0644); err != nil {
			log.Error().Err(err).Msgf("Failed to write profile for pod %s", pod.Name)
			continue
		}

		log.Info().Msgf("Generated seccomp profile for pod %s: %s", pod.Name, filename)
	}
}

// ValidateProfile checks if the generated profile is valid
func ValidateProfile(profile SeccompProfile) error {
	if profile.DefaultAction == "" {
		return fmt.Errorf("default action is required")
	}

	if len(profile.Architectures) == 0 {
		return fmt.Errorf("at least one architecture must be specified")
	}

	if len(profile.Syscalls) == 0 {
		return fmt.Errorf("at least one syscall rule must be specified")
	}

	return nil
}

// Helper function to merge multiple syscall lists
func MergeSyscalls(syscallLists ...[]string) []string {
	syscallMap := make(map[string]struct{})

	for _, list := range syscallLists {
		for _, syscall := range list {
			syscallMap[syscall] = struct{}{}
		}
	}

	merged := make([]string, 0, len(syscallMap))
	for syscall := range syscallMap {
		merged = append(merged, syscall)
	}

	return merged
}
