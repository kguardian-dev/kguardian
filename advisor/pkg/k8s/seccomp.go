package k8s

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	api "github.com/kguardian-dev/kguardian/advisor/pkg/api"
	log "github.com/rs/zerolog/log"
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

// ProfileOptions contains configuration for profile generation
type ProfileOptions struct {
	OutputDir     string
	DefaultAction string
	Architectures []string
}

// ValidSeccompActions is the whitelist of `defaultAction` values
// accepted by the CLI. Matches the help text the cobra flag advertises;
// expand cautiously — operators rely on the documented value being
// what the generated profile actually emits.
var ValidSeccompActions = []string{"SCMP_ACT_ERRNO", "SCMP_ACT_KILL", "SCMP_ACT_LOG"}

// SeccompArchitectures maps a captured CPU architecture (as recorded by the
// controller) to the seccomp arch tokens. Exported so callers that build a
// profile outside the file-writing GenerateSeccompProfile path (e.g. the
// `serve` HTTP API) reuse the same mapping rather than duplicating it.
// Keys MUST match the arch string the controller records, which is Rust's
// std::env::consts::ARCH (controller/src/syscall.rs) — i.e. "x86_64" or
// "aarch64". The previous "ARM64" key never matched anything the controller
// writes, so on ARM/aarch64 nodes the lookup missed and the generated profile
// had "architectures": null — a structurally invalid, unusable seccomp profile.
var SeccompArchitectures = map[string][]string{
	"x86_64":  {"SCMP_ARCH_X86_64"},
	"aarch64": {"SCMP_ARCH_ARM64"},
}

// BuildSeccompProfile constructs a SeccompProfile that allow-lists exactly the
// observed syscalls and denies everything else via defaultAction. It is the
// single source of truth for profile shape, shared between the CLI's
// file-writing path and the serve API. An empty defaultAction falls back to
// SCMP_ACT_ERRNO so callers always get a syntactically valid profile.
func BuildSeccompProfile(syscalls []string, arch, defaultAction string) SeccompProfile {
	if defaultAction == "" {
		defaultAction = "SCMP_ACT_ERRNO"
	}
	return SeccompProfile{
		DefaultAction: defaultAction,
		Architectures: SeccompArchitectures[arch],
		Syscalls: []Rule{
			{
				Names:  syscalls,
				Action: "SCMP_ACT_ALLOW",
			},
		},
	}
}

// NewProfileOptions constructs ProfileOptions from CLI input. A
// previous version of GenerateSeccompProfile hardcoded both OutputDir
// and DefaultAction inside the function, silently ignoring the
// equivalent CLI flags. This constructor is the seam that wires both
// through and validates DefaultAction against the documented set.
func NewProfileOptions(config *Config, defaultAction string) (ProfileOptions, error) {
	valid := false
	for _, v := range ValidSeccompActions {
		if v == defaultAction {
			valid = true
			break
		}
	}
	if !valid {
		return ProfileOptions{}, fmt.Errorf(
			"invalid default action %q; must be one of %v",
			defaultAction, ValidSeccompActions,
		)
	}
	outputDir := "seccomp-profiles"
	if config != nil && config.OutputDir != "" {
		outputDir = config.OutputDir
	}
	return ProfileOptions{
		OutputDir:     outputDir,
		DefaultAction: defaultAction,
	}, nil
}

func GenerateSeccompProfile(options GenerateOptions, config *Config, profileOpts ProfileOptions) {

	// Defensive defaults so a caller passing the zero ProfileOptions
	// (e.g. in a test) still produces a syntactically-valid profile.
	if profileOpts.OutputDir == "" {
		profileOpts.OutputDir = "seccomp-profiles"
	}
	if profileOpts.DefaultAction == "" {
		profileOpts.DefaultAction = "SCMP_ACT_ERRNO"
	}

	// Fetch pods based on options
	pods := GetResource(options, config)

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(profileOpts.OutputDir, 0755); err != nil {
		log.Fatal().Err(err).Msgf("failed to create output directory")
	}

	// Generate seccompprofile for each pod in pods
	for _, pod := range pods {
		podSysCalls, err := api.GetPodSysCall(pod.Name)
		if err != nil {
			log.Debug().Err(err).Msgf("Error retrieving %s pod syscall", pod.Name)
			continue
		}

		profile := BuildSeccompProfile(podSysCalls.Syscalls, podSysCalls.Arch, profileOpts.DefaultAction)

		// Generate profile JSON
		profileJSON, err := json.MarshalIndent(profile, "", "    ")
		if err != nil {
			log.Error().Err(err).Msgf("Failed to marshal profile for pod %s", pod.Name)
			continue
		}

		// Write profile to file
		filename := filepath.Join(profileOpts.OutputDir, fmt.Sprintf("%s-seccomp.json", pod.Name))
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
