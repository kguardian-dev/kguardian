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
// Values MUST be the OCI runtime-spec (libseccomp) names, which is what runc
// validates against: aarch64 is SCMP_ARCH_AARCH64. SCMP_ARCH_ARM64 is not an
// OCI name, and a profile carrying it fails every pod that references it with
// "string SCMP_ARCH_ARM64 is not a valid arch for seccomp".
var SeccompArchitectures = map[string][]string{
	"x86_64":  {"SCMP_ARCH_X86_64"},
	"aarch64": {"SCMP_ARCH_AARCH64"},
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

// ValidateProfile checks if the generated profile is valid.
//
// Reference implementation: it has no non-test caller in this repo today
// (the CLI path calls BuildSeccompProfile and writes straight out). It is
// kept because the frontend and llm-bridge validators are ports of it and
// the shared G2 fixtures lock all three together, so a change here is how
// a divergence gets caught. Do not assume the Go path enforces this at
// runtime.
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

	// The check above counts RULES. Generators emit exactly one rule even
	// when they observed no syscalls, so it never fires for the profile
	// that matters: a rule whose Names list is empty. Under a denying
	// DefaultAction that permits nothing at all, and the container never
	// starts, because the filter is installed before execve.
	//
	// Only meaningful when the default denies. A permissive default
	// (ALLOW / LOG) with an empty rule is a no-op, not a trap, and
	// audit-only profiles legitimately allow nothing by name.
	if !permissiveAction(profile.DefaultAction) {
		permits := false
		for _, rule := range profile.Syscalls {
			if permissiveAction(rule.Action) && len(rule.Names) > 0 {
				permits = true
				break
			}
		}
		if !permits {
			return fmt.Errorf(
				"defaultAction is %s and no rule allows any syscall, so every syscall would be denied and the container could not start",
				profile.DefaultAction,
			)
		}
	}

	return nil
}

// permissiveAction reports whether an action lets a syscall through.
// Everything else blocks it: ERRNO returns an errno, the KILL_* family
// terminates the process, TRAP raises SIGSYS, and TRACE without a
// listening tracer fails the call, as does NOTIFY with no supervisor
// attached.
//
// Unrecognised actions therefore fail safe: an action added in future
// makes this reject a profile it does not understand rather than pass
// it, which is the right default for a validator.
func permissiveAction(action string) bool {
	return action == "SCMP_ACT_ALLOW" || action == "SCMP_ACT_LOG"
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
