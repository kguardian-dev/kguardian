package k8s

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

// SeccompProfile validation defends the contract the runtime expects:
// a non-empty DefaultAction, at least one architecture, and at least
// one syscall rule. A profile that fails any of these gates would be
// loaded by Docker/CRI-O but produce an unusable result (most likely
// blocking everything because no allow-list rule exists).

func TestNewProfileOptions_AcceptsWhitelistedActions(t *testing.T) {
	// All three values from the cobra help text must round-trip.
	for _, action := range []string{"SCMP_ACT_ERRNO", "SCMP_ACT_KILL", "SCMP_ACT_LOG"} {
		got, err := NewProfileOptions(&Config{OutputDir: "/tmp/x"}, action)
		assert.NoError(t, err, "action=%s", action)
		assert.Equal(t, action, got.DefaultAction, "DefaultAction must thread through")
		assert.Equal(t, "/tmp/x", got.OutputDir, "OutputDir must thread through from Config")
	}
}

func TestNewProfileOptions_RejectsUnknownAction(t *testing.T) {
	// Pre-fix the --default-action flag was a no-op — now it errors
	// loudly when the value isnt recognised. The error message must
	// list both the offending value and the accepted whitelist so the
	// operator doesnt have to consult docs.
	for _, bad := range []string{"", "SCMP_ACT_ALLOW", "SCMP_ACT_KILL_PROCESS", "errno", "scmp_act_kill"} {
		t.Run(bad, func(t *testing.T) {
			_, err := NewProfileOptions(&Config{}, bad)
			assert.Error(t, err)
			if err != nil {
				assert.Contains(t, err.Error(), bad, "error must echo the bad value")
				assert.Contains(t, err.Error(), "SCMP_ACT_ERRNO", "error must list accepted values")
			}
		})
	}
}

func TestNewProfileOptions_FallsBackToDefaultDirWhenConfigEmpty(t *testing.T) {
	// A nil/empty Config.OutputDir means the user didn't pass
	// --output-dir; preserve the historical default of
	// "seccomp-profiles" so previously-written shell scripts keep
	// working without any flag.
	got, err := NewProfileOptions(&Config{}, "SCMP_ACT_ERRNO")
	assert.NoError(t, err)
	assert.Equal(t, "seccomp-profiles", got.OutputDir)

	gotNil, err := NewProfileOptions(nil, "SCMP_ACT_ERRNO")
	assert.NoError(t, err)
	assert.Equal(t, "seccomp-profiles", gotNil.OutputDir, "nil Config must not panic + still default")
}

func TestValidateProfile_Valid(t *testing.T) {
	p := SeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []Rule{
			{Names: []string{"read", "write"}, Action: "SCMP_ACT_ALLOW"},
		},
	}
	assert.NoError(t, ValidateProfile(p))
}

func TestValidateProfile_MissingDefaultAction(t *testing.T) {
	p := SeccompProfile{
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls:      []Rule{{Names: []string{"read"}, Action: "SCMP_ACT_ALLOW"}},
	}
	err := ValidateProfile(p)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "default action")
}

func TestValidateProfile_NoArchitectures(t *testing.T) {
	p := SeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: nil,
		Syscalls:      []Rule{{Names: []string{"read"}, Action: "SCMP_ACT_ALLOW"}},
	}
	err := ValidateProfile(p)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "architecture")
}

func TestValidateProfile_NoSyscalls(t *testing.T) {
	// A profile with no rules and a default-deny action would block
	// every syscall. Could be intentional but we treat empty as a
	// likely operator mistake.
	p := SeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls:      []Rule{},
	}
	err := ValidateProfile(p)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "syscall")
}

func TestValidateProfile_EmptyArchitectureSlice(t *testing.T) {
	// Distinguish nil vs empty — both must be rejected.
	p := SeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{},
		Syscalls:      []Rule{{Names: []string{"read"}, Action: "SCMP_ACT_ALLOW"}},
	}
	err := ValidateProfile(p)
	assert.Error(t, err)
}

// MergeSyscalls deduplicates the union of multiple syscall lists.
// Order of the output is map-iteration-order (non-deterministic), so
// tests compare against sorted slices.

func TestMergeSyscalls_Empty(t *testing.T) {
	assert.Empty(t, MergeSyscalls())
}

func TestMergeSyscalls_SingleListPassthrough(t *testing.T) {
	got := MergeSyscalls([]string{"read", "write", "open"})
	sort.Strings(got)
	assert.Equal(t, []string{"open", "read", "write"}, got)
}

func TestMergeSyscalls_DeduplicatesAcrossLists(t *testing.T) {
	got := MergeSyscalls(
		[]string{"read", "write"},
		[]string{"write", "open"},
		[]string{"read", "close"},
	)
	sort.Strings(got)
	assert.Equal(t, []string{"close", "open", "read", "write"}, got)
}

func TestMergeSyscalls_DeduplicatesWithinSingleList(t *testing.T) {
	got := MergeSyscalls([]string{"read", "read", "write", "write"})
	sort.Strings(got)
	assert.Equal(t, []string{"read", "write"}, got)
}

func TestMergeSyscalls_HandlesEmptyInputs(t *testing.T) {
	got := MergeSyscalls(nil, []string{}, []string{"read"}, nil)
	sort.Strings(got)
	assert.Equal(t, []string{"read"}, got)
}
