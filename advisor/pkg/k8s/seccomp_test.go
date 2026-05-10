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
