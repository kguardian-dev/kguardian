package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// formatClientVersion is the deterministic formatter behind
// `kguardian version`. Lock the wire shape so release-process scripts
// that grep this output (e.g. CI building images, the chart's
// kubectl-kguardian-version helm-test) don't break on a refactor.

func TestFormatClientVersion_AllFieldsPresent(t *testing.T) {
	var buf bytes.Buffer
	formatClientVersion(&buf, "v1.2.3", "abc1234", "2026-05-10", "go1.22.0", "linux", "amd64")

	out := buf.String()
	for _, want := range []string{
		"Client Version:",
		"Version:    v1.2.3",
		"Git Commit: abc1234",
		"Build Date: 2026-05-10",
		"Go Version: go1.22.0",
		"Platform:   linux/amd64",
	} {
		assert.True(
			t,
			strings.Contains(out, want),
			"output missing %q\nfull output:\n%s",
			want, out,
		)
	}
}

func TestFormatClientVersion_HandlesUnknownPlaceholders(t *testing.T) {
	// Default values when the binary isn't built with -ldflags. The
	// version command must still produce well-formed output rather
	// than empty fields the user can't grep.
	var buf bytes.Buffer
	formatClientVersion(&buf, "development", "unknown", "unknown", "go1.22.0", "linux", "amd64")

	out := buf.String()
	assert.Contains(t, out, "Version:    development")
	assert.Contains(t, out, "Git Commit: unknown")
	assert.Contains(t, out, "Build Date: unknown")
}

func TestFormatClientVersion_AlphabeticalLineCount(t *testing.T) {
	// Six lines: header + five fields. A regression that drops a field
	// would change the count visibly.
	var buf bytes.Buffer
	formatClientVersion(&buf, "v", "g", "b", "go", "os", "arch")
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	assert.Len(t, lines, 6, "expected exactly 6 lines (1 header + 5 fields)")
}

func TestFormatClientVersion_DoesNotPrintTrailingBlankLine(t *testing.T) {
	// The cobra Run() then prints "\nServer Version:" so the formatter
	// must NOT add its own leading/trailing blank line that would
	// produce two newlines in a row.
	var buf bytes.Buffer
	formatClientVersion(&buf, "v", "g", "b", "go", "os", "arch")
	out := buf.String()
	assert.False(t, strings.HasSuffix(out, "\n\n"), "must not double-newline at end")
}
