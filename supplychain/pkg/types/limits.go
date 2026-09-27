package types

// Limits the broker applies to one vulnerabilities payload
// (broker/src/supplychain.rs MAX_FILE_PATHS and MAX_VULNERABILITIES; a
// test keeps them equal). supplychain applies them before sending, so a
// payload never carries what the broker would throw away.
const (
	// MaxFindingFilePaths is how many of a package's file paths one finding
	// carries. The full list stays in the SBOM, which is what the runtime
	// in-use join reads.
	MaxFindingFilePaths = 16
	// MaxFindings is the most findings one payload may carry.
	MaxFindings = 20000
)

// CapFilePaths returns at most MaxFindingFilePaths of p in a new slice,
// so a capped finding never keeps a long list alive.
func CapFilePaths(p []string) []string {
	if len(p) <= MaxFindingFilePaths {
		return p
	}
	return append([]string(nil), p[:MaxFindingFilePaths]...)
}
