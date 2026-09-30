package rootfs

import (
	"bytes"
	"errors"
	"io"
	"runtime"
	"runtime/debug"
	"strings"
)

// Large binaries set the scan's memory peak (dev: 250 MiB Go binaries and
// CUDA libraries up to 690 MiB ran the 640 MiB worker out of memory, and
// the image fell back to os_only). Syft's catalogers buffer much of each
// binary they read: the .NET ELF-bundle search allocates the whole file,
// up to 512 MiB, for every ELF executable and shared library; the Go and
// GraalVM native-image catalogers read symbol tables. Two measures bound
// that without changing what is catalogued:
//
//   - reclaim: before a large file is handed to a cataloger, the previous
//     one's buffers are collected and returned to the kernel, so the peak
//     is one buffer, not the previous one still uncollected plus the next;
//   - the .NET bundle search is only given ELF files that carry the
//     bundle marker (mayBeDotnetBundle). Without it Syft's search finds
//     nothing and yields no package, so leaving those files out changes
//     no result; it only skips the whole-file allocation.

// LargeFileBytes: before a file this large is handed to a cataloger, the
// heap is collected (reclaim).
const LargeFileBytes = 32 << 20

// reclaim collects garbage and returns free memory to the kernel.
var reclaim = debug.FreeOSMemory

// Callers the resolver treats specially, by package path prefix.
const (
	// nixCataloger is the one package cataloger at the pinned Syft that
	// lists every file (the file catalogers, which also do, are off). It
	// keeps only paths in a Nix store, so its listing is recorded as the
	// store globs.
	nixCataloger = "github.com/anchore/syft/syft/pkg/cataloger/nix."
	// dotnetCataloger asks for ELF executables and shared libraries only
	// to look for single-file bundles.
	dotnetCataloger = "github.com/anchore/syft/syft/pkg/cataloger/dotnet."
)

var nixStoreGlobs = []string{"**/nix/store/*", "**/nix/store/*/**"}

// catalogerCaller is the function that called into the resolver: the
// first frame outside this package, Syft's resolver wrappers and the
// runtime.
func catalogerCaller() string {
	pcs := make([]uintptr, 32)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
	for {
		f, more := frames.Next()
		switch fn := f.Function; {
		case strings.HasPrefix(fn, "github.com/kguardian-dev/kguardian/cataloger/internal/rootfs."),
			strings.HasPrefix(fn, "github.com/anchore/syft/syft/internal/fileresolver."),
			strings.HasPrefix(fn, "runtime."):
		default:
			return fn
		}
		if !more {
			return ""
		}
	}
}

// dotnetBundleSignature is Syft's (and the .NET host's) single-file bundle
// marker: the SHA-256 of ".net core bundle".
var dotnetBundleSignature = []byte{
	0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38,
	0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
	0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18,
	0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae,
}

// bundleFilter turns the marker check on (tests compare with it off).
var bundleFilter = true

// bundleSearchBytes is how far Syft's bundle search looks at most
// (maxBundleSearchSize); the marker is looked for in at least that much.
const bundleSearchBytes = 512 << 20

// mayBeDotnetBundle reports whether the file at p can be a .NET
// single-file bundle: it has the marker in its first bundleSearchBytes,
// or it could not be checked (then Syft decides, as before).
func (r *Resolver) mayBeDotnetBundle(p string) (may bool) {
	if bundleCheckHook != nil {
		defer func() { bundleCheckHook(p, may) }()
	}
	f, err := r.root.OpenFile(p)
	if err != nil {
		return true
	}
	defer func() { _ = f.Close() }()
	found, err := hasMarker(io.LimitReader(f, bundleSearchBytes), dotnetBundleSignature)
	return found || err != nil
}

// bundleCheckHook, when set (tests only), sees every marker check.
var bundleCheckHook func(p string, may bool)

// hasMarker streams r looking for marker, in constant memory.
func hasMarker(r io.Reader, marker []byte) (bool, error) {
	const chunk = 1 << 20
	buf := make([]byte, len(marker)-1+chunk)
	keep := 0
	for {
		n, err := io.ReadFull(r, buf[keep:])
		if bytes.Contains(buf[:keep+n], marker) {
			return true, nil
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		// Carry the tail over, so a marker across two reads is found.
		keep = copy(buf, buf[keep+n-(len(marker)-1):keep+n])
	}
}
