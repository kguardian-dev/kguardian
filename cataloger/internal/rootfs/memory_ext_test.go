package rootfs_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/anchore/syft/syft"
	"golang.org/x/sys/unix"

	"github.com/kguardian-dev/kguardian/cataloger/internal/protocol"
	"github.com/kguardian-dev/kguardian/cataloger/internal/rootfs"
	"github.com/kguardian-dev/kguardian/cataloger/internal/scan"
)

var bundleMarker = []byte{
	0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38,
	0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
	0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18,
	0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae,
}

const depsJSON = `{
  "runtimeTarget": {"name": ".NETCoreApp,Version=v8.0/linux-x64"},
  "targets": {
    ".NETCoreApp,Version=v8.0/linux-x64": {
      "myapp/1.0.0": {"dependencies": {"Newtonsoft.Json": "13.0.3"}, "runtime": {"myapp.dll": {}}},
      "Newtonsoft.Json/13.0.3": {"runtime": {"lib/net6.0/Newtonsoft.Json.dll": {"assemblyVersion": "13.0.0.0", "fileVersion": "13.0.3.27908"}}}
    }
  },
  "libraries": {
    "myapp/1.0.0": {"type": "project", "serviceable": false, "sha512": ""},
    "Newtonsoft.Json/13.0.3": {"type": "package", "serviceable": true,
      "sha512": "sha512-HrC5BXdl00IP9zeV+0Z848QWPAoCr9P3bDEZguI+gkLcBKAOxix/tLEAAHC+UvDNPv4a2d18lOReHMOagPa+zQ==",
      "path": "newtonsoft.json/13.0.3", "hashPath": "newtonsoft.json.13.0.3.nupkg.sha512"}
  }
}`

// elf64 is a minimal ELF64 executable of total bytes whose one PT_LOAD
// segment spans the whole file, with body copied in after the headers.
func elf64(total int, body func(b []byte)) []byte {
	b := make([]byte, total)
	copy(b, "\x7fELF")
	b[4], b[5], b[6] = 2, 1, 1
	le := binary.LittleEndian
	le.PutUint16(b[16:], 2)    // ET_EXEC
	le.PutUint16(b[18:], 0x3e) // x86-64
	le.PutUint32(b[20:], 1)
	le.PutUint64(b[32:], 64) // e_phoff
	le.PutUint16(b[52:], 64)
	le.PutUint16(b[54:], 56)
	le.PutUint16(b[56:], 1)
	ph := b[64:]
	le.PutUint32(ph[0:], 1) // PT_LOAD
	le.PutUint64(ph[32:], uint64(total))
	le.PutUint64(ph[40:], uint64(total))
	body(b)
	return b
}

// singleFileBundle is an ELF .NET 8 single-file bundle whose manifest
// header points straight at an embedded deps.json.
func singleFileBundle() []byte {
	const total, sigAt, header, deps = 64 << 10, 4096, 8192, 16384
	return elf64(total, func(b []byte) {
		le := binary.LittleEndian
		le.PutUint64(b[sigAt-8:], header)
		copy(b[sigAt:], bundleMarker)
		h := b[header:]
		le.PutUint32(h[0:], 6) // major
		le.PutUint32(h[4:], 0)
		le.PutUint32(h[8:], 1) // files
		h[12] = 4              // bundle id, 7-bit length prefixed
		copy(h[13:], "abcd")
		v2 := h[17:]
		le.PutUint64(v2[0:], deps)
		le.PutUint64(v2[8:], uint64(len(depsJSON)))
		copy(b[deps:], depsJSON)
	})
}

func scanRoot(t *testing.T, dir string) *protocol.Response {
	t.Helper()
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	return scan.Run(context.Background(), fd, scan.Options{Profile: protocol.ProfileFull,
		Budgets: protocol.Budgets{}.Effective(), CapsModel: "i", Version: "test"})
}

// The .NET bundle search only sees ELF files with the bundle marker, and
// that changes no result: a real bundle is still found, and the packages
// are the same with the check off. A large ELF without the marker is
// never given to it, and a large file is read after a collection.
func TestDotnetBundleCheckKeepsResults(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"etc", "app", "usr/bin"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p string, b []byte, mode os.FileMode) {
		if err := os.WriteFile(filepath.Join(dir, p), b, mode); err != nil {
			t.Fatal(err)
		}
	}
	write("etc/os-release", []byte("ID=debian\nVERSION_ID=12\n"), 0o644)
	write("app/myapp", singleFileBundle(), 0o755)
	// 40 MiB, the marker nowhere: the search used to allocate all of it.
	write("usr/bin/big", elf64(40<<20, func([]byte) {}), 0o755)
	// A marker straddling the scanner's 1 MiB reads.
	write("usr/bin/straddle", elf64(3<<20, func(b []byte) { copy(b[1<<20-10:], bundleMarker) }), 0o755)

	var mu sync.Mutex
	checked := map[string]bool{}
	defer rootfs.OnBundleCheck(func(p string, may bool) {
		mu.Lock()
		checked[p] = may
		mu.Unlock()
	})()
	reclaims := 0
	defer rootfs.SetReclaim(func() { reclaims++ })()
	defer rootfs.SetReclaimAbove(0)()

	on := scanRoot(t, dir)
	if on.Status != protocol.StatusOK {
		t.Fatalf("%s %s: %s", on.Status, on.Reason, on.Message)
	}
	want := map[string]bool{"/app/myapp": true, "/usr/bin/big": false, "/usr/bin/straddle": true}
	if !reflect.DeepEqual(checked, want) {
		t.Errorf("marker checks %v, want %v", checked, want)
	}
	if reclaims == 0 || on.Stats.Reclaims != int64(reclaims) {
		t.Errorf("collections before the 40 MiB file: %d, stats %d", reclaims, on.Stats.Reclaims)
	}
	found := false
	for _, c := range on.Components {
		if c.Name == "Newtonsoft.Json" && c.Version == "13.0.3" {
			found = true
		}
	}
	if !found {
		t.Errorf("bundled package not found: %+v", on.Components)
	}

	defer rootfs.SetBundleFilter(false)()
	off := scanRoot(t, dir)
	on.Stats, off.Stats = protocol.Stats{}, protocol.Stats{}
	a, b := mustJSON(t, on), mustJSON(t, off)
	if !bytes.Equal(a, b) {
		t.Errorf("results differ with the check:\non  %s\noff %s", a, b)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The .NET bundle check applies to one query only: the one
// dotnet.findELFBundledDepsJSON makes, for exactly ELF executables and
// shared libraries. Any other MIME query from that package is answered in
// full (the filter is keyed on the exact caller and types), so a Syft
// that adds one loses no package; this fails so the filter is reviewed.
func TestDotnetBundleQueryIsTheOnlyOneFromDotnet(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "etc/os-release"), []byte("ID=debian\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	r, err := rootfs.Open(fd, scan.RootOptions(protocol.ProfileFull, protocol.Budgets{}.Effective(), nil, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	src := rootfs.NewSource(r)
	if _, err := syft.CreateSBOM(context.Background(), src, scan.SyftConfig(protocol.ProfileFull, "test")); err != nil {
		t.Fatal(err)
	}
	const want = "github.com/anchore/syft/syft/pkg/cataloger/dotnet.findELFBundledDepsJSON: application/x-executable,application/x-sharedlib"
	var fromDotnet []string
	for _, q := range src.Resolver().MIMEQueries() {
		if strings.HasPrefix(q, "github.com/anchore/syft/syft/pkg/cataloger/dotnet.") {
			fromDotnet = append(fromDotnet, q)
		}
	}
	if len(fromDotnet) != 1 || fromDotnet[0] != want {
		t.Errorf("MIME queries from the .NET catalogers: %q, want only %q", fromDotnet, want)
	}
}
