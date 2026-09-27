package engine

import (
	"encoding/json"
	"fmt"
	"runtime"
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kguardian-dev/kguardian/supplychain-matcher/internal/wire"
)

// kernelHeadersFanOut is the shape that took down supplychain on
// ghcr.io/open-webui/open-webui:0.11.3 (and python:3.12): one Debian
// linux-libc-dev with ~1 500 files matching ~2 100 kernel CVEs.
func kernelHeadersFanOut(cves, files int) ([]match.Match, []wire.Component) {
	const purl = "pkg:deb/debian/linux-libc-dev@6.1.180-1?arch=amd64&distro=debian-12"
	paths := make([]string, files)
	for i := range paths {
		paths[i] = fmt.Sprintf("usr/include/linux/header-%05d.h", i)
	}
	ms := make([]match.Match, cves)
	for i := range ms {
		ms[i] = match.Match{
			Package: pkg.Package{Name: "linux-libc-dev", Version: "6.1.180-1", Type: "deb", PURL: purl},
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{ID: fmt.Sprintf("CVE-2024-%05d", i), Namespace: "debian:distro:debian:12"},
				Metadata:  &vulnerability.Metadata{Severity: "High"},
			},
		}
	}
	return ms, []wire.Component{{Name: "linux-libc-dev", Version: "6.1.180-1", PURL: purl, FilePaths: paths}}
}

func TestConvertCapsFilePathsOnAKernelHeadersFanOut(t *testing.T) {
	ms, cs := kernelHeadersFanOut(2128, 1520)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	out := convert(ms, pathIndex(cs))
	body, err := json.Marshal(wire.MatchResponse{Vulnerabilities: out})
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2128 {
		t.Fatalf("%d findings", len(out))
	}
	for _, v := range out {
		if len(v.FilePaths) != wire.MaxFilePaths || cap(v.FilePaths) != wire.MaxFilePaths ||
			v.FilePaths[0] != cs[0].FilePaths[0] {
			t.Fatalf("%s: %d paths (cap %d)", v.ID, len(v.FilePaths), cap(v.FilePaths))
		}
	}
	// Uncapped this was ~130 MiB of JSON (2128 x 1520 paths).
	if len(body) > 4<<20 {
		t.Errorf("response %d bytes, want < 4 MiB", len(body))
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 32<<20 {
		t.Errorf("convert+encode allocated %d MiB, want < 32 MiB", alloc>>20)
	}
	t.Logf("2128 CVEs x 1520 files: %d findings, %.1f MiB response, %.1f MiB allocated",
		len(out), float64(len(body))/(1<<20), float64(after.TotalAlloc-before.TotalAlloc)/(1<<20))
}

func TestCapPathsLeavesShortListsAlone(t *testing.T) {
	p := []string{"a", "b"}
	if got := capPaths(p); len(got) != 2 || &got[0] != &p[0] {
		t.Errorf("%v", got)
	}
	if got := capPaths(nil); got != nil {
		t.Errorf("%v", got)
	}
}
