package match

import (
	"encoding/json"
	"fmt"
	"runtime"
	"sync"
	"testing"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// fatSBOM is shaped like a Debian-based Python image with a registry SBOM
// that lists files (open-webui:0.11.3's kind): linux-libc-dev with ~900
// headers, 450 more debs and 800 Python packages. It is decoded from JSON
// as the sources do, so every string is its own allocation.
func fatSBOM(t testing.TB, digest string) *types.ImageSBOM {
	t.Helper()
	fatOnce.Do(func() { fatJSON, fatErr = json.Marshal(buildFat()) })
	if fatErr != nil {
		t.Fatal(fatErr)
	}
	var out types.ImageSBOM
	if err := json.Unmarshal(fatJSON, &out); err != nil {
		t.Fatal(err)
	}
	out.Image.Digest = digest
	return &out
}

var (
	fatOnce sync.Once
	fatJSON []byte
	fatErr  error
)

func buildFat() types.ImageSBOM {
	s := types.ImageSBOM{Source: types.SourceRegistry, SBOMTrust: types.SBOMTrustUnverified}
	add := func(name, typ, purl string, files int, dir string) {
		c := types.Component{Name: name, Version: "1.2.3-4", Type: typ, PURL: purl, Licenses: []string{"MIT"}}
		for i := range files {
			c.FilePaths = append(c.FilePaths, fmt.Sprintf("%s/%s/file-%04d.h", dir, name, i))
		}
		s.Components = append(s.Components, c)
	}
	add("linux-libc-dev", "deb", "pkg:deb/debian/linux-libc-dev@6.1.180-1?arch=amd64&distro=debian-12", 907, "usr/include/linux")
	for i := range 450 {
		n := fmt.Sprintf("libdeb%03d", i)
		add(n, "deb", "pkg:deb/debian/"+n+"@1.2.3-4?arch=amd64&distro=debian-12", 40, "usr/lib/x86_64-linux-gnu")
	}
	for i := range 800 {
		n := fmt.Sprintf("pypkg%03d", i)
		add(n, "python", "pkg:pypi/"+n+"@1.2.3", 25, "usr/local/lib/python3.12/site-packages")
	}
	return s
}

func heapInuse() uint64 {
	var ms runtime.MemStats
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&ms)
	return ms.HeapInuse
}

// The estimate is what the budget counts, so it has to follow the heap,
// for a registry SBOM that lists files and for a Trivy one that does not.
func TestHeldBytesTracksTheHeap(t *testing.T) {
	shapes := map[string]func(d string) *types.ImageSBOM{
		"registry, with files": func(d string) *types.ImageSBOM { return fatSBOM(t, d) },
		"trivy, no files": func(d string) *types.ImageSBOM {
			s := fatSBOM(t, d)
			for i := range s.Components {
				s.Components[i].FilePaths = nil
			}
			return s
		},
	}
	for name, mk := range shapes {
		const n = 8
		before := heapInuse()
		keep := make([]*types.ImageSBOM, n)
		var est int64
		for i := range keep {
			keep[i] = mk(fmt.Sprintf("sha256:%d", i))
			est += heldBytes(keep[i])
		}
		after := heapInuse()
		runtime.KeepAlive(keep)
		real := int64(after - before)
		ratio := float64(real) / float64(est)
		t.Logf("%s: %d SBOMs x %d components: estimate %.1f MiB, heap %.1f MiB (heap/estimate %.2f)",
			name, n, len(keep[0].Components), float64(est)/(1<<20), float64(real)/(1<<20), ratio)
		if ratio < 0.8 || ratio > 1.25 {
			t.Errorf("%s: heap/estimate %.2f outside 0.8-1.25", name, ratio)
		}
	}
}

// Past the byte budget the least recently offered digests go first, and
// what is held stays within it, on the heap too.
func TestByteBudgetEvictsLeastRecentlyOffered(t *testing.T) {
	c, mt := newCoord(&mockMatcher{}, "")
	one := heldBytes(fatSBOM(t, "sha256:probe"))
	c.MaxHeldBytes = 3*one + one/2 // room for three

	before := heapInuse()
	for i := range 10 {
		c.Offer(fatSBOM(t, fmt.Sprintf("sha256:%d", i)))
	}
	after := heapInuse()
	if c.Held() != 3 {
		t.Fatalf("held %d, want 3", c.Held())
	}
	for _, d := range []string{"sha256:7", "sha256:8", "sha256:9"} {
		if _, ok := c.sboms[d]; !ok {
			t.Errorf("%s (most recent) evicted", d)
		}
	}
	if c.heldBytes != 3*one || testutil.ToFloat64(mt.GrypeSBOMBytesHeld) != float64(3*one) {
		t.Errorf("held bytes %d (gauge %v), want %d", c.heldBytes, testutil.ToFloat64(mt.GrypeSBOMBytesHeld), 3*one)
	}
	if v := testutil.ToFloat64(mt.GrypeSBOMsEvicted.WithLabelValues("bytes")); v != 7 {
		t.Errorf("evicted(bytes) = %v, want 7", v)
	}
	if real := int64(after) - int64(before); real > c.MaxHeldBytes*125/100 {
		t.Errorf("heap grew %.1f MiB holding a %.1f MiB budget", float64(real)/(1<<20), float64(c.MaxHeldBytes)/(1<<20))
	}
	runtime.KeepAlive(c)
}

// Re-offering the same (digest, source) replaces it; it is not counted twice.
func TestReofferIsNotCountedTwice(t *testing.T) {
	c, _ := newCoord(&mockMatcher{}, "")
	s := fatSBOM(t, "sha256:a")
	for range 5 {
		c.Offer(s)
	}
	c.Offer(trivySBOM("sha256:a", "openssl"))
	if want := heldBytes(s) + heldBytes(trivySBOM("sha256:a", "openssl")); c.heldBytes != want || c.Held() != 1 {
		t.Fatalf("held bytes %d, want %d (held %d)", c.heldBytes, want, c.Held())
	}
}

// One SBOM bigger than the whole budget is still matched: it is held
// alone, and nothing it evicts is left counted.
func TestOversizedSBOMIsHeldAlone(t *testing.T) {
	c, _ := newCoord(&mockMatcher{}, "")
	c.Offer(trivySBOM("sha256:small", "openssl"))
	big := fatSBOM(t, "sha256:big")
	c.MaxHeldBytes = heldBytes(big) / 2
	c.Offer(big)
	if c.Held() != 1 || c.heldBytes != heldBytes(big) {
		t.Fatalf("held %d, bytes %d", c.Held(), c.heldBytes)
	}
	if _, ok := c.queue[c.groupKeyLocked("sha256:big")]; !ok {
		t.Error("oversized SBOM not queued for matching")
	}
}

// The default budget, measured: how many fat SBOMs it holds and what the
// heap actually is at the cap.
func TestDefaultBudgetOnTheHeap(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates ~100 MiB")
	}
	c, mt := newCoord(&mockMatcher{}, "")
	before := heapInuse()
	for i := range 40 {
		c.Offer(fatSBOM(t, fmt.Sprintf("sha256:%d", i)))
	}
	after := heapInuse()
	real := int64(after) - int64(before)
	t.Logf("default %d MiB budget: %d of 40 fat SBOMs held, estimate %.1f MiB, heap %.1f MiB, evicted %v",
		DefaultMaxHeldBytes>>20, c.Held(), float64(c.heldBytes)/(1<<20), float64(real)/(1<<20),
		testutil.ToFloat64(mt.GrypeSBOMsEvicted.WithLabelValues("bytes")))
	if c.heldBytes > DefaultMaxHeldBytes || real > DefaultMaxHeldBytes*115/100 {
		t.Errorf("over budget: estimate %d, heap %d", c.heldBytes, real)
	}
	runtime.KeepAlive(c)
}
