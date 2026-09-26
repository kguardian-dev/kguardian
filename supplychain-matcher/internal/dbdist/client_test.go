package dbdist

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v6 "github.com/anchore/grype/grype/db/v6"
	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/klauspost/compress/zstd"
)

type entry struct {
	name string
	body string
	typ  byte
}

func tarZst(t *testing.T, es ...entry) []byte {
	t.Helper()
	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	for _, e := range es {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Mode: 0o600, Size: int64(len(e.body)), Typeflag: typ}
		if typ == tar.TypeSymlink {
			hdr.Size, hdr.Linkname = 0, "/etc/passwd"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			_, _ = tw.Write([]byte(e.body))
		}
	}
	_ = tw.Close()
	var zb bytes.Buffer
	zw, _ := zstd.NewWriter(&zb)
	_, _ = zw.Write(tb.Bytes())
	_ = zw.Close()
	return zb.Bytes()
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// server serves a v6 listing and one archive.
func server(t *testing.T, archive []byte, checksum string, built time.Time) *httptest.Server {
	t.Helper()
	const name = "vulnerability-db_v6.1.9_test.tar.zst"
	mux := http.NewServeMux()
	mux.HandleFunc("/databases/v6/latest.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"status":"active","schemaVersion":"v6.1.9","built":%q,"path":%q,"checksum":%q}`,
			built.Format(time.RFC3339), name, checksum)
	})
	mux.HandleFunc("/databases/v6/"+name, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			t.Errorf("checksum query leaked to the server: %s", r.URL.RawQuery)
		}
		_, _ = w.Write(archive)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func testClient(t *testing.T, base string) *Client {
	t.Helper()
	c, err := newClient(base, time.Minute, guard{allowLoopbackForTest: true})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDownloadVerifiesAndUnpacks(t *testing.T) {
	archive := tarZst(t, entry{name: "vulnerability.db", body: "sqlite bytes"})
	built := time.Date(2026, 9, 25, 6, 31, 49, 0, time.UTC)
	srv := server(t, archive, sum(archive), built)
	c := testClient(t, srv.URL+"/databases") // http allowed: configured as http

	upd, err := c.IsUpdateAvailable(nil)
	if err != nil || upd == nil {
		t.Fatalf("update: %v %v", upd, err)
	}
	u, err := c.ResolveArchiveURL(*upd)
	if err != nil || !strings.Contains(u, "checksum=sha256") {
		t.Fatalf("resolve: %s %v", u, err)
	}
	dir, err := c.Download(u, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "vulnerability.db"))
	if err != nil || string(b) != "sqlite bytes" {
		t.Fatalf("unpacked %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".archive")); !os.IsNotExist(err) {
		t.Error("archive left behind")
	}

	// Current DB at the same build: no update.
	cur := &v6.Description{SchemaVersion: upd.SchemaVersion, Built: v6.Time{Time: built}}
	if again, err := c.IsUpdateAvailable(cur); err != nil || again != nil {
		t.Errorf("same build offered again: %v %v", again, err)
	}
}

func TestDownloadChecksumMismatch(t *testing.T) {
	archive := tarZst(t, entry{name: "vulnerability.db", body: "x"})
	srv := server(t, archive, "sha256:"+strings.Repeat("0", 64), time.Now())
	c := testClient(t, srv.URL+"/databases")
	upd, _ := c.IsUpdateAvailable(nil)
	u, _ := c.ResolveArchiveURL(*upd)
	dest := t.TempDir()
	if _, err := c.Download(u, dest, nil); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("err %v", err)
	}
	if left, _ := os.ReadDir(dest); len(left) != 0 {
		t.Errorf("temp dir not cleaned: %v", left)
	}
}

func TestExtractRefusesUnsafeEntries(t *testing.T) {
	for name, a := range map[string][]byte{
		"traversal": tarZst(t, entry{name: "../../etc/cron.d/x", body: "x"}),
		"subdir":    tarZst(t, entry{name: "a/b.db", body: "x"}),
		"symlink":   tarZst(t, entry{name: "vulnerability.db", typ: tar.TypeSymlink}),
		"hidden":    tarZst(t, entry{name: ".ssh", body: "x"}),
		"empty":     tarZst(t),
		"too many files": func() []byte {
			var es []entry
			for i := 0; i <= MaxFiles; i++ {
				es = append(es, entry{name: fmt.Sprintf("f%02d", i), body: "x"})
			}
			return tarZst(t, es...)
		}(),
	} {
		srv := server(t, a, sum(a), time.Now())
		c := testClient(t, srv.URL+"/databases")
		upd, _ := c.IsUpdateAvailable(nil)
		u, _ := c.ResolveArchiveURL(*upd)
		if _, err := c.Download(u, t.TempDir(), nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestResolveRefusesEscapingPaths(t *testing.T) {
	c := testClient(t, "https://mirror.example/databases")
	for _, p := range []string{"../x.tar.zst", "/etc/x.tar.zst", "https://evil.example/x.tar.zst", "a/../../x"} {
		if _, err := c.ResolveArchiveURL(v6dist.Archive{Path: p}); err == nil {
			t.Errorf("accepted %q", p)
		}
	}
	u, err := c.ResolveArchiveURL(v6dist.Archive{Path: "vulnerability-db_v6.tar.zst", Checksum: "sha256:ab"})
	if err != nil || u != "https://mirror.example/databases/v6/vulnerability-db_v6.tar.zst?checksum=sha256%3Aab" {
		t.Errorf("resolve %s %v", u, err)
	}
}

func TestSchemeAndAddressPolicy(t *testing.T) {
	for _, bad := range []string{"git::https://x/y", "s3://bucket/x", "file:///etc", "ftp://x/y", "relative/path"} {
		if _, err := New(bad, 0); err == nil {
			t.Errorf("accepted base %q", bad)
		}
	}
	// https base: an http redirect or archive URL is refused.
	c, _ := New("https://grype.anchore.io/databases", 0)
	if err := c.checkScheme(mustURL("http://grype.anchore.io/x.tar.zst")); err == nil {
		t.Error("http accepted for an https-configured client")
	}
	// Metadata / loopback literals refused even for an http-configured mirror.
	h, _ := New("http://10.0.0.5/databases", 0)
	for _, u := range []string{"http://169.254.169.254/latest", "http://127.0.0.1/x", "http://[::1]/x", "http://[fe80::1]/x"} {
		var be *BlockedError
		if err := h.checkScheme(mustURL(u)); !errors.As(err, &be) {
			t.Errorf("%s: %v", u, err)
		}
	}
	if err := h.checkScheme(mustURL("http://10.0.0.5/databases/v6/x.tar.zst")); err != nil {
		t.Errorf("private mirror refused: %v", err)
	}
	g := guard{}
	for _, ip := range []string{"169.254.169.254", "127.0.0.1", "::1", "0.0.0.0", "224.0.0.1", "fe80::1"} {
		if g.checkIP(netip.MustParseAddr(ip)) == nil {
			t.Errorf("%s allowed", ip)
		}
	}
	for _, ip := range []string{"10.0.0.5", "192.168.1.1", "8.8.8.8"} {
		if g.checkIP(netip.MustParseAddr(ip)) != nil {
			t.Errorf("%s refused", ip)
		}
	}
}

// A redirect to the metadata address is refused, and the dial guard also
// refuses loopback when the test exemption is off.
func TestRedirectAndDialGuard(t *testing.T) {
	archive := tarZst(t, entry{name: "vulnerability.db", body: "x"})
	mux := http.NewServeMux()
	mux.HandleFunc("/databases/v6/latest.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"status":"active","schemaVersion":"v6.1.9","built":"2026-09-25T00:00:00Z","path":"x.tar.zst","checksum":%q}`, sum(archive))
	})
	mux.HandleFunc("/databases/v6/x.tar.zst", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/x.tar.zst", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := testClient(t, srv.URL+"/databases")
	upd, _ := c.IsUpdateAvailable(nil)
	u, _ := c.ResolveArchiveURL(*upd)
	_, err := c.Download(u, t.TempDir(), nil)
	var be *BlockedError
	if !errors.As(err, &be) {
		t.Fatalf("redirect to metadata: %v", err)
	}
	strict, _ := New(srv.URL+"/databases", 5*time.Second)
	if _, err := strict.Latest(); !errors.As(err, &be) {
		t.Fatalf("loopback dial: %v", err)
	}
}

func mustURL(s string) *url.URL { u, _ := url.Parse(s); return u }
