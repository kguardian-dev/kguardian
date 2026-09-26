package dbdist

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	v6 "github.com/anchore/grype/grype/db/v6"
	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/klauspost/compress/zstd"
	"github.com/wagoodman/go-progress"
)

// Limits.
const (
	maxListingBytes = 1 << 20
	// MaxArchiveBytes caps the compressed download (181 MB measured
	// 2026-09-26).
	MaxArchiveBytes = 2 << 30
	// MaxFileBytes caps one unpacked file (2.36 GB measured).
	MaxFileBytes = 16 << 30
	// MaxTotalBytes and MaxFiles cap the whole unpacked archive (one
	// 2.36 GB file measured).
	MaxTotalBytes = 20 << 30
	MaxFiles      = 16
	maxRedirects  = 5
)

// Client is a grype distribution.Client that downloads over plain HTTP(S).
type Client struct {
	listing   *url.URL
	allowHTTP bool
	guard     guard
	http      *http.Client
}

var _ v6dist.Client = (*Client)(nil)

// New returns a Client for the listing base URL (e.g.
// https://grype.anchore.io/databases, or a URL ending in .json). http is
// allowed only when baseURL itself is http.
func New(baseURL string, timeout time.Duration) (*Client, error) {
	return newClient(baseURL, timeout, guard{})
}

func newClient(baseURL string, timeout time.Duration, g guard) (*Client, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("DB URL %q must be an absolute https:// (or explicitly http://) URL", baseURL)
	}
	if !strings.HasSuffix(u.Path, ".json") {
		u.Path = strings.TrimRight(u.Path, "/") + fmt.Sprintf("/v%d/%s", v6.ModelVersion, v6dist.LatestFileName)
	}
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	allowHTTP := u.Scheme == "http"
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: g.control}
	tr := &http.Transport{
		// Proxy environment variables are ignored, as for registry
		// lookups: behind a proxy the dial guard would only see the proxy's
		// address. Air-gapped clusters point GRYPE_DB_URL at a mirror.
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: time.Minute,
		IdleConnTimeout:       90 * time.Second,
	}
	c := &Client{listing: u, allowHTTP: allowHTTP, guard: g}
	c.http = &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("too many redirects")
			}
			return c.checkScheme(req.URL)
		},
	}
	return c, nil
}

func (c *Client) checkScheme(u *url.URL) error {
	// IP-literal hosts are checked here too, so a refused address is caught
	// even when an HTTP proxy (which does the dialling) is configured.
	if ip, err := netip.ParseAddr(strings.Trim(u.Hostname(), "[]")); err == nil {
		if err := c.guard.checkIP(ip); err != nil {
			return err
		}
	}
	switch {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && c.allowHTTP:
		return nil
	}
	return fmt.Errorf("refused %s URL %s: only https (or http when configured) is allowed", u.Scheme, u.Redacted())
}

func (c *Client) get(u *url.URL, limit int64, w io.Writer) error {
	if err := c.checkScheme(u); err != nil {
		return err
	}
	resp, err := c.http.Get(u.String())
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", u.Redacted(), resp.Status)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if n > limit {
		return fmt.Errorf("GET %s: response exceeds %d bytes", u.Redacted(), limit)
	}
	return nil
}

// Latest fetches and parses the listing.
func (c *Client) Latest() (*v6dist.LatestDocument, error) {
	var buf strings.Builder
	if err := c.get(c.listing, maxListingBytes, &buf); err != nil {
		return nil, fmt.Errorf("DB listing: %w", err)
	}
	return v6dist.NewLatestFromReader(strings.NewReader(buf.String()))
}

// IsUpdateAvailable returns the listed archive when it supersedes current
// (same rules as grype's own client: a newer build of the same schema
// model, or anything when there is no current DB).
func (c *Client) IsUpdateAvailable(current *v6.Description) (*v6dist.Archive, error) {
	doc, err := c.Latest()
	if err != nil || doc == nil {
		return nil, err
	}
	cand := doc.Description
	switch {
	case current == nil:
		return &doc.Archive, nil
	case !current.SchemaVersion.Valid() || !cand.SchemaVersion.Valid():
		return nil, nil
	case cand.SchemaVersion.Model != current.SchemaVersion.Model:
		return nil, nil
	case cand.Built.After(current.Built.Time):
		return &doc.Archive, nil
	}
	return nil, nil
}

// ResolveArchiveURL resolves the archive path against the listing's
// directory; it may not leave the listing's host or directory tree. The
// expected checksum travels in a "checksum" query parameter that Download
// strips before the request (the same convention grype uses).
func (c *Client) ResolveArchiveURL(a v6dist.Archive) (string, error) {
	p := path.Clean("/" + a.Path)
	if strings.Contains(a.Path, "..") || strings.Contains(a.Path, "://") || strings.HasPrefix(a.Path, "/") {
		return "", fmt.Errorf("refused archive path %q from listing", a.Path)
	}
	u := *c.listing
	u.Path = path.Join(path.Dir(c.listing.Path), p)
	u.RawQuery = ""
	if a.Checksum != "" {
		q := url.Values{"checksum": {a.Checksum}}
		u.RawQuery = q.Encode()
	}
	return u.String(), nil
}

// Download fetches the archive, verifies its sha256 and unpacks it into a
// new temporary directory under dest, which it returns.
func (c *Client) Download(archiveURL, dest string, mon *progress.Manual) (string, error) {
	if mon != nil {
		defer mon.SetCompleted()
	}
	u, err := url.Parse(archiveURL)
	if err != nil {
		return "", err
	}
	want := u.Query().Get("checksum")
	u.RawQuery = ""
	if !strings.HasPrefix(want, "sha256:") {
		return "", fmt.Errorf("listing gave no sha256 checksum for %s", u.Redacted())
	}
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return "", err
	}
	tmp, err := os.MkdirTemp(dest, "grype-db-download")
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(tmp)
		}
	}()
	archivePath := filepath.Join(tmp, ".archive")
	f, err := os.Create(archivePath)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	err = c.get(u, MaxArchiveBytes, io.MultiWriter(f, h))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", fmt.Errorf("DB archive: %w", err)
	}
	if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != want {
		return "", fmt.Errorf("DB archive checksum mismatch: listing says %s, downloaded %s", want, got)
	}
	if err := extract(archivePath, path.Base(u.Path), tmp); err != nil {
		return "", err
	}
	_ = os.Remove(archivePath)
	ok = true
	return tmp, nil
}

// extract unpacks a .tar.zst or .tar.gz archive into dir, accepting only
// regular files at the archive root.
func extract(archivePath, name, dir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	var r io.Reader
	switch {
	case strings.HasSuffix(name, ".tar.zst"):
		zr, err := zstd.NewReader(f, zstd.WithDecoderMaxMemory(1<<30), zstd.WithDecoderConcurrency(1))
		if err != nil {
			return err
		}
		defer zr.Close()
		r = zr
	case strings.HasSuffix(name, ".tar.gz"), strings.HasSuffix(name, ".tgz"):
		gr, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer func() { _ = gr.Close() }()
		r = gr
	default:
		return fmt.Errorf("unsupported DB archive format %q (want .tar.zst or .tar.gz)", name)
	}
	tr := tar.NewReader(r)
	files := 0
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("DB archive: %w", err)
		}
		clean := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		switch {
		case hdr.Typeflag == tar.TypeDir && (clean == "." || clean == ""):
			continue
		case hdr.Typeflag != tar.TypeReg:
			return fmt.Errorf("DB archive: refused entry %q (type %c): only regular files", hdr.Name, hdr.Typeflag)
		case clean == "." || strings.Contains(clean, "/") || strings.HasPrefix(clean, "."):
			return fmt.Errorf("DB archive: refused entry %q: only files at the archive root", hdr.Name)
		case hdr.Size > MaxFileBytes:
			return fmt.Errorf("DB archive: entry %q is %d bytes, over the %d limit", hdr.Name, hdr.Size, int64(MaxFileBytes))
		case files >= MaxFiles:
			return fmt.Errorf("DB archive: more than %d files", MaxFiles)
		case total+hdr.Size > MaxTotalBytes:
			return fmt.Errorf("DB archive: unpacked size exceeds %d bytes", int64(MaxTotalBytes))
		}
		// Belt and braces on top of the root-only rule above: write only to
		// the base name, and only inside dir.
		target := filepath.Join(dir, filepath.Base(clean))
		if !strings.HasPrefix(target, filepath.Clean(dir)+string(os.PathSeparator)) {
			return fmt.Errorf("DB archive: refused entry %q: escapes the download directory", hdr.Name)
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		n, err := io.Copy(out, io.LimitReader(tr, MaxFileBytes+1))
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		if n > MaxFileBytes {
			return fmt.Errorf("DB archive: entry %q exceeds the size limit", hdr.Name)
		}
		files++
		total += n
	}
	if files == 0 {
		return errors.New("DB archive: no files")
	}
	return nil
}
