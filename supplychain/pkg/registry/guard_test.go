package registry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
)

func TestGuardCheckIP(t *testing.T) {
	always := []string{
		"127.0.0.1", "127.8.9.10", "::1", // loopback
		"169.254.169.254", "169.254.0.1", "fe80::1", // link-local, cloud metadata
		"0.0.0.0", "::", // unspecified
		"224.0.0.1", "239.255.255.250", "ff02::1", "ff05::2", // multicast
		"::ffff:127.0.0.1", "::ffff:169.254.169.254", // v4-mapped
	}
	private := []string{"10.0.0.1", "172.16.5.5", "192.168.1.10", "100.64.0.1", "fd00::1", "fc00::5"}
	public := []string{"8.8.8.8", "140.82.112.34", "2606:4700::1111"}

	for _, allowPrivate := range []bool{false, true} {
		g := Guard{AllowPrivate: allowPrivate}
		for _, s := range always {
			var be *BlockedError
			if err := g.CheckIP(netip.MustParseAddr(s)); !errors.As(err, &be) || be.Reason != ReasonBlockedAddress {
				t.Errorf("allowPrivate=%v %s: %v, want blocked_address", allowPrivate, s, err)
			}
		}
		for _, s := range private {
			err := g.CheckIP(netip.MustParseAddr(s))
			var be *BlockedError
			if allowPrivate && err != nil {
				t.Errorf("%s refused with allowPrivate: %v", s, err)
			}
			if !allowPrivate && (!errors.As(err, &be) || be.Reason != ReasonPrivateAddress) {
				t.Errorf("%s: %v, want private_address", s, err)
			}
		}
		for _, s := range public {
			if err := g.CheckIP(netip.MustParseAddr(s)); err != nil {
				t.Errorf("%s refused: %v", s, err)
			}
		}
	}
}

func TestGuardCheckHost(t *testing.T) {
	g := Guard{}
	cases := map[string]string{
		"localhost":          ReasonBlockedAddress,
		"foo.localhost":      ReasonBlockedAddress,
		"127.0.0.1":          ReasonBlockedAddress,
		"[::1]":              ReasonBlockedAddress,
		"169.254.169.254":    ReasonBlockedAddress,
		"registry.local":     ReasonLocalHostname,
		"registry.local.":    ReasonLocalHostname,
		"kguardian-registry": ReasonLocalHostname,
		"10.1.2.3":           ReasonPrivateAddress,
		"ghcr.io":            "",
		"index.docker.io":    "",
	}
	for host, want := range cases {
		err := g.CheckHost(host)
		reason, _ := func() (string, bool) {
			if err == nil {
				return "", true
			}
			return blockedReason(err)
		}()
		if reason != want {
			t.Errorf("CheckHost(%q) = %v, want %q", host, err, want)
		}
	}
	lan := Guard{AllowPrivate: true}
	for _, h := range []string{"registry.local", "kguardian-registry", "10.1.2.3"} {
		if err := lan.CheckHost(h); err != nil {
			t.Errorf("allowPrivate: %s refused: %v", h, err)
		}
	}
	if err := lan.CheckHost("localhost"); err == nil {
		t.Error("localhost must stay refused with allowPrivate")
	}
}

// The dial-time check sees the resolved address, whatever name was used,
// so a name that (re)binds to loopback or metadata is refused at connect.
func TestTransportRefusesAtDialTime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	rt := Guard{AllowPrivate: true}.Transport(time.Second).(*guardedRoundTripper)
	// Skip the name check to exercise only the dialer: this is the path a
	// rebinding public name would take.
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	_, err := rt.base.RoundTrip(req)
	if reason, ok := blockedReason(err); !ok || reason != ReasonBlockedAddress {
		t.Fatalf("dial to %s: %v, want blocked_address", srv.URL, err)
	}
}

// A redirect to the metadata address is refused on the second hop.
func TestTransportChecksRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()
	c := &http.Client{Transport: Guard{allowLoopbackForTest: true}.Transport(time.Second)}
	_, err := c.Get(srv.URL)
	if reason, ok := blockedReason(err); !ok || reason != ReasonBlockedAddress {
		t.Fatalf("redirect: %v, want blocked_address", err)
	}
}

// A registry that sends the anonymous token request to an internal realm
// gets the lookup skipped, not the token request made. A metadata-IP realm
// is already refused inside go-containerregistry; a LAN-name realm is
// refused by our transport.
func TestInspectRefusesInternalTokenRealm(t *testing.T) {
	for realm, reason := range map[string]string{
		"http://169.254.169.254/token":  ReasonBlockedRealm,
		"http://tokens.cluster.local/t": ReasonLocalHostname,
	} {
		inspectWithRealm(t, realm, reason)
	}
}

func inspectWithRealm(t *testing.T, realm, wantReason string) {
	t.Helper()
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.Header().Set("WWW-Authenticate", `Bearer realm="`+realm+`",service="x"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	var got [][2]string
	in := testInspector()
	in.OnLookup = func(result, reason string) { got = append(got, [2]string{result, reason}) }
	r := in.Inspect(context.Background(), host, "example/api", "sha256:"+strings.Repeat("a", 64))
	if r.Kind != types.DigestKindUnknown || r.Skipped != wantReason || r.PlatformManifests != nil {
		t.Fatalf("realm %s: result %+v", realm, r)
	}
	if len(got) != 1 || got[0] != [2]string{ResultSkipped, wantReason} {
		t.Errorf("realm %s: OnLookup calls %v", realm, got)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, p := range paths {
		if p != "/v2/" {
			t.Errorf("realm %s: unexpected request %s (only the ping should reach the registry)", realm, p)
		}
	}
}

// Refused registries are skipped before any network use, reported once,
// and cached.
func TestInspectSkipsRefusedRegistry(t *testing.T) {
	var got []string
	in := New(Guard{})
	in.OnLookup = func(result, reason string) { got = append(got, result+"/"+reason) }
	d := "sha256:" + strings.Repeat("b", 64)
	for _, reg := range []string{"169.254.169.254", "registry.local", "10.0.0.5:5000", "localhost:5000"} {
		r := in.Inspect(context.Background(), reg, "x/y", d)
		if r.Skipped == "" || r.Kind != types.DigestKindUnknown {
			t.Errorf("%s: %+v", reg, r)
		}
		in.Inspect(context.Background(), reg, "x/y", d) // cached
	}
	want := []string{"skipped/blocked_address", "skipped/local_hostname", "skipped/private_address", "skipped/blocked_address"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("OnLookup %v, want %v", got, want)
	}
	img := types.ImageRef{Registry: "169.254.169.254", Repository: "x/y", Digest: d, DigestKind: types.DigestKindUnknown}
	in.Enrich(context.Background(), &img)
	if img.DigestKind != types.DigestKindUnknown || img.PlatformManifests != nil {
		t.Errorf("skipped enrich changed the image: %+v", img)
	}
}
