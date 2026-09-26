package engine

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/kguardian-dev/kguardian/supplychain-matcher/internal/wire"
)

// The matcher is handed kguardian's normalised component list, not the
// original SBOM, so it re-expresses the components as a minimal CycloneDX
// 1.5 document and lets Grype's own SBOM reader turn that into packages.
// Two details decide whether OS packages match at all:
//
//   - Grype needs the distro to use distro advisories. Trivy SBOMs carry
//     it as an operating-system component; BuildKit/syft SPDX documents
//     often do not, and only say it in PURL qualifiers
//     (distro=alpine-3.20.10, or os_name/os_version). Without it, apk/deb/
//     rpm packages silently match nothing (TestMatchRealDB: libc6 on
//     debian 12 matches with the distro, 0 without).
//   - deb/rpm advisories are keyed by source package. Syft reads that from
//     the PURL "upstream" qualifier, which Trivy's PURLs omit, so it is
//     added from the component's src_name/src_version (TestMatchRealDB:
//     libc6 matches through upstream glibc, 0 without it).
//
// No CPEs are sent, so Grype's CPE-based matching (which, for alpine:3.20,
// produced its only 4 results from syft's own SBOM) does not run: fewer
// false positives, at the cost of binaries that have no PURL.

type cdxComponent struct {
	Type    string `json:"type"`
	BOMRef  string `json:"bom-ref,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
}

type cdxBOM struct {
	BOMFormat   string         `json:"bomFormat"`
	SpecVersion string         `json:"specVersion"`
	Version     int            `json:"version"`
	Components  []cdxComponent `json:"components"`
}

var distroQualifier = regexp.MustCompile(`^(.+?)-(\d[0-9A-Za-z._~+]*)$`)

// Distro is an operating system identity (os-release ID and VERSION_ID).
type Distro struct{ ID, Version string }

// inferDistro returns the distro stated by an operating-system component,
// else by the first PURL qualifier that carries one.
func inferDistro(cs []wire.Component) (Distro, bool) {
	for _, c := range cs {
		if c.Type == "operating-system" && c.Name != "" {
			return Distro{ID: strings.ToLower(c.Name), Version: c.Version}, true
		}
	}
	for _, c := range cs {
		q := purlQualifiers(c.PURL)
		if d := q.Get("distro"); d != "" {
			if m := distroQualifier.FindStringSubmatch(d); m != nil {
				return Distro{ID: m[1], Version: m[2]}, true
			}
			return Distro{ID: d}, true
		}
		if n := q.Get("os_name"); n != "" {
			return Distro{ID: n, Version: q.Get("os_version")}, true
		}
	}
	return Distro{}, false
}

func purlQualifiers(purl string) url.Values {
	i := strings.IndexByte(purl, '?')
	if i < 0 {
		return url.Values{}
	}
	rest := purl[i+1:]
	if j := strings.IndexByte(rest, '#'); j >= 0 {
		rest = rest[:j]
	}
	v, err := url.ParseQuery(rest)
	if err != nil {
		return url.Values{}
	}
	return v
}

// withUpstream adds the purl-spec "upstream" qualifier syft uses for a
// binary package's source package, when the component names one and the
// PURL does not already.
//
// src_name is authoritative when set (supplychain sends Trivy's scan data
// there and never lets an unverified SBOM change it): an upstream
// qualifier already in the PURL is replaced by it, not preferred over it.
func withUpstream(c wire.Component) string {
	if c.PURL == "" || c.SrcName == "" {
		return c.PURL
	}
	c.PURL = stripUpstream(c.PURL)
	up := c.SrcName
	if c.SrcVersion != "" && c.SrcVersion != c.Version {
		up += "@" + c.SrcVersion
	}
	if up == c.Name {
		return c.PURL
	}
	sep := "?"
	if strings.Contains(c.PURL, "?") {
		sep = "&"
	}
	base, frag, _ := strings.Cut(c.PURL, "#")
	out := base + sep + "upstream=" + url.QueryEscape(up)
	if frag != "" {
		out += "#" + frag
	}
	return out
}

// BuildCycloneDX renders cs as a CycloneDX 1.5 JSON document Grype can
// read. It reports the distro it used, if any.
func BuildCycloneDX(cs []wire.Component) ([]byte, *Distro) {
	bom := cdxBOM{BOMFormat: "CycloneDX", SpecVersion: "1.5", Version: 1}
	d, ok := inferDistro(cs)
	var used *Distro
	if ok {
		bom.Components = append(bom.Components, cdxComponent{Type: "operating-system", Name: d.ID, Version: d.Version, BOMRef: "os"})
		used = &d
	}
	for i, c := range cs {
		if c.Type == "operating-system" {
			continue
		}
		bom.Components = append(bom.Components, cdxComponent{
			Type: "library", BOMRef: "c" + strconv.Itoa(i), Name: c.Name, Version: c.Version, PURL: withUpstream(c),
		})
	}
	b, _ := json.Marshal(bom)
	return b, used
}
