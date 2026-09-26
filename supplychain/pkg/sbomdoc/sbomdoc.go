// Package sbomdoc parses SBOM documents found in registries - CycloneDX
// JSON and SPDX 2.x JSON, bare or wrapped in an in-toto statement or a DSSE
// envelope - into the component list of types.ImageSBOM.
//
// It is deliberately small: kguardian needs name, version, PURL, type,
// licences and owned file paths, not a full SBOM model, and a registry
// document is untrusted input. Callers bound the input size; this package
// bounds the output (MaxComponents).
package sbomdoc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
)

// Formats.
const (
	FormatCycloneDX = "CycloneDX"
	FormatSPDX      = "SPDX"
)

// Predicate types (in-toto) for SBOMs. Matched by prefix, so versioned
// variants (".../bom/v1.5", ".../Document/v2.3") are accepted.
const (
	PredicateCycloneDX = "https://cyclonedx.org/bom"
	PredicateSPDX      = "https://spdx.dev/Document"
)

// MaxComponents caps the components kept from one document.
const MaxComponents = 50000

// ErrNotSBOM is returned for well-formed documents that are not SBOMs
// (e.g. a SLSA provenance statement), so callers can skip them quietly.
var ErrNotSBOM = errors.New("not an SBOM document")

// Doc is a parsed SBOM.
type Doc struct {
	Format        string
	SpecVersion   string
	PredicateType string // set when it came from an in-toto statement
	// InToto is true when the document was an in-toto statement's
	// predicate; Subjects are that statement's subject digests
	// ("sha256:<hex>"), which a caller must check against the image the
	// document is attached to.
	InToto     bool
	Subjects   []string
	Components []types.Component
	Truncated  bool
}

// IsSBOMPredicate reports whether an in-toto predicate type is an SBOM.
func IsSBOMPredicate(pt string) bool {
	return strings.HasPrefix(pt, PredicateCycloneDX) || strings.HasPrefix(pt, PredicateSPDX)
}

// Parse detects and parses b: a DSSE envelope, a sigstore bundle, an
// in-toto statement, a CycloneDX BOM or an SPDX document (all JSON).
func Parse(b []byte) (*Doc, error) {
	var probe struct {
		// DSSE envelope
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		// Sigstore bundle
		DSSEEnvelope *struct {
			PayloadType string `json:"payloadType"`
			Payload     string `json:"payload"`
		} `json:"dsseEnvelope"`
		// in-toto statement
		Type          string          `json:"_type"`
		PredicateType string          `json:"predicateType"`
		Predicate     json.RawMessage `json:"predicate"`
		Subject       []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
		// SBOMs
		BOMFormat   string `json:"bomFormat"`
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, fmt.Errorf("not JSON: %w", err)
	}
	switch {
	case probe.DSSEEnvelope != nil:
		return parseDSSE(probe.DSSEEnvelope.PayloadType, probe.DSSEEnvelope.Payload)
	case probe.PayloadType != "" && probe.Payload != "":
		return parseDSSE(probe.PayloadType, probe.Payload)
	case strings.HasPrefix(probe.Type, "https://in-toto.io/Statement"):
		if !IsSBOMPredicate(probe.PredicateType) {
			return nil, fmt.Errorf("%w: predicate %s", ErrNotSBOM, probe.PredicateType)
		}
		d, err := Parse(unwrapPredicate(probe.Predicate))
		if err != nil {
			return nil, err
		}
		d.PredicateType = probe.PredicateType
		d.InToto = true
		// BuildKit lists one subject per image name, all with the same
		// digest; keep each digest once.
		seen := map[string]bool{}
		for _, sub := range probe.Subject {
			if h := strings.ToLower(sub.Digest["sha256"]); h != "" && !seen[h] {
				seen[h] = true
				d.Subjects = append(d.Subjects, "sha256:"+h)
			}
		}
		return d, nil
	case probe.BOMFormat == "CycloneDX":
		return parseCycloneDX(b)
	case strings.HasPrefix(probe.SPDXVersion, "SPDX-2"):
		return parseSPDX(b)
	}
	return nil, ErrNotSBOM
}

// unwrapPredicate handles cosign's legacy form, where a predicate may be a
// JSON string holding the document rather than the document itself.
func unwrapPredicate(raw json.RawMessage) []byte {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []byte(s)
	}
	return raw
}

func parseDSSE(payloadType, payload string) (*Doc, error) {
	if payloadType != "application/vnd.in-toto+json" {
		return nil, fmt.Errorf("%w: DSSE payload type %s", ErrNotSBOM, payloadType)
	}
	b, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		if b, err = base64.RawURLEncoding.DecodeString(payload); err != nil {
			return nil, fmt.Errorf("DSSE payload: %w", err)
		}
	}
	return Parse(b)
}

// --- CycloneDX ---------------------------------------------------------

type cdxLicense struct {
	License *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"license"`
	Expression string `json:"expression"`
}

type cdxComponent struct {
	BOMRef     string         `json:"bom-ref"`
	Type       string         `json:"type"`
	Group      string         `json:"group"`
	Name       string         `json:"name"`
	Version    string         `json:"version"`
	PURL       string         `json:"purl"`
	Licenses   []cdxLicense   `json:"licenses"`
	Properties []cdxProperty  `json:"properties"`
	Components []cdxComponent `json:"components"`
	Evidence   *struct {
		Occurrences []struct {
			Location string `json:"location"`
		} `json:"occurrences"`
	} `json:"evidence"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxBOM struct {
	SpecVersion  string         `json:"specVersion"`
	Components   []cdxComponent `json:"components"`
	Dependencies []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	} `json:"dependencies"`
}

func parseCycloneDX(b []byte) (*Doc, error) {
	var bom cdxBOM
	if err := json.Unmarshal(b, &bom); err != nil {
		return nil, fmt.Errorf("CycloneDX: %w", err)
	}
	// File components are the targets of package -> file dependencies.
	files := map[string]string{}
	var flat []cdxComponent
	var walk func([]cdxComponent)
	walk = func(cs []cdxComponent) {
		for _, c := range cs {
			if c.Type == "file" {
				if c.BOMRef != "" {
					files[c.BOMRef] = c.Name
				}
			} else {
				flat = append(flat, c)
			}
			walk(c.Components)
		}
	}
	walk(bom.Components)
	owned := map[string][]string{}
	for _, d := range bom.Dependencies {
		for _, dep := range d.DependsOn {
			if f, ok := files[dep]; ok {
				owned[d.Ref] = append(owned[d.Ref], f)
			}
		}
	}

	doc := &Doc{Format: FormatCycloneDX, SpecVersion: bom.SpecVersion}
	for _, c := range flat {
		if len(doc.Components) >= MaxComponents {
			doc.Truncated = true
			break
		}
		nc := types.Component{Name: c.Name, Version: c.Version, PURL: c.PURL, Type: purlType(c.PURL)}
		if c.Group != "" {
			nc.Name = c.Group + "/" + c.Name
		}
		if c.Type == "operating-system" {
			nc.Type = "operating-system"
		}
		paths := map[string]struct{}{}
		for _, f := range owned[c.BOMRef] {
			paths[cleanPath(f)] = struct{}{}
		}
		if c.Evidence != nil {
			for _, o := range c.Evidence.Occurrences {
				if o.Location != "" {
					paths[cleanPath(o.Location)] = struct{}{}
				}
			}
		}
		for _, p := range c.Properties {
			switch p.Name {
			case "aquasecurity:trivy:FilePath":
				paths[cleanPath(p.Value)] = struct{}{}
			case "aquasecurity:trivy:PkgType":
				nc.Type = p.Value
			case "aquasecurity:trivy:Class":
				nc.Class = p.Value
			case "aquasecurity:trivy:SrcName":
				nc.SrcName = p.Value
			case "aquasecurity:trivy:SrcVersion":
				nc.SrcVersion = p.Value
			case "aquasecurity:trivy:LayerDigest":
				nc.LayerDigest = p.Value
			}
		}
		delete(paths, "")
		nc.FilePaths = sortedSet(paths)
		for _, l := range c.Licenses {
			switch {
			case l.Expression != "":
				nc.Licenses = append(nc.Licenses, l.Expression)
			case l.License != nil && l.License.ID != "":
				nc.Licenses = append(nc.Licenses, l.License.ID)
			case l.License != nil && l.License.Name != "":
				nc.Licenses = append(nc.Licenses, l.License.Name)
			}
		}
		doc.Components = append(doc.Components, nc)
	}
	sortComponents(doc.Components)
	return doc, nil
}

// --- SPDX 2.x ----------------------------------------------------------

type spdxDoc struct {
	SPDXVersion string `json:"spdxVersion"`
	Packages    []struct {
		SPDXID           string `json:"SPDXID"`
		Name             string `json:"name"`
		VersionInfo      string `json:"versionInfo"`
		LicenseConcluded string `json:"licenseConcluded"`
		LicenseDeclared  string `json:"licenseDeclared"`
		PrimaryPurpose   string `json:"primaryPackagePurpose"`
		ExternalRefs     []struct {
			Category string `json:"referenceCategory"`
			Type     string `json:"referenceType"`
			Locator  string `json:"referenceLocator"`
		} `json:"externalRefs"`
		HasFiles []string `json:"hasFiles"`
	} `json:"packages"`
	Files []struct {
		SPDXID   string `json:"SPDXID"`
		FileName string `json:"fileName"`
	} `json:"files"`
	Relationships []struct {
		Element string `json:"spdxElementId"`
		Related string `json:"relatedSpdxElement"`
		Type    string `json:"relationshipType"`
	} `json:"relationships"`
}

func parseSPDX(b []byte) (*Doc, error) {
	var d spdxDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("SPDX: %w", err)
	}
	files := make(map[string]string, len(d.Files))
	for _, f := range d.Files {
		files[f.SPDXID] = f.FileName
	}
	owned := map[string][]string{}
	for _, r := range d.Relationships {
		switch r.Type {
		case "CONTAINS":
			if f, ok := files[r.Related]; ok {
				owned[r.Element] = append(owned[r.Element], f)
			}
		case "CONTAINED_BY":
			if f, ok := files[r.Element]; ok {
				owned[r.Related] = append(owned[r.Related], f)
			}
		}
	}
	doc := &Doc{Format: FormatSPDX, SpecVersion: strings.TrimPrefix(d.SPDXVersion, "SPDX-")}
	for _, p := range d.Packages {
		if len(doc.Components) >= MaxComponents {
			doc.Truncated = true
			break
		}
		nc := types.Component{Name: p.Name, Version: p.VersionInfo}
		for _, r := range p.ExternalRefs {
			if r.Type == "purl" && nc.PURL == "" {
				nc.PURL = r.Locator
			}
		}
		nc.Type = purlType(nc.PURL)
		if p.PrimaryPurpose == "OPERATING-SYSTEM" {
			nc.Type = "operating-system"
		}
		if (nc.PURL == "" && nc.Type == "") || nc.Type == "docker" || nc.Type == "oci" {
			// The image itself / the document root: not a package.
			continue
		}
		for _, l := range []string{p.LicenseDeclared, p.LicenseConcluded} {
			if l != "" && l != "NOASSERTION" && l != "NONE" {
				nc.Licenses = []string{l}
				break
			}
		}
		paths := map[string]struct{}{}
		for _, f := range owned[p.SPDXID] {
			paths[cleanPath(f)] = struct{}{}
		}
		for _, id := range p.HasFiles {
			if f, ok := files[id]; ok {
				paths[cleanPath(f)] = struct{}{}
			}
		}
		delete(paths, "")
		nc.FilePaths = sortedSet(paths)
		doc.Components = append(doc.Components, nc)
	}
	sortComponents(doc.Components)
	return doc, nil
}

// purlType extracts the package-URL type ("pkg:apk/alpine/musl@..." -> "apk").
func purlType(purl string) string {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return ""
	}
	if i := strings.IndexByte(rest, '/'); i > 0 {
		return strings.ToLower(rest[:i])
	}
	return ""
}

// cleanPath makes paths image-root relative with no leading slash, the
// form Trivy uses, so paths from every source compare equal.
func cleanPath(p string) string {
	return strings.TrimLeft(strings.TrimSpace(p), "/")
}

func sortedSet(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortComponents(cs []types.Component) {
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].PURL != cs[j].PURL {
			return cs[i].PURL < cs[j].PURL
		}
		if cs[i].Name != cs[j].Name {
			return cs[i].Name < cs[j].Name
		}
		return cs[i].Version < cs[j].Version
	})
}
