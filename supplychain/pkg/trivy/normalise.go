package trivy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
)

var digestRE = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// NormaliseDigest returns d if it is a well-formed sha256 content digest,
// accepting a "<repo>@sha256:..." repo digest too. Anything else yields "".
func NormaliseDigest(d string) string {
	d = strings.TrimSpace(d)
	if i := strings.LastIndex(d, "@"); i >= 0 {
		d = d[i+1:]
	}
	d = strings.ToLower(d)
	if digestRE.MatchString(d) {
		return d
	}
	return ""
}

// DecodeVulnerabilityReport decodes an unstructured object (as served by the
// dynamic client) into a VulnerabilityReport. A JSON round trip rather than
// runtime.DefaultUnstructuredConverter because the API server hands integer
// scores (e.g. "score: 9") back as int64, which the converter will not put
// into a float64 field.
func DecodeVulnerabilityReport(obj map[string]interface{}) (*VulnerabilityReport, error) {
	var r VulnerabilityReport
	if err := roundTrip(obj, &r); err != nil {
		return nil, fmt.Errorf("decoding VulnerabilityReport: %w", err)
	}
	return &r, nil
}

// DecodeSbomReport is DecodeVulnerabilityReport for SbomReports.
func DecodeSbomReport(obj map[string]interface{}) (*SbomReport, error) {
	var r SbomReport
	if err := roundTrip(obj, &r); err != nil {
		return nil, fmt.Errorf("decoding SbomReport: %w", err)
	}
	return &r, nil
}

func roundTrip(obj map[string]interface{}, out interface{}) error {
	b, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// workloadOf returns the workload container a report was produced for, from
// trivy-operator's labels, falling back to the report's own namespace.
func workloadOf(m reportMeta) types.WorkloadRef {
	ns := m.Labels[LabelResourceNamespace]
	if ns == "" {
		ns = m.Namespace
	}
	return types.WorkloadRef{
		Namespace: ns,
		Kind:      m.Labels[LabelResourceKind],
		Name:      m.Labels[LabelResourceName],
		Container: m.Labels[LabelContainerName],
	}
}

// imageRefOf builds the image identity from the report's registry/artifact.
// digest is the already-resolved digest ("" when unknown).
func imageRefOf(reg registry, a artifact, digest string) types.ImageRef {
	ref := a.Repository
	if reg.Server != "" && ref != "" {
		ref = reg.Server + "/" + ref
	}
	if a.Tag != "" && ref != "" {
		ref += ":" + string(a.Tag)
	}
	return types.ImageRef{
		Digest:     digest,
		Ref:        ref,
		Registry:   reg.Server,
		Repository: a.Repository,
		Tag:        string(a.Tag),
	}
}

func parseTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}

func normaliseSeverity(s string) string {
	switch u := strings.ToUpper(strings.TrimSpace(s)); u {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN":
		return u
	default:
		return "UNKNOWN"
	}
}

// NormaliseVulnerabilities converts a VulnerabilityReport into the payload
// for digest. The caller resolves digest (see Tracker); the report's own
// artifact digest is not consulted here. filePaths maps a package PURL to the
// in-image paths an SBOM attributed to it, and may be nil.
func NormaliseVulnerabilities(r *VulnerabilityReport, digest string, filePaths map[string][]string) *types.ImageVulnerabilities {
	d := r.Report
	out := &types.ImageVulnerabilities{
		SchemaVersion: types.SchemaVersion,
		Image:         imageRefOf(d.Registry, d.Artifact, digest),
		Source:        types.SourceTrivyOperator,
		Scanner:       types.Scanner{Name: d.Scanner.Name, Vendor: d.Scanner.Vendor, Version: string(d.Scanner.Version)},
		OS:            types.OS{Family: d.OS.Family, Name: string(d.OS.Name), EOSL: d.OS.EOSL},
		ObservedIn:    []types.WorkloadRef{workloadOf(r.Metadata)},
	}
	if t := parseTime(d.UpdateTimestamp); t != nil {
		out.ScannedAt = *t
	}

	seen := make(map[string]struct{}, len(d.Vulnerabilities))
	vulns := make([]types.Vulnerability, 0, len(d.Vulnerabilities))
	for _, v := range d.Vulnerabilities {
		if strings.TrimSpace(v.VulnerabilityID) == "" {
			continue
		}
		nv := types.Vulnerability{
			ID: v.VulnerabilityID,
			Package: types.Package{
				Name:    v.Resource,
				Version: v.InstalledVersion,
				Type:    v.PackageType,
				PURL:    v.PkgPURL,
			},
			FixedVersion:   strings.TrimSpace(v.FixedVersion),
			Severity:       normaliseSeverity(v.Severity),
			Score:          v.Score,
			Title:          v.Title,
			PrimaryURL:     v.PrimaryLink,
			Target:         v.Target,
			Class:          v.Class,
			PublishedAt:    parseTime(v.PublishedDate),
			LastModifiedAt: parseTime(v.LastModifiedDate),
		}
		if len(v.CVSS) > 0 {
			nv.CVSS = make(map[string]types.CVSS, len(v.CVSS))
			for vendor, c := range v.CVSS {
				nv.CVSS[vendor] = types.CVSS{
					V2Score: c.V2Score, V2Vector: c.V2Vector,
					V3Score: c.V3Score, V3Vector: c.V3Vector,
					V40Score: c.V40Score, V40Vector: c.V40Vector,
				}
			}
		}
		paths := map[string]struct{}{}
		if p := strings.TrimSpace(v.PkgPath); p != "" {
			paths[p] = struct{}{}
		}
		if v.PkgPURL != "" {
			for _, p := range filePaths[v.PkgPURL] {
				paths[p] = struct{}{}
			}
		}
		nv.FilePaths = sortedKeys(paths)

		// Trivy can repeat a finding verbatim (same CVE, package, version,
		// path and target); keep one.
		k := strings.Join([]string{nv.ID, nv.Package.Name, nv.Package.Version, v.PkgPath, nv.Target}, "\x00")
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		vulns = append(vulns, nv)
	}
	sort.SliceStable(vulns, func(i, j int) bool {
		a, b := vulns[i], vulns[j]
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.Package.Name != b.Package.Name {
			return a.Package.Name < b.Package.Name
		}
		if a.Package.Version != b.Package.Version {
			return a.Package.Version < b.Package.Version
		}
		return a.Target < b.Target
	})
	out.Vulnerabilities = vulns
	return out
}

// sbomDigest returns the image digest an SbomReport states, preferring the
// artifact digest and falling back to the CycloneDX metadata component's
// RepoDigest property.
func sbomDigest(r *SbomReport) string {
	if d := NormaliseDigest(r.Report.Artifact.Digest); d != "" {
		return d
	}
	if md := r.Report.BOM.Metadata; md != nil && md.Component != nil {
		for _, p := range md.Component.Properties {
			if p.Name == propRepoDigest {
				// Multi-value properties are comma separated.
				for _, v := range strings.Split(p.Value, ",") {
					if d := NormaliseDigest(v); d != "" {
						return d
					}
				}
			}
		}
	}
	return ""
}

// NormaliseSBOM converts an SbomReport into the payload for digest.
func NormaliseSBOM(r *SbomReport, digest string) *types.ImageSBOM {
	d := r.Report
	out := &types.ImageSBOM{
		SchemaVersion: types.SchemaVersion,
		Image:         imageRefOf(d.Registry, d.Artifact, digest),
		Source:        types.SourceTrivyOperator,
		Scanner:       types.Scanner{Name: d.Scanner.Name, Vendor: d.Scanner.Vendor, Version: string(d.Scanner.Version)},
		Format:        d.BOM.BOMFormat,
		SpecVersion:   string(d.BOM.SpecVersion),
		ObservedIn:    []types.WorkloadRef{workloadOf(r.Metadata)},
	}
	if t := parseTime(d.UpdateTimestamp); t != nil {
		out.ScannedAt = *t
	}
	comps := make([]types.Component, 0, len(d.BOM.Components))
	for _, c := range d.BOM.Components {
		nc := types.Component{Name: c.Name, Version: string(c.Version), PURL: c.PURL}
		if c.Group != "" {
			nc.Name = c.Group + "/" + c.Name
		}
		paths := map[string]struct{}{}
		for _, p := range c.Properties {
			switch p.Name {
			case propPkgType:
				nc.Type = p.Value
			case propType:
				if nc.Type == "" {
					nc.Type = p.Value
				}
			case propClass:
				nc.Class = p.Value
			case propSrcName:
				nc.SrcName = p.Value
			case propSrcVersion:
				nc.SrcVersion = p.Value
			case propLayerDigest:
				nc.LayerDigest = p.Value
			case propFilePath:
				if v := strings.TrimSpace(p.Value); v != "" {
					paths[v] = struct{}{}
				}
			}
		}
		if c.Type == "operating-system" {
			// The distro itself; its family is the component name.
			nc.Type = "operating-system"
		}
		nc.FilePaths = sortedKeys(paths)
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
		comps = append(comps, nc)
	}
	sort.SliceStable(comps, func(i, j int) bool {
		if comps[i].PURL != comps[j].PURL {
			return comps[i].PURL < comps[j].PURL
		}
		if comps[i].Name != comps[j].Name {
			return comps[i].Name < comps[j].Name
		}
		return comps[i].Version < comps[j].Version
	})
	out.Components = comps
	return out
}

// FilePathsByPURL indexes an SBOM payload's file paths by PURL, for joining
// onto vulnerabilities that do not carry a packagePath themselves.
func FilePathsByPURL(s *types.ImageSBOM) map[string][]string {
	if s == nil {
		return nil
	}
	m := map[string][]string{}
	for _, c := range s.Components {
		if c.PURL != "" && len(c.FilePaths) > 0 {
			m[c.PURL] = append(m[c.PURL], c.FilePaths...)
		}
	}
	return m
}

func sortedKeys(m map[string]struct{}) []string {
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
