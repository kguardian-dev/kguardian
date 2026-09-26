package engine

import (
	"sort"
	"strings"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kguardian-dev/kguardian/supplychain-matcher/internal/wire"
)

// convert maps Grype matches onto kguardian's vulnerability shape.
// paths returns the in-image file paths kguardian knows for a matched
// package (from the original SBOM), since Grype's packages here carry none.
func convert(ms []match.Match, paths func(purl, name, version string) []string) []wire.Vulnerability {
	out := make([]wire.Vulnerability, 0, len(ms))
	seen := map[string]bool{}
	for _, m := range ms {
		v := m.Vulnerability
		key := v.ID + "\x00" + m.Package.Name + "\x00" + m.Package.Version + "\x00" + m.Package.PURL
		if seen[key] {
			continue
		}
		seen[key] = true
		w := wire.Vulnerability{
			ID: v.ID,
			Package: wire.Package{
				Name: m.Package.Name, Version: m.Package.Version,
				Type: string(m.Package.Type), PURL: m.Package.PURL,
			},
			Severity:  "UNKNOWN",
			Target:    v.Namespace,
			Class:     classOf(m),
			FilePaths: paths(stripUpstream(m.Package.PURL), m.Package.Name, m.Package.Version),
		}
		if v.Fix.State == vulnerability.FixStateFixed && len(v.Fix.Versions) > 0 {
			w.FixedVersion = strings.Join(v.Fix.Versions, ", ")
		}
		if md := v.Metadata; md != nil {
			w.Severity = severity(md.Severity)
			w.PrimaryURL = md.DataSource
			applyCVSS(&w, md.Cvss)
			for _, k := range md.KnownExploited {
				w.KnownExploited = true
				if k.DateAdded != nil && (w.KEVDateAdded == nil || k.DateAdded.Before(*w.KEVDateAdded)) {
					t := k.DateAdded.UTC()
					w.KEVDateAdded = &t
				}
			}
			if len(md.EPSS) > 0 {
				e, p := md.EPSS[0].EPSS, md.EPSS[0].Percentile
				if e >= 0 && e <= 1 {
					w.EPSS = &e
				}
				if p >= 0 && p <= 1 {
					w.EPSSPercentile = &p
				}
			}
		}
		out = append(out, w)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.Package.Name != b.Package.Name {
			return a.Package.Name < b.Package.Name
		}
		return a.Package.Version < b.Package.Version
	})
	return out
}

func severity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "CRITICAL"
	case "high":
		return "HIGH"
	case "medium":
		return "MEDIUM"
	case "low":
		return "LOW"
	case "negligible":
		return "NONE"
	}
	return "UNKNOWN"
}

// applyCVSS fills the per-vendor CVSS map (keyed by source, lowercased)
// and the headline score: the highest v3/v4 base score, else v2.
func applyCVSS(w *wire.Vulnerability, cs []vulnerability.Cvss) {
	var best float64
	for _, c := range cs {
		if c.Metrics.BaseScore <= 0 {
			continue
		}
		src := strings.ToLower(c.Source)
		if src == "" {
			src = "unknown"
		}
		if w.CVSS == nil {
			w.CVSS = map[string]wire.CVSS{}
		}
		e := w.CVSS[src]
		score := c.Metrics.BaseScore
		switch {
		case strings.HasPrefix(c.Version, "2"):
			e.V2Score, e.V2Vector = &score, c.Vector
		case strings.HasPrefix(c.Version, "4"):
			e.V40Score, e.V40Vector = &score, c.Vector
		default:
			e.V3Score, e.V3Vector = &score, c.Vector
		}
		w.CVSS[src] = e
		if score > best {
			best = score
		}
	}
	if best > 0 {
		w.Score = &best
	}
}

func classOf(m match.Match) string {
	switch string(m.Package.Type) {
	case "apk", "deb", "rpm", "alpm", "portage":
		return "os-pkgs"
	}
	return "lang-pkgs"
}

// stripUpstream undoes withUpstream so paths can be looked up by the
// component's original PURL.
func stripUpstream(purl string) string {
	base, frag, hasFrag := strings.Cut(purl, "#")
	i := strings.IndexByte(base, '?')
	if i < 0 {
		return purl
	}
	q := purlQualifiers(base)
	if !q.Has("upstream") {
		return purl
	}
	parts := strings.Split(base[i+1:], "&")
	kept := parts[:0]
	for _, p := range parts {
		if !strings.HasPrefix(p, "upstream=") {
			kept = append(kept, p)
		}
	}
	out := base[:i]
	if len(kept) > 0 {
		out += "?" + strings.Join(kept, "&")
	}
	if hasFrag {
		out += "#" + frag
	}
	return out
}
