package registry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/sbomdoc"
	sctypes "github.com/kguardian-dev/kguardian/supplychain/pkg/types"
)

// Media and artifact types recognised as SBOM carriers. Sources:
// cosign specs/SBOM_SPEC.md and ATTESTATION_SPEC.md, cosign
// specs/BUNDLE_SPEC.md (v3.1.3), BuildKit docs/attestations/
// attestation-storage.md.
const (
	mtInToto       = "application/vnd.in-toto+json"
	mtDSSE         = "application/vnd.dsse.envelope.v1+json"
	mtBundlePrefix = "application/vnd.dev.sigstore.bundle"
	mtSPDXJSON     = "text/spdx+json"
	mtSPDXJSON2    = "application/spdx+json"
	mtCDXJSON      = "application/vnd.cyclonedx+json"

	annPredicateType       = "in-toto.io/predicate-type"
	annBundlePredicateType = "dev.sigstore.bundle.predicateType"
	annRefType             = "vnd.docker.reference.type"
	annRefDigest           = "vnd.docker.reference.digest"
)

// Limits on what one digest may cost to inspect.
const (
	// MaxSBOMBytes caps one SBOM layer (compressed as stored).
	MaxSBOMBytes = 32 << 20
	// MaxArtifacts caps referrer/attestation manifests examined per digest.
	MaxArtifacts = 16
)

// FoundSBOM is one SBOM located for an image.
type FoundSBOM struct {
	// Subject is the digest the SBOM describes: the digest asked about,
	// or, for BuildKit attestations of an index, one platform manifest.
	Subject     string
	Doc         *sbomdoc.Doc
	Attestation sctypes.Attestation
}

// FetchSBOMs finds SBOMs attached to repository@digest, anonymously and
// through the guard, in this order of preference per subject:
//  1. OCI referrers (sigstore bundles, in-toto, SPDX/CycloneDX artifacts),
//  2. cosign attestations (tag sha256-<hex>.att),
//  3. cosign attached SBOMs (tag sha256-<hex>.sbom),
//  4. BuildKit attestation manifests inside an index.
//
// The first SBOM found for a subject wins. A refused destination returns
// a *BlockedError; "nothing attached" is an empty result, not an error.
func (i *Inspector) FetchSBOMs(ctx context.Context, registry, repository, digest string) ([]FoundSBOM, error) {
	d, err := i.digestRef(registry, repository, digest)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 6*i.timeout())
	defer cancel()
	opts := i.remoteOpts(ctx)

	var out []FoundSBOM
	have := map[string]bool{}
	add := func(f []FoundSBOM) {
		for _, x := range f {
			if !have[x.Subject] {
				have[x.Subject] = true
				out = append(out, x)
			}
		}
	}
	var errs []error
	collect := func(f []FoundSBOM, err error) {
		add(f)
		if err != nil {
			errs = append(errs, err)
		}
	}
	collect(i.fromReferrers(d, opts))
	if !have[digest] {
		collect(i.fromCosignTag(d, "att", sctypes.MechanismCosignAttestation, opts))
	}
	if !have[digest] {
		collect(i.fromCosignTag(d, "sbom", sctypes.MechanismCosignSBOM, opts))
	}
	collect(i.fromBuildKit(d, opts))

	// A refusal anywhere is the answer: the destination is off limits.
	for _, e := range errs {
		if _, ok := blockedReason(e); ok {
			return nil, e
		}
	}
	if len(out) == 0 && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}

func (i *Inspector) digestRef(registry, repository, digest string) (name.Digest, error) {
	repo := repository
	if registry != "" && !strings.HasPrefix(repository, registry+"/") {
		repo = registry + "/" + repository
	}
	var opts []name.Option
	if i.Insecure {
		opts = append(opts, name.Insecure)
	}
	d, err := name.NewDigest(repo+"@"+digest, opts...)
	if err != nil {
		return name.Digest{}, err
	}
	if err := i.Guard.CheckHost(hostOnly(d.RegistryStr())); err != nil {
		return name.Digest{}, err
	}
	return d, nil
}

func (i *Inspector) remoteOpts(ctx context.Context) []remote.Option {
	return []remote.Option{
		remote.WithAuth(authn.Anonymous),
		remote.WithContext(ctx),
		remote.WithTransport(i.rt()),
	}
}

func isNotFound(err error) bool {
	var te *transport.Error
	return errors.As(err, &te) && te.StatusCode == http.StatusNotFound
}

func (i *Inspector) fromReferrers(d name.Digest, opts []remote.Option) ([]FoundSBOM, error) {
	idx, err := remote.Referrers(d, opts...)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("referrers: %w", err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}
	var out []FoundSBOM
	for n, desc := range im.Manifests {
		if n >= MaxArtifacts {
			break
		}
		at := desc.ArtifactType
		if !isCarrier(at) {
			continue
		}
		// Skip bundles that announce a non-SBOM predicate without fetching.
		if pt := desc.Annotations[annBundlePredicateType]; pt != "" && !sbomdoc.IsSBOMPredicate(pt) {
			continue
		}
		docs, err := i.sbomsInManifest(d.Context().Digest(desc.Digest.String()), opts)
		if err != nil {
			return out, err
		}
		for _, doc := range docs {
			out = append(out, FoundSBOM{Subject: d.DigestStr(), Doc: doc.doc, Attestation: sctypes.Attestation{
				Mechanism: sctypes.MechanismOCIReferrer, ArtifactDigest: desc.Digest.String(),
				MediaType: doc.mediaType, PredicateType: doc.doc.PredicateType,
			}})
			return out, nil
		}
	}
	return out, nil
}

func (i *Inspector) fromCosignTag(d name.Digest, suffix, mechanism string, opts []remote.Option) ([]FoundSBOM, error) {
	tag := d.Context().Tag(strings.Replace(d.DigestStr(), ":", "-", 1) + "." + suffix)
	desc, err := remote.Get(tag, opts...)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("cosign %s: %w", suffix, err)
	}
	docs, err := i.sbomsInManifest(d.Context().Digest(desc.Digest.String()), opts)
	if err != nil {
		return nil, err
	}
	for _, doc := range docs {
		return []FoundSBOM{{Subject: d.DigestStr(), Doc: doc.doc, Attestation: sctypes.Attestation{
			Mechanism: mechanism, ArtifactDigest: desc.Digest.String(),
			MediaType: doc.mediaType, PredicateType: doc.doc.PredicateType,
		}}}, nil
	}
	return nil, nil
}

// fromBuildKit reads SBOM attestations BuildKit stores inside an image
// index as unknown/unknown manifests pointing at a platform manifest.
func (i *Inspector) fromBuildKit(d name.Digest, opts []remote.Option) ([]FoundSBOM, error) {
	desc, err := remote.Get(d, opts...)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if !desc.MediaType.IsIndex() {
		return nil, nil
	}
	idx, err := desc.ImageIndex()
	if err != nil {
		return nil, err
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}
	var out []FoundSBOM
	seen := 0
	for _, m := range im.Manifests {
		if m.Annotations[annRefType] != "attestation-manifest" {
			continue
		}
		if seen++; seen > MaxArtifacts {
			break
		}
		subject := m.Annotations[annRefDigest]
		if subject == "" {
			continue
		}
		docs, err := i.sbomsInManifest(d.Context().Digest(m.Digest.String()), opts)
		if err != nil {
			return out, err
		}
		for _, doc := range docs {
			out = append(out, FoundSBOM{Subject: subject, Doc: doc.doc, Attestation: sctypes.Attestation{
				Mechanism: sctypes.MechanismBuildKitAttestation, ArtifactDigest: m.Digest.String(),
				MediaType: doc.mediaType, PredicateType: doc.doc.PredicateType,
			}})
			break
		}
	}
	return out, nil
}

type parsedLayer struct {
	doc       *sbomdoc.Doc
	mediaType string
}

// sbomsInManifest parses every SBOM-bearing layer of one artifact
// manifest, skipping layers that announce a non-SBOM predicate.
func (i *Inspector) sbomsInManifest(ref name.Digest, opts []remote.Option) ([]parsedLayer, error) {
	img, err := remote.Image(ref, opts...)
	if err != nil {
		return nil, fmt.Errorf("artifact %s: %w", ref.DigestStr(), err)
	}
	m, err := img.Manifest()
	if err != nil {
		return nil, err
	}
	var out []parsedLayer
	for n, l := range m.Layers {
		if n >= MaxArtifacts {
			break
		}
		mt := string(l.MediaType)
		if pt := l.Annotations[annPredicateType]; pt != "" && !sbomdoc.IsSBOMPredicate(pt) {
			continue
		}
		if !isCarrier(mt) {
			continue
		}
		if l.Size > MaxSBOMBytes {
			continue
		}
		b, err := readLayer(img, l)
		if err != nil {
			return out, err
		}
		doc, err := sbomdoc.Parse(b)
		if err != nil {
			continue // not an SBOM, or a format we do not read (XML, tag-value)
		}
		out = append(out, parsedLayer{doc: doc, mediaType: mt})
	}
	return out, nil
}

// isCarrier reports whether a media or artifact type can hold an SBOM:
// an in-toto statement, a DSSE envelope, a sigstore bundle, or a bare
// SPDX/CycloneDX JSON document.
func isCarrier(mt string) bool {
	return mt == mtInToto || mt == mtDSSE || strings.HasPrefix(mt, mtBundlePrefix) || isSBOMMediaType(mt)
}

func isSBOMMediaType(mt string) bool {
	switch mt {
	case mtSPDXJSON, mtSPDXJSON2, mtCDXJSON:
		return true
	}
	return false
}

func readLayer(img v1.Image, l v1.Descriptor) ([]byte, error) {
	layer, err := img.LayerByDigest(l.Digest)
	if err != nil {
		return nil, err
	}
	rc, err := layer.Compressed()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, MaxSBOMBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxSBOMBytes {
		return nil, fmt.Errorf("layer %s exceeds %d bytes", l.Digest, MaxSBOMBytes)
	}
	return b, nil
}
