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

// Rejection reasons for documents that were found but not used.
const (
	RejectEmpty           = "empty"            // no components
	RejectSubjectMissing  = "subject_missing"  // in-toto statement without a sha256 subject
	RejectSubjectMismatch = "subject_mismatch" // subject is neither the image nor one of its platform manifests
)

// FoundSBOM is one SBOM located for an image.
type FoundSBOM struct {
	// Subject is the digest the SBOM describes: the digest asked about,
	// or one platform manifest of it when the digest is an index.
	Subject string
	// IndexDigest is the index Subject belongs to, when Subject is a
	// platform manifest of the digest asked about.
	IndexDigest string
	Doc         *sbomdoc.Doc
	Attestation sctypes.Attestation
	// Trust is SBOMTrustUnverified for an in-toto statement whose subject
	// matched, SBOMTrustAttachedUnbound for a bare document.
	Trust string
}

// fetch is one FetchSBOMs call's state.
type fetch struct {
	i    *Inspector
	d    name.Digest
	opts []remote.Option
	// index is set when d is an image index; allowed holds d and its
	// platform manifests: the only subjects a statement may name.
	index    *v1.IndexManifest
	allowed  map[string]bool
	rejected []string
}

// FetchSBOMs finds SBOMs attached to repository@digest, anonymously and
// through the guard, in this order of preference per subject:
//  1. OCI referrers (sigstore bundles, in-toto, SPDX/CycloneDX artifacts),
//  2. cosign attestations (tag sha256-<hex>.att),
//  3. cosign attached SBOMs (tag sha256-<hex>.sbom),
//  4. BuildKit attestation manifests inside an index.
//
// Nothing here verifies a signature, so every document is untrusted:
//   - an in-toto statement must name, as a sha256 subject, the digest asked
//     about or one of its platform manifests; otherwise it is rejected;
//   - a bare SPDX/CycloneDX document cannot say what it describes and is
//     accepted as "attached-unbound";
//   - a document with no components is rejected.
//
// The first acceptable SBOM per subject wins. Rejection reasons are
// returned alongside. A refused destination returns a *BlockedError;
// "nothing attached" is an empty result, not an error.
func (i *Inspector) FetchSBOMs(ctx context.Context, registry, repository, digest string) ([]FoundSBOM, []string, error) {
	d, err := i.digestRef(registry, repository, digest)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 6*i.timeout())
	defer cancel()
	f := &fetch{i: i, d: d, opts: i.remoteOpts(ctx), allowed: map[string]bool{digest: true}}

	var errs []error
	if err := f.loadIndex(); err != nil {
		errs = append(errs, err)
	}
	var out []FoundSBOM
	have := map[string]bool{}
	collect := func(found []FoundSBOM, err error) {
		for _, x := range found {
			if !have[x.Subject] {
				have[x.Subject] = true
				out = append(out, x)
			}
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	collect(f.fromReferrers())
	if !have[digest] {
		collect(f.fromCosignTag("att", sctypes.MechanismCosignAttestation))
	}
	if !have[digest] {
		collect(f.fromCosignTag("sbom", sctypes.MechanismCosignSBOM))
	}
	collect(f.fromBuildKit())

	// A refusal anywhere is the answer: the destination is off limits.
	for _, e := range errs {
		if _, ok := blockedReason(e); ok {
			return nil, nil, e
		}
	}
	if len(out) == 0 && len(errs) > 0 {
		return nil, f.rejected, errors.Join(errs...)
	}
	return out, f.rejected, nil
}

func (f *fetch) loadIndex() error {
	desc, err := remote.Get(f.d, f.opts...)
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return err
	}
	if !desc.MediaType.IsIndex() {
		return nil
	}
	idx, err := desc.ImageIndex()
	if err != nil {
		return err
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return err
	}
	f.index = im
	for _, m := range im.Manifests {
		if m.Annotations[annRefType] == "" && m.MediaType.IsImage() {
			f.allowed[m.Digest.String()] = true
		}
	}
	return nil
}

// accept validates doc for the subject the carrier points at (want) and
// returns the FoundSBOM, or records a rejection and returns false.
func (f *fetch) accept(doc *sbomdoc.Doc, want string, att sctypes.Attestation) (FoundSBOM, bool) {
	if len(doc.Components) == 0 {
		f.rejected = append(f.rejected, RejectEmpty)
		return FoundSBOM{}, false
	}
	found := FoundSBOM{Doc: doc, Attestation: att, Subject: want, Trust: sctypes.SBOMTrustAttachedUnbound}
	if doc.InToto {
		if len(doc.Subjects) == 0 {
			f.rejected = append(f.rejected, RejectSubjectMissing)
			return FoundSBOM{}, false
		}
		match := ""
		for _, s := range doc.Subjects {
			if s == want {
				match = s
				break
			}
			if match == "" && f.allowed[s] {
				match = s
			}
		}
		if match == "" {
			f.rejected = append(f.rejected, RejectSubjectMismatch)
			return FoundSBOM{}, false
		}
		found.Subject = match
		found.Trust = sctypes.SBOMTrustUnverified
	}
	if found.Subject != f.d.DigestStr() {
		found.IndexDigest = f.d.DigestStr()
	}
	return found, true
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

func (f *fetch) fromReferrers() ([]FoundSBOM, error) {
	idx, err := remote.Referrers(f.d, f.opts...)
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
	for n, desc := range im.Manifests {
		if n >= MaxArtifacts {
			break
		}
		if !isCarrier(desc.ArtifactType) {
			continue
		}
		// Skip bundles that announce a non-SBOM predicate without fetching.
		if pt := desc.Annotations[annBundlePredicateType]; pt != "" && !sbomdoc.IsSBOMPredicate(pt) {
			continue
		}
		docs, err := f.sbomsInManifest(f.d.Context().Digest(desc.Digest.String()))
		if err != nil {
			return nil, err
		}
		for _, doc := range docs {
			att := sctypes.Attestation{Mechanism: sctypes.MechanismOCIReferrer, ArtifactDigest: desc.Digest.String(),
				MediaType: doc.mediaType, PredicateType: doc.doc.PredicateType}
			if found, ok := f.accept(doc.doc, f.d.DigestStr(), att); ok {
				return []FoundSBOM{found}, nil
			}
		}
	}
	return nil, nil
}

func (f *fetch) fromCosignTag(suffix, mechanism string) ([]FoundSBOM, error) {
	tag := f.d.Context().Tag(strings.Replace(f.d.DigestStr(), ":", "-", 1) + "." + suffix)
	desc, err := remote.Get(tag, f.opts...)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("cosign %s: %w", suffix, err)
	}
	docs, err := f.sbomsInManifest(f.d.Context().Digest(desc.Digest.String()))
	if err != nil {
		return nil, err
	}
	for _, doc := range docs {
		att := sctypes.Attestation{Mechanism: mechanism, ArtifactDigest: desc.Digest.String(),
			MediaType: doc.mediaType, PredicateType: doc.doc.PredicateType}
		if found, ok := f.accept(doc.doc, f.d.DigestStr(), att); ok {
			return []FoundSBOM{found}, nil
		}
	}
	return nil, nil
}

// fromBuildKit reads SBOM attestations BuildKit stores inside an image
// index as unknown/unknown manifests pointing at a platform manifest.
func (f *fetch) fromBuildKit() ([]FoundSBOM, error) {
	if f.index == nil {
		return nil, nil
	}
	var out []FoundSBOM
	seen := 0
	for _, m := range f.index.Manifests {
		if m.Annotations[annRefType] != "attestation-manifest" {
			continue
		}
		if seen++; seen > MaxArtifacts {
			break
		}
		platform := m.Annotations[annRefDigest]
		if platform == "" || !f.allowed[platform] {
			continue
		}
		docs, err := f.sbomsInManifest(f.d.Context().Digest(m.Digest.String()))
		if err != nil {
			return out, err
		}
		for _, doc := range docs {
			att := sctypes.Attestation{Mechanism: sctypes.MechanismBuildKitAttestation, ArtifactDigest: m.Digest.String(),
				MediaType: doc.mediaType, PredicateType: doc.doc.PredicateType}
			if found, ok := f.accept(doc.doc, platform, att); ok {
				out = append(out, found)
				break
			}
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
func (f *fetch) sbomsInManifest(ref name.Digest) ([]parsedLayer, error) {
	img, err := remote.Image(ref, f.opts...)
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
