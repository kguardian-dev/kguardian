package attest

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// Cosign legacy annotations on a .sig / .att layer.
const (
	annSignature   = "dev.cosignproject.cosign/signature"
	annCertificate = "dev.sigstore.cosign/certificate"
	annChain       = "dev.sigstore.cosign/chain"
	annBundle      = "dev.sigstore.cosign/bundle" // Rekor SET
	annPredicate   = "predicateType"

	mediaSimpleSigning = "application/vnd.dev.cosign.simplesigning.v1+json"
	mediaDSSE          = "application/vnd.dsse.envelope.v1+json"
	payloadTypeInToto  = "application/vnd.in-toto+json"
	bundleV01          = "application/vnd.dev.sigstore.bundle+json;version=0.1"
	maxDetail          = 256
)

// verifyError is a failed check with a machine Reason.
type verifyError struct {
	reason string
	err    error
}

func (e *verifyError) Error() string { return e.reason + ": " + e.err.Error() }

func vErr(reason string, format string, a ...any) *verifyError {
	return &verifyError{reason: reason, err: fmt.Errorf(format, a...)}
}

// reasonOf maps any error from this file or the fetcher to a Reason.
func reasonOf(err error) string {
	var ve *verifyError
	if errors.As(err, &ve) {
		return ve.reason
	}
	var fe *fetchError
	if errors.As(err, &fe) {
		return fe.reason
	}
	return ReasonBadSignature
}

func detail(err error) string {
	s := err.Error()
	if len(s) > maxDetail {
		s = s[:maxDetail]
	}
	return s
}

// verifier wraps sigstore-go with the options kguardian uses for every
// keyless signature: one transparency-log entry, one observer timestamp
// (the log's integrated time or an RFC 3161 timestamp) and, by default,
// one SCT. Key-signed signatures are checked against the configured keys
// only; a transparency-log entry is not required for them (cosign's
// --tlog-upload=false), matching "cosign verify --key
// --insecure-ignore-tlog".
type verifier struct {
	v    *verify.Verifier
	keys []trustedKey
}

func newVerifier(tm root.TrustedMaterial, requireSCT bool, keys []trustedKey) (*verifier, error) {
	opts := []verify.VerifierOption{verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1)}
	if requireSCT {
		opts = append(opts, verify.WithSignedCertificateTimestamps(1))
	}
	v, err := verify.NewVerifier(tm, opts...)
	if err != nil {
		return nil, err
	}
	return &verifier{v: v, keys: keys}, nil
}

// anyIdentity accepts any issuer and SAN. Discovery records who signed;
// matching the signer to a trust policy is a separate step, done on the
// identity sigstore-go extracted from the verified certificate.
var anyIdentity = func() verify.CertificateIdentity {
	id, err := verify.NewShortCertificateIdentity("", ".+", "", ".+")
	if err != nil {
		panic(err)
	}
	return id
}()

func signerFrom(res *verify.VerificationResult) Signer {
	var s Signer
	if res == nil {
		return s
	}
	if res.Signature != nil && res.Signature.Certificate != nil {
		s.Kind = SignerKeyless
		s.Issuer = res.Signature.Certificate.Issuer
		s.SAN = res.Signature.Certificate.SubjectAlternativeName
	}
	for _, ts := range res.VerifiedTimestamps {
		if ts.Type == "Tlog" {
			t := ts.Timestamp.UTC()
			s.IntegratedTime = &t
			break
		}
	}
	return s
}

func tlogIndex(b *bundle.Bundle) *int64 {
	if b == nil || b.VerificationMaterial == nil {
		return nil
	}
	for _, e := range b.VerificationMaterial.GetTlogEntries() {
		i := e.GetLogIndex()
		return &i
	}
	return nil
}

func digestBytes(digest string) (string, []byte, error) {
	alg, hexPart, ok := strings.Cut(digest, ":")
	if !ok {
		return "", nil, fmt.Errorf("malformed digest %q", digest)
	}
	b, err := hex.DecodeString(hexPart)
	if err != nil {
		return "", nil, fmt.Errorf("malformed digest %q: %w", digest, err)
	}
	return alg, b, nil
}

// statement is the part of an in-toto statement read before and after
// verification.
type statement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	Predicate json.RawMessage `json:"predicate"`
}

func (s *statement) names(digest string) bool {
	alg, hexPart, _ := strings.Cut(digest, ":")
	for _, sub := range s.Subject {
		if strings.EqualFold(sub.Digest[alg], hexPart) {
			return true
		}
	}
	return false
}

// dsseCheck is the verified content of one DSSE-signed statement.
type dsseCheck struct {
	predicateType string
	payloadSHA256 string
	stmt          *statement
	signer        Signer
}

// verifyDSSEBundle verifies a bundle whose content is a DSSE envelope over
// an in-toto statement, and that the statement names digest as a subject.
func (v *verifier) verifyDSSEBundle(b *bundle.Bundle, digest string) (*dsseCheck, error) {
	env := b.GetDsseEnvelope()
	if env == nil {
		return nil, vErr(ReasonUnsupportedFormat, "bundle content is not a DSSE envelope")
	}
	if env.GetPayloadType() != payloadTypeInToto {
		return nil, vErr(ReasonUnsupportedFormat, "DSSE payload type %q", env.GetPayloadType())
	}
	payload := env.GetPayload()
	var st statement
	if err := json.Unmarshal(payload, &st); err != nil {
		return nil, vErr(ReasonMalformed, "in-toto statement: %v", err)
	}
	sum := sha256.Sum256(payload)
	out := &dsseCheck{predicateType: st.PredicateType, payloadSHA256: hex.EncodeToString(sum[:]), stmt: &st}
	// Checked before the signature so a statement about another image is
	// reported as such, whatever its signature state.
	if !st.names(digest) {
		return out, vErr(ReasonDigestMismatch, "statement subjects do not include %s", digest)
	}
	if pk := b.VerificationMaterial.GetPublicKey(); pk != nil {
		sigs := make([][]byte, 0, len(env.GetSignatures()))
		for _, s := range env.GetSignatures() {
			sigs = append(sigs, s.GetSig())
		}
		signer, err := verifyWithKeys(v.keys, pae(env.GetPayloadType(), payload), sigs, pk.GetHint())
		out.signer = signer
		return out, err
	}
	alg, raw, err := digestBytes(digest)
	if err != nil {
		return out, vErr(ReasonMalformed, "%v", err)
	}
	res, err := v.v.Verify(b, verify.NewPolicy(verify.WithArtifactDigest(alg, raw), verify.WithCertificateIdentity(anyIdentity)))
	if err != nil {
		return out, &verifyError{reason: ReasonBadSignature, err: err}
	}
	out.signer = signerFrom(res)
	out.signer.TlogIndex = tlogIndex(b)
	return out, nil
}

// --- Legacy cosign (.sig / .att tags) ---

// rekorSET is the dev.sigstore.cosign/bundle annotation.
type rekorSET struct {
	SignedEntryTimestamp string `json:"SignedEntryTimestamp"`
	Payload              struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogIndex       int64  `json:"logIndex"`
		LogID          string `json:"logID"`
	} `json:"Payload"`
}

// legacyMaterial builds bundle v0.1 verification material from cosign's
// layer annotations: the Fulcio certificate and chain, and the Rekor
// signed entry timestamp (an inclusion promise).
func legacyMaterial(ann map[string]string) (*protobundle.VerificationMaterial, error) {
	certPEM := ann[annCertificate]
	if certPEM == "" {
		return nil, vErr(ReasonUntrustedKey, "no certificate (key-signed signature)")
	}
	var certs []*protocommon.X509Certificate
	rest := []byte(certPEM + "\n" + ann[annChain])
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			certs = append(certs, &protocommon.X509Certificate{RawBytes: blk.Bytes})
		}
	}
	if len(certs) == 0 {
		return nil, vErr(ReasonMalformed, "certificate annotation holds no PEM certificate")
	}
	setJSON := ann[annBundle]
	if setJSON == "" {
		return nil, vErr(ReasonBadSignature, "no transparency log entry (%s)", annBundle)
	}
	var set rekorSET
	if err := json.Unmarshal([]byte(setJSON), &set); err != nil {
		return nil, vErr(ReasonMalformed, "rekor bundle: %v", err)
	}
	body, err := base64.StdEncoding.DecodeString(set.Payload.Body)
	if err != nil {
		return nil, vErr(ReasonMalformed, "rekor body: %v", err)
	}
	var kv struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
	}
	if err := json.Unmarshal(body, &kv); err != nil {
		return nil, vErr(ReasonMalformed, "rekor body: %v", err)
	}
	sets, err := base64.StdEncoding.DecodeString(set.SignedEntryTimestamp)
	if err != nil {
		return nil, vErr(ReasonMalformed, "signed entry timestamp: %v", err)
	}
	logID, err := hex.DecodeString(set.Payload.LogID)
	if err != nil {
		return nil, vErr(ReasonMalformed, "log id: %v", err)
	}
	return &protobundle.VerificationMaterial{
		Content: &protobundle.VerificationMaterial_X509CertificateChain{
			X509CertificateChain: &protocommon.X509CertificateChain{Certificates: certs},
		},
		TlogEntries: []*protorekor.TransparencyLogEntry{{
			LogIndex:          set.Payload.LogIndex,
			LogId:             &protocommon.LogId{KeyId: logID},
			KindVersion:       &protorekor.KindVersion{Kind: kv.Kind, Version: kv.APIVersion},
			IntegratedTime:    set.Payload.IntegratedTime,
			InclusionPromise:  &protorekor.InclusionPromise{SignedEntryTimestamp: sets},
			CanonicalizedBody: body,
		}},
	}, nil
}

// simpleSigning is cosign's legacy signed payload.
type simpleSigning struct {
	Critical struct {
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
		Type string `json:"type"`
	} `json:"critical"`
}

// verifyLegacySig verifies a .sig layer: the signature over the
// simplesigning payload, and that the payload names digest.
func (v *verifier) verifyLegacySig(payload []byte, ann map[string]string, digest string) (Signer, error) {
	var ss simpleSigning
	if err := json.Unmarshal(payload, &ss); err != nil {
		return Signer{}, vErr(ReasonMalformed, "simplesigning payload: %v", err)
	}
	if ss.Critical.Image.DockerManifestDigest != digest {
		return Signer{}, vErr(ReasonDigestMismatch, "signature is for %s, not %s", ss.Critical.Image.DockerManifestDigest, digest)
	}
	sig, err := base64.StdEncoding.DecodeString(ann[annSignature])
	if err != nil || len(sig) == 0 {
		return Signer{}, vErr(ReasonMalformed, "signature annotation is not base64")
	}
	if ann[annCertificate] == "" {
		// Key-signed: the signature is over the payload bytes.
		return verifyWithKeys(v.keys, payload, [][]byte{sig}, "")
	}
	vm, err := legacyMaterial(ann)
	if err != nil {
		return Signer{}, err
	}
	sum := sha256.Sum256(payload)
	pb := &protobundle.Bundle{
		MediaType:            bundleV01,
		VerificationMaterial: vm,
		Content: &protobundle.Bundle_MessageSignature{MessageSignature: &protocommon.MessageSignature{
			MessageDigest: &protocommon.HashOutput{Algorithm: protocommon.HashAlgorithm_SHA2_256, Digest: sum[:]},
			Signature:     sig,
		}},
	}
	b, err := bundle.NewBundle(pb)
	if err != nil {
		return Signer{}, vErr(ReasonMalformed, "%v", err)
	}
	res, err := v.v.Verify(b, verify.NewPolicy(verify.WithArtifact(bytes.NewReader(payload)), verify.WithCertificateIdentity(anyIdentity)))
	if err != nil {
		return Signer{}, &verifyError{reason: ReasonBadSignature, err: err}
	}
	s := signerFrom(res)
	s.TlogIndex = tlogIndex(b)
	return s, nil
}

// dsseEnvelopeJSON is a DSSE envelope as cosign stores it in a .att layer.
type dsseEnvelopeJSON struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signatures  []struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	} `json:"signatures"`
}

// verifyLegacyAtt verifies a .att layer (a DSSE envelope) as a v0.1
// bundle.
func (v *verifier) verifyLegacyAtt(envJSON []byte, ann map[string]string, digest string) (*dsseCheck, error) {
	var ej dsseEnvelopeJSON
	if err := json.Unmarshal(envJSON, &ej); err != nil {
		return nil, vErr(ReasonMalformed, "DSSE envelope: %v", err)
	}
	payload, err := base64.StdEncoding.DecodeString(ej.Payload)
	if err != nil {
		return nil, vErr(ReasonMalformed, "DSSE payload: %v", err)
	}
	env := &protodsse.Envelope{PayloadType: ej.PayloadType, Payload: payload}
	for _, s := range ej.Signatures {
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			return nil, vErr(ReasonMalformed, "DSSE signature: %v", err)
		}
		env.Signatures = append(env.Signatures, &protodsse.Signature{Sig: sig, Keyid: s.KeyID})
	}
	if ann[annCertificate] == "" {
		// Key-signed DSSE envelope.
		out := &dsseCheck{predicateType: ann[annPredicate]}
		var st statement
		if err := json.Unmarshal(payload, &st); err != nil {
			return out, vErr(ReasonMalformed, "in-toto statement: %v", err)
		}
		sum := sha256.Sum256(payload)
		out.predicateType, out.stmt, out.payloadSHA256 = st.PredicateType, &st, hex.EncodeToString(sum[:])
		if !st.names(digest) {
			return out, vErr(ReasonDigestMismatch, "statement subjects do not include %s", digest)
		}
		sigs := make([][]byte, 0, len(env.Signatures))
		for _, s := range env.Signatures {
			sigs = append(sigs, s.Sig)
		}
		signer, err := verifyWithKeys(v.keys, pae(ej.PayloadType, payload), sigs, "")
		out.signer = signer
		return out, err
	}
	vm, err := legacyMaterial(ann)
	if err != nil {
		// Still report what the statement claims.
		out := &dsseCheck{predicateType: ann[annPredicate]}
		var st statement
		if json.Unmarshal(payload, &st) == nil {
			out.predicateType, out.stmt = st.PredicateType, &st
			sum := sha256.Sum256(payload)
			out.payloadSHA256 = hex.EncodeToString(sum[:])
		}
		return out, err
	}
	b, err := bundle.NewBundle(&protobundle.Bundle{
		MediaType:            bundleV01,
		VerificationMaterial: vm,
		Content:              &protobundle.Bundle_DsseEnvelope{DsseEnvelope: env},
	})
	if err != nil {
		return nil, vErr(ReasonMalformed, "%v", err)
	}
	return v.verifyDSSEBundle(b, digest)
}

// loadBundle parses a Sigstore bundle (any supported version).
func loadBundle(raw []byte) (*bundle.Bundle, error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(raw); err != nil {
		return nil, vErr(ReasonMalformed, "bundle: %v", err)
	}
	return &b, nil
}

// provenanceOf extracts builder and source from a SLSA v1 or v0.2
// predicate. Missing fields stay empty.
func provenanceOf(predicateType string, predicate json.RawMessage) *Provenance {
	switch predicateType {
	case PredicateSLSAv1:
		var p struct {
			BuildDefinition struct {
				BuildType          string `json:"buildType"`
				ExternalParameters struct {
					Workflow struct {
						Ref        string `json:"ref"`
						Repository string `json:"repository"`
					} `json:"workflow"`
				} `json:"externalParameters"`
				ResolvedDependencies []struct {
					URI    string            `json:"uri"`
					Digest map[string]string `json:"digest"`
				} `json:"resolvedDependencies"`
			} `json:"buildDefinition"`
			RunDetails struct {
				Builder struct {
					ID string `json:"id"`
				} `json:"builder"`
			} `json:"runDetails"`
		}
		if json.Unmarshal(predicate, &p) != nil {
			return nil
		}
		out := &Provenance{
			BuilderID:  p.RunDetails.Builder.ID,
			BuildType:  p.BuildDefinition.BuildType,
			SourceRepo: p.BuildDefinition.ExternalParameters.Workflow.Repository,
			SourceRef:  p.BuildDefinition.ExternalParameters.Workflow.Ref,
		}
		for _, d := range p.BuildDefinition.ResolvedDependencies {
			if c := d.Digest["gitCommit"]; c != "" {
				out.SourceCommit = c
				if out.SourceRepo == "" {
					out.SourceRepo, _, _ = strings.Cut(strings.TrimPrefix(d.URI, "git+"), "@")
				}
				break
			}
		}
		return out
	case PredicateSLSAv02:
		var p struct {
			Builder struct {
				ID string `json:"id"`
			} `json:"builder"`
			BuildType  string `json:"buildType"`
			Invocation struct {
				ConfigSource struct {
					URI    string            `json:"uri"`
					Digest map[string]string `json:"digest"`
				} `json:"configSource"`
			} `json:"invocation"`
		}
		if json.Unmarshal(predicate, &p) != nil {
			return nil
		}
		repo, ref, _ := strings.Cut(strings.TrimPrefix(p.Invocation.ConfigSource.URI, "git+"), "@")
		return &Provenance{
			BuilderID:    p.Builder.ID,
			BuildType:    p.BuildType,
			SourceRepo:   repo,
			SourceRef:    ref,
			SourceCommit: p.Invocation.ConfigSource.Digest["sha1"],
		}
	}
	return nil
}

// now is replaceable in tests.
var now = func() time.Time { return time.Now().UTC() }
