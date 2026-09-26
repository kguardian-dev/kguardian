/**
 * Image signature results (#1533 P2-1), as the Broker serves them
 * (broker/src/attestation.rs, docs/api-reference/endpoints/attestations.mdx).
 * The Broker never verifies anything itself: it stores what the supplychain
 * component reported.
 */

/**
 * - `verified`: a signature verified. Valid, not trusted: any Fulcio
 *   identity or configured key can produce one. Never shown without its signer.
 * - `key_signed`: signed with a public key kguardian was not given; not checked.
 * - `unsigned`: no signature, and every lookup answered.
 * - `invalid`: signatures exist and none verified (tampered, wrong digest, malformed).
 * - `unknown`: could not be checked; not the same as unsigned.
 */
export type SignatureVerdict = 'verified' | 'key_signed' | 'unsigned' | 'invalid' | 'unknown';

/** A verified signer in a summary or the running feed. */
export type Signer =
  | { kind: 'keyless'; issuer?: string; san?: string }
  | { kind: 'key'; keyName?: string; keyFingerprint?: string };

export interface Provenance {
  builderId?: string;
  buildType?: string;
  sourceRepo?: string;
  sourceCommit?: string;
  sourceRef?: string;
}

/** One signature (or attestation) as checked. Unverified ones carry `error`/`detail` and no identity. */
export interface SignatureCheck {
  format: string;
  source: string;
  verified: boolean;
  error?: string;
  detail?: string;
  subject?: string;
  signerKind?: 'keyless' | 'key' | string;
  issuer?: string;
  san?: string;
  keyName?: string;
  keyFingerprint?: string;
  keyPem?: string;
  keyHint?: string;
  integratedTime?: string;
  tlogIndex?: number;
}

export interface AttestationCheck extends SignatureCheck {
  predicateType: string;
  payloadSha256?: string;
  provenance?: Provenance;
}

/** `GET /images/{digest}/attestation`. */
export interface ImageAttestation {
  digest: string;
  repository: string;
  verdict: string;
  reason: string | null;
  trustRoot: string | null;
  /** `self`, or `index` when the signature is on the multi-arch index that lists the digest. */
  signedVia: string | null;
  signedDigest: string | null;
  signatures: SignatureCheck[];
  attestations: AttestationCheck[];
  checkedAt: string;
  receivedAt: string;
}

/** One item of `GET /attestations`. Identity strings are cut to 256 bytes here. */
export interface AttestationSummary {
  digest: string;
  repository: string;
  verdict: string;
  reason: string | null;
  signedVia: string | null;
  signers: Signer[];
  verifiedPredicates: string[];
  checkedAt: string;
}

export interface AttestationPage {
  items: AttestationSummary[];
  nextAfter: string | null;
}

/** One running workload container of `GET /attestations/running`. `verdict` null = not checked (never "unsigned"). */
export interface RunningImageSignature {
  namespace: string;
  workloadKind: string;
  workloadName: string;
  container: string;
  digest: string;
  imageRef: string;
  repository: string | null;
  verdict: string | null;
  reason: string | null;
  checkedAt: string | null;
  signers: SignatureCheck[];
  attestations: AttestationCheck[];
}

export interface RunningSignaturePage {
  items: RunningImageSignature[];
  nextAfter: string | null;
}

export type AdmissionFormat = 'kguardian' | 'kyverno' | 'policy-controller';

/** One document of a workload export bundle (`format=zip-manifest`). */
export interface ExportDocument {
  artifact: string;
  fileName: string;
  available: boolean;
  refused: string | null;
  reason: string | null;
  apiVersion: string | null;
  kind: string | null;
  mode: 'audit' | 'enforce';
  contentType: string | null;
  content: string | null;
  applyWith: string | null;
}

export interface ExportManifest {
  workload: { namespace: string; kind: string; name: string };
  mode: 'audit' | 'enforce';
  generatedAt: string;
  recorded: boolean;
  documents: ExportDocument[];
}
