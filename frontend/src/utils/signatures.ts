import type { LensBadge } from '../types';
import type { RunningImageSignature, SignatureCheck, SignatureVerdict, Signer } from '../types/attestations';
import type { ProfileSigner, SupplyChainDimension } from '../types/profile';

/**
 * How image signature results are shown. The rules this exists to hold:
 *  - `verified` means a signature is valid, not that the signer is trusted:
 *    it is never green, never "trusted", and never shown without its signer;
 *  - `unknown`, an unrecognised verdict or reason, and "not checked" are
 *    never good and never "unsigned";
 *  - a workload's state is its worst image, so one unchecked image keeps it
 *    from reading as signed.
 * kguardian computes none of this: every verdict is the supplychain
 * component's, stored by the Broker.
 */

/** A verdict, or `unchecked` (no result for the digest). Anything else the Broker sends reads as unknown. */
export type SignatureState = SignatureVerdict | 'unchecked';

const VERDICTS: readonly SignatureVerdict[] = ['verified', 'key_signed', 'unsigned', 'invalid', 'unknown'];

export function asSignatureState(v: string | null | undefined): SignatureState {
  if (v == null) return 'unchecked';
  return (VERDICTS as readonly string[]).includes(v) ? (v as SignatureVerdict) : 'unknown';
}

export const SIGNATURE_LABEL: Record<SignatureState, string> = {
  verified: 'Signature verified',
  key_signed: 'Signed, key not held',
  unsigned: 'Unsigned',
  invalid: 'Invalid signature',
  unknown: 'Unknown',
  unchecked: 'Not checked',
};

/** Short form for badges. */
export const SIGNATURE_SHORT: Record<SignatureState, string> = {
  verified: 'signed',
  key_signed: 'key-signed',
  unsigned: 'unsigned',
  invalid: 'sig invalid',
  unknown: 'sig unknown',
  unchecked: 'not checked',
};

export const SIGNATURE_MEANING: Record<SignatureState, string> = {
  verified: 'A signature verified. Valid, not trusted: anyone who can push to the repository can attach one. Check the signer.',
  key_signed: 'Signed with a public key kguardian was not given: the signature exists and was not checked.',
  unsigned: 'No signature, and every lookup answered.',
  invalid: 'Signatures exist and none verified.',
  unknown: 'Could not be checked. Not the same as unsigned.',
  unchecked: 'No signature result for this image yet (not checked, or signature discovery is off). Not the same as unsigned.',
};

/** Badge tone. Verified is neutral, never good: a valid signature is not a trusted one. */
export const SIGNATURE_TONE: Record<SignatureState, LensBadge['tone']> = {
  verified: 'neutral',
  key_signed: 'unknown',
  unsigned: 'warn',
  invalid: 'risk',
  unknown: 'unknown',
  unchecked: 'unknown',
};

/** Worst first: a workload reads as its worst image. */
const ORDER: readonly SignatureState[] = ['invalid', 'unsigned', 'key_signed', 'unknown', 'unchecked', 'verified'];
export const signatureRank = (s: SignatureState) => ORDER.indexOf(s);

const REASON_TEXT: Record<string, string> = {
  bad_signature: 'a signature did not verify',
  digest_mismatch: 'a signature is for a different digest',
  malformed: 'a signature is malformed',
  registry_auth: 'the registry needs credentials kguardian does not have (a private image)',
  rate_limited: 'the registry rate-limited the lookup',
  network: 'the registry could not be reached',
  timeout: 'the lookup timed out',
  registry_error: 'the registry returned an error',
  no_repo_digest: 'the image has no registry digest (only a config ID)',
  trust_root_unavailable: 'the Sigstore trust root could not be loaded',
  untrusted_root: 'signed under a trust root kguardian does not use',
  untrusted_key: 'signed with a key kguardian was not given',
  too_large: 'the signature data was too large to read',
  unsupported_format: 'a signature format kguardian cannot read',
  blocked_address: 'the registry address is blocked by the component\'s network rules',
  private_address: 'the registry address is private and blocked by the component\'s network rules',
  local_hostname: 'the registry host is local and blocked by the component\'s network rules',
  blocked_realm: 'the registry\'s auth realm is blocked by the component\'s network rules',
  unrecognised_reason: 'a reason this Broker does not know (the supplychain component is newer than the Broker)',
};

/** A reason code in words; an unknown code is shown as itself, never dropped. */
export function reasonText(code: string | null | undefined): string | null {
  if (!code) return null;
  return REASON_TEXT[code] ?? `reason "${code}"`;
}

/** A verified signature as a signer (the running feed and single reads carry checks, summaries carry signers). */
export function signerOf(c: SignatureCheck): Signer | null {
  if (!c.verified) return null; // a claimed signer is never shown as a fact
  if (c.signerKind === 'key') return { kind: 'key', keyName: c.keyName, keyFingerprint: c.keyFingerprint };
  return { kind: 'keyless', issuer: c.issuer, san: c.san };
}

/**
 * A running container's state. "Verified" with no verified signer to show
 * is unknown: a verdict is never shown as signed without its signer.
 */
export function runningState(it: RunningImageSignature): SignatureState {
  const st = asSignatureState(it.verdict);
  return st === 'verified' && !it.signers.some((c) => signerOf(c) !== null) ? 'unknown' : st;
}

/** The Broker said verified but sent no verified signer (shown as unknown, with why). */
export const verifiedWithoutSigner = (it: RunningImageSignature) => asSignatureState(it.verdict) === 'verified' && runningState(it) === 'unknown';

const shortFp = (fp?: string) => (fp ? `sha256:${fp.slice(0, 12)}…` : 'unknown fingerprint');

/** Who signed, in full: the identity a policy would trust. */
export function signerText(s: Signer): string {
  if (s.kind === 'key') return `key ${s.keyName ?? '(unnamed)'} (${shortFp(s.keyFingerprint)})`;
  return `${s.san ?? '(no subject)'} via ${s.issuer ?? '(no issuer)'}`;
}

/** The same identity, compact: for badges and chips. */
export function signerShort(s: Signer): string {
  if (s.kind === 'key') return `key ${s.keyName ?? shortFp(s.keyFingerprint)}`;
  const san = s.san ?? '';
  // A GitHub Actions workflow identity: owner/repo/workflow@ref reads better than the URL.
  const gh = san.match(/^https:\/\/github\.com\/([^/]+\/[^/]+)\/\.github\/workflows\/([^@]+)@(.+)$/);
  if (gh) return `${gh[1]} ${gh[2]}`;
  return san || '(no subject)';
}

export const signerKey = (s: Signer) => (s.kind === 'key' ? `key:${s.keyFingerprint ?? s.keyName}` : `keyless:${s.issuer}|${s.san}`);

export function uniqueSigners(list: Signer[]): Signer[] {
  const seen = new Map<string, Signer>();
  for (const s of list) if (!seen.has(signerKey(s))) seen.set(signerKey(s), s);
  return [...seen.values()];
}

/** What one workload's running containers say about their images' signatures. */
export interface WorkloadSignatures {
  /** Distinct running digests, by state. */
  byState: Record<SignatureState, string[]>;
  digests: string[];
  signers: Signer[];
  /** The workload's worst state. */
  worst: SignatureState;
}

const emptyStates = (): Record<SignatureState, string[]> => ({ verified: [], key_signed: [], unsigned: [], invalid: [], unknown: [], unchecked: [] });

/** Fold the running feed into per-workload summaries (key ns/kind/name). */
export function signaturesByWorkload(items: RunningImageSignature[], keyOf: (ns: string, kind: string, name: string) => string): Map<string, WorkloadSignatures> {
  const out = new Map<string, WorkloadSignatures>();
  for (const it of items) {
    const key = keyOf(it.namespace, it.workloadKind, it.workloadName);
    const acc = out.get(key) ?? { byState: emptyStates(), digests: [], signers: [], worst: 'verified' as SignatureState };
    if (!acc.digests.includes(it.digest)) {
      acc.digests.push(it.digest);
      const st = runningState(it);
      acc.byState[st].push(it.digest);
      if (signatureRank(st) < signatureRank(acc.worst)) acc.worst = st;
      if (st === 'verified') acc.signers = uniqueSigners([...acc.signers, ...it.signers.map(signerOf).filter((s): s is Signer => s !== null)]);
    }
    out.set(key, acc);
  }
  return out;
}


/** "2 unsigned, 1 not checked": every state but the worst's own count, so nothing unknown is hidden. */
export function stateCounts(w: WorkloadSignatures): string {
  return ORDER.filter((s) => w.byState[s].length > 0)
    .map((s) => `${w.byState[s].length} ${SIGNATURE_SHORT[s] === 'signed' ? 'verified' : SIGNATURE_SHORT[s]}`)
    .join(', ');
}

/** One line for a workload: the worst state, the counts, and every verified signer. */
export function workloadSignatureText(w: WorkloadSignatures): string {
  const n = w.digests.length;
  const signers = w.signers.length ? ` Signed by ${w.signers.map(signerText).join('; ')} (valid, not vetted: review before trusting).` : '';
  if (w.worst === 'verified') return `Every running image (${n}) has a verified signature.${signers}`;
  const counts = stateCounts(w);
  return `${SIGNATURE_LABEL[w.worst]}: ${SIGNATURE_MEANING[w.worst]} Running images: ${counts}.${signers}`;
}

/** Map badge text for a workload. */
export function signatureBadgeText(w: WorkloadSignatures): string {
  const n = w.digests.length;
  const bad = w.byState[w.worst].length;
  // Short, so the card keeps its name; the signer is in the badge's label (tooltip / accessible name).
  if (w.worst === 'verified') return n > 1 ? `signed ${n}/${n}` : 'signed';
  return n > 1 ? `${SIGNATURE_SHORT[w.worst]} ${bad}/${n}` : SIGNATURE_SHORT[w.worst];
}

/** One running image digest and what is known about who signed it. */
export interface DigestSignature {
  digest: string;
  /** The Broker said verified but sent no verified signer: shown as unknown. */
  noSigner: boolean;
  imageRef: string;
  repository: string | null;
  state: SignatureState;
  reason: string | null;
  checkedAt: string | null;
  signers: Signer[];
  /** Predicate types of verified attestations. */
  predicates: string[];
  /** Where the SLSA provenance says it was built from, when verified. */
  source: string | null;
  workloads: Array<{ namespace: string; kind: string; name: string; containers: string[] }>;
}

/** Group the running feed by digest, worst first. */
export function signaturesByDigest(items: RunningImageSignature[]): DigestSignature[] {
  const by = new Map<string, DigestSignature>();
  for (const it of items) {
    let d = by.get(it.digest);
    if (!d) {
      const prov = it.attestations.find((a) => a.verified && a.provenance?.sourceRepo)?.provenance;
      d = {
        digest: it.digest,
        imageRef: it.imageRef,
        repository: it.repository,
        state: runningState(it),
        noSigner: verifiedWithoutSigner(it),
        reason: it.reason,
        checkedAt: it.checkedAt,
        signers: uniqueSigners(it.signers.map(signerOf).filter((s): s is Signer => s !== null)),
        predicates: [...new Set(it.attestations.filter((a) => a.verified).map((a) => a.predicateType))],
        source: prov ? `${prov.sourceRepo}${prov.sourceRef ? ` @ ${prov.sourceRef}` : ''}` : null,
        workloads: [],
      };
      by.set(it.digest, d);
    }
    const w = d.workloads.find((x) => x.namespace === it.namespace && x.kind === it.workloadKind && x.name === it.workloadName);
    if (w) {
      if (!w.containers.includes(it.container)) w.containers.push(it.container);
    } else {
      d.workloads.push({ namespace: it.namespace, kind: it.workloadKind, name: it.workloadName, containers: [it.container] });
    }
  }
  return [...by.values()].sort((a, b) => signatureRank(a.state) - signatureRank(b.state) || a.imageRef.localeCompare(b.imageRef));
}

/** The comment header the Broker writes (identities to review, images not covered) and the YAML after it. */
export function splitHeader(text: string): { header: string[]; body: string } {
  const lines = text.split('\n');
  let i = 0;
  while (i < lines.length && lines[i].startsWith('#')) i++;
  return { header: lines.slice(0, i).map((l) => l.replace(/^# ?/, '')), body: lines.slice(i).join('\n') };
}

/** A profile signer (v1.8) as a Signer; one without an identity is none. */
export function profileSigner(p: ProfileSigner): Signer | null {
  const blank = (v?: string | null) => !v || !v.trim();
  if (p.signerKind === 'key') return blank(p.keyFingerprint) ? null : { kind: 'key', keyName: p.keyName ?? undefined, keyFingerprint: p.keyFingerprint ?? undefined };
  return blank(p.issuer) || blank(p.san) ? null : { kind: 'keyless', issuer: p.issuer ?? undefined, san: p.san ?? undefined };
}

/**
 * The profile's supplyChain (v1.8) as a workload summary: the same shape the
 * running feed folds into, so the chip reads one source whichever the
 * Broker has. The worst state is the Broker's verdict (`not_checked` reads as
 * not checked; `no_signer_identity` and a verified verdict without a named
 * signer as unknown). Per-state counts come from the Broker's counts.
 * `null` for `not_configured`, which the caller shows as its own state.
 */
export function summaryFromProfile(sc: SupplyChainDimension): WorkloadSignatures | null {
  if (sc.status === 'not_configured' || sc.verdict === 'not_configured') return null;
  const signers = uniqueSigners(sc.signers.map(profileSigner).filter((s): s is Signer => s !== null));
  let worst: SignatureState = sc.verdict === 'unknown' && sc.reason === 'not_checked' ? 'unchecked' : asSignatureState(sc.verdict);
  if (worst === 'verified' && signers.length === 0) worst = 'unknown';
  const fill = (n: number, tag: string) => Array.from({ length: n }, (_, i) => `${tag}-${i}`);
  const c = sc.counts;
  const byState: Record<SignatureState, string[]> = {
    verified: fill(c.verified, 'v'),
    key_signed: fill(c.keySigned, 'k'),
    unsigned: fill(c.unsigned, 'u'),
    invalid: fill(c.invalid, 'i'),
    unknown: fill(c.unknown, 'x'),
    unchecked: fill(c.notChecked, 'n'),
  };
  return { byState, digests: Object.values(byState).flat(), signers, worst };
}
