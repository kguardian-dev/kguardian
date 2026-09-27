import type { ImageTrust, SupplyChainDimension } from '../types/profile';
import { reasonText } from './signatures';

/**
 * How ImageTrustPolicy results (contract v1.9) are shown. The one rule:
 * no answer is never an all-clear. Absent (older Broker), not read,
 * `available: false` and `evaluatedAt: null` are unknown and say why;
 * only a finished evaluation can say what would be denied.
 */

export type TrustVerdict = 'WouldDeny' | 'Unknown' | 'Trusted';

/** A verdict the UI does not know (a newer evaluator) reads as Unknown, never Trusted. */
export const asTrustVerdict = (v: string): TrustVerdict => (v === 'WouldDeny' || v === 'Trusted' ? v : 'Unknown');

export const TRUST_LABEL: Record<TrustVerdict, string> = {
  WouldDeny: 'Would deny',
  Unknown: 'Unknown',
  Trusted: 'Trusted',
};

/** Tone classes. Trusted is neutral, never green: a policy's own trust, not ours. */
export const TRUST_CLASS: Record<TrustVerdict, string> = {
  WouldDeny: 'bg-severity-critical/15 text-severity-critical border-severity-critical/30',
  Unknown: 'text-tertiary border-dashed border-hubble-border-strong',
  Trusted: 'bg-hubble-border/30 text-secondary border-hubble-border-strong',
};

const REASON: Record<string, string> = {
  unsigned: 'the image has no signature',
  invalid: 'the image signature does not verify',
  'untrusted-signer': 'signed, but not by a signer the policy trusts',
  'key-not-verified': 'signed with a key the evaluator could not verify',
  'attestation-missing': 'a required attestation is missing',
  'not-checked': 'the image has no signature result yet',
  'namespace-unknown': 'the evaluator could not tell whether the policy selects this namespace',
  'broker-unavailable': 'the evaluator could not read the Broker',
  'broker-unauthorized': 'the Broker refused the evaluator\'s token',
  no_signer_identity: 'the signature names no signer',
};

/** An evaluator reason in words; a discovery reason passed through reads as the signature reason. */
export function trustReasonText(code: string | null | undefined): string | null {
  if (!code) return null;
  return REASON[code] ?? reasonText(code);
}

/** What the workload page can say about image trust, and whether it is an answer at all. */
export type TrustState =
  | { kind: 'absent' }
  | { kind: 'not_read' }
  | { kind: 'unavailable'; reason: string }
  | { kind: 'pending' }
  | { kind: 'none_apply' }
  | { kind: 'answer'; trust: ImageTrust };

export function trustState(sc: SupplyChainDimension | null | undefined): TrustState {
  if (!sc || !('imageTrust' in sc) || sc.imageTrust === undefined) return { kind: 'absent' };
  const t = sc.imageTrust;
  if (t === null) return { kind: 'not_read' };
  if (!t.available) return { kind: 'unavailable', reason: t.reason?.trim() || 'no reason given' };
  if (t.evaluatedAt === null) return { kind: 'pending' };
  if (t.total === 0) return { kind: 'none_apply' };
  return { kind: 'answer', trust: t };
}

/** One sentence for the state: a summary line, and the chip's tooltip. Never "nothing would be denied" without an answer. */
export function trustSummary(s: TrustState): string {
  switch (s.kind) {
    case 'absent':
      return 'Image trust policies: not reported by this Broker (unknown).';
    case 'not_read':
      return 'Image trust policies: not read for this workload (unknown).';
    case 'unavailable':
      return `Image trust policies: unknown, ${s.reason}.`;
    case 'pending':
      return 'Image trust policies: the evaluator has not finished a pass yet (unknown).';
    case 'none_apply':
      return 'Image trust policies: no policy selects these containers, so none was evaluated (not the same as allowed).';
    case 'answer': {
      const t = s.trust;
      const parts = [`${t.wouldDeny} would deny`, `${t.unknown} unknown`, `${t.trusted} trusted`];
      return `Image trust policies: ${parts.join(', ')} (${t.total} result${t.total === 1 ? '' : 's'} over ${t.policies.length} polic${t.policies.length === 1 ? 'y' : 'ies'}).`;
    }
  }
}
