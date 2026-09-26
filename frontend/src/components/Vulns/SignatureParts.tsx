import { CircleHelp, KeyRound, ShieldAlert, ShieldOff, ShieldX, Signature } from 'lucide-react';
import type { Signer } from '../../types/attestations';
import { reasonText, SIGNATURE_LABEL, SIGNATURE_MEANING, signerText, type SignatureState } from '../../utils/signatures';

const pill = 'inline-flex items-center gap-1 shrink-0 rounded-full border px-2 py-0.5 text-[11px] font-medium whitespace-nowrap';

/** Verified is neutral, never green: a valid signature is not a trusted signer. */
const CLASS: Record<SignatureState, string> = {
  verified: 'bg-hubble-border/30 text-primary border-hubble-border-strong',
  key_signed: 'text-secondary border-dashed border-hubble-border-strong',
  unsigned: 'bg-severity-medium/15 text-severity-medium border-severity-medium/30',
  invalid: 'bg-severity-critical/15 text-severity-critical border-severity-critical/30',
  unknown: 'text-tertiary border-dashed border-hubble-border-strong',
  unchecked: 'text-tertiary border-dashed border-hubble-border-strong',
};

const ICON: Record<SignatureState, typeof Signature> = {
  verified: Signature,
  key_signed: KeyRound,
  unsigned: ShieldOff,
  invalid: ShieldX,
  unknown: CircleHelp,
  unchecked: CircleHelp,
};

/** A signature state pill. `reason` (a code) goes in the tooltip as words. */
export function SignatureBadge({ state, reason }: { state: SignatureState; reason?: string | null }) {
  const Icon = ICON[state];
  const why = reasonText(reason);
  return (
    <span data-signature={state} className={`${pill} ${CLASS[state]}`} title={`${SIGNATURE_MEANING[state]}${why ? ` Reason: ${why}.` : ''}`}>
      <Icon className="w-3 h-3" aria-hidden />
      {SIGNATURE_LABEL[state]}
    </span>
  );
}

/** Every verified signer, in full: the identity a policy would trust. */
export function SignerList({ signers, className = '' }: { signers: Signer[]; className?: string }) {
  if (signers.length === 0) return null;
  return (
    <ul className={`space-y-0.5 ${className}`} aria-label="Verified signers">
      {signers.map((s) => (
        <li key={signerText(s)} className="flex items-baseline gap-1 text-[11px] text-secondary">
          <span className="text-tertiary shrink-0">{s.kind === 'key' ? 'Key' : 'Signer'}</span>
          <span className="font-mono text-primary [overflow-wrap:anywhere]" title={s.kind === 'key' ? `sha256:${s.keyFingerprint ?? '?'}` : `Issuer ${s.issuer ?? '?'}`}>
            {signerText(s)}
          </span>
        </li>
      ))}
    </ul>
  );
}

/** The one-line "valid, not trusted" reminder shown wherever a verified signer is. */
export function NotTrustedNote({ className = '' }: { className?: string }) {
  return (
    <p className={`flex items-start gap-1.5 text-[11px] text-tertiary ${className}`}>
      <ShieldAlert className="w-3.5 h-3.5 shrink-0 mt-px" aria-hidden />
      <span>Verified means the signature is valid, not that the signer is trusted: anyone who can push to a repository can attach a valid signature. Review each identity.</span>
    </p>
  );
}
