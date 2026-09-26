import { BadgeCheck, Bug, CircleHelp, FileWarning, KeyRound, Link2, ShieldQuestion } from 'lucide-react';
import { vulnErrorKind, vulnErrorMessage } from '../../services/vulnApi';
import { EmptyState } from '../ui/EmptyState';
import { SectionError } from '../Profile/parts';
import type { JoinKind, SbomTrust, VulnSeverity } from '../../types/vulns';
import { SEVERITY_BADGE_CLASS, TIER_BADGE_CLASS } from '../../utils/severity';
import { JOIN_LABEL, toSeverity } from '../../utils/vulnView';
import { TIER_UNKNOWN_TITLE, type Factor, type RiskTierName } from '../../utils/tiers';

const pill = 'inline-flex items-center gap-1 shrink-0 rounded-full border px-2 py-0.5 text-[11px] font-medium whitespace-nowrap';

export function SeverityBadge({ severity }: { severity: VulnSeverity }) {
  const s = toSeverity(severity);
  if (!s) {
    return <span className={`${pill} text-tertiary border-dashed border-hubble-border-strong`} title="The source gave no severity">Unknown</span>;
  }
  return <span className={`${pill} ${SEVERITY_BADGE_CLASS[s]}`}>{severity.charAt(0)}{severity.slice(1).toLowerCase()}</span>;
}

/**
 * The Broker's tier; null (no tier yet) is a dashed "Tier ?", never a
 * guessed tier. `atLeast`: other rows are unknown, so the real answer may be
 * higher; it reads "≥P2" (a P0 cannot be exceeded, so it stays "P0").
 * `pending`: the read for this row is still in flight ("…").
 */
export function TierBadge({ tier, title, atLeast = false, pending = false }: { tier: RiskTierName | null; title?: string; atLeast?: boolean; pending?: boolean }) {
  if (pending) {
    return (
      <span data-tier="pending" title="Reading this image's finding" className="shrink-0 rounded-md border border-dashed border-hubble-border-strong px-1.5 py-px text-[11px] font-mono text-tertiary">
        …
      </span>
    );
  }
  if (tier === null) {
    return (
      <span data-tier="unknown" title={TIER_UNKNOWN_TITLE} className="shrink-0 rounded-md border border-dashed border-hubble-border-strong px-1.5 py-px text-[11px] font-mono font-semibold text-tertiary whitespace-nowrap">
        Tier ?
      </span>
    );
  }
  const cls = tier === 'Background' ? 'bg-hubble-border/40 text-secondary border-hubble-border' : TIER_BADGE_CLASS[tier];
  return (
    <span data-tier={tier} data-at-least={atLeast && tier !== 'P0' ? 'true' : undefined} title={atLeast && tier !== 'P0' ? `${title ? `${title}. ` : ''}At least ${tier}: some workloads have no tier yet.` : title} className={`shrink-0 rounded-md border px-1.5 py-px text-[11px] font-mono font-semibold ${cls}`}>
      {atLeast && tier !== 'P0' ? '≥' : ''}
      {tier === 'Background' ? 'Bkg' : tier}
    </span>
  );
}

const FACTOR_TONE: Record<Factor['tone'], string> = {
  risk: 'bg-severity-critical/10 text-severity-critical border-severity-critical/30',
  warn: 'bg-severity-medium/10 text-severity-medium border-severity-medium/30',
  neutral: 'bg-hubble-border/30 text-secondary border-hubble-border',
  good: 'bg-state-enforcing/10 text-state-enforcing border-state-enforcing/30',
  unknown: 'text-tertiary border-dashed border-hubble-border-strong',
};

export function FactorChips({ factors, only, wrap = false }: { factors: Factor[]; only?: string[]; /** Let a long chip wrap (narrow table cells). */ wrap?: boolean }) {
  const shown = only ? only.flatMap((k) => factors.filter((f) => f.key === k)) : factors;
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      {shown.map((f) => (
        <span key={f.key} data-factor={f.key} title={f.title} className={`${wrap ? pill.replace('whitespace-nowrap', 'whitespace-normal text-left').replace('shrink-0', 'min-w-0').replace('rounded-full', 'rounded-md') : pill} ${FACTOR_TONE[f.tone]}`}>
          {f.key === 'inuse' && f.tone === 'unknown' && <CircleHelp className="w-3 h-3" aria-hidden />}
          {f.label}
        </span>
      ))}
    </span>
  );
}

export function JoinBadge({ join }: { join: JoinKind }) {
  const j = Object.hasOwn(JOIN_LABEL, join) ? JOIN_LABEL[join] : { label: join, title: '', weak: true };
  return (
    <span data-join={join} title={j.title} className={`${pill} ${j.weak ? 'bg-severity-medium/10 text-severity-medium border-severity-medium/30' : 'bg-hubble-border/30 text-secondary border-hubble-border'}`}>
      {j.weak ? <FileWarning className="w-3 h-3" aria-hidden /> : <Link2 className="w-3 h-3" aria-hidden />}
      {j.label}
    </span>
  );
}

/** SBOM trust. Only `verified` may read as signed; null is "not stated", never inferred. */
export function TrustBadge({ trust }: { trust: SbomTrust | null }) {
  if (trust === 'verified') {
    return <span className={`${pill} bg-state-enforcing/10 text-state-enforcing border-state-enforcing/30`} title="A signed attestation whose signature was verified"><BadgeCheck className="w-3 h-3" aria-hidden />Verified</span>;
  }
  if (trust === null) {
    return <span className={`${pill} text-tertiary border-dashed border-hubble-border-strong`} title="The source did not state how trustworthy its SBOM is">Trust not stated</span>;
  }
  const text: Record<Exclude<SbomTrust, 'verified'>, [string, string]> = {
    scanned: ['Scanned in cluster', "Trivy Operator's in-cluster scan"],
    unverified: ['Unverified', 'An in-toto statement naming the image; the signature was not checked'],
    'attached-unbound': ['Attached, unbound', 'A bare SBOM attached to the image in its registry, not bound to it by a signature'],
  };
  const [label, title] = Object.hasOwn(text, trust) ? text[trust as Exclude<SbomTrust, 'verified'>] : [trust, ''];
  return <span className={`${pill} bg-hubble-border/30 text-secondary border-hubble-border`} title={title}><ShieldQuestion className="w-3 h-3" aria-hidden />{label}</span>;
}

/**
 * A failed supply-chain read, by kind: auth required (401/403), a Broker
 * without the endpoints, or a retryable error. Never an empty "clean" state.
 */
export function VulnErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const kind = vulnErrorKind(error);
  if (kind === 'auth') {
    return <EmptyState icon={KeyRound} compact title="Broker token required" description={vulnErrorMessage(error)} />;
  }
  if (kind === 'unsupported') {
    return <EmptyState icon={Bug} compact title="Vulnerability data not available" description={vulnErrorMessage(error)} />;
  }
  return <SectionError message={vulnErrorMessage(error)} onRetry={onRetry} />;
}
