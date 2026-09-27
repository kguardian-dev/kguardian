import type { DimensionName, WorkloadProfile } from '../../types/profile';
import { asStatus, DIMENSION_LABEL, pssLevelText } from '../../utils/posture';
import type { ProfileTab } from '../../utils/profileView';
import { StatusPill } from './parts';
import type { WorkloadSignatureState } from '../../hooks/useSignatures';
import { SIGNATURE_LABEL, signerShort, signerText, stateCounts, summaryFromProfile, workloadSignatureText, type SignatureState } from '../../utils/signatures';
import { SignatureBadge } from '../Vulns/SignatureParts';
import { trustState, trustSummary } from '../../utils/imageTrust';

const ORDER: DimensionName[] = ['network', 'syscalls', 'podSecurity', 'images', 'compute'];

/** The tab a dimension pill opens; compute has none (informational only). */
const TAB_OF: Partial<Record<DimensionName, ProfileTab>> = {
  network: 'network',
  syscalls: 'syscalls',
  podSecurity: 'podSecurity',
  images: 'images',
};

/** A short fact next to a dimension's status; never a score. */
function detailOf(p: WorkloadProfile, d: DimensionName): string | null {
  const dims = p.dimensions;
  if (d === 'podSecurity') {
    // The level is useful even while the status is unknown (upper bound).
    return dims.podSecurity.level ? pssLevelText(dims.podSecurity.level, dims.podSecurity.levelConfidence) : null;
  }
  if (d === 'images') {
    // Inventory is known even while the status is unknown (no vulnerability data).
    const running = dims.images.containers.reduce((n, c) => n + c.running.length, 0);
    return dims.images.containers.length ? `${running} running digest${running === 1 ? '' : 's'}` : null;
  }
  if (asStatus(dims[d].status) === 'unknown') return null;
  if (d === 'syscalls') {
    const cr = dims.syscalls.cr;
    return cr ? (cr.mode === 'enforce' ? 'Enforcing' : 'Audit') : 'No CR';
  }
  if (d === 'network') return dims.network.policy.audit ? 'Audit' : null;
  return null;
}

/**
 * One pill per dimension plus the rollup: status, how much of the profile
 * that status covers, and the reasons behind it. No numeric score (contract
 * v1.2). A dimension with no data shows "No data": listed, not hidden, and
 * never drawn as clean.
 */
export function PostureStrip({ profile, onOpenTab, signatures }: { profile: WorkloadProfile; onOpenTab: (t: ProfileTab) => void; signatures?: WorkloadSignatureState }) {
  const p = profile.posture;
  const overall = asStatus(p.status);
  const coveragePct = Math.round(p.coverage * 100);
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="text-tertiary">Posture</span>
        <StatusPill
          status={overall}
          title={overall === 'unknown' ? 'No dimension has data yet' : 'Worst status across the dimensions with data. Dimensions with no data are excluded, not counted as clean.'}
        />
        <span className="font-mono tabular-nums text-tertiary" title="Share of the four core dimensions (network, syscalls, pod security, images) with a known status">
          coverage {coveragePct}%
        </span>
        {p.unknownDimensions.length > 0 && (
          <span className="text-tertiary">· no data for {p.unknownDimensions.map((d) => DIMENSION_LABEL[d] ?? d).join(', ').toLowerCase()}</span>
        )}
      </div>
      <ul aria-label="Posture by dimension" className="flex flex-wrap gap-2">
        {ORDER.map((d) => {
          const dim = profile.dimensions[d];
          const status = asStatus(dim.status);
          const detail = detailOf(profile, d);
          const tab = TAB_OF[d];
          const why = dim.reasons.map((r) => r.message).join('\n');
          const body = (
            <>
              <span className="text-secondary">{DIMENSION_LABEL[d]}</span>
              <StatusPill status={status} />
              {detail && <span className="text-tertiary">{detail}</span>}
            </>
          );
          const cls = 'inline-flex items-center gap-1.5 rounded-control border border-hubble-border bg-hubble-card px-2 py-1 text-xs';
          return (
            <li key={d} data-dimension={d}>
              {tab ? (
                <button type="button" onClick={() => onOpenTab(tab)} title={why || undefined} className={`${cls} hover:border-hubble-border-strong hover:bg-hubble-hover/40 transition-colors`}>
                  {body}
                </button>
              ) : (
                <span className={cls} title={why ? `${why}\nInformational: not part of the rollup.` : 'Informational: not part of the rollup.'}>
                  {body}
                </span>
              )}
            </li>
          );
        })}
        {signatures && (
          <li data-dimension="supplyChain">
            <SupplyChainChip profile={profile} sig={signatures} onOpen={() => onOpenTab('images')} />
          </li>
        )}
      </ul>
      {p.reasons.length > 0 && (
        <ul aria-label="Why this posture" className="space-y-0.5 text-xs">
          {p.reasons.map((r) => (
            <li key={`${r.dimension}-${r.message}`} className="flex items-baseline gap-1.5">
              <StatusPill status={asStatus(r.status)}>{DIMENSION_LABEL[r.dimension] ?? r.dimension}</StatusPill>
              <span className="text-secondary">{r.message}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** How a verdict affects the posture under profile contract v1.8 (section 2.2, images). */
function postureEffect(worst: SignatureState): string {
  if (worst === 'invalid') return 'Affects the posture: an invalid signature makes Images risk.';
  if (worst === 'verified') return 'Verified with a named signer lets Images be OK once vulnerability data exists; signatures alone never make it OK.';
  return 'Not verified: keeps Images from OK once vulnerability data exists, but is not a risk on its own.';
}

/**
 * The workload's image signatures. From the profile's `images.supplyChain`
 * (contract v1.8) when the Broker has it, so the chip and the posture rollup
 * read the same verdict; from the running signature feed only for an older
 * Broker (supplyChain null while current digests run). `not_configured`
 * (discovery off) is its own state, neither unknown nor not checked.
 * Unknown and not checked are never good; verified shows its signer.
 */
function SupplyChainChip({ profile, sig, onOpen }: { profile: WorkloadProfile; sig: WorkloadSignatureState; onOpen: () => void }) {
  const cls = 'inline-flex items-center gap-1.5 rounded-control border border-hubble-border bg-hubble-card px-2 py-1 text-xs hover:border-hubble-border-strong hover:bg-hubble-hover/40 transition-colors';
  const images = profile.dimensions.images;
  const sc = images.supplyChain;
  const running = images.containers.some((c) => c.running.length > 0);
  const fromProfile = sc != null;
  const notConfigured = sc != null && (sc.status === 'not_configured' || sc.verdict === 'not_configured');
  const s = sc != null ? summaryFromProfile(sc) : running ? sig.summary : null;
  let body;
  let title: string;
  let effect: string;
  if (notConfigured) {
    body = (
      <span data-signature="not_configured" className="rounded-full border border-dashed border-hubble-border-strong px-2 py-0.5 text-[11px] text-tertiary">
        Not configured
      </span>
    );
    title = 'Image signature discovery is off in this deployment: no signature is checked.';
    effect = 'Signatures do not affect the posture.';
  } else if (s) {
    const n = s.digests.length;
    const bad = s.byState[s.worst].length;
    const detail =
      s.worst === 'verified'
        ? s.signers.length === 1
          ? signerShort(s.signers[0])
          : s.signers.length > 1
            ? `${s.signers.length} signers`
            : null
        : n > 1
          ? `${bad} of ${n} images`
          : null;
    body = (
      <>
        <SignatureBadge state={s.worst} reason={fromProfile ? sc?.reason : undefined} />
        {detail && <span className="text-tertiary">{detail}</span>}
      </>
    );
    title = `${workloadSignatureText(s)}${n > 1 ? ` (${stateCounts(s)})` : ''}`;
    effect = fromProfile ? postureEffect(s.worst) : 'Informational: this Broker\'s posture does not use signatures.';
  } else if (!fromProfile && running && sig.loading) {
    body = <span className="text-tertiary">…</span>;
    title = 'Reading signature results';
    effect = '';
  } else if (!fromProfile && running && sig.error != null) {
    body = <StatusPill status="unknown">read failed</StatusPill>;
    title = 'The signature read failed: unknown.';
    effect = '';
  } else {
    body = <StatusPill status="unknown" />;
    title = !running ? 'No current digest for this workload: unknown.' : sig.truncated ? 'Not read (capped): unknown.' : 'No signature result for its running images: unknown.';
    effect = '';
  }
  const name = notConfigured ? 'not configured' : s ? `${SIGNATURE_LABEL[s.worst]}${s.worst === 'verified' && s.signers.length ? `, signed by ${s.signers.map(signerText).join('; ')}` : ''}` : 'no data';
  return (
    <button type="button" onClick={onOpen} title={[title, effect, fromProfile && !notConfigured ? trustSummary(trustState(sc)) : ''].filter(Boolean).join('\n')} aria-label={`Supply chain: ${name}`} data-source={fromProfile ? 'profile' : 'feed'} className={cls}>
      <span className="text-secondary">Supply chain</span>
      {body}
    </button>
  );
}
