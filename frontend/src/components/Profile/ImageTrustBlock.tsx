import { ShieldQuestion } from 'lucide-react';
import type { ImageContainer, SupplyChainDimension } from '../../types/profile';
import { asTrustVerdict, TRUST_CLASS, TRUST_LABEL, trustReasonText, trustState, trustSummary } from '../../utils/imageTrust';
import { formatAgo, formatTimestamp, shortDigest } from '../../utils/posture';
import { asUtc } from '../../utils/vulnView';

const pill = 'inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium whitespace-nowrap';

/**
 * The evaluator's ImageTrustPolicy results for this workload (profile
 * contract v1.9, `supplyChain.imageTrust`). Report-only: nothing is
 * admitted or blocked, and it never sets posture. No answer is shown as
 * unknown with its reason, never as "nothing would be denied".
 */
export function ImageTrustBlock({ supplyChain, containers }: { supplyChain: SupplyChainDimension | null | undefined; containers?: readonly Pick<ImageContainer, 'running'>[] }) {
  const s = trustState(supplyChain, containers);
  const answered = s.kind === 'answer' || s.kind === 'none_apply';
  return (
    <section aria-label="Image trust policies" data-trust-state={s.kind} className="px-4 py-3 border-t border-hubble-border space-y-2 text-xs">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="font-medium text-primary">Image trust policies</span>
        <span className="text-[11px] text-tertiary">Report only: never blocks, not part of the posture</span>
      </div>
      <p className={answered ? 'text-secondary' : 'flex items-start gap-1.5 text-tertiary'} data-testid="trust-summary">
        {!answered && <ShieldQuestion className="w-3.5 h-3.5 shrink-0 mt-px" aria-hidden />}
        <span>{trustSummary(s)}</span>
      </p>
      {s.kind === 'answer' && (
        <>
          <ul className="space-y-1.5" aria-label="Image trust results">
            {s.trust.results.map((r) => {
              const v = asTrustVerdict(r.verdict);
              const why = trustReasonText(r.reason);
              return (
                <li key={`${r.policy}/${r.container}/${r.digest}`} data-trust-verdict={v} className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
                  <span className={`${pill} ${TRUST_CLASS[v]}`} data-trust-tone={v}>{TRUST_LABEL[v]}</span>
                  <span className="font-mono text-primary [overflow-wrap:anywhere]">{r.policy}</span>
                  <span className="min-w-0 text-tertiary [overflow-wrap:anywhere]">
                    container <span className="font-mono">{r.container}</span> · <span className="font-mono" title={r.digest}>{r.image ? `${r.image}@` : ''}{shortDigest(r.digest)}</span>
                  </span>
                  {why && <span className="basis-full text-[11px] text-secondary">{why}</span>}
                </li>
              );
            })}
          </ul>
          {s.trust.truncated && <p className="text-[11px] text-tertiary">More results than listed; the counts above cover all of them.</p>}
          {s.trust.evaluatedAt && (
            <p className="text-[11px] text-tertiary" title={formatTimestamp(asUtc(s.trust.evaluatedAt))}>Evaluated {formatAgo(asUtc(s.trust.evaluatedAt))}.</p>
          )}
        </>
      )}
    </section>
  );
}
