import { useMemo } from 'react';
import { Copy, ExternalLink, Map as MapIcon, SearchX, Sparkles } from 'lucide-react';
import { useCveDetail, usePssByWorkload } from '../../hooks/useVulns';
import { profileApi as defaultProfileApi, type ProfileApi } from '../../services/profileApi';
import { workloadKey } from '../../utils/workloads';
import { vulnErrorKind, type VulnApi } from '../../services/vulnApi';
import type { CveSummary } from '../../types/vulns';
import { copyText } from '../../utils/clipboard';
import { shortDigest } from '../../utils/posture';
import { backgroundCaveat, brokerTier, IN_USE_UNKNOWN_TITLE, tierRank, WORKLOAD_FACTORS } from '../../utils/tiers';
import { cveAiPrompt, cveHeadline, safeHttpUrl, workloadFactors } from '../../utils/vulnView';
import { Button } from '../ui/Button';
import { EmptyState } from '../ui/EmptyState';
import { Modal } from '../ui/Modal';
import { SectionSkeleton } from '../Profile/parts';
import { FactorChips, JoinBadge, SeverityBadge, TierBadge, VulnErrorState } from './parts';

interface CveDrawerProps {
  id: string;
  /** The list row, when opened from the list (KEV / EPSS before the detail loads). */
  summary?: CveSummary;
  onClose: () => void;
  onOpenWorkload: (ns: string, kind: string, name: string) => void;
  onShowOnMap: (ns: string) => void;
  onAskAI: (prompt: string) => void;
  api?: VulnApi;
  /** Workload profiles: the Privileged chip. */
  profileApi?: ProfileApi;
}

/**
 * CVE triage drawer (`#/images?cve=` / `#/cve?id=`): is it running, where,
 * is it exposed, is there a fix. Impact runs images → workloads → running.
 * Tiers are the Broker's (#1678); each workload row adds its own in-use
 * state, observed exposure and PSS level. Unknown stays
 * unknown throughout; kguardian applies nothing.
 */
export function CveDrawer({ id, summary, onClose, onOpenWorkload, onShowOnMap, onAskAI, api, profileApi = defaultProfileApi }: CveDrawerProps) {
  const { exposure: e, findings, failed, pending, finding: f, loading, error, reload } = useCveDetail(id, api);
  const namespaces = useMemo(() => (e ? e.workloads.map((w) => w.namespace) : []), [e]);
  const pss = usePssByWorkload(namespaces, profileApi);

  // Every tier here is the Broker's: the CVE's (list row, or its most
  // urgent image finding) and, per workload, its image's finding.
  const rows = useMemo(
    () =>
      e
        ? e.workloads
            .map((w) => {
              const imageFinding = findings.get(w.imageDigest) ?? null;
              return {
                w,
                tier: brokerTier(imageFinding?.tier),
                factors: workloadFactors(w, e, imageFinding, pss ? (pss.get(workloadKey(w.namespace, w.kind, w.name)) ?? null) : undefined),
              };
            })
            .sort((a, b) => Number(b.w.running) - Number(a.w.running) || tierRank(b.tier) - tierRank(a.tier))
        : [],
    [e, findings, pss],
  );
  const backgroundRow = rows.find((r) => r.tier === 'Background');
  // Worst case over every row; pending until every read has settled.
  const head = cveHeadline(rows, { pending, failed: failed.size, summaryTier: summary?.tier });
  const overall = head.pending ? null : head.tier;
  const link = safeHttpUrl(f?.primaryUrl);

  let body;
  if (loading && !e) body = <SectionSkeleton rows={5} />;
  else if (error && vulnErrorKind(error) === 'not_found') {
    body = <EmptyState icon={SearchX} title={`${id} affects nothing in the inventory`} description="No image the Broker knows about carries this vulnerability. It may have been fixed, or the images that had it are gone." />;
  } else if (error) body = <VulnErrorState error={error} onRetry={() => void reload()} />;
  else if (e) {
    const running = e.workloads.filter((w) => w.running);
    const exposed = e.workloads.filter((w) => w.network?.exposed === true);
    const unknownExp = e.workloads.filter((w) => w.network?.exposed == null);
    body = (
      <div className="px-5 py-4 space-y-5">
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={e.severity} />
            {head.pending ? (
              <span data-testid="headline-pending" title="Reading each affected image's finding" className="rounded-md border border-dashed border-hubble-border-strong px-1.5 py-px text-[11px] font-mono text-tertiary">…</span>
            ) : (
              <>
                <TierBadge tier={overall} title="The most urgent tier over every affected workload (the Broker's tiers)" />
                <FactorChips factors={head.factors} only={['inuse', 'exposure', 'kev', 'epss', 'cvss', 'fix']} />
                {head.unknownRows > 0 && (
                  <FactorChips factors={[{ key: 'tier-unknown', tone: 'unknown', label: `${head.unknownRows} unknown`, title: `${head.unknownRows} affected workload${head.unknownRows === 1 ? ' has' : 's have'} no tier yet. Unknown, not low.` }]} />
                )}
                {head.failedReads > 0 && (
                  <FactorChips factors={[{ key: 'read-failed', tone: 'unknown', label: 'read failed', title: `The finding read failed for ${head.failedReads} image${head.failedReads === 1 ? '' : 's'}: their tier is unknown. Retry with Refresh.` }]} />
                )}
              </>
            )}
          </div>
          {f?.title && <p className="text-sm text-primary">{f.title}</p>}
          {f && <p className="text-xs text-tertiary">Package <span className="font-mono text-secondary">{f.package.name}</span> {f.installedVersion}{f.kevDateAdded && <> · in KEV since {f.kevDateAdded.slice(0, 10)}</>}</p>}
          {link && (
            <a href={link} target="_blank" rel="noopener noreferrer nofollow" className="inline-flex items-center gap-1 text-xs text-hubble-accent hover:underline">
              Advisory <ExternalLink className="w-3 h-3" aria-hidden />
            </a>
          )}
        </div>

        <section aria-label="Impact in this cluster" className="rounded-control border border-hubble-border bg-hubble-darker/40 px-4 py-3">
          <h3 className="text-[11px] uppercase tracking-wide text-tertiary">Impact in this cluster</h3>
          <p className="mt-1 text-sm text-primary" data-testid="cve-impact">
            <span className="font-mono tabular-nums">{e.images.length}</span> image{e.images.length === 1 ? '' : 's'} carry it →{' '}
            <span className="font-mono tabular-nums">{e.workloads.length}</span> workload container{e.workloads.length === 1 ? '' : 's'} →{' '}
            <span className="font-mono tabular-nums">{running.length}</span> running →{' '}
            <span className={`font-mono tabular-nums ${exposed.length ? 'text-severity-critical' : ''}`}>{exposed.length}</span> with outside ingress
            {unknownExp.length > 0 && <span className="text-tertiary"> · exposure unknown for {unknownExp.length}</span>}
          </p>
          <p className="mt-1 text-[11px] text-tertiary" title={IN_USE_UNKNOWN_TITLE}>
            {e.inUse === null ? 'No runtime evidence that any affected workload loads the package: unknown is ranked as if loaded. ' : ''}
            Exposure is observed traffic, not reachability.
          </p>
          {backgroundRow && <p className="mt-1 text-[11px] text-secondary" data-testid="background-caveat">{backgroundCaveat(findings.get(backgroundRow.w.imageDigest)?.inUseDetail?.windowHours)}</p>}
          {e.truncated && <p className="mt-1 text-[11px] text-severity-medium">More images or workloads are affected than the Broker lists (first 200 each).</p>}
        </section>

        <section aria-label="Affected workloads">
          <h3 className="text-sm font-semibold text-primary mb-2">Workloads</h3>
          <div className="overflow-x-auto rounded-control border border-hubble-border">
            <table className="w-full text-sm">
              <thead className="text-[11px] uppercase tracking-wide text-tertiary">
                <tr className="border-b border-hubble-border">
                  <th scope="col" className="text-left font-medium px-3 py-2">Tier</th>
                  <th scope="col" className="text-left font-medium px-3 py-2">Workload</th>
                  <th scope="col" className="hidden sm:table-cell text-left font-medium px-3 py-2">Running</th>
                  <th scope="col" className="hidden sm:table-cell text-left font-medium px-3 py-2">Why this tier</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-hubble-border">
                {rows.map(({ w, tier, factors }) => {
                  return (
                    <tr key={`${w.namespace}/${w.kind}/${w.name}/${w.container}/${w.imageDigest}`} data-testid="cve-workload">
                      <td className="px-3 py-2 align-top"><TierBadge tier={tier} title="The Broker's tier for this CVE in this workload's image (worst over every container running it)" /></td>
                      <td className="px-3 py-2 align-top sm:min-w-36">
                        <button type="button" onClick={() => onOpenWorkload(w.namespace, w.kind, w.name)} className="text-left text-primary hover:underline">
                          {w.namespace}/{w.name}
                        </button>
                        <div className="text-[11px] text-tertiary font-mono">{w.kind} · {w.container}</div>
                        <div className="mt-1"><JoinBadge join={w.join} /></div>
                        <div className="mt-1.5 space-y-1 sm:hidden text-xs">
                          <div className={w.running ? 'text-primary' : 'text-tertiary'}>{w.running ? 'running' : 'not running'}</div>
                          <FactorChips factors={factors} only={WORKLOAD_FACTORS} wrap />
                        </div>
                      </td>
                      <td className="hidden sm:table-cell px-3 py-2 align-top text-xs whitespace-nowrap">{w.running ? <span className="text-primary">running</span> : <span className="text-tertiary">not running</span>}</td>
                      <td className="hidden sm:table-cell px-3 py-2 text-xs"><FactorChips factors={factors} only={WORKLOAD_FACTORS} wrap /></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>

        <section aria-label="Affected images">
          <h3 className="text-sm font-semibold text-primary mb-2">Images and fixes</h3>
          <ul className="space-y-2">
            {e.images.map((img) => (
              <li key={img.digest} className="rounded-control border border-hubble-border px-3 py-2 text-xs">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-primary [overflow-wrap:anywhere]">{img.repository ?? 'unknown repository'}{img.tags.length ? `:${img.tags.join(', ')}` : ''}</span>
                  <span className="font-mono text-tertiary" title={img.digest}>{shortDigest(img.digest)}</span>
                  <JoinBadge join={img.join} />
                </div>
                <ul className="mt-1.5 space-y-0.5">
                  {img.packages.map((p) => (
                    <li key={`${p.name}@${p.installedVersion}`} className="text-secondary">
                      <span className="font-mono">{p.name}</span> {p.installedVersion} →{' '}
                      {p.fixedVersions.length ? <span className="font-mono text-state-enforcing">{p.fixedVersions.join(' / ')}</span> : <span className="text-severity-medium">no fix yet</span>}
                      <span className="text-tertiary"> · {p.sources.join(', ')}</span>
                    </li>
                  ))}
                </ul>
              </li>
            ))}
          </ul>
        </section>

        {e.namespaces.length > 0 && (
          <section aria-label="By namespace" className="text-xs">
            <h3 className="text-sm font-semibold text-primary mb-2">By namespace</h3>
            <ul className="space-y-1">
              {e.namespaces.map((n) => (
                <li key={n.namespace} className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-mono text-primary">{n.namespace}</span>
                  <span className="text-secondary">
                    {n.runningWorkloads}/{n.workloads} running · {n.exposedWorkloads} with outside ingress
                    {n.unknownExposureWorkloads > 0 && <span className="text-tertiary"> · {n.unknownExposureWorkloads} unknown</span>}
                  </span>
                  <Button variant="ghost" size="sm" leftIcon={MapIcon} onClick={() => onShowOnMap(n.namespace)}>
                    Show on map
                  </Button>
                </li>
              ))}
            </ul>
          </section>
        )}
      </div>
    );
  }

  return (
    <Modal
      isOpen
      onClose={onClose}
      align="right"
      className="w-full max-w-2xl"
      title={<span className="font-mono">{id}</span>}
      subtitle="Is it running, where, is it exposed?"
      footer={
        e ? (
          <>
            <Button variant="ghost" size="sm" leftIcon={Copy} onClick={() => void copyText(cveAiPrompt(e, f, overall))}>
              Copy summary
            </Button>
            <Button variant="primary" size="sm" leftIcon={Sparkles} onClick={() => onAskAI(cveAiPrompt(e, f, overall))}>
              Ask AI
            </Button>
          </>
        ) : undefined
      }
    >
      {body}
    </Modal>
  );
}
