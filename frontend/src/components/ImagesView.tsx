import { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Bug, ChevronRight, Flame, Layers, Package, ShieldQuestion } from 'lucide-react';
import { CVE_TOTALS_LIMIT, useCveList, useCveTotals, useImageList, type ImageEnrichment } from '../hooks/useVulns';
import { vulnErrorMessage, vulnApi, type VulnApi } from '../services/vulnApi';
import type { ProfileApi } from '../services/profileApi';
import type { CveSummary, ImageSummary, VulnSeverity } from '../types/vulns';
import { formatTimestamp, shortDigest } from '../utils/posture';
import { backgroundCaveat, brokerTier, IN_USE_UNKNOWN_TITLE, LIST_FACTORS, TIER_UNKNOWN_TITLE, tierRank } from '../utils/tiers';
import { asUtc, cveRowFactors, sbomFromMatcher, sourceLabel } from '../utils/vulnView';
import { Button } from './ui/Button';
import { EmptyState } from './ui/EmptyState';
import { StatStrip, StatTile } from './ui/StatTile';
import { Tabs } from './ui/Tabs';
import { SectionSkeleton } from './Profile/parts';
import { FactorChips, JoinBadge, SeverityBadge, TierBadge, TrustBadge, VulnErrorState } from './Vulns/parts';
import { CveDrawer } from './Vulns/CveDrawer';
import { ImageDrawer } from './Vulns/ImageDrawer';
import { SupplyChainTab } from './Vulns/SupplyChainTab';

export type ImagesTab = 'vulns' | 'images' | 'supply';
const TABS: readonly { id: ImagesTab; label: string }[] = [
  { id: 'vulns', label: 'Vulnerabilities' },
  { id: 'images', label: 'Images' },
  { id: 'supply', label: 'Supply chain' },
];

interface ImagesViewProps {
  /** Header namespace; applied only when not showing all namespaces. */
  namespace: string;
  allNamespaces: boolean;
  /** URL params this view owns. */
  tab?: string;
  cve?: string;
  digest?: string;
  onParamsChange: (patch: Record<string, string | undefined>) => void;
  onOpenWorkload: (ns: string, kind: string, name: string) => void;
  onShowOnMap: (ns: string) => void;
  onAskAI: (prompt: string) => void;
  refreshTick?: number;
  api?: VulnApi;
  profileApi?: ProfileApi;
}

const TIER_FILTERS: Array<{ id: string; label: string; value: string[] | undefined }> = [
  { id: 'all', label: 'All tiers', value: undefined },
  { id: 'p0', label: 'P0', value: ['P0'] },
  { id: 'p01', label: 'P0 + P1', value: ['P0', 'P1'] },
  { id: 'bg', label: 'Background', value: ['Background'] },
];

const SEVERITY_FILTERS: Array<{ id: string; label: string; value: VulnSeverity[] | undefined }> = [
  { id: 'all', label: 'All severities', value: undefined },
  { id: 'ch', label: 'Critical + high', value: ['CRITICAL', 'HIGH'] },
  { id: 'c', label: 'Critical', value: ['CRITICAL'] },
];

/**
 * Images (`#/images`): the cluster-wide vulnerability and image inventory.
 * Vulnerabilities are grouped by CVE and tiered (UX section 3); Images are
 * per digest with who runs them and what reported on them; Supply chain is
 * who signed each running digest (the supplychain component's verdicts). Cluster-wide by default: the
 * namespace selector filters, it does not scope.
 */
export function ImagesView({ namespace, allNamespaces, tab: tabParam, cve, digest, onParamsChange, onOpenWorkload, onShowOnMap, onAskAI, refreshTick, api = vulnApi, profileApi }: ImagesViewProps) {
  const tab: ImagesTab = TABS.some((t) => t.id === tabParam) ? (tabParam as ImagesTab) : 'vulns';
  const ns = allNamespaces ? undefined : namespace;
  const [sevId, setSevId] = useState('all');
  const [fixable, setFixable] = useState(false);
  const [running, setRunning] = useState(false);
  const [tierId, setTierId] = useState('all');
  const severity = SEVERITY_FILTERS.find((f) => f.id === sevId)?.value;
  const tierFilter = TIER_FILTERS.find((f) => f.id === tierId)?.value;
  const cves = useCveList({ namespace: ns, severity, fixable: fixable || undefined, running: running || undefined, tier: tierFilter }, refreshTick, api);
  // The header tiles count the scope alone, not the table's filters or its first page.
  const totals = useCveTotals(ns, refreshTick, api);
  const [openedFrom, setOpenedFrom] = useState<CveSummary | undefined>(undefined);

  // Tiers are the Broker's (#1678). A Broker without them sends no `tier`:
  // the rows say "Tier ?" and the tier tiles say unknown. Judged on the
  // scope-only read, so a filter that empties the table changes nothing.
  const tierRows = totals.items.length > 0 ? totals.items : cves.items;
  const tiersKnown = tierRows.some((c) => c.tier != null);
  const preTierBroker = tierRows.length > 0 && !tiersKnown;
  const rows = useMemo(
    () => cves.items.map((c) => ({ c, tier: brokerTier(c.tier), factors: cveRowFactors(c) })).sort((a, b) => tierRank(b.tier) - tierRank(a.tier)),
    [cves.items],
  );
  const counts = useMemo(() => {
    const by: Record<string, number> = { P0: 0, P1: 0, P2: 0, Background: 0 };
    for (const c of totals.items) {
      const t = brokerTier(c.tier);
      if (t) by[t] += 1;
    }
    const all = totals.items;
    return { P0: by.P0, P1: by.P1, running: all.filter((c) => c.runningWorkloads > 0).length, kev: all.filter((c) => c.kev === true).length, kevUnknown: all.filter((c) => c.kev === null).length, loaded: all.filter((c) => c.inUse === true).length, loadedUnknown: all.filter((c) => c.inUse === null).length };
  }, [totals.items]);

  const openCve = (id: string, from?: CveSummary) => {
    setOpenedFrom(from);
    onParamsChange({ cve: id, digest: undefined });
  };
  const scopeLabel = allNamespaces ? 'all namespaces' : namespace;
  // The tiles cover every CVE in scope unless the Broker had more than one read returns.
  const loadedAll = !totals.capped;
  // Nothing could be read: the tiles say so instead of counting zero.
  const unread = totals.error != null && totals.items.length === 0;
  const tableUnread = cves.error != null && cves.items.length === 0;
  const tilesLoading = totals.loading && totals.items.length === 0;
  // Loaded-package state is null (unknown) on every row until a Broker has runtime evidence.
  const loadedKnown = totals.items.some((c) => c.inUse !== null);
  const tierTile = (n: number) => (tiersKnown || totals.items.length === 0 ? n : 'unknown');
  const filtered = sevId !== 'all' || tierId !== 'all' || fixable || running;
  const cappedNote = loadedAll ? '' : ` Counted over the first ${CVE_TOTALS_LIMIT} CVEs in scope; more exist.`;
  const reloadAll = () => {
    void cves.reload();
    void totals.reload();
  };
  // A count of known values says how many it could not count.
  const tileSuffix = (unknown: number) => {
    const more = loadedAll || unread ? '' : '+';
    if (unknown <= 0 || unread) return more || undefined;
    return (
      <>
        {more}
        <span className="ml-2 text-xs font-sans font-normal">{unknown} unknown</span>
      </>
    );
  };

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-6xl px-4 sm:px-6 py-6 space-y-5">
        <div>
          <h2 className="text-base font-semibold text-primary">Images</h2>
          <p className="text-xs text-tertiary mt-0.5">
            Vulnerabilities in the images running in {scopeLabel}, ranked by tier. Findings come from Trivy Operator reports and, when the opt-in Grype matcher is enabled, from kguardian matching SBOMs itself. kguardian never blocks a workload.
          </p>
        </div>

        <div className="space-y-1.5">
          <StatStrip count={5} label="Vulnerability posture">
            <StatTile label="P0 act now" value={tilesLoading ? '…' : unread ? '—' : tierTile(counts.P0)} icon={Flame} tone={tiersKnown && counts.P0 > 0 ? 'text-tier-p0' : 'text-secondary'} suffix={loadedAll || unread || !tiersKnown ? undefined : '+'} title={(tiersKnown ? "The Broker's P0: in use (unknown counts), KEV or EPSS over its threshold, and exposed (unknown counts)." : TIER_UNKNOWN_TITLE) + cappedNote} />
            <StatTile label="P1 schedule" value={tilesLoading ? '…' : unread ? '—' : tierTile(counts.P1)} icon={AlertTriangle} tone={tiersKnown && counts.P1 > 0 ? 'text-tier-p1' : 'text-secondary'} suffix={loadedAll || unread || !tiersKnown ? undefined : '+'} title={tiersKnown ? cappedNote.trim() || undefined : TIER_UNKNOWN_TITLE + cappedNote} />
            <StatTile label="CVEs on running workloads" value={tilesLoading ? '…' : unread ? '—' : counts.running} icon={Layers} suffix={loadedAll || unread ? undefined : '+'} title={cappedNote.trim() || undefined} />
            <StatTile label="In CISA KEV" value={tilesLoading ? '…' : unread ? '—' : counts.kev} icon={Bug} tone={counts.kev > 0 ? 'text-severity-critical' : 'text-secondary'} suffix={tilesLoading ? undefined : tileSuffix(counts.kevUnknown)} title={(counts.kevUnknown > 0 ? `${counts.kevUnknown} CVE${counts.kevUnknown === 1 ? '' : 's'}: no source said whether it is in KEV (unknown, not "no").` : '') + cappedNote || undefined} />
            {loadedKnown ? (
              <StatTile label="Executed or loaded" value={tilesLoading ? '…' : unread ? '—' : counts.loaded} icon={ShieldQuestion} suffix={tilesLoading ? undefined : tileSuffix(counts.loadedUnknown)} title={`CVEs whose package a workload was observed executing or loading. Unknown: no runtime evidence either way.${cappedNote}`} />
            ) : (
              <StatTile label="Executed or loaded" value={unread ? '—' : 'unknown'} icon={ShieldQuestion} tone="text-tertiary" title={IN_USE_UNKNOWN_TITLE} />
            )}
          </StatStrip>
          {(filtered || !loadedAll) && !unread && !tilesLoading && (
            <p className="text-[11px] text-tertiary" data-testid="tiles-caption">
              The tiles count every CVE in {scopeLabel}{loadedAll ? '' : ` (the first ${CVE_TOTALS_LIMIT})`}; the filters below narrow the table only.
            </p>
          )}
        </div>

        <Tabs tabs={TABS} active={tab} onChange={(t) => onParamsChange({ tab: t === 'vulns' ? undefined : t })} label="Images sections" idPrefix="images" />

        <div role="tabpanel" id={`images-panel-${tab}`} aria-labelledby={`images-tab-${tab}`} tabIndex={0} className="focus-visible:outline-none">
          {tab === 'vulns' && (
            <section aria-label="Vulnerabilities by CVE" className="rounded-surface border border-hubble-border bg-hubble-card overflow-hidden">
              <header className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 border-b border-hubble-border">
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <label className="flex items-center gap-1.5 text-tertiary">
                    Severity
                    <select value={sevId} onChange={(e) => setSevId(e.target.value)} className="h-8 rounded-control border border-hubble-border bg-hubble-darker px-2 text-xs text-primary">
                      {SEVERITY_FILTERS.map((f) => <option key={f.id} value={f.id}>{f.label}</option>)}
                    </select>
                  </label>
                  {(!preTierBroker || tierId !== 'all') && (
                    <label className="flex items-center gap-1.5 text-tertiary">
                      Tier
                      <select value={tierId} onChange={(e) => setTierId(e.target.value)} className="h-8 rounded-control border border-hubble-border bg-hubble-darker px-2 text-xs text-primary">
                        {TIER_FILTERS.map((f) => <option key={f.id} value={f.id}>{f.label}</option>)}
                      </select>
                    </label>
                  )}
                  <label className="flex items-center gap-1.5 text-secondary">
                    <input type="checkbox" checked={fixable} onChange={(e) => setFixable(e.target.checked)} /> Fix available
                  </label>
                  <label className="flex items-center gap-1.5 text-secondary">
                    <input type="checkbox" checked={running} onChange={(e) => setRunning(e.target.checked)} /> Running workloads only
                  </label>
                </div>
                {!tableUnread && <SummaryFreshness computedAt={cves.computedAt} staleSeconds={cves.staleSeconds} receivedAt={cves.receivedAt} loading={cves.loading} />}
              </header>
              {cves.loading && cves.items.length === 0 ? (
                <SectionSkeleton rows={4} />
              ) : cves.error && cves.items.length === 0 ? (
                <VulnErrorState error={cves.error} onRetry={reloadAll} />
              ) : cves.items.length === 0 ? (
                cves.computedAt === null ? (
                  <EmptyState icon={Bug} compact title="Not computed yet" description="The Broker rebuilds the vulnerability summary every few minutes. Until its first rebuild there is nothing to list; that is not the same as no vulnerabilities." />
                ) : (
                  <EmptyState
                    icon={Bug}
                    compact
                    title={`No CVEs reported for ${scopeLabel}${sevId !== 'all' || tierId !== 'all' || fixable || running ? ' with these filters' : ''}`}
                    description="Only images a source has reported on are counted. Images with no vulnerability data are listed on the Images tab as unknown, not clean."
                  />
                )
              ) : (
                <>
                  {cves.error != null && <StaleNotice error={cves.error} onRetry={reloadAll} />}
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead className="text-[11px] uppercase tracking-wide text-tertiary">
                        <tr className="border-b border-hubble-border">
                          <th scope="col" className="text-left font-medium pl-4 pr-1 sm:pr-3 py-2">Tier</th>
                          <th scope="col" className="text-left font-medium px-3 py-2">CVE</th>
                          <th scope="col" className="hidden sm:table-cell text-left font-medium px-3 py-2">Factors</th>
                          <th scope="col" className="hidden md:table-cell text-right font-medium px-3 py-2">Images</th>
                          <th scope="col" className="text-right font-medium px-3 py-2" title="Running / all workloads that have an affected image">Workloads</th>
                          <th scope="col" className="hidden md:table-cell text-left font-medium px-3 py-2">Match</th>
                          <th scope="col" className="relative hidden sm:table-cell px-2 py-2"><span className="sr-only">Open</span></th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-hubble-border">
                        {rows.map(({ c, tier, factors }) => (
                          <tr key={c.id} data-testid="cve-row" onClick={() => openCve(c.id, c)} className="cursor-pointer hover:bg-hubble-hover/40 transition-colors">
                            <td className="pl-4 pr-1 sm:pr-3 py-2.5 align-top"><TierBadge tier={tier} title="The Broker's tier: the most urgent over every affected workload container in scope" /></td>
                            <td className="px-3 py-2.5 align-top sm:min-w-40">
                              <button type="button" onClick={(e) => { e.stopPropagation(); openCve(c.id, c); }} className="font-mono text-xs text-primary hover:underline">{c.id}</button>
                              <div className="mt-0.5 flex flex-wrap items-center gap-1.5">
                                <SeverityBadge severity={c.severity} />
                                <span className="text-[11px] text-tertiary font-mono [overflow-wrap:anywhere]">{c.packages.join(', ')}</span>
                              </div>
                              <div className="mt-1.5 sm:hidden"><FactorChips factors={factors} only={LIST_FACTORS} wrap /></div>
                            </td>
                            <td className="hidden sm:table-cell px-3 py-2.5 align-top"><FactorChips factors={factors} only={LIST_FACTORS} /></td>
                            <td className="hidden md:table-cell px-3 py-2.5 align-top text-right font-mono text-xs tabular-nums text-secondary">{c.images}</td>
                            <td className="px-3 py-2.5 align-top text-right font-mono text-xs tabular-nums whitespace-nowrap">
                              <span className={c.runningWorkloads > 0 ? 'text-primary' : 'text-tertiary'}>{c.runningWorkloads}</span>
                              <span className="text-tertiary">/{c.workloads}</span>
                            </td>
                            <td className="hidden md:table-cell px-3 py-2.5 align-top">
                              <JoinBadge join={c.weakestJoin} />
                              <div className="mt-0.5 text-[11px] text-tertiary">{c.sources.map(sourceLabel).join(', ')}</div>
                            </td>
                            <td className="hidden sm:table-cell px-2 py-2.5 align-top text-tertiary"><ChevronRight className="w-4 h-4" aria-hidden /></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <footer className="flex flex-wrap items-center justify-between gap-2 px-4 py-2 border-t border-hubble-border text-[11px] text-tertiary">
                    <span title={IN_USE_UNKNOWN_TITLE}>
                      {rows.some((r) => r.tier === 'Background') && <span className="block text-secondary" data-testid="background-caveat">{backgroundCaveat(null)}</span>}
                      {!tiersKnown
                        ? 'No tiers yet (not computed, or this Broker predates them) and no loaded-package data: both unknown. '
                        : loadedKnown ? '' : 'No runtime evidence of loading yet: unknown is ranked as if loaded. '}
                      Privilege and per-workload exposure are in the CVE drawer.
                    </span>
                    {cves.hasMore && (
                      <Button variant="secondary" size="sm" onClick={() => void cves.loadMore()} disabled={cves.loadingMore || cves.loading}>
                        {cves.loadingMore ? 'Loading…' : 'Load more CVEs'}
                      </Button>
                    )}
                  </footer>
                </>
              )}
            </section>
          )}

          {tab === 'images' && <ImagesTable namespace={ns} scopeLabel={scopeLabel} refreshTick={refreshTick} api={api} onOpen={(d) => onParamsChange({ digest: d, cve: undefined })} />}

          {tab === 'supply' && <SupplyChainTab namespace={ns} scopeLabel={scopeLabel} refreshTick={refreshTick} api={api} onOpenWorkload={onOpenWorkload} />}
        </div>
      </div>

      {cve && (
        <CveDrawer
          id={cve}
          summary={openedFrom?.id === cve ? openedFrom : cves.items.find((c) => c.id === cve)}
          onClose={() => onParamsChange({ cve: undefined })}
          onOpenWorkload={onOpenWorkload}
          onShowOnMap={onShowOnMap}
          onAskAI={onAskAI}
          api={api}
          profileApi={profileApi}
        />
      )}
      {digest && !cve && (
        <ImageDrawer digest={digest} onClose={() => onParamsChange({ digest: undefined })} onOpenCve={(id) => openCve(id)} onOpenWorkload={onOpenWorkload} api={api} />
      )}
    </div>
  );
}

/** A refresh failed while rows are on screen: they are the last good result, not current. */
function StaleNotice({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  return (
    <div role="alert" className="flex flex-wrap items-center justify-between gap-2 px-4 py-2 border-b border-hubble-border bg-severity-medium/10 text-xs text-severity-medium">
      <span>Could not refresh ({vulnErrorMessage(error)}). Showing the last result.</span>
      <Button variant="secondary" size="sm" onClick={onRetry}>Retry</Button>
    </div>
  );
}

const FRESHNESS_TICK_MS = 30_000;

/** Re-render every `ms`, so an age keeps moving while the page sits open. */
function useTick(ms: number): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(id);
  }, [ms]);
  return now;
}

function SummaryFreshness({ computedAt, staleSeconds, receivedAt, loading }: { computedAt: string | null; staleSeconds: number | null; receivedAt: number | null; loading: boolean }) {
  const now = useTick(FRESHNESS_TICK_MS);
  if (loading) return null;
  if (computedAt === null) return <span className="text-[11px] text-tertiary">Summary not computed yet</span>;
  // The Broker's own age at response time, advanced by this browser's clock since: the two clocks need not agree.
  const stale = (staleSeconds ?? 0) + (receivedAt === null ? 0 : Math.max(0, Math.round((now - receivedAt) / 1000)));
  const age = stale < 90 ? `${stale}s` : stale < 5400 ? `${Math.round(stale / 60)}m` : `${Math.round(stale / 3600)}h`;
  return (
    <span className={`text-[11px] ${stale > 3600 ? 'text-severity-medium' : 'text-tertiary'}`} title={`Rebuilt ${formatTimestamp(asUtc(computedAt))}. The Broker rebuilds this summary on an interval; counts can lag new scans by up to one interval.`}>
      Summary rebuilt {age} ago
    </span>
  );
}

function ImagesTable({ namespace, scopeLabel, refreshTick, api, onOpen }: { namespace?: string; scopeLabel: string; refreshTick?: number; api: VulnApi; onOpen: (digest: string) => void }) {
  const list = useImageList(namespace, refreshTick, api);
  return (
    <section aria-label="Images by digest" className="rounded-surface border border-hubble-border bg-hubble-card overflow-hidden">
      {list.loading && list.items.length === 0 ? (
        <SectionSkeleton rows={4} />
      ) : list.error && list.items.length === 0 ? (
        <VulnErrorState error={list.error} onRetry={() => void list.reload()} />
      ) : list.items.length === 0 ? (
        <EmptyState icon={Package} compact title={`No images in ${scopeLabel}`} description="An image appears once the Controller reports a container running it." />
      ) : (
        <>
          {list.error != null && <StaleNotice error={list.error} onRetry={() => void list.reload()} />}
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-[11px] uppercase tracking-wide text-tertiary">
                <tr className="border-b border-hubble-border">
                  <th scope="col" className="text-left font-medium px-4 py-2">Image</th>
                  <th scope="col" className="hidden sm:table-cell text-left font-medium px-3 py-2">Workloads</th>
                  <th scope="col" className="hidden sm:table-cell text-left font-medium px-3 py-2">Vulnerability data</th>
                  <th scope="col" className="hidden sm:table-cell text-left font-medium px-3 py-2">SBOM</th>
                  <th scope="col" className="relative px-2 py-2"><span className="sr-only">Open</span></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-hubble-border">
                {list.items.map((img) => (
                  <ImageRow key={img.digest} img={img} e={list.enriched.get(img.digest)} onOpen={() => onOpen(img.digest)} />
                ))}
              </tbody>
            </table>
          </div>
          <footer className="flex flex-wrap items-center justify-between gap-2 px-4 py-2 border-t border-hubble-border text-[11px] text-tertiary">
            <span>Keyed by digest. Each row reads the image and its vulnerability reports, then its SBOMs when a source reported on it (2 to 3 reads per digest, a few at a time).</span>
            {list.hasMore && (
              <Button variant="secondary" size="sm" onClick={() => void list.loadMore()} disabled={list.loadingMore || list.loading}>
                {list.loadingMore ? 'Loading…' : 'Load more images'}
              </Button>
            )}
          </footer>
        </>
      )}
    </section>
  );
}

const UnknownPill = ({ error }: { error: unknown }) => (
  <span className="rounded-full border border-dashed border-hubble-border-strong px-2 py-0.5 text-[11px] text-tertiary" title={`Could not read: ${vulnErrorMessage(error)}`}>Unknown</span>
);

function WorkloadsCell({ e }: { e: ImageEnrichment | undefined }) {
  if (e === undefined) return <span className="text-tertiary">…</span>;
  if (e.workloadsError) return <UnknownPill error={e.workloadsError} />;
  const workloads = e.workloads ?? [];
  const running = workloads.filter((w) => w.running);
  const names = [...new Set(workloads.map((w) => `${w.namespace}/${w.workloadName}`))];
  return (
    <>
      <div className="text-primary break-words">{names.slice(0, 2).join(', ') || <span className="text-tertiary">none now</span>}{names.length > 2 && <span className="text-tertiary"> +{names.length - 2}</span>}</div>
      <div className="text-[11px] text-tertiary">{running.length} running container{running.length === 1 ? '' : 's'}{e.workloadsTruncated ? ' (more not listed)' : ''}</div>
    </>
  );
}

function VulnDataCell({ e }: { e: ImageEnrichment | undefined }) {
  if (e === undefined) return <span className="text-tertiary">…</span>;
  if (e.vulnError) return <UnknownPill error={e.vulnError} />;
  if (e.vulnReports && e.vulnReports.length === 0) {
    return <span className="rounded-full border border-dashed border-hubble-border-strong px-2 py-0.5 text-[11px] text-tertiary" title="No source has reported on this digest: unknown, not clean">No data</span>;
  }
  return (
    <div className="flex flex-wrap items-center gap-1">
      {e.vulnReports?.map((r) => (
        <span key={r.source} className="inline-flex flex-wrap items-center gap-1 text-[11px] text-secondary">
          {sourceLabel(r.source)} <span className="text-tertiary tabular-nums">{r.itemCount} finding{r.itemCount === 1 ? '' : 's'}</span> <JoinBadge join={r.join} />
        </span>
      ))}
    </div>
  );
}

function SbomCell({ e }: { e: ImageEnrichment | undefined }) {
  if (e === undefined) return <span className="text-tertiary">…</span>;
  if (e.sbomError) return <UnknownPill error={e.sbomError} />;
  if (e.sbomSkipped) {
    return <span className="rounded-full border border-dashed border-hubble-border-strong px-2 py-0.5 text-[11px] text-tertiary" title="No source has reported on this digest, so its SBOM was not looked up here. Open the image to read it.">Not read</span>;
  }
  if (e.sbomReports && e.sbomReports.length === 0) {
    const matched = sbomFromMatcher(e.vulnReports);
    if (matched.length > 0) {
      return (
        <div className="flex flex-col gap-1">
          {matched.map((m) => (
            <span key={`${m.matcher}-${m.sbomSource}`} data-testid="sbom-matched" className="inline-flex flex-wrap items-center gap-1 text-[11px] text-secondary" title="This report says it was matched from that SBOM, but the Broker never received the document itself, so only the report says it exists.">
              {sourceLabel(m.sbomSource)} <TrustBadge trust={m.trust} /> <span className="text-tertiary">used by {sourceLabel(m.matcher)}; not held by the Broker</span>
            </span>
          ))}
        </div>
      );
    }
    return <span className="rounded-full border border-dashed border-hubble-border-strong px-2 py-0.5 text-[11px] text-tertiary" title="No source has an SBOM for this digest: its contents are unknown">No SBOM</span>;
  }
  return (
    <div className="flex flex-col gap-1">
      {e.sbomReports?.map((r) => (
        <span key={r.source} className="inline-flex flex-wrap items-center gap-1 text-[11px] text-secondary">
          {sourceLabel(r.source)} <TrustBadge trust={r.sbomTrust} />
        </span>
      ))}
    </div>
  );
}

function ImageRow({ img, e, onOpen }: { img: ImageSummary; e: ImageEnrichment | undefined; onOpen: () => void }) {
  return (
    <tr data-testid="image-row" onClick={onOpen} className="cursor-pointer hover:bg-hubble-hover/40 transition-colors">
      <td className="px-4 py-2.5 align-top sm:min-w-52">
        <button type="button" onClick={(ev) => { ev.stopPropagation(); onOpen(); }} className="text-left font-mono text-xs text-primary hover:underline [overflow-wrap:anywhere]">
          {img.repository ?? 'unknown repository'}{img.tags.length ? `:${img.tags.join(', ')}` : ''}
        </button>
        <div className="text-[11px] text-tertiary font-mono" title={img.digest}>
          {shortDigest(img.digest)}
          {/* Only the kind that changes what the digest means is worth showing. */}
          {img.digestKind === 'config' && <span title="The kubelet reported only the image config ID, not a registry digest: registry SBOMs and signatures cannot be looked up by it."> · config ID</span>}
        </div>
        {/* Phones: the other columns stack here. */}
        <div className="sm:hidden mt-2 space-y-1.5 text-xs">
          <WorkloadsCell e={e} />
          <VulnDataCell e={e} />
          <SbomCell e={e} />
        </div>
      </td>
      <td className="hidden sm:table-cell px-3 py-2.5 align-top text-xs min-w-40"><WorkloadsCell e={e} /></td>
      <td className="hidden sm:table-cell px-3 py-2.5 align-top text-xs"><VulnDataCell e={e} /></td>
      <td className="hidden sm:table-cell px-3 py-2.5 align-top text-xs"><SbomCell e={e} /></td>
      <td className="px-2 py-2.5 align-top text-tertiary"><ChevronRight className="w-4 h-4" aria-hidden /></td>
    </tr>
  );
}

export default ImagesView;
