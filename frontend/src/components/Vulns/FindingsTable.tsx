import type { Finding, Report } from '../../types/vulns';
import { formatAgo, formatTimestamp, shortDigest } from '../../utils/posture';
import { backgroundCaveat, brokerTier, IN_USE_UNKNOWN_TITLE, LIST_FACTORS } from '../../utils/tiers';
import { asUtc, findingFactors, sourceLabel } from '../../utils/vulnView';
import { Button } from '../ui/Button';
import { FactorChips, JoinBadge, SeverityBadge, TierBadge, TrustBadge } from './parts';

/** The reports behind an image's findings: source, match, scanner, freshness, SBOM trust. */
export function ReportList({ reports }: { reports: Report[] }) {
  return (
    <ul className="space-y-1.5" aria-label="Vulnerability sources">
      {reports.map((r) => (
        <li key={`${r.source}-${r.reportDigest}`} className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs" data-testid="vuln-report">
          <span className="font-medium text-primary">{sourceLabel(r.source)}</span>
          <JoinBadge join={r.join} />
          <span className="text-tertiary">
            {r.scannerName ?? 'scanner not stated'} {r.scannerVersion ?? ''} · scanned <span title={formatTimestamp(asUtc(r.scannedAt))}>{formatAgo(asUtc(r.scannedAt))}</span>
            {r.dbUpdatedAt ? <> · DB <span title={formatTimestamp(asUtc(r.dbUpdatedAt))}>{formatAgo(asUtc(r.dbUpdatedAt))}</span></> : ' · DB age not stated'}
          </span>
          {r.sbomSources.length > 0 && <span className="text-tertiary">matched from {r.sbomSources.map(sourceLabel).join(', ')}</span>}
          {(r.sbomSources.length > 0 || r.sbomTrust !== null) && <TrustBadge trust={r.sbomTrust} />}
          {r.digestKind === 'index' && <span className="text-tertiary" title={r.reportDigest}>reported on index {shortDigest(r.reportDigest)}</span>}
        </li>
      ))}
    </ul>
  );
}

interface FindingsTableProps {
  items: Finding[];
  onOpenCve: (id: string) => void;
  hasMore?: boolean;
  loadingMore?: boolean;
  onLoadMore?: () => void;
}

/**
 * One image's findings, deduplicated across sources, most severe first,
 * with the Broker's tier and tier factors (worst over every workload
 * container running the image).
 */
export function FindingsTable({ items, onOpenCve, hasMore, loadingMore, onLoadMore }: FindingsTableProps) {
  const background = items.find((f) => f.tier === 'Background');
  return (
    <div>
      <p className="px-1 pb-2 text-[11px] text-tertiary" title={IN_USE_UNKNOWN_TITLE}>
        {items.every((f) => f.tier == null) ? 'No tier yet for any finding: not computed, or this Broker predates tiers. ' : ''}
        A finding's tier is its worst over every workload running this image; open a CVE for each workload's exposure and privilege.
      </p>
      {background && <p className="px-1 pb-2 text-[11px] text-secondary" data-testid="background-caveat">{backgroundCaveat(background.inUseDetail?.windowHours)}</p>}
      <div className="overflow-x-auto rounded-control border border-hubble-border">
        <table className="w-full text-sm">
          <thead className="text-[11px] uppercase tracking-wide text-tertiary">
            <tr className="border-b border-hubble-border">
              <th scope="col" className="text-left font-medium px-3 py-2">Tier</th>
              <th scope="col" className="text-left font-medium px-3 py-2">Vulnerability</th>
              <th scope="col" className="hidden sm:table-cell text-left font-medium px-3 py-2">Package</th>
              <th scope="col" className="hidden sm:table-cell text-left font-medium px-3 py-2">Factors</th>
              <th scope="col" className="hidden sm:table-cell text-left font-medium px-3 py-2">Sources</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-hubble-border">
            {items.map((f) => {
              const tier = brokerTier(f.tier);
              const factors = findingFactors(f);
              return (
                <tr key={`${f.id}|${f.package.name}|${f.installedVersion}`} data-testid="finding-row">
                  <td className="px-3 py-2 align-top"><TierBadge tier={tier} title={f.tierFactors?.length ? `Broker tier from: ${f.tierFactors.join(', ')}` : undefined} /></td>
                  <td className="px-3 py-2 align-top sm:min-w-44">
                    <button type="button" onClick={() => onOpenCve(f.id)} className="font-mono text-xs text-primary hover:underline">{f.id}</button>
                    <div className="mt-0.5"><SeverityBadge severity={f.severity} /></div>
                    {/* Phones: the other columns stack here. */}
                    <div className="sm:hidden mt-1.5 space-y-1.5 text-xs">
                      <div className="font-mono [overflow-wrap:anywhere]"><span className="text-primary">{f.package.name}</span> <span className="text-tertiary">{f.installedVersion}</span></div>
                      <FactorChips factors={factors} only={LIST_FACTORS} wrap />
                      <div className="text-[11px] text-tertiary">{f.sources.map(sourceLabel).join(', ')}</div>
                    </div>
                  </td>
                  <td className="hidden sm:table-cell px-3 py-2 align-top text-xs">
                    <div className="font-mono text-primary [overflow-wrap:anywhere]">{f.package.name}</div>
                    <div className="text-tertiary font-mono whitespace-nowrap">{f.installedVersion}</div>
                  </td>
                  <td className="hidden sm:table-cell px-3 py-2 align-top"><FactorChips factors={factors} only={LIST_FACTORS} /></td>
                  <td className="hidden sm:table-cell px-3 py-2 align-top text-[11px] text-tertiary whitespace-nowrap">{f.sources.map(sourceLabel).join(', ')}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {hasMore && onLoadMore && (
        <div className="pt-2">
          <Button variant="secondary" size="sm" onClick={onLoadMore} disabled={loadingMore}>
            {loadingMore ? 'Loading…' : 'Load more findings'}
          </Button>
        </div>
      )}
    </div>
  );
}
