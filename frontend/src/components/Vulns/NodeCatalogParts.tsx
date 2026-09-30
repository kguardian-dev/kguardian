import { CircleSlash, HardDrive, Hourglass, ShieldCheck, TriangleAlert } from 'lucide-react';
import type { CatalogCoverage, NodeCatalogState, Report } from '../../types/vulns';
import { byTrustRank, catalogInUse, completenessNote, coverageSummary, provenanceLabel, reasonShort, type NotAssessable } from '../../utils/nodeCatalog';
import { TrustBadge } from './parts';

const pill = 'inline-flex items-center gap-1 shrink-0 rounded-full border px-2 py-0.5 text-[11px] font-medium whitespace-nowrap';
const NEUTRAL = 'bg-hubble-border/30 text-secondary border-hubble-border';
const WARN = 'bg-severity-medium/10 text-severity-medium border-severity-medium/30';
const UNKNOWN = 'text-tertiary border-dashed border-hubble-border-strong';

/** Sources whose SBOM trust is fixed by the Broker: both are in-cluster scans (`scanned`). */
const SCANNED_SOURCES = new Set(['trivy-operator', 'node']);

/**
 * Which SBOM sources exist for an image (`sbomSources` on `GET /images`),
 * one chip each, by trust rank (Trivy Operator, node, registry): the node
 * catalog's with the platform it was cataloged for, plus its completeness
 * when that is partial or OS-only. Trivy Operator and the node catalog are
 * always `scanned` (the Broker stores them so); a registry SBOM's trust
 * varies and is shown only once its report was read (`reports`).
 */
export function ProvenanceChips({ sources, nodeCatalog, reports = null }: { sources: readonly string[]; nodeCatalog?: NodeCatalogState | null; reports?: readonly Report[] | null }) {
  return (
    <span className="flex flex-col items-start gap-1">
      {byTrustRank(sources).map((s) => {
        const report = reports?.find((r) => r.source === s);
        const trust = SCANNED_SOURCES.has(s) ? 'scanned' : report ? report.sbomTrust : undefined;
        const partial = s === 'node' ? completenessNote(nodeCatalog) : null;
        return (
          <span key={s} className="inline-flex flex-wrap items-center gap-1">
            <span data-testid="provenance-chip" data-source={s} className={`${pill} ${NEUTRAL}`} title={s === 'node' ? "kguardian's cataloger read the running container's files on its node. Trivy Operator stays authoritative; a node SBOM only adds." : undefined}>
              {s === 'node' && <HardDrive className="w-3 h-3" aria-hidden />}
              {provenanceLabel(s, nodeCatalog)}
            </span>
            {partial && <span data-testid="provenance-completeness" className={`${pill} ${WARN}`} title={partial.title}>{partial.label}</span>}
            {trust !== undefined && <TrustBadge trust={trust} source={s} />}
          </span>
        );
      })}
    </span>
  );
}

/** The node catalog is still at work on an image (pending or cataloging). */
export function CatalogPendingChip({ label, title }: { label: string; title: string }) {
  return (
    <span data-testid="catalog-pending" className={`${pill} ${UNKNOWN}`} title={title}>
      <Hourglass className="w-3 h-3" aria-hidden />
      {label}
    </span>
  );
}

/**
 * "Not assessable": no SBOM from any source, and the node catalog could not
 * produce one. Never "0 CVEs". `compact` is the table-cell chip (reason as
 * text, the sentence in the title); otherwise a block with the sentence.
 */
export function NotAssessableState({ na, compact = false }: { na: NotAssessable; compact?: boolean }) {
  const title = `${na.copy}${na.retry ? ` ${na.retry}` : ''}`;
  if (compact) {
    return (
      <span data-testid="not-assessable" data-reason={na.reason} className="inline-flex flex-col items-start gap-0.5">
        {/* The sentence is a tooltip (the TrustBadge pattern, which has no focusable disclosure); screen readers get it once, as text, so the tooltip is hidden from them. */}
        <span className={`${pill} ${WARN}`} title={title} aria-hidden="true">
          <CircleSlash className="w-3 h-3" aria-hidden />
          Not assessable
        </span>
        <span className="sr-only">Not assessable: </span>
        <span className="text-[11px] text-tertiary">{reasonShort(na.reason)}</span>
        <span className="sr-only">. {title}</span>
      </span>
    );
  }
  return (
    <div data-testid="not-assessable" data-reason={na.reason} className="rounded-control border border-severity-medium/30 bg-severity-medium/10 px-3 py-2 text-xs">
      <p className="flex items-center gap-1.5 font-medium text-severity-medium">
        <CircleSlash className="w-3.5 h-3.5" aria-hidden />
        Not assessable: {reasonShort(na.reason)}
      </p>
      <p className="mt-1 text-secondary">{na.copy}</p>
      {na.retry && <p className="mt-0.5 text-tertiary">{na.retry}</p>}
    </div>
  );
}

/**
 * The Images page's coverage line. Cluster-wide, like the app's other
 * status banners (NodeReportingBanner): it is labelled so and stays when a
 * namespace filter is on, since the Broker counts every running image. A
 * plain region, not a live one, so a Refresh does not re-announce it.
 *
 * The coverage line from `GET /catalog/coverage`: how many
 * running images have a trusted SBOM (Trivy Operator or the node catalog),
 * and what the node catalog still has queued or could not do, by reason.
 * Renders nothing without data (the hook returns null for an older Broker,
 * a busy one, or any failure) or when the catalog is not enabled (no
 * catalog token), even with rows left from when it was.
 */
export function CoverageBanner({ coverage }: { coverage: CatalogCoverage | null }) {
  if (!coverage || !catalogInUse(coverage)) return null;
  const s = coverageSummary(coverage);
  return (
    <section aria-label="Node catalog coverage" data-testid="coverage-banner" className="rounded-surface border border-hubble-border bg-hubble-card px-4 py-2.5 text-xs">
      <p className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <ShieldCheck className="w-3.5 h-3.5 shrink-0 text-accent-fg" aria-hidden />
        <span className="text-tertiary" data-testid="coverage-scope">Cluster-wide:</span>
        <span className="font-medium text-primary" data-testid="coverage-headline">{s.headline}</span>
        {s.queue && <span className="text-secondary" data-testid="coverage-queue">· {s.queue}</span>}
      </p>
      {s.reasons.length > 0 && (
        <p className="mt-1 text-tertiary" data-testid="coverage-reasons">
          Not cataloged, by reason:{' '}
          {s.reasons.map((r, i) => (
            <span key={r.reason} title={r.copy}>
              {i > 0 && ', '}
              {r.label} <span className="tabular-nums">{r.count}</span>
            </span>
          ))}
        </p>
      )}
      {s.warnings.map((w) => (
        <p key={w} className="mt-1 flex items-center gap-1.5 text-severity-medium" data-testid="coverage-warning">
          <TriangleAlert className="w-3 h-3 shrink-0" aria-hidden />
          {w}
        </p>
      ))}
    </section>
  );
}
