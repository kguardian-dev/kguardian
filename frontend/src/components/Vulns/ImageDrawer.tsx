import { useCallback, useEffect, useRef, useState } from 'react';
import { Bug, FileBox, SearchX } from 'lucide-react';
import { useImageVulns } from '../../hooks/useVulns';
import { vulnApi, vulnErrorKind, vulnErrorMessage, type VulnApi } from '../../services/vulnApi';
import type { ImageDetail, Report } from '../../types/vulns';
import { shortDigest } from '../../utils/posture';
import { sbomFromMatcher, sourceLabel } from '../../utils/vulnView';
import { EmptyState } from '../ui/EmptyState';
import { Modal } from '../ui/Modal';
import { SectionSkeleton } from '../Profile/parts';
import { FindingsTable, ReportList } from './FindingsTable';
import { TrustBadge, VulnErrorState } from './parts';

interface ImageDrawerProps {
  digest: string;
  onClose: () => void;
  onOpenCve: (id: string) => void;
  onOpenWorkload: (ns: string, kind: string, name: string) => void;
  api?: VulnApi;
}

/**
 * One image digest (`#/images?digest=`): who runs it, what reported on it
 * (source, match, trust), and its findings. No reports = no vulnerability
 * data: unknown, never clean. The image and SBOM reads settle on their own,
 * so one failing does not blank the other.
 */
export function ImageDrawer({ digest, onClose, onOpenCve, onOpenWorkload, api = vulnApi }: ImageDrawerProps) {
  const [detail, setDetail] = useState<ImageDetail | null>(null);
  const [detailError, setDetailError] = useState<unknown>(null);
  const [sbomReports, setSbomReports] = useState<Report[] | null>(null);
  const [sbomError, setSbomError] = useState<unknown>(null);
  const vulns = useImageVulns(digest, api);
  const seq = useRef(0);

  const loadDetail = useCallback(async () => {
    // A new digest (or a retry) starts from the skeleton: nothing of the previous image stays on screen.
    const id = ++seq.current;
    setDetail(null);
    setDetailError(null);
    setSbomReports(null);
    setSbomError(null);
    const [d, s] = await Promise.allSettled([api.getImage(digest), api.getImageSbom(digest, { limit: 1 })]);
    if (id !== seq.current) return;
    if (d.status === 'fulfilled') setDetail(d.value);
    else setDetailError(d.reason ?? 'read failed');
    if (s.status === 'fulfilled') setSbomReports(s.value.reports);
    else setSbomError(s.reason ?? 'read failed');
  }, [api, digest]);
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch when the drawer opens / digest changes
    void loadDetail();
  }, [loadDetail]);

  const detailKind = vulnErrorKind(detailError);
  const notFound = detailError != null && detailKind === 'not_found';
  // The digest itself is the problem (unknown or malformed): the other sections have nothing to say about it.
  const badDigest = detailError != null && (detailKind === 'not_found' || detailKind === 'bad_request');
  const ref = detail ? `${detail.repository ?? 'unknown repository'}${detail.tags.length ? `:${detail.tags.join(', ')}` : ''}` : shortDigest(digest);
  const matched = sbomFromMatcher(vulns.reports);

  return (
    <Modal isOpen onClose={onClose} align="right" className="w-full max-w-3xl" title={<span className="font-mono">{ref}</span>} subtitle={<span className="font-mono" title={digest}>{digest}</span>}>
      <div className="px-5 py-4 space-y-5">
        {notFound ? (
          <EmptyState icon={SearchX} title="Image not in the inventory" description="No workload has reported this digest, or retention has pruned it." />
        ) : detailError ? (
          <VulnErrorState error={detailError} onRetry={() => void loadDetail()} />
        ) : !detail ? (
          <SectionSkeleton rows={3} />
        ) : (
          <section aria-label="Workloads running this image">
            <h3 className="text-sm font-semibold text-primary mb-2">Workloads</h3>
            {detail.workloads.length === 0 ? (
              <p className="text-xs text-tertiary">No workload container reports this digest now.</p>
            ) : (
              <ul className="space-y-1 text-xs">
                {detail.workloads.map((w) => (
                  <li key={`${w.namespace}/${w.workloadKind}/${w.workloadName}/${w.containerName}`} className="flex flex-wrap items-center gap-2">
                    <button type="button" className="text-primary hover:underline" onClick={() => onOpenWorkload(w.namespace, w.workloadKind, w.workloadName)}>
                      {w.namespace}/{w.workloadName}
                    </button>
                    <span className="text-tertiary font-mono">{w.workloadKind} · {w.containerName}</span>
                    {w.running ? <span className="text-primary">running</span> : <span className="text-tertiary">{w.ranAsInit ? 'ran as init' : w.state ? `${w.state}${w.stateReason ? `: ${w.stateReason}` : ''}` : 'not running'}</span>}
                  </li>
                ))}
              </ul>
            )}
            {detail.truncated && <p className="mt-1 text-[11px] text-tertiary">More workloads run this image than are listed.</p>}
          </section>
        )}

        {!badDigest && (
          <section aria-label="SBOMs">
            <h3 className="flex items-center gap-2 text-sm font-semibold text-primary mb-2"><FileBox className="w-4 h-4 text-hubble-accent" aria-hidden />SBOMs</h3>
            {sbomError != null ? (
              <p className="text-xs text-tertiary" data-testid="sbom-unread">Could not read the SBOMs: {vulnErrorMessage(sbomError)}</p>
            ) : sbomReports === null || (sbomReports.length === 0 && vulns.loading && !vulns.reports) ? (
              <SectionSkeleton rows={1} />
            ) : sbomReports.length === 0 && matched.length > 0 ? (
              <ul className="space-y-1.5 text-xs">
                {matched.map((m) => (
                  <li key={`${m.matcher}-${m.sbomSource}`} className="flex flex-wrap items-center gap-2" data-testid="sbom-matched">
                    <span className="font-medium text-primary">{sourceLabel(m.sbomSource)}</span>
                    <TrustBadge trust={m.trust} />
                    <span className="text-tertiary" title="This report says it was matched from that SBOM, but the Broker never received the document itself (the supplychain component fetches it), so only the report says it exists.">used by {sourceLabel(m.matcher)}; the Broker does not hold it</span>
                  </li>
                ))}
              </ul>
            ) : sbomReports.length === 0 ? (
              <p className="text-xs text-tertiary">No SBOM from any source.</p>
            ) : (
              <ul className="space-y-1.5 text-xs">
                {sbomReports.map((r) => (
                  <li key={`${r.source}-${r.reportDigest}`} className="flex flex-wrap items-center gap-2" data-testid="sbom-report">
                    <span className="font-medium text-primary">{sourceLabel(r.source)}</span>
                    <TrustBadge trust={r.sbomTrust} />
                    <span className="text-tertiary">{r.itemCount} components{r.sbomFormat ? ` · ${r.sbomFormat}` : ''}</span>
                    {r.attestation && (
                      <span className="text-tertiary">
                        via {r.attestation.mechanism ?? 'attachment'}
                        {r.attestation.verified === true ? ' (signature verified)' : ' (signature not checked)'}
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </section>
        )}

        {!badDigest && (
          <section aria-label="Vulnerabilities">
            <h3 className="flex items-center gap-2 text-sm font-semibold text-primary mb-2"><Bug className="w-4 h-4 text-hubble-accent" aria-hidden />Vulnerabilities</h3>
            {vulns.loading && !vulns.reports ? (
              <SectionSkeleton rows={3} />
            ) : vulns.error && vulns.items.length === 0 ? (
              <VulnErrorState error={vulns.error} onRetry={() => void vulns.reload()} />
            ) : vulns.reports && vulns.reports.length === 0 ? (
              <EmptyState icon={Bug} compact title="No vulnerability data for this image" description="No source has reported on this digest. That is unknown, not clean." />
            ) : (
              <div className="space-y-3">
                {vulns.reports && <ReportList reports={vulns.reports} />}
                {vulns.items.length === 0 ? (
                  <p className="text-xs text-secondary">The sources above reported no vulnerabilities for this digest in their latest scans.</p>
                ) : (
                  // With findings on screen an error is a failed next page: they stay, and it is said under them.
                  <FindingsTable items={vulns.items} onOpenCve={onOpenCve} hasMore={vulns.hasMore} loadingMore={vulns.loadingMore} loadMoreError={vulns.error} onLoadMore={() => void vulns.loadMore()} />
                )}
              </div>
            )}
          </section>
        )}
      </div>
    </Modal>
  );
}
