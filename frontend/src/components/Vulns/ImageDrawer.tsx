import { useCallback, useEffect, useState } from 'react';
import { Bug, FileBox, SearchX } from 'lucide-react';
import { useImageVulns } from '../../hooks/useVulns';
import { vulnApi, vulnErrorKind, type VulnApi } from '../../services/vulnApi';
import type { ImageDetail, Report } from '../../types/vulns';
import { shortDigest } from '../../utils/posture';
import { sourceLabel } from '../../utils/vulnView';
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
 * data: unknown, never clean.
 */
export function ImageDrawer({ digest, onClose, onOpenCve, onOpenWorkload, api = vulnApi }: ImageDrawerProps) {
  const [detail, setDetail] = useState<ImageDetail | null>(null);
  const [detailError, setDetailError] = useState<unknown>(null);
  const [sbomReports, setSbomReports] = useState<Report[] | null>(null);
  const vulns = useImageVulns(digest, api);

  const loadDetail = useCallback(async () => {
    try {
      const [d, s] = await Promise.all([api.getImage(digest), api.getImageSbom(digest, { limit: 1 })]);
      setDetail(d);
      setSbomReports(s.reports);
      setDetailError(null);
    } catch (err) {
      setDetailError(err);
    }
  }, [api, digest]);
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch when the drawer opens
    void loadDetail();
  }, [loadDetail]);

  const notFound = vulnErrorKind(detailError) === 'not_found';
  const ref = detail ? `${detail.repository ?? 'unknown repository'}${detail.tags.length ? `:${detail.tags.join(', ')}` : ''}` : shortDigest(digest);

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

        <section aria-label="SBOMs">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-primary mb-2"><FileBox className="w-4 h-4 text-hubble-accent" aria-hidden />SBOMs</h3>
          {sbomReports === null ? (
            detailError ? null : <SectionSkeleton rows={1} />
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

        <section aria-label="Vulnerabilities">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-primary mb-2"><Bug className="w-4 h-4 text-hubble-accent" aria-hidden />Vulnerabilities</h3>
          {vulns.loading && !vulns.reports ? (
            <SectionSkeleton rows={3} />
          ) : vulns.error ? (
            <VulnErrorState error={vulns.error} onRetry={() => void vulns.reload()} />
          ) : vulns.reports && vulns.reports.length === 0 ? (
            <EmptyState icon={Bug} compact title="No vulnerability data for this image" description="No source has reported on this digest. That is unknown, not clean." />
          ) : (
            <div className="space-y-3">
              {vulns.reports && <ReportList reports={vulns.reports} />}
              {vulns.items.length === 0 ? (
                <p className="text-xs text-secondary">The sources above reported no vulnerabilities for this digest in their latest scans.</p>
              ) : (
                <FindingsTable items={vulns.items} onOpenCve={onOpenCve} hasMore={vulns.hasMore} loadingMore={vulns.loadingMore} onLoadMore={() => void vulns.loadMore()} />
              )}
            </div>
          )}
        </section>
      </div>
    </Modal>
  );
}
