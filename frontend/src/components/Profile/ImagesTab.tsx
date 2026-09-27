import { useState } from 'react';
import { Box, Bug, FileBadge2, FileSignature, Package } from 'lucide-react';
import type { VulnApi } from '../../services/vulnApi';
import type { WorkloadSignatureState } from '../../hooks/useSignatures';
import { Button } from '../ui/Button';
import { VulnErrorState } from '../Vulns/parts';
import { DigestRow } from '../Vulns/SupplyChainTab';
import { NotTrustedNote } from '../Vulns/SignatureParts';
import { AdmissionPolicyModal } from '../Vulns/AdmissionPolicyModal';
import { SectionSkeleton } from './parts';
import type { ImageContainer, ImageDigestRow, ImagesDimension, SupplyChainDimension } from '../../types/profile';
import { ImageTrustBlock } from './ImageTrustBlock';
import { asStatus, formatAgo, formatTimestamp, shortDigest } from '../../utils/posture';
import { digestStateLabel } from '../../utils/profileView';
import { EmptyState } from '../ui/EmptyState';
import { Panel, Reasons, StatusPill } from './parts';

function DigestRows({ rows, current }: { rows: ImageDigestRow[]; current: boolean }) {
  return (
    <ul className="divide-y divide-hubble-border">
      {rows.map((r) => {
        const s = digestStateLabel(r, current);
        return (
          <li key={`${r.digest}-${r.imageRef}`} className="px-4 py-2 text-xs flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
            <div className="min-w-0">
              <div className="font-mono text-primary [overflow-wrap:anywhere]">{r.imageRef}</div>
              <div className="font-mono text-tertiary" title={r.digest}>{shortDigest(r.digest)}</div>
            </div>
            <div className="text-right shrink-0">
              <div className={s.tone} data-testid="digest-state">{s.text}</div>
              <div className="text-tertiary" title={`First seen ${formatTimestamp(r.firstSeen)} · last seen ${formatTimestamp(r.lastSeen)}`}>
                last seen {formatAgo(r.lastSeen)}
                {r.lastPodName && <> · <span className="font-mono">{r.lastPodName}</span></>}
              </div>
            </div>
          </li>
        );
      })}
    </ul>
  );
}

function ContainerCard({ c }: { c: ImageContainer }) {
  return (
    <div className="rounded-control border border-hubble-border overflow-hidden" data-testid="image-container">
      <div className="flex flex-wrap items-center gap-2 px-4 py-2 bg-hubble-hover/30 border-b border-hubble-border">
        <span className="font-mono text-sm text-primary">{c.name}</span>
        <span className="text-[11px] text-tertiary">{c.kind}</span>
        {c.stale && (
          <span
            className="rounded-full border border-dashed border-hubble-border-strong px-2 py-0.5 text-[11px] text-tertiary"
            title="No digest of this container has been reported recently: it may have been removed from the spec. Kept until retention prunes it."
          >
            Stale
          </span>
        )}
        {c.mixedDigests && (
          <span
            className="rounded-full border px-2 py-0.5 text-[11px] font-medium bg-severity-medium/15 text-severity-medium border-severity-medium/30"
            title="More than one digest running at once: a rollout in progress, or nodes that resolved the same tag to different images"
          >
            Mixed digests
          </span>
        )}
      </div>
      {c.running.length > 0 ? (
        <DigestRows rows={c.running} current />
      ) : (
        <p className="px-4 py-2 text-xs text-tertiary">Not running now.</p>
      )}
      {c.previous.length > 0 && (
        <details className="border-t border-hubble-border">
          <summary className="px-4 py-2 text-xs text-secondary cursor-pointer hover:text-primary">
            {c.previous.length} earlier or not-started digest{c.previous.length === 1 ? '' : 's'}
          </summary>
          <DigestRows rows={c.previous} current={false} />
        </details>
      )}
    </div>
  );
}

/** Who signed this workload's running images, and its admission policy export. */
function SupplyChainPanel({ sig, workload, api, supplyChain }: { sig: WorkloadSignatureState; workload: { ns: string; kind: string; name: string }; api: VulnApi; supplyChain: SupplyChainDimension | null }) {
  const [exporting, setExporting] = useState(false);
  return (
    <Panel
      icon={FileBadge2}
      title="Supply chain"
      hint="Signature verdicts from the supplychain component, per running digest"
      action={
        <Button variant="secondary" size="sm" leftIcon={FileSignature} onClick={() => setExporting(true)}>
          Export admission policy
        </Button>
      }
    >
      {sig.loading && sig.rows.length === 0 ? (
        <SectionSkeleton rows={2} />
      ) : sig.error != null && sig.rows.length === 0 ? (
        <VulnErrorState error={sig.error} unsupportedTitle="Signature results not available" onRetry={() => void sig.reload()} />
      ) : sig.rows.length === 0 ? (
        <p className="px-4 py-3 text-xs text-tertiary">
          {sig.truncated ? 'Not read: the namespace has more running containers than one read covers, so this workload may be among them. Unknown.' : 'No running container of this workload is in the image inventory, so there is nothing to check yet. Unknown, not unsigned.'}
        </p>
      ) : (
        <>
          <ul className="divide-y divide-hubble-border">
            {sig.rows.map((r) => <DigestRow key={r.digest} r={r} />)}
          </ul>
          <NotTrustedNote className="px-4 py-2.5 border-t border-hubble-border" />
        </>
      )}
      <ImageTrustBlock supplyChain={supplyChain} />
      {exporting && <AdmissionPolicyModal api={api} scope={{ kind: 'workload', namespace: workload.ns, workloadKind: workload.kind, name: workload.name }} onClose={() => setExporting(false)} />}
    </Panel>
  );
}

export function ImagesTab({ dim, signatures, workload, api }: { dim: ImagesDimension; signatures?: WorkloadSignatureState; workload?: { ns: string; kind: string; name: string }; api?: VulnApi }) {
  const status = asStatus(dim.status);
  return (
    <div className="space-y-4">
      <Panel
        icon={Package}
        title="Image inventory"
        hint={`Digests per container, keyed by digest. "Running" means reported in the last ${Math.round(dim.runningWindowSeconds / 60)} min.`}
        action={<StatusPill status={status} />}
      >
        <div className="px-4 py-3 space-y-3">
          <Reasons reasons={dim.reasons} />
          {dim.containers.length === 0 ? (
            <EmptyState icon={Box} compact title="No image inventory yet" description="The Controller reports each container's image digest when it sees the pod. Nothing has arrived for this workload." />
          ) : (
            <div className="space-y-3">
              {dim.containers.map((c) => <ContainerCard key={`${c.kind}-${c.name}`} c={c} />)}
            </div>
          )}
          {dim.truncated && <p className="text-[11px] text-tertiary">More digests exist than are shown.</p>}
        </div>
      </Panel>

      <Panel icon={Bug} title="Vulnerabilities">
        {dim.vulnerabilities === null ? (
          <EmptyState
            icon={Bug}
            compact
            title="Vulnerability data not configured"
            description="No vulnerability source is connected, so these images are inventoried but not scanned. This is not the same as zero vulnerabilities."
          />
        ) : (
          <p className="px-4 py-3 text-xs text-secondary">Vulnerability data is available from the Broker; the detailed view ships with the Images inventory.</p>
        )}
      </Panel>

      {signatures && workload && api ? (
        <SupplyChainPanel sig={signatures} workload={workload} api={api} supplyChain={dim.supplyChain} />
      ) : (
        <Panel icon={FileBadge2} title="Supply chain">
          <p className="px-4 py-3 text-xs text-tertiary">Signature results are not loaded here.</p>
        </Panel>
      )}
    </div>
  );
}
