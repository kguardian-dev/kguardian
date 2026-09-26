import { Box, Bug, FileBadge2, Package } from 'lucide-react';
import type { ImageContainer, ImageDigestRow, ImagesDimension } from '../../types/profile';
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

export function ImagesTab({ dim }: { dim: ImagesDimension }) {
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

      <Panel icon={FileBadge2} title="Supply chain">
        {dim.supplyChain === null ? (
          <p className="px-4 py-3 text-xs text-tertiary">Signature and provenance checks are not configured. Unsigned and unchecked are different states; kguardian shows neither until checks run.</p>
        ) : (
          <p className="px-4 py-3 text-xs text-secondary">Supply-chain data is available from the Broker.</p>
        )}
      </Panel>
    </div>
  );
}
