import { useMemo, useState } from 'react';
import { FileSignature, Info, ShieldCheck, Signature } from 'lucide-react';
import { useRunningSignatures } from '../../hooks/useSignatures';
import { vulnErrorMessage, type VulnApi } from '../../services/vulnApi';
import { formatAgo, formatTimestamp, shortDigest } from '../../utils/posture';
import { asUtc } from '../../utils/vulnView';
import { reasonText, SIGNATURE_LABEL, SIGNATURE_MEANING, signaturesByDigest, type DigestSignature, type SignatureState } from '../../utils/signatures';
import { Button } from '../ui/Button';
import { EmptyState } from '../ui/EmptyState';
import { StatStrip, StatTile } from '../ui/StatTile';
import { SectionSkeleton } from '../Profile/parts';
import { VulnErrorState } from './parts';
import { NotTrustedNote, SignatureBadge, SignerList } from './SignatureParts';
import { AdmissionPolicyModal, type AdmissionScope } from './AdmissionPolicyModal';

const FILTERS: Array<{ id: 'all' | SignatureState; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'invalid', label: 'Invalid' },
  { id: 'unsigned', label: 'Unsigned' },
  { id: 'key_signed', label: 'Key not held' },
  { id: 'unknown', label: 'Unknown' },
  { id: 'unchecked', label: 'Not checked' },
  { id: 'verified', label: 'Verified' },
];

const shortPredicate = (p: string) => (p.includes('slsa.dev/provenance') ? 'SLSA provenance' : p.includes('spdx') ? 'SPDX SBOM' : p.includes('cyclonedx') ? 'CycloneDX SBOM' : p.includes('vuln') ? 'vulnerability scan' : p);

/**
 * Images → Supply chain: who signed each running image digest, as the
 * supplychain component checked it. A digest with no result is "Not
 * checked", never unsigned; unknown is never good; a verified signature is
 * shown with its signer and never as trusted.
 */
export function SupplyChainTab({ namespace, scopeLabel, refreshTick, api, onOpenWorkload }: { namespace?: string; scopeLabel: string; refreshTick?: number; api: VulnApi; onOpenWorkload: (ns: string, kind: string, name: string) => void }) {
  const running = useRunningSignatures(namespace, refreshTick, api);
  const [filter, setFilter] = useState<'all' | SignatureState>('all');
  const [exporting, setExporting] = useState(false);
  const rows = useMemo(() => signaturesByDigest(running.items), [running.items]);
  const counts = useMemo(() => {
    const c: Record<SignatureState, number> = { verified: 0, key_signed: 0, unsigned: 0, invalid: 0, unknown: 0, unchecked: 0 };
    for (const r of rows) c[r.state] += 1;
    return c;
  }, [rows]);
  const shown = filter === 'all' ? rows : rows.filter((r) => r.state === filter);
  const unread = running.error != null && rows.length === 0;
  const none = !running.loading && !unread && rows.length > 0 && counts.unchecked === rows.length;
  // Counts are a lower bound while a first read's pages are still arriving, and when the read hit its cap.
  const more = running.truncated || running.partial ? '+' : undefined;
  const tile = (n: number) => (running.loading && rows.length === 0 ? '…' : unread ? '—' : n);
  const exportScope = useMemo<AdmissionScope>(() => ({ kind: 'cluster', namespace }), [namespace]);
  const progress = running.loading && running.progress && running.progress.items > 0 ? running.progress : null;

  return (
    <div className="space-y-4">
      <StatStrip count={4} label="Signature posture">
        <StatTile label="Invalid or unsigned" value={tile(counts.invalid + counts.unsigned)} icon={FileSignature} tone={counts.invalid + counts.unsigned > 0 ? 'text-severity-critical' : 'text-secondary'} suffix={more} title="Running image digests whose signatures failed to verify, or that have none." />
        <StatTile label="Unknown or not checked" value={tile(counts.unknown + counts.unchecked + counts.key_signed)} icon={Info} tone="text-tertiary" suffix={more} title="Could not be checked, not checked yet, or signed with a key kguardian was not given. None of these is unsigned, and none is good." />
        <StatTile label="Verified signature" value={tile(counts.verified)} icon={Signature} suffix={more} title="A signature verified. Valid, not trusted: review the signer on each row." />
        <StatTile label="Running digests" value={tile(rows.length)} icon={ShieldCheck} suffix={more} />
      </StatStrip>

      <section aria-label="Signatures by digest" className="rounded-surface border border-hubble-border bg-hubble-card overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 border-b border-hubble-border">
          <label className="flex items-center gap-1.5 text-xs text-tertiary">
            Signature
            <select value={filter} onChange={(e) => setFilter(e.target.value as 'all' | SignatureState)} className="h-8 rounded-control border border-hubble-border bg-hubble-darker px-2 text-xs text-primary">
              {FILTERS.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.label} ({f.id === 'all' ? rows.length : counts[f.id]})
                </option>
              ))}
            </select>
          </label>
          <Button variant="secondary" size="sm" leftIcon={FileSignature} onClick={() => setExporting(true)}>
            Export admission policy
          </Button>
        </div>

        {running.loading && rows.length === 0 ? (
          <>
            <SectionSkeleton rows={4} />
            {progress && <p role="status" data-testid="running-progress" className="px-4 pb-3 text-xs text-tertiary">Read {progress.items} running containers so far (page {progress.pages})…</p>}
          </>
        ) : unread ? (
          <VulnErrorState error={running.error} unsupportedTitle="Signature results not available" onRetry={() => void running.reload()} />
        ) : rows.length === 0 ? (
          <EmptyState icon={Signature} compact title={`No running images in ${scopeLabel}`} description="A digest appears once the Controller reports a container running it." />
        ) : (
          <>
            {running.error != null && (
              <div role="alert" className="flex flex-wrap items-center justify-between gap-2 px-4 py-2 border-b border-hubble-border bg-severity-medium/10 text-xs text-severity-medium">
                <span>Could not refresh ({vulnErrorMessage(running.error)}). {running.partial ? 'Showing the pages read before it failed; counts are a lower bound.' : 'Showing the last result.'}</span>
                <Button variant="secondary" size="sm" onClick={() => void running.reload()}>Retry</Button>
              </div>
            )}
            {progress && (
              <p role="status" data-testid="running-progress" className="px-4 py-2 border-b border-hubble-border text-xs text-tertiary">
                Still reading: {progress.items} running containers so far (page {progress.pages}).{running.partial ? ' Counts and filters are incomplete until it finishes.' : ' The rows below are the last complete read.'}
              </p>
            )}
            {none && (
              <p role="status" className="px-4 py-2.5 border-b border-hubble-border text-xs text-secondary bg-hubble-hover/20">
                No running image has a signature result yet: signature discovery is off (<span className="font-mono">supplychain.signatureDiscovery.enabled</span>) or has not run. Not checked is not unsigned.
              </p>
            )}
            <ul className="divide-y divide-hubble-border">
              {shown.map((r) => <DigestRow key={r.digest} r={r} onOpenWorkload={onOpenWorkload} />)}
              {shown.length === 0 && <li className="px-4 py-4 text-xs text-tertiary">No running digest in this state.</li>}
            </ul>
          </>
        )}
        <footer className="space-y-1.5 px-4 py-2.5 border-t border-hubble-border">
          <NotTrustedNote />
          <p className="text-[11px] text-tertiary">
            ImageTrustPolicy results (would-deny and unknown containers) are written by the evaluator to each policy&apos;s status; the Broker does not serve them, so they are not shown here. Read them with <span className="font-mono">kubectl get imagetrustpolicies,clusterimagetrustpolicies -A -o yaml</span>.
          </p>
          {(running.truncated || (running.partial && !running.loading)) && <p className="text-[11px] text-severity-medium">More running containers exist than were read; counts are a lower bound.</p>}
        </footer>
      </section>

      {exporting && <AdmissionPolicyModal api={api} scope={exportScope} onClose={() => setExporting(false)} />}
    </div>
  );
}

/** One running digest: verdict, signer or reason, attestations, and (optionally) who runs it. */
export function DigestRow({ r, onOpenWorkload }: { r: DigestSignature; onOpenWorkload?: (ns: string, kind: string, name: string) => void }) {
  const why = r.state === 'verified' ? null : reasonText(r.reason);
  return (
    <li data-testid="signature-row" data-state={r.state} className="px-4 py-3 text-xs">
      <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-1.5">
        <div className="min-w-0 flex-1 basis-64">
          <div className="font-mono text-primary [overflow-wrap:anywhere]">{r.imageRef}</div>
          <div className="font-mono text-[11px] text-tertiary" title={r.digest}>{shortDigest(r.digest)}</div>
        </div>
        <div className="flex flex-col items-start sm:items-end gap-1 shrink-0">
          <SignatureBadge state={r.state} reason={r.reason} />
          <span className="text-[11px] text-tertiary" title={r.checkedAt ? formatTimestamp(asUtc(r.checkedAt)) : undefined}>{r.checkedAt ? `checked ${formatAgo(asUtc(r.checkedAt))}` : 'no result'}</span>
        </div>
      </div>
      <div className="mt-2 space-y-1">
        {r.state === 'verified' && <SignerList signers={r.signers} />}
        {r.noSigner ? (
          <p className="text-[11px] text-severity-medium">Reported verified, but no verified signer identity came with it: unknown, not signed.</p>
        ) : (
          r.state !== 'verified' && <p className="text-[11px] text-secondary">{why ? `${SIGNATURE_LABEL[r.state]}: ${why}.` : SIGNATURE_MEANING[r.state]}</p>
        )}
        {r.predicates.length > 0 && (
          <p className="text-[11px] text-secondary">
            Verified attestations: {r.predicates.map(shortPredicate).join(', ')}
            {r.source && <> · built from <span className="font-mono [overflow-wrap:anywhere]">{r.source}</span></>}
          </p>
        )}
        {onOpenWorkload && <p className="text-[11px] text-tertiary">
          Run by{' '}
          {r.workloads.map((w, i) => (
            <span key={`${w.namespace}/${w.kind}/${w.name}`}>
              {i > 0 && ', '}
              <button type="button" onClick={() => onOpenWorkload(w.namespace, w.kind, w.name)} className="text-secondary hover:text-primary hover:underline">
                {w.namespace}/{w.name}
              </button>
            </span>
          ))}
        </p>}
      </div>
    </li>
  );
}
