import type { CatalogCoverage, ImageSummary, NodeCatalogState } from '../types/vulns';
import { sourceLabel } from './vulnView';

/**
 * The node catalog (docs/design/node-catalog.md): kguardian's own
 * cataloger reads a running container's filesystem on its node and stores
 * the packages as SBOM source `node` (trust `scanned`). Trivy Operator stays
 * authoritative; a node SBOM only adds.
 *
 * Every field here is optional on the wire: an older Broker sends no
 * `sbomSources`, no `nodeCatalog` and no `/catalog/coverage`, and the UI
 * then shows exactly what it showed before.
 */

/**
 * Why a claim ended, for every reason the Broker accepts
 * (broker/src/node_catalog.rs): `short` fits a chip or a list, `copy` is
 * the sentence. An unrecognised reason is shown as sent.
 */
export const CATALOG_REASON: Record<string, { short: string; copy: string }> = {
  // Back off 1 h, 6 h, then daily.
  timeout: { short: 'timed out', copy: 'The scan ran past its time limit. It is retried after a back-off.' },
  oom: { short: 'out of memory', copy: 'The scan ran out of memory. It is retried after a back-off, with OS packages only.' },
  error: { short: 'scan error', copy: 'The cataloger failed on this image. It is retried after a back-off.' },
  // Another running instance may take it at once.
  pid_gone: { short: 'container went away', copy: 'The container exited or restarted during the scan. Another running instance is tried.' },
  drift: { short: 'container changed', copy: 'The running container changed its packages after it started, so it no longer matches the image. Another instance is tried.' },
  exited_before_catalog: { short: 'exited first', copy: 'The container exited before it could be cataloged (a short-lived Job or init container). It is tried again when it runs.' },
  // This node cannot catalog it; other nodes may.
  sandboxed: { short: 'sandboxed runtime', copy: 'The container runs in a sandboxed runtime (gVisor, Kata) whose files the node cannot read.' },
  lazy_snapshotter: { short: 'lazily pulled', copy: 'The image is lazily pulled (stargz, SOCI, nydus), so its files are not all on the node.' },
  unsupported_rootfs: { short: 'unsupported filesystem', copy: "The container's root filesystem is not a containerd overlay the cataloger can verify." },
  kernel_unsupported: { short: 'kernel too old', copy: "The node's kernel is too old for confined reads (Linux 5.8 or later is needed)." },
  lsm_denied: { short: 'LSM denied', copy: "SELinux or AppArmor denied the cataloger access to the container's files." },
  caps_unavailable: { short: 'no capability', copy: "The cataloger could not get the capability it needs to read the container's files." },
  deferred_pressure: { short: 'node busy', copy: 'The node was under CPU, memory or I/O pressure, so the scan was put off.' },
  worker_unavailable: { short: 'cataloger down', copy: 'The cataloger sidecar on the node was not running or did not answer.' },
  no_cataloger: { short: 'no cataloger', copy: 'No node running this image has a cataloger (a Windows node, or a node without the Controller).' },
  retry_cap: { short: 'too many retries', copy: 'Too many attempts failed on one node, so that node is skipped for 24 hours.' },
  // Done without an SBOM.
  no_packages_found: { short: 'no packages found', copy: 'The cataloger read the image and found no packages it recognises (a scratch image or stripped binaries). Its vulnerabilities cannot be assessed. That is not the same as no CVEs.' },
  superseded: { short: 'replaced', copy: 'A newer catalog of this image replaced this one.' },
};

const RETRY_REASONS = new Set(['pid_gone', 'drift', 'exited_before_catalog']);
const PER_NODE_REASONS = new Set(['sandboxed', 'lazy_snapshotter', 'unsupported_rootfs', 'kernel_unsupported', 'lsm_denied', 'caps_unavailable', 'deferred_pressure', 'worker_unavailable', 'no_cataloger', 'retry_cap']);

export const reasonShort = (r: string) => (Object.hasOwn(CATALOG_REASON, r) ? CATALOG_REASON[r].short : r);
export const reasonCopy = (r: string) => (Object.hasOwn(CATALOG_REASON, r) ? CATALOG_REASON[r].copy : `The node catalog reported ${r}.`);

export const COMPLETENESS_LABEL: Record<string, { label: string; title: string }> = {
  partial: { label: 'partial', title: 'Some of the image could not be read (drift unknown, files cut, or a budget hit). Findings may be missing, and in-use stays unknown rather than not observed.' },
  os_only: { label: 'OS packages only', title: 'The full scan ran over budget, so only the OS packages and binaries were cataloged. Language packages may be missing.' },
};

/** "Cataloged on node (linux/arm64)": where a node SBOM came from. */
export function nodeSourceLabel(nc: NodeCatalogState | null | undefined): string {
  return nc?.platform ? `Cataloged on node (${nc.platform})` : 'Cataloged on node';
}

/** The completeness worth showing (partial or OS-only); null for full or unknown. */
export function completenessNote(nc: NodeCatalogState | null | undefined): { label: string; title: string } | null {
  const c = nc?.completeness;
  return c && Object.hasOwn(COMPLETENESS_LABEL, c) ? COMPLETENESS_LABEL[c] : null;
}

/** A source's label, with the node catalog's platform when known. */
export function provenanceLabel(source: string, nc?: NodeCatalogState | null): string {
  return source === 'node' ? nodeSourceLabel(nc) : sourceLabel(source);
}

export interface NotAssessable {
  reason: string;
  /** The reason's sentence. */
  copy: string;
  /** Nothing to retry: no node will find packages (`no_packages_found`). */
  terminal: boolean;
  /** When it is tried again, when it will be. */
  retry: string | null;
}

/**
 * "Not assessable": no source holds an SBOM for the image and the node
 * catalog has given up on it for now: nothing to catalog, a scan that
 * failed and backs off, or every node tried so far unable to read it.
 * A pending claim, or one released to another instance, is not this: it
 * is still being cataloged. Without `nodeCatalog` (older Broker, or no
 * node offered the digest) there is nothing to say.
 */
export function notAssessable(img: Pick<ImageSummary, 'sbomSources' | 'nodeCatalog'>): NotAssessable | null {
  const nc = img.nodeCatalog;
  if (!nc || (img.sbomSources?.length ?? 0) > 0) return null;
  const reason = nc.reason ?? '';
  if (nc.state === 'done' && reason === 'no_packages_found') return { reason, copy: reasonCopy(reason), terminal: true, retry: null };
  if (nc.state === 'failed') return { reason: reason || 'error', copy: reasonCopy(reason || 'error'), terminal: false, retry: 'Retried after a back-off.' };
  if (nc.state === 'pending' && PER_NODE_REASONS.has(reason)) return { reason, copy: reasonCopy(reason), terminal: false, retry: 'Other nodes may still catalog it; this node is retried after 24 hours.' };
  return null;
}

/** A node catalog still at work on an image with no node SBOM yet; null otherwise. */
export function catalogPending(img: Pick<ImageSummary, 'sbomSources' | 'nodeCatalog'>): { label: string; title: string } | null {
  const nc = img.nodeCatalog;
  if (!nc || img.sbomSources?.includes('node') || notAssessable(img)) return null;
  if (nc.state === 'claimed') return { label: 'Node catalog: cataloging', title: 'A node is cataloging this image now.' };
  if (nc.state === 'pending') {
    const last = nc.reason && RETRY_REASONS.has(nc.reason) ? ` Last attempt: ${reasonCopy(nc.reason)}` : '';
    return { label: 'Node catalog: pending', title: `Waiting for a node that runs this image to catalog it.${last}` };
  }
  return null;
}

// ── GET /catalog/coverage ────────────────────────────────────────────────

const sum = (m: Record<string, number> | undefined) => Object.values(m ?? {}).reduce((a, b) => a + (Number.isFinite(b) ? b : 0), 0);

/**
 * Whether the catalog is in use at all. A Broker whose catalog was never
 * enabled still answers `/catalog/coverage`, with no token, no claims and
 * no node that ever offered: that reads as "disabled", and the banner stays
 * hidden like it does for an older Broker (404) or a busy one (503).
 */
export function catalogInUse(c: CatalogCoverage): boolean {
  return c.tokenConfigured || sum(c.byState) > 0 || Object.keys(c.platforms ?? {}).length > 0;
}

export interface CoverageSummary {
  /** "12 of 20 running images have a trusted SBOM: 8 Trivy, 6 node" */
  headline: string;
  /** "3 pending, 2 failed" or null when neither. */
  queue: string | null;
  /** Reasons, most frequent first: "LSM denied 3, timed out 1". */
  reasons: Array<{ reason: string; label: string; count: number; copy: string }>;
  /** Operator-facing warnings (kill switch, missing token). */
  warnings: string[];
}

export function coverageSummary(c: CatalogCoverage): CoverageSummary {
  const n = (x: number) => (Number.isFinite(x) ? x : 0);
  const imgs = (x: number) => `${x} running image${x === 1 ? '' : 's'}`;
  const headline = `${n(c.trusted)} of ${imgs(n(c.runningImages))} ${n(c.runningImages) === 1 ? 'has' : 'have'} a trusted SBOM: ${n(c.trivy)} Trivy, ${n(c.node)} node`;
  const pending = n(c.byState?.pending ?? 0) + n(c.byState?.claimed ?? 0);
  const failed = n(c.byState?.failed ?? 0);
  const parts = [pending > 0 ? `${pending} pending` : null, failed > 0 ? `${failed} failed` : null].filter(Boolean);
  const reasons = Object.entries(c.byReason ?? {})
    .filter(([, count]) => n(count) > 0)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([reason, count]) => ({ reason, label: reasonShort(reason), count, copy: reasonCopy(reason) }));
  const warnings: string[] = [];
  if (!c.grantsEnabled) warnings.push('New node catalog grants are off (the kill switch, nodeCatalog.grants=false).');
  if (!c.tokenConfigured) warnings.push('The Broker has no catalog token, so node SBOMs cannot be stored.');
  return { headline, queue: parts.length ? parts.join(', ') : null, reasons, warnings };
}
