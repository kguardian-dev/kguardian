import type { Change, CrRef, ImageDigestRow, NetworkPeer, NetworkRule, ProfileDiff } from '../types/profile';
import { fieldValue, shortDigest } from './posture';

/**
 * View-model helpers for the Workload Security Profile page, kept out of the
 * component files (fast refresh) and unit-tested on their own.
 */

export type ProfileTab = 'overview' | 'network' | 'syscalls' | 'images' | 'podSecurity' | 'versions';

export const PROFILE_TABS: readonly { id: ProfileTab; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'network', label: 'Network' },
  { id: 'syscalls', label: 'Syscalls' },
  { id: 'images', label: 'Image & packages' },
  { id: 'podSecurity', label: 'Pod security' },
  { id: 'versions', label: 'Versions' },
];

/** A `tab=` value from the URL; anything unrecognised is the Overview. */
export function parseTab(v: string | undefined): ProfileTab {
  return PROFILE_TABS.some((t) => t.id === v) ? (v as ProfileTab) : 'overview';
}

export function parseRevision(v: string | undefined): number | undefined {
  if (!v || !/^\d+$/.test(v)) return undefined;
  const n = Number(v);
  return n > 0 ? n : undefined;
}


/** Props for the panel belonging to the active tab. */
export function tabPanelProps(idPrefix: string, id: string) {
  return {
    role: 'tabpanel' as const,
    id: `${idPrefix}-panel-${id}`,
    'aria-labelledby': `${idPrefix}-tab-${id}`,
    tabIndex: 0,
  };
}

export type LineKind = 'add' | 'remove' | 'change';

export interface DiffLine {
  kind: LineKind;
  text: string;
}

const ruleText = (r: NetworkRule) => `${r.direction} ${r.protocol}/${r.port ?? '?'} ${r.peer}`;
const crText = (c: CrRef | null) => (c ? `${c.name} (${c.defaultAction})` : 'none');
const change = (label: string, c: Change): DiffLine => ({ kind: 'change', text: `${label}: ${fieldValue(c.from)} → ${fieldValue(c.to)}` });

/**
 * Flatten one dimension of a diff into lines. Exported for tests: the
 * contract's "unchanged scalar is null" rule means a null field emits no line.
 */
export function diffLines(diff: ProfileDiff): Record<'podSecurity' | 'images' | 'syscalls' | 'network', DiffLine[]> {
  const d = diff.dimensions;
  const ps: DiffLine[] = [];
  if (d.podSecurity.level) ps.push(change('PSS level', d.podSecurity.level));
  for (const f of d.podSecurity.pod) ps.push(change(`pod ${f.field}`, f));
  for (const c of d.podSecurity.containersAdded) ps.push({ kind: 'add', text: `container ${c}` });
  for (const c of d.podSecurity.containersRemoved) ps.push({ kind: 'remove', text: `container ${c}` });
  for (const c of d.podSecurity.containers) for (const f of c.fields) ps.push(change(`${c.name} ${f.field}`, f));

  const im: DiffLine[] = [];
  for (const c of d.images.containersAdded) im.push({ kind: 'add', text: `container ${c}` });
  for (const c of d.images.containersRemoved) im.push({ kind: 'remove', text: `container ${c}` });
  for (const c of d.images.containers) {
    for (const g of c.added) im.push({ kind: 'add', text: `${c.name} ${shortDigest(g)}` });
    for (const g of c.removed) im.push({ kind: 'remove', text: `${c.name} ${shortDigest(g)}` });
  }

  const sc: DiffLine[] = [];
  for (const s of d.syscalls.added) sc.push({ kind: 'add', text: s });
  for (const s of d.syscalls.removed) sc.push({ kind: 'remove', text: s });
  if (d.syscalls.captureLevel) sc.push(change('capture level', d.syscalls.captureLevel));
  if (d.syscalls.cr) sc.push({ kind: 'change', text: `SeccompProfile CR: ${crText(d.syscalls.cr.from)} → ${crText(d.syscalls.cr.to)}` });

  const nw: DiffLine[] = [];
  for (const r of d.network.added) nw.push({ kind: 'add', text: ruleText(r) });
  for (const r of d.network.removed) nw.push({ kind: 'remove', text: ruleText(r) });
  if (d.network.audited) nw.push(change('covered by audit policy', d.network.audited));

  return { podSecurity: ps, images: im, syscalls: sc, network: nw };
}


/**
 * What a digest row's state means, in words. `null` state is an older
 * Controller that does not report it — "unknown", not "running".
 */
export function digestStateLabel(r: ImageDigestRow, current: boolean): { text: string; tone: string } {
  if (r.ranAsInit) return { text: 'Ran as init (completed)', tone: 'text-secondary' };
  if (r.state === 'running') return { text: current ? 'Running' : 'Not running now', tone: current ? 'text-state-enforcing' : 'text-tertiary' };
  if (r.state === 'waiting') {
    const bad = r.stateReason === 'CrashLoopBackOff' || r.stateReason === 'ImagePullBackOff' || r.stateReason === 'ErrImagePull';
    return { text: `Waiting${r.stateReason ? `: ${r.stateReason}` : ''}`, tone: bad ? 'text-severity-medium' : 'text-secondary' };
  }
  if (r.state === 'terminated') return { text: `Terminated${r.stateReason ? `: ${r.stateReason}` : ''}`, tone: 'text-tertiary' };
  return { text: 'State unknown (older Controller)', tone: 'text-tertiary' };
}


export function peerLabel(p: NetworkPeer['peer']): { primary: string; secondary: string } {
  switch (p.kind) {
    case 'pod':
      return {
        primary: `${p.namespace ?? '?'}/${p.workloadName ?? p.name ?? p.ip ?? '?'}`,
        secondary: p.workloadKind ? `${p.workloadKind} · ${p.ip ?? ''}` : `pod · ${p.ip ?? ''}`,
      };
    case 'service':
      return { primary: `${p.namespace ?? '?'}/${p.name ?? p.ip ?? '?'}`, secondary: `Service · ${p.ip ?? ''}` };
    case 'node':
      return { primary: p.name ?? p.ip ?? 'node', secondary: `node · ${p.ip ?? ''}` };
    case 'external':
      return { primary: p.ip ?? 'external', secondary: 'external (outside the cluster)' };
    default:
      return { primary: p.ip ?? 'unresolved', secondary: 'in-cluster, identity not resolved' };
  }
}

