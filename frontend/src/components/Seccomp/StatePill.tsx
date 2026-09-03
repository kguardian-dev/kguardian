import type { CrStatus } from '../../utils/seccompCapture';

const STYLE: Record<CrStatus, { label: string; className: string; title: string }> = {
  none: {
    label: 'No CR',
    className: 'bg-hubble-border/40 text-secondary border-hubble-border',
    title: 'No SeccompProfile CR references this workload — nothing is on any node.',
  },
  audit: {
    label: 'Audit',
    className: 'bg-hubble-accent/15 text-hubble-accent border-hubble-accent/30',
    title: 'A SeccompProfile CR is deployed with SCMP_ACT_LOG — syscalls are logged, never blocked.',
  },
  enforcing: {
    label: 'Enforcing',
    className: 'bg-hubble-error/15 text-hubble-error border-hubble-error/30',
    title: 'The deployed SeccompProfile CR has a blocking defaultAction — unlisted syscalls fail.',
  },
};

/** CR status pill: derived purely from the mirrored CR's defaultAction. */
export function StatePill({ state }: { state: CrStatus }) {
  const s = STYLE[state];
  return (
    <span title={s.title} className={`shrink-0 rounded-full border px-2 py-0.5 text-xs font-medium ${s.className}`}>
      {s.label}
    </span>
  );
}
