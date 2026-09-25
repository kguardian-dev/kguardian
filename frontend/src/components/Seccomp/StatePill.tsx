import { Lock } from 'lucide-react';
import type { CrStatus } from '../../utils/seccompCapture';

/**
 * Lifecycle vocabulary for a control: none → audit → enforcing. Enforcing is
 * the GOOD end state, so it is drawn in the posture green with a lock — never
 * in the red that the severity scale reserves for "critical".
 */
const STATE_PILL: Record<CrStatus, { label: string; className: string; title: string }> = {
  none: {
    label: 'No CR',
    className: 'bg-hubble-border/40 text-secondary border-hubble-border',
    title: 'No SeccompProfile CR references this workload — nothing is on any node.',
  },
  audit: {
    label: 'Audit',
    className: 'bg-state-audit/15 text-state-audit border-state-audit/30',
    title: 'A SeccompProfile CR is deployed with SCMP_ACT_LOG — syscalls are logged, never blocked.',
  },
  enforcing: {
    label: 'Enforcing',
    className: 'bg-state-enforcing/15 text-state-enforcing border-state-enforcing/30',
    title: 'The deployed SeccompProfile CR has a blocking defaultAction — unlisted syscalls fail.',
  },
};

/** CR status pill: derived purely from the mirrored CR's defaultAction. */
export function StatePill({ state }: { state: CrStatus }) {
  const s = STATE_PILL[state];
  return (
    <span
      title={s.title}
      className={`inline-flex items-center gap-1 shrink-0 rounded-full border px-2 py-0.5 text-xs font-medium ${s.className}`}
    >
      {state === 'enforcing' && <Lock className="w-3 h-3" aria-hidden />}
      {s.label}
    </span>
  );
}
