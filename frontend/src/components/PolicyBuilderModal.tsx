import { useMemo, useRef, useState } from 'react';
import { FileCode, Search, Server, Network, Activity, ChevronRight, Boxes } from 'lucide-react';
import type { PodNodeData } from '../types';
import { Modal } from './ui/Modal';
import { EmptyState } from './ui/EmptyState';
import NetworkPolicyEditor from './NetworkPolicyEditor';
import type { PolicyType } from '../hooks/policyEditor';

interface PolicyBuilderModalProps {
  onClose: () => void;
  /** Non-external workloads that can have a policy generated. */
  workloads: PodNodeData[];
  /** Pre-selected workload (contextual "Build Policy") — skips the picker. */
  initialPod: PodNodeData | null;
  /** Tab to open on (a finding's "Policy" action picks the relevant one). */
  initialPolicyType?: PolicyType;
}

function label(pod: PodNodeData): string {
  return pod.label || pod.pod.pod_identity || pod.pod.pod_name;
}

function syscallCount(pod: PodNodeData): number {
  return (pod.syscalls ?? []).reduce((total, r) => total + r.syscalls.split(',').filter((s) => s.trim()).length, 0);
}

/**
 * Entry point for policy authoring. Contextual "Build Policy" buttons pass the
 * workload directly (initialPod) and go straight to the editor. The rail's
 * Policy Builder opens it with no workload, so it first shows a searchable
 * picker — a workload-first path to the same editor, rather than requiring you
 * to find the node on the map. The heavy editor stays behind this lazy chunk.
 */
export function PolicyBuilderModal({ onClose, workloads, initialPod, initialPolicyType }: PolicyBuilderModalProps) {
  const [chosen, setChosen] = useState<PodNodeData | null>(initialPod);

  if (chosen) {
    return <NetworkPolicyEditor isOpen onClose={onClose} pod={chosen} allPods={workloads} initialPolicyType={initialPolicyType} />;
  }
  return <WorkloadPicker workloads={workloads} onPick={setChosen} onClose={onClose} />;
}

function WorkloadPicker({
  workloads,
  onPick,
  onClose,
}: {
  workloads: PodNodeData[];
  onPick: (pod: PodNodeData) => void;
  onClose: () => void;
}) {
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  const listRef = useRef<HTMLUListElement>(null);

  const matches = useMemo(() => {
    const q = query.trim().toLowerCase();
    const sorted = [...workloads].sort((a, b) => label(a).localeCompare(label(b)));
    if (!q) return sorted;
    return sorted.filter((p) => {
      const ns = p.pod.pod_namespace ?? '';
      return label(p).toLowerCase().includes(q) || ns.toLowerCase().includes(q);
    });
  }, [workloads, query]);

  const clampedActive = Math.min(active, Math.max(0, matches.length - 1));

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActive((a) => Math.min(a + 1, matches.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActive((a) => Math.max(a - 1, 0));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const pod = matches[clampedActive];
      if (pod) onPick(pod);
    }
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title="Policy Builder"
      subtitle="Pick a workload to generate a policy from its observed traffic & syscalls"
      size="lg"
      contentClassName="flex-1 min-h-0 flex flex-col"
    >
      <div className="px-4 pt-3 pb-2 shrink-0">
        <div className="flex items-center gap-2 h-9 px-3 rounded-control border border-hubble-border bg-hubble-darker focus-within:border-hubble-accent">
          <Search className="w-4 h-4 text-tertiary shrink-0" />
          <input
            autoFocus
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setActive(0);
            }}
            onKeyDown={onKeyDown}
            placeholder="Search workloads by name or namespace…"
            className="flex-1 bg-transparent text-sm text-primary placeholder:text-tertiary focus:outline-none"
          />
          <span className="text-[11px] text-tertiary tabular-nums shrink-0">{matches.length}</span>
        </div>
      </div>

      {matches.length === 0 ? (
        <EmptyState
          icon={Server}
          title={query ? 'No matching workloads' : 'No workloads in this namespace'}
          description={query ? 'Try a different search term.' : 'Switch namespaces to find a workload to build a policy for.'}
          compact
        />
      ) : (
        <ul ref={listRef} className="flex-1 min-h-0 overflow-y-auto px-2 pb-2">
          {matches.map((pod, i) => {
            const ns = pod.pod.pod_namespace ?? 'default';
            const conns = pod.traffic?.length ?? 0;
            const sys = syscallCount(pod);
            return (
              <li key={pod.id}>
                <button
                  onClick={() => onPick(pod)}
                  onMouseEnter={() => setActive(i)}
                  className={`w-full flex items-center gap-3 px-2.5 py-2 rounded-control text-left transition-colors ${
                    i === clampedActive ? 'bg-hubble-accent/15' : 'hover:bg-hubble-hover'
                  }`}
                >
                  <span className="grid place-items-center w-8 h-8 shrink-0 rounded-control bg-hubble-accent/10 text-hubble-accent">
                    <Server className="w-4 h-4" />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block text-sm font-medium text-primary truncate">{label(pod)}</span>
                    <span className="flex items-center gap-3 text-[11px] text-tertiary">
                      <span className="flex items-center gap-1"><Boxes className="w-3 h-3" />{ns}</span>
                      <span className="flex items-center gap-1"><Network className="w-3 h-3" />{conns} conns</span>
                      {sys > 0 && <span className="flex items-center gap-1"><Activity className="w-3 h-3" />{sys} syscalls</span>}
                    </span>
                  </span>
                  <FileCode className="w-4 h-4 shrink-0 text-tertiary" />
                  <ChevronRight className="w-4 h-4 shrink-0 text-tertiary" />
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </Modal>
  );
}
