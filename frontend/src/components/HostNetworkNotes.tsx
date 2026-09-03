import { AlertTriangle, Server } from 'lucide-react';

// Read-only affordances for the host-network shapes the generators emit.
// A host-network peer is rendered as an ipBlock (standard) or an entities
// list (Cilium) plus a comment explaining why; a host-network TARGET gets a
// leading warning block. None of these are user-editable in the visual
// editor — they mirror what the YAML view shows.

/** The `# WARNING:` block a policy carries when its target is host-network. */
export function HostNetworkWarningBanner({ warnings }: { warnings?: string[] }) {
  if (!warnings || warnings.length === 0) return null;
  return (
    <div
      role="alert"
      className="mx-6 mt-4 flex items-start gap-3 rounded-surface border border-hubble-warning/40 bg-hubble-warning/10 px-4 py-3"
    >
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-hubble-warning" />
      <div className="space-y-0.5 text-xs text-secondary">
        {warnings.map((line) => (
          <p key={line} className={line.startsWith('WARNING:') ? 'font-semibold text-primary' : ''}>
            {line}
          </p>
        ))}
      </div>
    </div>
  );
}

/** `# ...` comment lines attached to one rule (host-network peer notes). */
export function RuleComments({ comments }: { comments?: string[] }) {
  if (!comments || comments.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-1.5">
      {comments.map((c) => (
        <span
          key={c}
          title="Emitted as a YAML comment above this rule"
          className="inline-flex items-center gap-1 rounded-control border border-hubble-warning/40 bg-hubble-warning/10 px-2 py-0.5 text-[11px] text-secondary"
        >
          <Server className="h-3 w-3 text-hubble-warning" />
          {c}
        </span>
      ))}
    </div>
  );
}

/** Cilium `fromEntities` / `toEntities` — shown as read-only chips. */
export function EntitiesPeer({ label, entities }: { label: string; entities?: string[] }) {
  if (!entities || entities.length === 0) return null;
  return (
    <div>
      <label className="mb-2 block text-xs font-medium text-secondary">{label}</label>
      <div className="flex flex-wrap gap-1.5">
        {entities.map((e) => (
          <span
            key={e}
            title="Cilium entity — node identity, not a pod label; edit in the YAML view"
            className="rounded-control border border-hubble-border bg-hubble-dark px-2 py-0.5 font-mono text-[11px] text-secondary"
          >
            {e}
          </span>
        ))}
      </div>
    </div>
  );
}
