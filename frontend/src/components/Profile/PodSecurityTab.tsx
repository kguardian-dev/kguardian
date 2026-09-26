import { FileCode, ShieldCheck, UserCog } from 'lucide-react';
import type { FailingCheck, PodSecurityDimension } from '../../types/profile';
import { asStatus, fieldValue, pssLevelText, shortDigest } from '../../utils/posture';
import { CopyButton } from '../ui/CopyButton';
import { EmptyState } from '../ui/EmptyState';
import { Fact, Panel, Reasons, ScoredStatus } from './parts';

const LEVEL_TONE: Record<string, string> = {
  privileged: 'text-severity-critical',
  baseline: 'text-severity-medium',
  restricted: 'text-state-enforcing',
};

function tone(level: string | null): string {
  return level && Object.hasOwn(LEVEL_TONE, level) ? LEVEL_TONE[level] : 'text-tertiary';
}

function FailingList({ failing }: { failing: FailingCheck[] }) {
  return (
    <ul className="space-y-1.5">
      {failing.map((f) => (
        <li key={`${f.check}-${f.field}`} className="text-xs">
          <div className="flex flex-wrap items-baseline gap-2">
            <span className={`rounded-md border px-1.5 py-px text-[11px] ${f.level === 'baseline' ? 'bg-severity-critical/10 text-severity-critical border-severity-critical/30' : 'bg-severity-medium/10 text-severity-medium border-severity-medium/30'}`}>
              {f.level}
            </span>
            <span className="text-primary">{f.message}</span>
          </div>
          <div className="mt-0.5 font-mono text-[11px] text-tertiary [overflow-wrap:anywhere]">
            {f.field} = {fieldValue(f.value)}
          </div>
        </li>
      ))}
    </ul>
  );
}

export function PodSecurityTab({ dim }: { dim: PodSecurityDimension }) {
  const status = asStatus(dim.status);
  if (dim.level === null && dim.containers.length === 0) {
    return (
      <Panel icon={ShieldCheck} title="Pod Security Standards" action={<ScoredStatus status={status} score={dim.score} />}>
        <EmptyState
          icon={ShieldCheck}
          compact
          title="No securityContext reported yet"
          description="The level is computed from each container's securityContext, which the Controller reports with the pod spec. Nothing has arrived for this workload."
        />
      </Panel>
    );
  }
  const pod = dim.pod;
  return (
    <div className="space-y-4">
      <Panel icon={ShieldCheck} title="Pod Security Standards" hint={dim.pssVersion} action={<ScoredStatus status={status} score={dim.score} />}>
        <div className="px-4 py-3 space-y-3">
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <span className="text-[11px] uppercase tracking-wide text-tertiary">Level</span>
            <span className={`text-lg font-semibold ${tone(dim.level)}`} data-testid="pss-level">
              {pssLevelText(dim.level, dim.levelConfidence)}
            </span>
            {dim.levelConfidence === 'upper_bound' && (
              <span className="text-xs text-tertiary">unverified: {dim.unevaluatedChecks.length} checks kguardian cannot see</span>
            )}
          </div>
          <Reasons reasons={dim.reasons} />
          {dim.unevaluatedChecks.length > 0 && (
            <details className="text-xs">
              <summary className="cursor-pointer text-secondary hover:text-primary">Checks not evaluated ({dim.unevaluatedChecks.length})</summary>
              <p className="mt-1 font-mono text-tertiary [overflow-wrap:anywhere]">{dim.unevaluatedChecks.join(', ')}</p>
              <p className="mt-1 text-tertiary">{dim.coverage.note}</p>
            </details>
          )}
          {pod && (
            <dl className="divide-y divide-hubble-border">
              <Fact label="ServiceAccount"><span className="font-mono">{pod.serviceAccountName ?? 'unset'}</span></Fact>
              <Fact label="automountServiceAccountToken">
                <span className="font-mono">{pod.automountServiceAccountToken === null ? 'unset (token assumed mounted)' : String(pod.automountServiceAccountToken)}</span>
              </Fact>
              <Fact label="hostNetwork / hostPID / hostIPC">
                <span className="font-mono">{[pod.hostNetwork, pod.hostPID, pod.hostIPC].map(fieldValue).join(' / ')}</span>
              </Fact>
              <Fact label="Pod runAsNonRoot / runAsUser">
                <span className="font-mono">{fieldValue(pod.securityContext.runAsNonRoot)} / {fieldValue(pod.securityContext.runAsUser)}</span>
              </Fact>
              <Fact label="Pod seccompProfile"><span className="font-mono">{fieldValue(pod.securityContext.seccompProfileType)}</span></Fact>
            </dl>
          )}
          {pod && pod.failing.length > 0 && (
            <div data-testid="pss-pod-failing">
              <p className="text-[11px] uppercase tracking-wide text-tertiary mb-1">Pod-level failing checks</p>
              <FailingList failing={pod.failing} />
            </div>
          )}
        </div>
      </Panel>

      <Panel icon={UserCog} title="Containers" hint="Failing checks per container. Values are exactly what the Controller reported; unset means not set in the spec.">
        <ul className="divide-y divide-hubble-border">
          {dim.containers.map((c) => (
            <li key={`${c.kind}-${c.name}`} className="px-4 py-3" data-testid="pss-container">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <div className="flex flex-wrap items-baseline gap-2">
                  <span className="font-mono text-sm text-primary">{c.name}</span>
                  <span className="text-[11px] text-tertiary">
                    {c.kind} · {c.source === 'running' ? 'running' : 'last known'} · <span className="font-mono" title={c.digest}>{shortDigest(c.digest)}</span>
                  </span>
                </div>
                <span className={`text-xs font-medium ${tone(c.level)}`}>{c.level ? c.level : 'No data'}</span>
              </div>
              {c.failing.length === 0 ? (
                <p className="mt-1.5 text-xs text-secondary">Passes every evaluated check.</p>
              ) : (
                <div className="mt-2"><FailingList failing={c.failing} /></div>
              )}
            </li>
          ))}
        </ul>
      </Panel>

      <Panel
        icon={FileCode}
        title="Recommended securityContext patch"
        hint="A recommendation. kguardian never applies it: review it, commit it, apply it yourself."
        action={dim.recommendation ? <CopyButton text={dim.recommendation.yaml} label="Copy patch" ariaLabel="Copy securityContext patch" /> : undefined}
      >
        {dim.recommendation ? (
          <div className="px-4 py-3 space-y-3">
            <p className="text-xs text-secondary">
              <span className="rounded-full border px-2 py-0.5 text-[11px] font-medium bg-state-audit/15 text-state-audit border-state-audit/30 mr-2">Recommendation</span>
              Target <span className="font-mono">{dim.recommendation.targetLevel}</span> · {dim.recommendation.format}
            </p>
            <pre className="text-xs font-mono leading-relaxed bg-hubble-darker border border-hubble-border rounded-control p-3 overflow-x-auto text-secondary" data-testid="pss-patch">
              {dim.recommendation.yaml}
            </pre>
            {dim.recommendation.caveats.length > 0 && (
              <ul className="space-y-1 text-xs text-tertiary list-disc pl-4">
                {dim.recommendation.caveats.map((c) => <li key={c}>{c}</li>)}
              </ul>
            )}
          </div>
        ) : (
          <p className="px-4 py-3 text-xs text-secondary">No patch: every evaluated check already passes restricted. Checks kguardian cannot see may still fail.</p>
        )}
      </Panel>
    </div>
  );
}
