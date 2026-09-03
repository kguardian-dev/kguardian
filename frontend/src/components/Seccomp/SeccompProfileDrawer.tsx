import { useMemo, useState } from 'react';
import { AlertTriangle, Check, CheckCircle2, Copy, Download, FileCode, RefreshCw, RotateCcw, X } from 'lucide-react';
import type { SeccompApi } from '../../services/seccompApi';
import type { WorkloadProfileSummary } from '../../types/seccompWorkload';
import { CR_DEFAULT_ACTIONS } from '../../types/seccompWorkload';
import type { SeccompAction } from '../../types/seccompProfile';
import { useSeccompProfileDetail } from '../../hooks/useSeccompProfiles';
import { useSeccompProfileEditor, useSyscallAutocomplete } from '../../hooks/policyEditor';
import { crStatus, describePartialCapture, isBlockingAction, resolveCapture, securityContextSnippet } from '../../utils/seccompCapture';
import { allowedSyscalls, stagedEdits } from '../../utils/seccompCr';
import { Modal } from '../ui/Modal';
import { Button } from '../ui/Button';
import { Skeleton } from '../ui/Skeleton';
import { CaptureBadge } from './CaptureBadge';
import { PartialCaptureWarning } from './PartialCaptureWarning';
import { StatePill } from './StatePill';
import { ExportCrModal } from './ExportCrModal';
import { copyText } from '../../utils/clipboard';

interface SeccompProfileDrawerProps {
  api: SeccompApi;
  workload: { ns: string; kind: string; name: string };
  /** Row from the list, used until the detail loads. */
  summary: WorkloadProfileSummary | null;
  onClose: () => void;
}

const CR_NAME_RE = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

/**
 * One workload's seccomp picture, read-only: capture completeness (headline),
 * the deployed SeccompProfile CR's status and drift, the reference snippet,
 * and a local pre-export editor whose staged changes flow into "Export CR".
 * Nothing here writes cluster or broker state.
 */
export function SeccompProfileDrawer({ api, workload, summary, onClose }: SeccompProfileDrawerProps) {
  const { ns, kind, name } = workload;
  const { detail, loading, error, reload } = useSeccompProfileDetail(api, ns, kind, name);
  const current: WorkloadProfileSummary | null = detail ?? summary;

  const capture = useMemo(() => resolveCapture(current), [current]);
  const partial = describePartialCapture(capture);
  const status = current ? crStatus(current) : 'none';
  const cr = current?.cr ?? null;

  const [copied, setCopied] = useState(false);
  const [exporting, setExporting] = useState(false);

  // ── Pre-export editor (the pod-profile editor hook, seeded from the broker's
  //    observed profile; a reload re-seeds via the key).
  // When a CR is deployed, start from ITS defaultAction so an "updated CR"
  // export does not silently flip audit ↔ enforcing; otherwise the observed
  // profile's SCMP_ACT_LOG.
  const seed = useMemo(() => {
    if (!detail) return null;
    const action = (detail.cr?.defaultAction ?? detail.profile.defaultAction) as SeccompAction;
    return { key: `${ns}/${kind}/${name}:${detail.hash}:${detail.cr?.hash ?? ''}`, profile: { ...detail.profile, defaultAction: action } };
  }, [detail, ns, kind, name]);
  const { seccompProfile, resetProfile, updateDefaultAction, addSyscallToRule, removeSyscallFromRule, addSyscallRule, syscallErrors, clearSyscallError } =
    useSeccompProfileEditor({ pod: null, isOpen: true, seed });
  const autocomplete = useSyscallAutocomplete();

  // Name/note are keyed to the loaded profile (derived, not synced via an effect).
  const seedKey = seed?.key ?? null;
  const [nameEdit, setNameEdit] = useState<{ key: string | null; value: string }>({ key: null, value: '' });
  const [noteEdit, setNoteEdit] = useState<{ key: string | null; value: string }>({ key: null, value: '' });
  const suggested = cr?.name ?? current?.suggestedName ?? `${kind.toLowerCase()}-${name}`;
  const crName = nameEdit.key === seedKey ? nameEdit.value : suggested;
  const note = noteEdit.key === seedKey ? noteEdit.value : '';
  const crNameValid = CR_NAME_RE.test(crName);

  const observed = useMemo(() => (detail ? allowedSyscalls(detail.profile) : new Set<string>()), [detail]);
  const effective = useMemo(() => allowedSyscalls(seccompProfile), [seccompProfile]);
  const edits = useMemo(
    () => (detail && seccompProfile ? stagedEdits(detail.profile, seccompProfile, note) : null),
    [detail, seccompProfile, note],
  );
  const kept = useMemo(() => [...observed].filter((n) => effective.has(n)).sort(), [observed, effective]);
  const dirty = Boolean(edits && (edits.added.length || edits.removed.length || edits.defaultAction !== seed?.profile.defaultAction || edits.note));

  const allowRuleIndex = seccompProfile?.syscalls?.findIndex((r) => r.action === 'SCMP_ACT_ALLOW') ?? -1;
  const addName = (raw: string): boolean => {
    if (!seccompProfile) return false;
    let idx = allowRuleIndex;
    if (idx < 0) {
      addSyscallRule();
      idx = seccompProfile.syscalls?.length ?? 0;
    }
    return addSyscallToRule(idx, raw);
  };
  const removeName = (n: string) => {
    seccompProfile?.syscalls?.forEach((rule, ri) => {
      if (rule.action !== 'SCMP_ACT_ALLOW') return;
      const si = rule.names.indexOf(n);
      if (si >= 0) removeSyscallFromRule(ri, si);
    });
  };
  const resetAll = () => {
    resetProfile();
    setNameEdit({ key: null, value: '' });
    setNoteEdit({ key: null, value: '' });
  };

  const copySnippet = async () => {
    if (!current) return;
    if (await copyText(securityContextSnippet(current))) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const exportLabel = cr && !cr.drift.inSync ? 'Export updated CR' : 'Export CR';

  return (
    <Modal
      isOpen
      onClose={onClose}
      size="xl"
      title={
        <span className="flex items-center gap-2">
          <span className="font-mono">{name}</span>
          {current && <StatePill state={status} />}
          {current && <CaptureBadge capture={capture} />}
        </span>
      }
      subtitle={`${kind} · ${ns}`}
      contentClassName="flex-1 min-h-0 overflow-y-auto"
      className="h-[88vh]"
    >
      <div className="px-5 py-4 space-y-4">
        {error && (
          <div role="alert" className="rounded-surface border border-hubble-error/40 bg-hubble-error/10 px-4 py-3 text-sm text-hubble-error">
            {error}
          </div>
        )}

        {/* The headline: unmistakable partial-capture warning. */}
        <PartialCaptureWarning capture={capture} />

        {/* CR status */}
        {current ? (
          <section className="rounded-surface border border-hubble-border bg-hubble-dark px-4 py-3 space-y-2" aria-label="SeccompProfile CR status">
            {cr ? (
              <>
                <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
                  <span className="text-tertiary">SeccompProfile CR</span>
                  <span className="font-mono text-primary">{cr.name}</span>
                  <StatePill state={status} />
                  <span className="font-mono tabular-nums text-secondary">{cr.defaultAction}</span>
                  <span className="text-secondary">
                    nodes <span className={`font-mono tabular-nums ${cr.distribution.state === 'Ready' ? 'text-hubble-success' : cr.distribution.state === 'Partial' ? 'text-hubble-warning' : 'text-tertiary'}`}>{cr.distribution.ready}/{cr.distribution.total}</span>{' '}
                    <span className="text-tertiary">{cr.distribution.state}</span>
                  </span>
                  <span className="text-secondary">
                    syscalls <span className="font-mono tabular-nums">{cr.syscallCount}</span>
                  </span>
                  {current.crCount && current.crCount > 1 && (
                    <span className="text-hubble-warning">{current.crCount} CRs reference this workload — showing the newest</span>
                  )}
                </div>
                {cr.drift.inSync ? (
                  <p className="flex items-center gap-1.5 text-xs text-hubble-success">
                    <CheckCircle2 className="w-3.5 h-3.5" /> In sync — every observed syscall is in the CR.
                  </p>
                ) : (
                  <div className="flex items-start gap-2 rounded-control border border-hubble-warning/40 bg-hubble-warning/10 px-3 py-2 text-xs" role="status">
                    <AlertTriangle className="w-3.5 h-3.5 text-hubble-warning shrink-0 mt-0.5" />
                    <div className="min-w-0 flex-1 space-y-1">
                      {cr.drift.missing.length > 0 && (
                        <p className="text-secondary">
                          <span className="font-medium text-hubble-warning">{cr.drift.missing.length} observed syscall{cr.drift.missing.length === 1 ? '' : 's'} not in your CR</span>
                          {isBlockingAction(cr.defaultAction) && <span className="text-hubble-error"> (blocked while enforcing)</span>}:{' '}
                          <span className="font-mono text-primary">{cr.drift.missing.join(', ')}</span>
                        </p>
                      )}
                      {cr.drift.extra.length > 0 && (
                        <p className="text-tertiary">
                          {cr.drift.extra.length} CR syscall{cr.drift.extra.length === 1 ? '' : 's'} never observed: <span className="font-mono">{cr.drift.extra.join(', ')}</span>
                        </p>
                      )}
                    </div>
                    <Button variant="secondary" size="sm" leftIcon={FileCode} onClick={() => setExporting(true)} disabled={!detail || !seccompProfile}>
                      Export updated CR
                    </Button>
                  </div>
                )}
              </>
            ) : (
              <p className="text-xs text-secondary">
                <span className="font-medium text-primary">No SeccompProfile deployed.</span> Export the CR below, commit it, apply it, and reference the
                path in your pod template. kguardian writes the node file from the CR and reports readiness and drift here.
              </p>
            )}
            <div className="flex items-start gap-2">
              <pre className="flex-1 text-[11px] font-mono text-tertiary bg-hubble-card border border-hubble-border rounded-control px-3 py-2 overflow-x-auto">
                {securityContextSnippet(current)}
              </pre>
              <Button variant="ghost" size="sm" leftIcon={copied ? Check : Copy} onClick={() => void copySnippet()} title="Copy the securityContext fragment">
                {copied ? 'Copied' : 'Copy'}
              </Button>
            </div>
          </section>
        ) : (
          <Skeleton className="h-20 w-full" />
        )}

        {/* Actions */}
        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant={partial ? 'danger' : 'primary'}
            size="sm"
            leftIcon={partial ? AlertTriangle : Download}
            onClick={() => setExporting(true)}
            disabled={!detail || !seccompProfile || !crNameValid}
            title={partial ? `${partial.title}. The exported profile will block syscalls the app uses.` : 'Render the SeccompProfile CR manifest'}
          >
            {partial ? `${exportLabel} anyway` : exportLabel}
          </Button>
          <Button variant="ghost" size="sm" iconOnly leftIcon={RefreshCw} onClick={() => void reload()} aria-label="Reload" title="Reload" disabled={loading} className={loading ? '[&_svg]:animate-spin' : ''} />
          <span className="text-xs text-tertiary">
            Observed <span className="font-mono tabular-nums text-secondary">{current?.syscallCount ?? '—'}</span> syscalls
            {current?.architectures && current.architectures.length > 0 && <> · {current.architectures.map((a) => a.replace('SCMP_ARCH_', '')).join(', ')}</>}
            {current?.hash && <> · <span className="font-mono">{current.hash.slice(0, 12)}</span></>}
          </span>
        </div>

        {/* Pre-export editor */}
        <section className="rounded-surface border border-hubble-border bg-hubble-card overflow-hidden">
          <header className="flex items-center justify-between gap-3 px-4 py-3 border-b border-hubble-border">
            <div>
              <h3 className="text-sm font-semibold text-primary">Before you export</h3>
              <p className="text-[11px] text-tertiary">Local edits only — they shape the manifest you export and commit. The observed set underneath is never changed.</p>
            </div>
            <Button variant="ghost" size="sm" leftIcon={RotateCcw} onClick={resetAll} disabled={!dirty && nameEdit.key !== seedKey}>
              Reset
            </Button>
          </header>

          {!detail || !seccompProfile ? (
            <div className="space-y-2 p-4">
              <Skeleton className="h-6 w-1/3" />
              <Skeleton className="h-16 w-full" />
            </div>
          ) : (
            <div className="p-4 space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <label className="block text-xs">
                  <span className="text-tertiary">CR name</span>
                  <input
                    value={crName}
                    onChange={(e) => setNameEdit({ key: seedKey, value: e.target.value })}
                    aria-invalid={!crNameValid}
                    className={`mt-1 w-full bg-hubble-dark text-primary px-3 py-2 rounded-control border focus:outline-none focus:ring-2 focus:ring-hubble-accent text-sm font-mono ${crNameValid ? 'border-hubble-border' : 'border-hubble-error'}`}
                  />
                  <span className="mt-1 block text-tertiary">{crNameValid ? `Node file: kguardian/${ns}/${crName}.json` : 'DNS-1123: lowercase letters, digits, dashes.'}</span>
                </label>
                <label className="block text-xs">
                  <span className="text-tertiary">Default action for unlisted syscalls</span>
                  <select
                    value={seccompProfile.defaultAction}
                    onChange={(e) => updateDefaultAction(e.target.value as SeccompAction)}
                    className="mt-1 w-full bg-hubble-dark text-primary px-3 py-2 rounded-control border border-hubble-border focus:outline-none focus:ring-2 focus:ring-hubble-accent text-sm font-mono"
                  >
                    {CR_DEFAULT_ACTIONS.map((a) => (
                      <option key={a} value={a}>
                        {a}
                      </option>
                    ))}
                  </select>
                  <span className="mt-1 block text-tertiary">
                    {isBlockingAction(seccompProfile.defaultAction)
                      ? 'Blocks: a syscall the app makes but kguardian has not observed fails on the next restart.'
                      : 'Audit: allow and log. Start here; promote to SCMP_ACT_ERRNO by editing the CR in git.'}
                  </span>
                </label>
                <label className="block text-xs">
                  <span className="text-tertiary">Note (emitted as a comment)</span>
                  <textarea
                    value={note}
                    onChange={(e) => setNoteEdit({ key: seedKey, value: e.target.value })}
                    rows={3}
                    placeholder="Why this profile differs from observed…"
                    className="mt-1 w-full bg-hubble-dark text-primary px-3 py-2 rounded-control border border-hubble-border focus:outline-none focus:ring-2 focus:ring-hubble-accent text-sm"
                  />
                </label>
              </div>

              <div className="text-xs text-secondary">
                Observed <span className="font-mono tabular-nums text-primary">{observed.size}</span> · Export{' '}
                <span className="font-mono tabular-nums text-primary">{effective.size}</span>
                {edits && edits.added.length > 0 && <span className="text-hubble-success"> · +{edits.added.length} added</span>}
                {edits && edits.removed.length > 0 && <span className="text-hubble-error"> · −{edits.removed.length} removed</span>}
              </div>

              {/* Add */}
              <div className="relative">
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    placeholder="Add a syscall the app needs (e.g. clock_settime)…"
                    value={autocomplete.syscallInputValues[0] || ''}
                    onChange={(e) => {
                      autocomplete.handleInputChange(0, e.target.value);
                      clearSyscallError(allowRuleIndex);
                    }}
                    onKeyDown={(e) =>
                      autocomplete.handleKeyDown(0, e, (s) => {
                        if (addName(s)) autocomplete.clearInput(0);
                      })
                    }
                    aria-label="Add syscall"
                    className={`w-full max-w-md bg-hubble-dark text-primary px-3 py-2 rounded-control border text-sm font-mono focus:outline-none focus:ring-2 focus:ring-hubble-accent ${
                      syscallErrors[allowRuleIndex] ? 'border-hubble-error' : 'border-hubble-border'
                    }`}
                  />
                  <span className="text-[11px] text-tertiary">↑↓ navigate · Enter to add</span>
                </div>
                {autocomplete.syscallSuggestions[0]?.length > 0 && (
                  <div className="absolute z-10 mt-1 w-full max-w-md bg-hubble-dark border border-hubble-border rounded-control shadow-lg max-h-48 overflow-y-auto">
                    {autocomplete.syscallSuggestions[0].map((s, i) => (
                      <button
                        key={s}
                        type="button"
                        onClick={() => {
                          if (addName(s)) autocomplete.clearInput(0);
                        }}
                        className={`w-full text-left px-3 py-1.5 text-xs font-mono hover:bg-hubble-card transition-colors ${
                          (autocomplete.activeSuggestionIndex[0] ?? -1) === i ? 'bg-hubble-accent text-white' : 'text-secondary'
                        }`}
                      >
                        {s}
                      </button>
                    ))}
                  </div>
                )}
                {syscallErrors[allowRuleIndex] && <p className="mt-1 text-xs text-hubble-error">{syscallErrors[allowRuleIndex]}</p>}
              </div>

              {/* Diff view */}
              <div className="space-y-3">
                {edits && edits.added.length > 0 && (
                  <ChipGroup label="Added (not observed)" tone="success">
                    {edits.added.map((n) => (
                      <Chip key={n} name={n} onRemove={() => removeName(n)} removeTitle="Un-add" />
                    ))}
                  </ChipGroup>
                )}
                {edits && edits.removed.length > 0 && (
                  <ChipGroup label="Removed (observed, but left out of the export)" tone="error">
                    {edits.removed.map((n) => (
                      <Chip key={n} name={n} onRestore={() => addName(n)} />
                    ))}
                  </ChipGroup>
                )}
                <ChipGroup label={`Observed & exported (${kept.length})`} tone="neutral">
                  {kept.map((n) => (
                    <Chip key={n} name={n} onRemove={() => removeName(n)} removeTitle="Leave out of the export" />
                  ))}
                </ChipGroup>
              </div>
            </div>
          )}
        </section>
      </div>

      {exporting && detail && seccompProfile && edits && (
        <ExportCrModal api={api} detail={detail} edited={seccompProfile} crName={crName} edits={edits} capture={capture} onClose={() => setExporting(false)} />
      )}
    </Modal>
  );
}

function ChipGroup({ label, tone, children }: { label: string; tone: 'success' | 'error' | 'neutral'; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[11px] text-tertiary mb-1.5">{label}</div>
      <div className="flex flex-wrap gap-1.5" data-tone={tone}>
        {children}
      </div>
    </div>
  );
}

function Chip({ name, onRemove, onRestore, removeTitle }: { name: string; onRemove?: () => void; onRestore?: () => void; removeTitle?: string }) {
  return (
    <span className="inline-flex items-center gap-1 rounded border border-hubble-border bg-hubble-dark px-1.5 py-0.5 text-[11px] font-mono text-secondary [[data-tone=success]_&]:border-hubble-success/40 [[data-tone=success]_&]:text-hubble-success [[data-tone=error]_&]:border-hubble-error/40 [[data-tone=error]_&]:text-hubble-error [[data-tone=error]_&]:line-through">
      {name}
      {onRemove && (
        <button onClick={onRemove} title={removeTitle} aria-label={`${removeTitle ?? 'Remove'} ${name}`} className="opacity-60 hover:opacity-100">
          <X className="w-3 h-3" />
        </button>
      )}
      {onRestore && (
        <button onClick={onRestore} title="Restore" aria-label={`Restore ${name}`} className="opacity-60 hover:opacity-100">
          <RotateCcw className="w-3 h-3" />
        </button>
      )}
    </span>
  );
}
