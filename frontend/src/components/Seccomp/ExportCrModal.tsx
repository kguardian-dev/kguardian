import { useEffect, useMemo, useState } from 'react';
import { Check, Copy, Download, FileCode, RefreshCw } from 'lucide-react';
import { SeccompApiError, type SeccompApi } from '../../services/seccompApi';
import { describeSeccompError } from '../../hooks/useSeccompProfiles';
import type { SeccompProfile } from '../../types/seccompProfile';
import type { CaptureInfo, WorkloadProfileDetail } from '../../types/seccompWorkload';
import { allowedSyscalls, buildExportYaml, crSyscalls, diffSyscalls, hasStagedSyscallEdits, renderEditedExportLocally, type StagedEdits } from '../../utils/seccompCr';
import { describePartialCapture } from '../../utils/seccompCapture';
import { Modal } from '../ui/Modal';
import { Button } from '../ui/Button';
import { Skeleton } from '../ui/Skeleton';
import { PartialCaptureWarning } from './PartialCaptureWarning';
import { copyText } from '../../utils/clipboard';

interface ExportCrModalProps {
  api: SeccompApi;
  detail: WorkloadProfileDetail;
  /** The (possibly edited) profile the export should reflect. */
  edited: SeccompProfile;
  crName: string;
  edits: StagedEdits;
  capture: CaptureInfo;
  onClose: () => void;
}

function download(filename: string, content: string) {
  const blob = new Blob([content], { type: 'text/yaml' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * The one way a profile leaves the UI: a `SeccompProfile` CR manifest the
 * user commits and applies. Fetches the broker's export (source of truth,
 * with its capture comment block), re-renders it locally when edits are
 * staged, and — when a CR is already deployed — shows what applying this
 * manifest changes versus it.
 */
export function ExportCrModal({ api, detail, edited, crName, edits, capture, onClose }: ExportCrModalProps) {
  const [rendered, setRendered] = useState<{ yaml: string; localFallback: boolean } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const partial = describePartialCapture(capture);

  const { namespace, kind, name } = detail;
  const { added, removed } = edits;
  const withEdits = hasStagedSyscallEdits(edits);
  useEffect(() => {
    let cancelled = false;
    const params = { name: crName, defaultAction: edited.defaultAction };
    const run = async () => {
      if (!withEdits) return { yaml: await api.exportProfile(namespace, kind, name, params), localFallback: false };
      try {
        return { yaml: await api.exportEdited(namespace, kind, name, { ...params, add: added, remove: removed }), localFallback: false };
      } catch (e) {
        // Older broker without POST /export: render the edits locally under its header.
        if (e instanceof SeccompApiError && (e.status === 404 || e.status === 405)) {
          const brokerYaml = await api.exportProfile(namespace, kind, name, params);
          return { yaml: renderEditedExportLocally({ brokerYaml, detail, edited, crName, edits }), localFallback: true };
        }
        throw e;
      }
    };
    run()
      .then((r) => {
        if (!cancelled) setRendered(r);
      })
      .catch((e) => {
        if (!cancelled) setError(describeSeccompError(e));
      });
    return () => {
      cancelled = true;
    };
    // `detail`/`edited`/`edits` only matter for the fallback path; keyed on their stable parts above.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api, namespace, kind, name, crName, edited.defaultAction, withEdits, added.join(','), removed.join(',')]);

  const yaml = useMemo(
    () => (rendered === null ? null : rendered.localFallback ? rendered.yaml : buildExportYaml({ brokerYaml: rendered.yaml, edits })),
    [rendered, edits],
  );

  const diff = useMemo(() => {
    if (!detail.cr) return null;
    const current = crSyscalls(allowedSyscalls(detail.profile), detail.cr);
    return diffSyscalls(current, allowedSyscalls(edited));
  }, [detail, edited]);
  const changed = diff?.filter((d) => d.kind !== 'same') ?? [];
  const actionChanged = detail.cr ? detail.cr.defaultAction !== edited.defaultAction : false;

  const onCopy = async () => {
    if (!yaml) return;
    if (await copyText(yaml)) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      size="lg"
      title={detail.cr ? 'Export updated SeccompProfile CR' : 'Export SeccompProfile CR'}
      subtitle={`${crName} · ${namespace} — commit this manifest and apply it; kguardian writes the node file from the CR.`}
      className="h-[85vh]"
      contentClassName="flex-1 min-h-0 overflow-y-auto"
      footer={
        <>
          <Button variant="ghost" size="sm" onClick={onClose}>
            Close
          </Button>
          <Button variant="secondary" size="sm" leftIcon={copied ? Check : Copy} onClick={() => void onCopy()} disabled={!yaml}>
            {copied ? 'Copied' : 'Copy YAML'}
          </Button>
          <Button variant={partial ? 'danger' : 'primary'} size="sm" leftIcon={Download} onClick={() => yaml && download(`${crName}.yaml`, yaml)} disabled={!yaml}>
            {partial ? 'Download anyway' : 'Download YAML'}
          </Button>
        </>
      }
    >
      <div className="px-5 py-4 space-y-4">
        <PartialCaptureWarning capture={capture} compact />

        {error && (
          <div role="alert" className="rounded-surface border border-hubble-error/40 bg-hubble-error/10 px-4 py-3 text-sm text-hubble-error">
            Could not render the export: {error}
          </div>
        )}

        {detail.cr && diff && (
          <section className="rounded-surface border border-hubble-border bg-hubble-dark overflow-hidden">
            <header className="px-4 py-2.5 border-b border-hubble-border text-xs">
              <span className="font-semibold text-primary">Changes vs deployed CR</span>{' '}
              <span className="font-mono text-tertiary">{detail.cr.name}</span>
              <span className="text-tertiary">
                {' '}
                · {changed.filter((d) => d.kind === 'add').length} added, {changed.filter((d) => d.kind === 'remove').length} removed
                {actionChanged && (
                  <>
                    {' '}
                    · defaultAction <span className="font-mono">{detail.cr.defaultAction}</span> → <span className="font-mono text-primary">{edited.defaultAction}</span>
                  </>
                )}
              </span>
            </header>
            {changed.length === 0 && !actionChanged ? (
              <p className="px-4 py-3 text-xs text-tertiary">No changes — the deployed CR already matches this export.</p>
            ) : (
              <pre className="px-4 py-3 text-xs font-mono leading-5 overflow-x-auto" aria-label="Syscall diff">
                {actionChanged && (
                  <>
                    <span className="text-hubble-error">- defaultAction: {detail.cr.defaultAction}</span>
                    {'\n'}
                    <span className="text-hubble-success">+ defaultAction: {edited.defaultAction}</span>
                    {'\n'}
                  </>
                )}
                {changed.map((d) => (
                  <span key={d.name} className={d.kind === 'add' ? 'text-hubble-success' : 'text-hubble-error'}>
                    {d.kind === 'add' ? '+' : '-'} {d.name}
                    {'\n'}
                  </span>
                ))}
                <span className="text-tertiary">  {diff.length - changed.length} unchanged</span>
              </pre>
            )}
          </section>
        )}

        <section className="rounded-surface border border-hubble-border bg-hubble-dark overflow-hidden">
          <header className="flex items-center gap-2 px-4 py-2.5 border-b border-hubble-border text-xs text-secondary">
            <FileCode className="w-3.5 h-3.5" />
            <span className="font-mono">{crName}.yaml</span>
          </header>
          {yaml === null && !error ? (
            <div className="p-4 space-y-2">
              <div className="flex items-center gap-2 text-xs text-tertiary">
                <RefreshCw className="w-3.5 h-3.5 animate-spin" /> Rendering…
              </div>
              <Skeleton className="h-40 w-full" />
            </div>
          ) : (
            yaml && <pre className="px-4 py-3 text-xs font-mono text-secondary overflow-x-auto whitespace-pre">{yaml}</pre>
          )}
        </section>
      </div>
    </Modal>
  );
}
