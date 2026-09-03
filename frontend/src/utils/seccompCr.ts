import type { SeccompProfile } from '../types/seccompProfile';
import type { CaptureInfo, CrInfo, WorkloadProfileDetail } from '../types/seccompWorkload';
import type { PodNodeData } from '../types';
import { quoteYamlValue } from './networkPolicyGenerator';
import { describePartialCapture, normalizeLevel } from './seccompCapture';

/**
 * Client-side helpers for the export-only workflow. The broker's `/export` is
 * the source of truth for an unedited manifest; when the operator stages edits
 * in the pre-export editor the manifest is re-rendered here from the edited
 * profile, keeping the broker's leading comment block (capture level + the
 * partial-capture WARNING) so nothing the broker wanted said is lost.
 */

/** Every syscall name the profile allows, across all ALLOW rules. */
export function allowedSyscalls(profile: SeccompProfile | null | undefined): Set<string> {
  const out = new Set<string>();
  profile?.syscalls?.forEach((rule) => {
    if (rule.action === 'SCMP_ACT_ALLOW') rule.names.forEach((n) => out.add(n));
  });
  return out;
}

/** Leading `#` comment lines of a YAML document (the broker's header). */
export function extractCommentHeader(yaml: string): string[] {
  const out: string[] = [];
  for (const line of yaml.split('\n')) {
    if (line.startsWith('#') || line.trim() === '') {
      if (line.startsWith('#')) out.push(line);
      else if (out.length > 0) break;
      continue;
    }
    break;
  }
  return out;
}

export interface CrRenderInput {
  name: string;
  namespace: string;
  profile: SeccompProfile;
  workloadRef?: { kind: string; name: string } | null;
  /** Comment lines (without trailing newline) placed above the document. */
  header?: string[];
}

/** Render a `kguardian.dev/v1alpha1` SeccompProfile CR manifest. */
export function renderSeccompProfileCR({ name, namespace, profile, workloadRef, header = [] }: CrRenderInput): string {
  const y: string[] = [...header];
  if (header.length > 0) y.push('');
  y.push('apiVersion: kguardian.dev/v1alpha1');
  y.push('kind: SeccompProfile');
  y.push('metadata:');
  y.push(`  name: ${quoteYamlValue(name)}`);
  y.push(`  namespace: ${quoteYamlValue(namespace)}`);
  y.push('spec:');
  y.push(`  defaultAction: ${profile.defaultAction}`);
  if (profile.architectures && profile.architectures.length > 0) {
    y.push('  architectures:');
    profile.architectures.forEach((a) => y.push(`  - ${a}`));
  }
  const rules = (profile.syscalls ?? []).filter((r) => r.names.length > 0);
  y.push('  syscalls:');
  rules.forEach((rule) => {
    y.push('  - names:');
    [...rule.names].sort().forEach((n) => y.push(`    - ${n}`));
    y.push(`    action: ${rule.action}`);
  });
  if (workloadRef) {
    y.push('  workloadRef:');
    y.push(`    kind: ${workloadRef.kind}`);
    y.push(`    name: ${quoteYamlValue(workloadRef.name)}`);
  }
  return y.join('\n') + '\n';
}

/**
 * Comment header for a CR rendered client-side (the per-pod Policy Builder
 * path, which has no broker export to borrow a header from). Mirrors the
 * broker's: what it was generated from, the capture level, and the loud
 * WARNING when capture is partial.
 */
export function captureHeaderLines(opts: { namespace: string; kind?: string | null; name: string; syscallCount: number; capture: CaptureInfo }): string[] {
  const { namespace, kind, name, syscallCount, capture } = opts;
  const lines = [
    '# kguardian SeccompProfile export — generated from observed syscalls',
    `# workload: ${namespace} ${kind ? `${kind}/` : ''}${name}`,
    `# observed syscalls: ${syscallCount}`,
    `# capture: ${normalizeLevel(capture.level)} — ${capture.complete ? 'complete' : 'partial'}`,
  ];
  const partial = describePartialCapture(capture);
  if (partial) {
    lines.push(`# WARNING: ${partial.title.toLowerCase()} — this profile will block syscalls the workload makes.`);
    lines.push(`# WARNING: ${partial.fix}`);
  }
  return lines;
}

/** Owning workload of a pod group, if the controller reported one. */
export function podWorkloadRef(pod: PodNodeData): { kind: string; name: string } | null {
  const rows = pod.pods?.length ? pod.pods : [pod.pod];
  const owner = rows.find((p) => p.workload_kind && p.workload_name);
  return owner ? { kind: owner.workload_kind!, name: owner.workload_name! } : null;
}

/** `<kind lowercased>-<workload name>`, or the pod identity/name for a bare pod. */
export function suggestedCrName(pod: PodNodeData): string {
  const ref = podWorkloadRef(pod);
  const raw = ref ? `${ref.kind.toLowerCase()}-${ref.name}` : pod.pod.pod_identity || pod.pod.pod_name;
  return raw.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 253) || 'seccomp-profile';
}

/**
 * The Policy Builder's per-pod export as a kguardian.dev SeccompProfile CR —
 * the same renderer the workload view uses, so both paths produce the
 * manifest the docs describe.
 */
export function podProfileToKguardianCR(pod: PodNodeData, profile: SeccompProfile, capture: CaptureInfo): string {
  const namespace = pod.pod.pod_namespace || 'default';
  const workloadRef = podWorkloadRef(pod);
  const name = suggestedCrName(pod);
  return renderSeccompProfileCR({
    name,
    namespace,
    profile,
    workloadRef,
    header: captureHeaderLines({ namespace, kind: workloadRef?.kind, name: workloadRef?.name ?? pod.pod.pod_name, syscallCount: allowedSyscalls(profile).size, capture }),
  });
}

export interface StagedEdits {
  added: string[];
  removed: string[];
  defaultAction: string;
  note?: string;
}

/** What the editor changed relative to the broker's observed profile. */
export function stagedEdits(observed: SeccompProfile, edited: SeccompProfile, note?: string): StagedEdits {
  const obs = allowedSyscalls(observed);
  const eff = allowedSyscalls(edited);
  return {
    added: [...eff].filter((n) => !obs.has(n)).sort(),
    removed: [...obs].filter((n) => !eff.has(n)).sort(),
    defaultAction: edited.defaultAction,
    note: note?.trim() || undefined,
  };
}

export function hasStagedSyscallEdits(e: StagedEdits): boolean {
  return e.added.length > 0 || e.removed.length > 0;
}

/** Comment lines describing staged edits, appended under the broker header. */
export function editsCommentLines(e: StagedEdits): string[] {
  const out: string[] = [];
  if (hasStagedSyscallEdits(e)) {
    out.push('# Edited in the kguardian UI before export:');
    if (e.added.length > 0) out.push(`#   added:   ${e.added.join(', ')}`);
    if (e.removed.length > 0) out.push(`#   removed: ${e.removed.join(', ')}`);
  }
  if (e.note) out.push(`# Note: ${e.note.replace(/\r?\n/g, ' ')}`);
  return out;
}

/** The syscall names the deployed CR allows, reconstructed from observed ∪ drift. */
export function crSyscalls(observed: Iterable<string>, cr: CrInfo | null | undefined): Set<string> {
  const out = new Set(observed);
  if (!cr) return out;
  cr.drift.missing.forEach((n) => out.delete(n));
  cr.drift.extra.forEach((n) => out.add(n));
  return out;
}

export interface DiffLine {
  kind: 'add' | 'remove' | 'same';
  name: string;
}

/** Unified-diff style lines: what applying the export changes vs the deployed CR. */
export function diffSyscalls(current: Iterable<string>, next: Iterable<string>): DiffLine[] {
  const cur = new Set(current);
  const nxt = new Set(next);
  const names = [...new Set([...cur, ...nxt])].sort();
  return names.map((name) => ({
    kind: cur.has(name) && nxt.has(name) ? 'same' : nxt.has(name) ? 'add' : 'remove',
    name,
  }));
}

/** Insert comment lines directly under the broker's leading comment block. */
export function insertAfterHeader(yaml: string, lines: string[]): string {
  if (lines.length === 0) return yaml;
  const n = extractCommentHeader(yaml).length;
  const all = yaml.split('\n');
  return [...all.slice(0, n), ...lines, ...all.slice(n)].join('\n');
}

/**
 * Build the manifest to show/copy/download from the broker's document.
 * `brokerYaml` is the GET export (no edits) or the POST export (edits applied
 * server-side); this only adds the edits/note comment lines under the broker
 * header so the reviewer of the commit sees what was changed in the UI.
 */
export function buildExportYaml(opts: { brokerYaml: string; edits: StagedEdits }): string {
  return insertAfterHeader(opts.brokerYaml, editsCommentLines(opts.edits));
}

/**
 * Older-broker fallback (no `POST …/export`): re-render the CR locally from the
 * edited profile under the broker's comment header plus the edits block.
 */
export function renderEditedExportLocally(opts: {
  brokerYaml: string;
  detail: WorkloadProfileDetail;
  edited: SeccompProfile;
  crName: string;
  edits: StagedEdits;
}): string {
  const { brokerYaml, detail, edited, crName, edits } = opts;
  const header = [...extractCommentHeader(brokerYaml), ...editsCommentLines(edits)];
  return renderSeccompProfileCR({
    name: crName,
    namespace: detail.namespace,
    profile: edited,
    workloadRef: { kind: detail.kind, name: detail.name },
    header,
  });
}
