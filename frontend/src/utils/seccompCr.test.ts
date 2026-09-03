import { describe, expect, test } from 'vitest';
import {
  allowedSyscalls,
  buildExportYaml,
  crSyscalls,
  diffSyscalls,
  editsCommentLines,
  extractCommentHeader,
  insertAfterHeader,
  renderEditedExportLocally,
  renderSeccompProfileCR,
  stagedEdits,
  captureHeaderLines,
  podProfileToKguardianCR,
  suggestedCrName,
} from './seccompCr';
import type { PodNodeData } from '../types';
import type { SeccompProfile } from '../types/seccompProfile';
import type { WorkloadProfileDetail } from '../types/seccompWorkload';

const observed: SeccompProfile = {
  defaultAction: 'SCMP_ACT_LOG',
  architectures: ['SCMP_ARCH_X86_64'],
  syscalls: [{ names: ['write', 'read', 'futex'], action: 'SCMP_ACT_ALLOW' }],
};

const detail: WorkloadProfileDetail = {
  namespace: 'prod',
  kind: 'Deployment',
  name: 'web',
  hash: 'h',
  syscallCount: 3,
  architectures: ['SCMP_ARCH_X86_64'],
  updatedAt: '',
  suggestedName: 'deployment-web',
  cr: null,
  profile: observed,
};

const brokerYaml = [
  '# kguardian SeccompProfile export',
  '# capture: low (partial) — 1 of 2 pods below full',
  '# WARNING: partial capture (low on 1 pod) — this profile will block syscalls the workload makes',
  '',
  'apiVersion: kguardian.dev/v1alpha1',
  'kind: SeccompProfile',
  'metadata:',
  '  name: deployment-web',
  '  namespace: prod',
  'spec:',
  '  defaultAction: SCMP_ACT_LOG',
  '  syscalls:',
  '  - names: [futex, read, write]',
  '    action: SCMP_ACT_ALLOW',
  '',
].join('\n');

describe('seccompCr', () => {
  test('allowedSyscalls only counts ALLOW rules', () => {
    expect([...allowedSyscalls({ ...observed, syscalls: [...observed.syscalls!, { names: ['ptrace'], action: 'SCMP_ACT_ERRNO' }] })].sort()).toEqual(['futex', 'read', 'write']);
  });

  test('extractCommentHeader keeps only the leading comment block', () => {
    expect(extractCommentHeader(brokerYaml)).toHaveLength(3);
    expect(extractCommentHeader('apiVersion: x\n# not a header\n')).toEqual([]);
  });

  test('renderSeccompProfileCR emits the kguardian.dev CR with sorted names and workloadRef', () => {
    const y = renderSeccompProfileCR({
      name: 'deployment-web',
      namespace: 'prod',
      profile: observed,
      workloadRef: { kind: 'Deployment', name: 'web' },
      header: ['# hi'],
    });
    expect(y).toBe(
      [
        '# hi',
        '',
        'apiVersion: kguardian.dev/v1alpha1',
        'kind: SeccompProfile',
        'metadata:',
        '  name: "deployment-web"',
        '  namespace: prod',
        'spec:',
        '  defaultAction: SCMP_ACT_LOG',
        '  architectures:',
        '  - SCMP_ARCH_X86_64',
        '  syscalls:',
        '  - names:',
        '    - futex',
        '    - read',
        '    - write',
        '    action: SCMP_ACT_ALLOW',
        '  workloadRef:',
        '    kind: Deployment',
        '    name: web',
        '',
      ].join('\n'),
    );
  });

  test('stagedEdits + editsCommentLines describe the diff against observed', () => {
    const edited: SeccompProfile = { ...observed, defaultAction: 'SCMP_ACT_ERRNO', syscalls: [{ names: ['read', 'write', 'clock_settime'], action: 'SCMP_ACT_ALLOW' }] };
    const e = stagedEdits(observed, edited, '  cron needs clock  ');
    expect(e).toEqual({ added: ['clock_settime'], removed: ['futex'], defaultAction: 'SCMP_ACT_ERRNO', note: 'cron needs clock' });
    expect(editsCommentLines(e)).toEqual([
      '# Edited in the kguardian UI before export:',
      '#   added:   clock_settime',
      '#   removed: futex',
      '# Note: cron needs clock',
    ]);
    expect(editsCommentLines(stagedEdits(observed, observed))).toEqual([]);
  });

  test('crSyscalls reconstructs the CR set from observed ∪ drift', () => {
    const set = crSyscalls(['read', 'write', 'futex'], {
      name: 'x', defaultAction: 'SCMP_ACT_LOG', hash: 'h', syscallCount: 3,
      distribution: { ready: 1, total: 1, state: 'Ready' },
      drift: { missing: ['futex'], extra: ['ptrace'], inSync: false },
    });
    expect([...set].sort()).toEqual(['ptrace', 'read', 'write']);
    expect([...crSyscalls(['a'], null)]).toEqual(['a']);
  });

  test('diffSyscalls is a sorted unified diff', () => {
    expect(diffSyscalls(['read', 'ptrace'], ['read', 'futex'])).toEqual([
      { kind: 'add', name: 'futex' },
      { kind: 'remove', name: 'ptrace' },
      { kind: 'same', name: 'read' },
    ]);
  });

  test('buildExportYaml: broker YAML verbatim when nothing is staged', () => {
    expect(buildExportYaml({ brokerYaml, edits: stagedEdits(observed, observed) })).toBe(brokerYaml);
  });

  test('buildExportYaml: broker document kept, edits/note comments inserted under its header', () => {
    const edited: SeccompProfile = { ...observed, syscalls: [{ names: ['read', 'write'], action: 'SCMP_ACT_ALLOW' }] };
    const y = buildExportYaml({ brokerYaml, edits: stagedEdits(observed, edited, 'why') });
    const lines = y.split('\n');
    expect(lines.slice(0, 3)).toEqual(brokerYaml.split('\n').slice(0, 3));
    expect(lines[3]).toBe('# Edited in the kguardian UI before export:');
    expect(lines[4]).toBe('#   removed: futex');
    expect(lines[5]).toBe('# Note: why');
    expect(lines.slice(6).join('\n')).toBe(brokerYaml.split('\n').slice(3).join('\n'));
    expect(insertAfterHeader('a: 1\n', ['# x'])).toBe('# x\na: 1\n');
  });

  test('renderEditedExportLocally: older-broker fallback re-renders with header + edits block', () => {
    const edited: SeccompProfile = { ...observed, syscalls: [{ names: ['read', 'write'], action: 'SCMP_ACT_ALLOW' }] };
    const y = renderEditedExportLocally({ brokerYaml, detail, edited, crName: 'my-web', edits: stagedEdits(observed, edited) });
    expect(y.startsWith('# kguardian SeccompProfile export\n# capture: low')).toBe(true);
    expect(y).toContain('# WARNING: partial capture');
    expect(y).toContain('#   removed: futex');
    expect(y).toContain('  name: "my-web"');
    expect(y).not.toContain('futex\n    action');
    expect(y).toContain('  workloadRef:\n    kind: Deployment\n    name: web');
  });

  test('captureHeaderLines mirrors the broker header, with the WARNING when partial', () => {
    const full = captureHeaderLines({ namespace: 'prod', kind: 'Deployment', name: 'web', syscallCount: 3, capture: { level: 'full', complete: true, pods: [] } });
    expect(full).toEqual([
      '# kguardian SeccompProfile export — generated from observed syscalls',
      '# workload: prod Deployment/web',
      '# observed syscalls: 3',
      '# capture: full — complete',
    ]);
    const low = captureHeaderLines({ namespace: 'prod', kind: null, name: 'bare', syscallCount: 3, capture: { level: 'low', complete: false, pods: [{ name: 'p', level: 'low' }] } });
    expect(low[1]).toBe('# workload: prod bare');
    expect(low[3]).toBe('# capture: low — partial');
    expect(low[4]).toMatch(/^# WARNING: partial capture — low tier, 1 pod — this profile will block/);
    expect(low[5]).toContain('kguardian.dev/syscall-capture: full');
  });

  test('podProfileToKguardianCR: workloadRef + suggested name from the pod rows, SPO not involved', () => {
    const pod: PodNodeData = {
      id: 'web',
      label: 'web',
      pod: { pod_name: 'web-1', pod_ip: '', pod_namespace: 'prod', time_stamp: '', node_name: '', is_dead: false, pod_identity: 'web', workload_kind: 'Deployment', workload_name: 'Web' },
      pods: [],
      traffic: [],
      isExpanded: false,
    };
    expect(suggestedCrName(pod)).toBe('deployment-web');
    const y = podProfileToKguardianCR(pod, { ...observed, defaultAction: 'SCMP_ACT_ERRNO' }, { level: 'low', complete: false, pods: [{ name: 'web-1', level: 'low' }] });
    expect(y).toContain('apiVersion: kguardian.dev/v1alpha1');
    // Audit-first: the generator's ERRNO default never leaks into the CR…
    expect(y).toContain('  defaultAction: SCMP_ACT_LOG');
    // …unless the operator explicitly chose an action.
    expect(podProfileToKguardianCR(pod, observed, { level: 'full', complete: true, pods: [] }, { defaultAction: 'SCMP_ACT_ERRNO' })).toContain('  defaultAction: SCMP_ACT_ERRNO');
    expect(y).not.toContain('security-profiles-operator');
    expect(y).toContain('# WARNING: partial capture');
    expect(y).toContain('  name: "deployment-web"');
    expect(y).toContain('  workloadRef:\n    kind: Deployment\n    name: Web');
    const bare: PodNodeData = { ...pod, pod: { ...pod.pod, workload_kind: null, workload_name: null, pod_identity: null, pod_name: 'Solo_Pod' } };
    expect(suggestedCrName(bare)).toBe('solo-pod');
    expect(podProfileToKguardianCR(bare, observed, { level: 'full', complete: true, pods: [] })).not.toContain('workloadRef');
  });
});
