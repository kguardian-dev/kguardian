import { describe, expect, test } from 'vitest';
import {
  captureFromPods,
  crStatus,
  describePartialCapture,
  isBlockingAction,
  normalizeLevel,
  resolveCapture,
  securityContextSnippet,
} from './seccompCapture';
import type { WorkloadProfileSummary } from '../types/seccompWorkload';

const base: WorkloadProfileSummary = {
  namespace: 'prod',
  kind: 'Deployment',
  name: 'web',
  hash: 'abc',
  syscallCount: 10,
  architectures: ['SCMP_ARCH_X86_64'],
  updatedAt: '2026-09-03T00:00:00',
  suggestedName: 'deployment-web',
  cr: null,
  recommendedSnippet: { seccompProfile: { type: 'Localhost', localhostProfile: 'kguardian/prod/deployment-web.json' } },
};
const cr = (defaultAction: string) => ({
  name: 'deployment-web',
  defaultAction,
  hash: 'h',
  syscallCount: 10,
  distribution: { ready: 1, total: 1, state: 'Ready' },
  drift: { missing: [], extra: [], inSync: true },
});

describe('normalizeLevel', () => {
  test('accepts the five tiers case-insensitively, everything else is unknown', () => {
    expect(normalizeLevel('FULL')).toBe('full');
    expect(normalizeLevel(' low ')).toBe('low');
    expect(normalizeLevel('custom')).toBe('custom');
    expect(normalizeLevel('')).toBe('unknown');
    expect(normalizeLevel(null)).toBe('unknown');
    expect(normalizeLevel('everything')).toBe('unknown');
  });
});

describe('captureFromPods', () => {
  test('lowest tier wins and complete only when every pod is full', () => {
    const c = captureFromPods([
      { pod_name: 'a', capture_level: 'full', is_dead: false },
      { pod_name: 'b', capture_level: 'high', is_dead: false },
      { pod_name: 'c', capture_level: 'low', is_dead: false },
    ]);
    expect(c.level).toBe('low');
    expect(c.complete).toBe(false);
    expect(c.pods.map((p) => p.name)).toEqual(['a', 'b', 'c']);
  });

  test('all full ⇒ complete', () => {
    const c = captureFromPods([
      { pod_name: 'a', capture_level: 'full', is_dead: false },
      { pod_name: 'b', capture_level: 'full', is_dead: false },
    ]);
    expect(c).toEqual({ level: 'full', complete: true, pods: [{ name: 'a', level: 'full' }, { name: 'b', level: 'full' }] });
  });

  test('worst-first order matches the broker: custom ranks below unknown, unknown below low', () => {
    expect(
      captureFromPods([
        { pod_name: 'a', capture_level: 'unknown', is_dead: false },
        { pod_name: 'b', capture_level: 'custom', is_dead: false },
        { pod_name: 'c', capture_level: 'low', is_dead: false },
      ]).level,
    ).toBe('custom');
    expect(
      captureFromPods([
        { pod_name: 'a', capture_level: null, is_dead: false },
        { pod_name: 'c', capture_level: 'low', is_dead: false },
      ]).level,
    ).toBe('unknown');
    const w = describePartialCapture({
      level: 'custom',
      complete: false,
      pods: [{ name: 'p-low', level: 'low' }, { name: 'p-custom', level: 'custom' }, { name: 'p-unknown', level: 'unknown' }],
    });
    expect(w!.affectedPods.map((p) => p.name)).toEqual(['p-custom', 'p-unknown', 'p-low']);
  });

  test('missing capture_level is unknown and never complete', () => {
    const c = captureFromPods([{ pod_name: 'a', capture_level: null, is_dead: false }]);
    expect(c.level).toBe('unknown');
    expect(c.complete).toBe(false);
  });

  test('dead pods are ignored when live ones exist', () => {
    const c = captureFromPods([
      { pod_name: 'old', capture_level: 'low', is_dead: true },
      { pod_name: 'new', capture_level: 'full', is_dead: false },
    ]);
    expect(c.complete).toBe(true);
    expect(c.pods).toHaveLength(1);
  });

  test('no pods ⇒ unknown, incomplete', () => {
    expect(captureFromPods([])).toEqual({ level: 'unknown', complete: false, pods: [] });
  });
});

describe('resolveCapture', () => {
  test('prefers the broker capture block over pod rows', () => {
    const c = resolveCapture(
      { ...base, capture: { level: 'medium', complete: false, pods: [{ name: 'x', level: 'medium' }] } },
      [{ pod_name: 'x', pod_ip: '', pod_namespace: 'prod', time_stamp: '', node_name: '', is_dead: false, capture_level: 'full' }],
    );
    expect(c.level).toBe('medium');
    expect(c.complete).toBe(false);
  });

  test('falls back to pods when the summary has no capture (older broker)', () => {
    const c = resolveCapture(base, [
      { pod_name: 'x', pod_ip: '', pod_namespace: 'prod', time_stamp: '', node_name: '', is_dead: false, capture_level: 'full' },
    ]);
    expect(c.complete).toBe(true);
  });

  test('nothing to go on ⇒ unknown, incomplete — never assume full', () => {
    expect(resolveCapture(null)).toEqual({ level: 'unknown', complete: false, pods: [] });
    expect(resolveCapture(base).complete).toBe(false);
  });
});

describe('describePartialCapture', () => {
  test('null when complete', () => {
    expect(describePartialCapture({ level: 'full', complete: true, pods: [] })).toBeNull();
  });

  test('names the tier, the pod count, the consequence, and both fixes', () => {
    const w = describePartialCapture({
      level: 'low',
      complete: false,
      pods: [
        { name: 'web-1', level: 'full' },
        { name: 'web-2', level: 'low' },
        { name: 'web-3', level: 'high' },
      ],
    });
    expect(w).not.toBeNull();
    expect(w!.title).toBe('Partial capture — low tier, 2 pods');
    expect(w!.consequence).toContain('Profile is incomplete and will block syscalls the app uses.');
    expect(w!.fix).toContain('kguardian.dev/syscall-capture: full');
    expect(w!.fix).toContain('syscalls.captureLevel=full');
    // Worst tier first; full pods are not listed as affected.
    expect(w!.affectedPods.map((p) => p.name)).toEqual(['web-2', 'web-3']);
  });

  test('singular pod and unknown tier phrasing', () => {
    const w = describePartialCapture({ level: 'unknown', complete: false, pods: [{ name: 'p', level: 'unknown' }] });
    expect(w!.title).toBe('Partial capture — unknown tier, 1 pod');
  });

  test('no live pods (scaled to zero / CronJob between runs) is called out, still partial', () => {
    const w = describePartialCapture({ level: 'unknown', complete: false, pods: [] });
    expect(w!.title).toBe('Partial capture — unknown tier, no live pods');
    expect(w!.consequence).toContain('No live pod reported a capture tier');
    expect(w!.affectedPods).toEqual([]);
  });
});

describe('crStatus', () => {
  test('none without a CR, regardless of anything else', () => {
    expect(crStatus({ cr: null })).toBe('none');
    expect(crStatus({})).toBe('none');
  });
  test('audit for LOG, enforcing for ERRNO/KILL*', () => {
    expect(crStatus({ cr: cr('SCMP_ACT_LOG') })).toBe('audit');
    expect(crStatus({ cr: cr('SCMP_ACT_ERRNO') })).toBe('enforcing');
    expect(crStatus({ cr: cr('SCMP_ACT_KILL_PROCESS') })).toBe('enforcing');
  });
  test('isBlockingAction', () => {
    expect(isBlockingAction('SCMP_ACT_LOG')).toBe(false);
    expect(isBlockingAction('SCMP_ACT_ALLOW')).toBe(false);
    expect(isBlockingAction('SCMP_ACT_KILL_PROCESS')).toBe(true);
    expect(isBlockingAction(null)).toBe(false);
  });
});

describe('securityContextSnippet', () => {
  test('uses the broker snippet path, else derives from the CR / suggested name', () => {
    expect(securityContextSnippet(base)).toBe(
      'securityContext:\n  seccompProfile:\n    type: Localhost\n    localhostProfile: kguardian/prod/deployment-web.json',
    );
    expect(securityContextSnippet({ namespace: 'x', suggestedName: 'deployment-y', cr: null })).toContain('kguardian/x/deployment-y.json');
    expect(securityContextSnippet({ namespace: 'x', suggestedName: 'deployment-y', cr: { ...cr('SCMP_ACT_LOG'), name: 'custom' } })).toContain('kguardian/x/custom.json');
  });
});
