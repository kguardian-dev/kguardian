import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, test } from 'vitest';
import type { PodInfo } from '../types';
import { POD_NODE_MEMO_IGNORED, POD_NODE_MEMO_KEYS, podNodePropsEqual, type PodNodeRenderData } from './podNodeMemo';

// PodNode's memo comparator decides whether a card refreshes on poll. A
// field the card renders but the comparator ignores goes stale silently —
// exactly the trap the upcoming security badges would fall into. These tests
// make the field list complete by construction.

const source = readFileSync(fileURLToPath(new URL('./PodNode.tsx', import.meta.url)), 'utf8');

const pod = (over: Partial<PodInfo> = {}): PodInfo => ({
  pod_name: 'api-1', pod_ip: '10.0.0.1', pod_namespace: 'payments', time_stamp: 't', node_name: 'worker-1', is_dead: false, ...over,
});

const base = (): PodNodeRenderData => ({
  id: 'payments-api',
  label: 'api',
  pod: pod(),
  pods: [pod()],
  traffic: [],
  syscalls: [{ pod_name: 'api-1', syscalls: 'read,write' } as never],
  isExpanded: false,
  isExternal: false,
  layoutDirection: 'LR',
});

describe('POD_NODE_MEMO_KEYS covers everything PodNode renders', () => {
  test('every data.<field> read in PodNode.tsx is either a memo key or explicitly ignored', () => {
    const read = new Set([...source.matchAll(/\bdata\.(\w+)/g)].map((m) => m[1]));
    expect(read.size).toBeGreaterThan(5); // the scan itself works
    const uncovered = [...read].filter((f) => !(f in POD_NODE_MEMO_KEYS) && !(f in POD_NODE_MEMO_IGNORED));
    expect(uncovered, 'add these to POD_NODE_MEMO_KEYS in podNodeMemo.ts').toEqual([]);
  });

  test('PodNode does not destructure data (which would hide reads from the scan)', () => {
    expect(source).not.toMatch(/\}\s*=\s*data\b/);
  });

  test('PodNode uses the shared comparator', () => {
    expect(source).toMatch(/React\.memo\([\s\S]*podNodePropsEqual\)/);
  });
});

describe('podNodePropsEqual', () => {
  test('identical-by-value data from a fresh poll does not re-render', () => {
    // usePodData rebuilds every object each poll; that alone must not re-render.
    expect(podNodePropsEqual({ data: base() }, { data: base() })).toBe(true);
  });

  test('selection change re-renders', () => {
    expect(podNodePropsEqual({ data: base(), selected: false }, { data: base(), selected: true })).toBe(false);
  });

  const changes: Record<string, (d: PodNodeRenderData) => void> = {
    id: (d) => { d.id = 'other'; },
    label: (d) => { d.label = 'api-v2'; },
    pod: (d) => { d.pod = pod({ pod_identity: 'renamed' }); },
    pods: (d) => { d.pods = [pod(), pod({ pod_name: 'api-2' })]; },
    tooltip: (d) => { d.tooltip = 'why'; },
    externalNamespace: (d) => { d.externalNamespace = 'observability'; },
    isExpanded: (d) => { d.isExpanded = true; },
    isExternal: (d) => { d.isExternal = true; },
    layoutDirection: (d) => { d.layoutDirection = 'TB'; },
    traffic: (d) => { d.traffic = [{} as never]; },
    // Same record count, more syscalls: the old length-only check missed this.
    syscalls: (d) => { d.syscalls = [{ pod_name: 'api-1', syscalls: 'read,write,ptrace' } as never]; },
    compute: (d) => { d.compute = {} as never; },
  };

  test('every memo key has a change case here', () => {
    expect(Object.keys(changes).sort()).toEqual(Object.keys(POD_NODE_MEMO_KEYS).sort());
  });

  test.each(Object.keys(changes))('a change to %s re-renders', (field) => {
    const next = base();
    changes[field](next);
    expect(podNodePropsEqual({ data: base() }, { data: next })).toBe(false);
  });

  test('a DaemonSet member flips the spine, so it re-renders at the same pod count', () => {
    const next = base();
    next.pods = [pod({ workload_kind: 'DaemonSet' })];
    expect(podNodePropsEqual({ data: base() }, { data: next })).toBe(false);
  });

  test('a new onBuildPolicy handler alone does not re-render', () => {
    const a = { ...base(), onBuildPolicy: () => {} };
    const b = { ...base(), onBuildPolicy: () => {} };
    expect(podNodePropsEqual({ data: a }, { data: b })).toBe(true);
  });
});
