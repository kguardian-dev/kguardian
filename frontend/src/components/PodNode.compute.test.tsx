// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { cleanup, render } from '@testing-library/react';
import { ReactFlowProvider } from 'reactflow';
import PodNode from './PodNode';
import type { PodInfo } from '../types';
import type { ComputeFinding, PodComputeData } from '../types/compute';
import { COMPUTE_DOT_CLASS } from '../utils/compute';

const NOW = Date.parse('2026-09-14T10:00:00Z');

// Compute gauges on the card (design D8): a node WITHOUT compute data must
// render exactly as before the feature — no dot, no bar, no sparklines —
// and a node WITH it gets the header dot + two-segment micro bar, and the
// sparklines + chips once expanded.

afterEach(cleanup);

const pod = (name: string, extra: Partial<PodInfo> = {}): PodInfo => ({
  pod_name: name, pod_ip: '10.0.0.1', pod_namespace: 'payments', time_stamp: 't', node_name: 'worker-1', is_dead: false, ...extra,
});

const finding = (over: Partial<ComputeFinding> = {}): ComputeFinding => ({
  kind: 'noisy-neighbor', severity: 'high',
  victim: { pod_uid: 'uid-a', namespace: 'payments', pod_name: 'api-1', container: 'app', container_uid: 'uid-a/app', node: 'worker-1' },
  culprit: { kind: 'pod', ref: 'batch/etl-1/worker', pod_uid: 'uid-b', namespace: 'batch', pod_name: 'etl-1', container_uid: 'uid-b/worker', blame_share: 0.71, cpu_usage_millis: 1900, cpu_request_millis: 500 },
  evidence: { window_minutes: 5, cpu_psi_some10_max: 31, cpu_psi_full10_max: 4.2, runq_p99_us_max: 48000, throttled_ratio: 0.02, mem_psi_some10_max: 0, node_mem_some10_max: 0, refault_delta: 0, mem_events_high_delta: 0 },
  first_seen: 't', last_seen: 't',
  message: 'payments/api-1 is starved for CPU by batch/etl-1 (71% of its wait)',
  ...over,
});

const compute = (over: Partial<PodComputeData> = {}): PodComputeData => ({
  cpuPct: 42, memPct: 65, cpuDenominator: 'limit', memDenominator: 'request', status: 'ok', findings: [],
  // Points carry the instant they were observed; the window is the hour to now.
  sparkCpu: [
    { at: NOW - 120_000, value: 100 }, { at: NOW - 60_000, value: 120 }, { at: NOW, value: 210 },
  ],
  sparkMem: [
    { at: NOW - 120_000, value: 800 }, { at: NOW - 60_000, value: 820 }, { at: NOW, value: 850 },
  ],
  sparkWindow: { from: NOW - 60 * 60_000, to: NOW },
  cpuMillis: 210, memBytes: 850 * 1024 * 1024, cpuCapacityMillis: 500, memCapacityBytes: 1300 * 1024 * 1024,
  // A gauged card needs at least one container row (hasComputeGauges).
  containers: [{ container_uid: 'uid-a/app' } as PodComputeData['containers'][number]],
  ...over,
});

const renderNode = (data: Record<string, unknown>) =>
  render(
    <ReactFlowProvider>
      <PodNode id="n" data={data as never} selected={false} type="podNode" xPos={0} yPos={0} zIndex={0} isConnectable={false} dragging={false} />
    </ReactFlowProvider>,
  );

const base = (over: Record<string, unknown> = {}) => ({
  id: 'payments-api', label: 'api', pod: pod('api-1'), pods: [pod('api-1')], traffic: [], isExpanded: false, isExternal: false,
  onToggle: () => {}, onFocus: () => {}, ...over,
});

test('without compute data the card has no dot, bar, sparkline or chip', () => {
  const { container } = renderNode(base({ isExpanded: true }));
  expect(container.querySelector('[data-testid="compute-status-dot"]')).toBeNull();
  expect(container.querySelector('[data-testid="compute-microbar"]')).toBeNull();
  expect(container.querySelector('[data-testid="sparkline"]')).toBeNull();
  expect(container.querySelector('[data-testid="compute-detail"]')).toBeNull();
  expect(container.textContent).not.toMatch(/CPU|Memory|Starved|Throttled/);
});

test('collapsed: status dot + two-segment micro bar, denominator named in the tooltip', () => {
  const { container } = renderNode(base({ compute: compute() }));
  const dot = container.querySelector('[data-testid="compute-status-dot"]')!;
  expect(dot).not.toBeNull();
  expect(dot.className).toContain(COMPUTE_DOT_CLASS.ok);
  expect(dot.getAttribute('title')).toMatch(/no active findings/);
  const cpuBar = container.querySelector('[data-testid="compute-cpu-bar"]')!;
  const memBar = container.querySelector('[data-testid="compute-mem-bar"]')!;
  expect(cpuBar.getAttribute('title')).toBe('CPU 210m — 42% of 500m limit');
  expect(memBar.getAttribute('title')).toMatch(/^Memory 850 MiB — 65% of 1\.3 GiB request$/);
  expect((cpuBar.firstElementChild as HTMLElement).style.width).toBe('42%');
  expect((memBar.firstElementChild as HTMLElement).style.width).toBe('65%');
  // Collapsed: no sparklines.
  expect(container.querySelector('[data-testid="sparkline"]')).toBeNull();
});

test('a gauge past its denominator is clamped to 100% and painted as an error', () => {
  const { container } = renderNode(base({ compute: compute({ cpuPct: 140 }) }));
  const fill = container.querySelector('[data-testid="compute-cpu-bar"]')!.firstElementChild as HTMLElement;
  expect(fill.style.width).toBe('100%');
  expect(fill.className).toContain('bg-hubble-error');
});

test('expanded: two sparklines with the current value and denominator', () => {
  const { container } = renderNode(base({ isExpanded: true, compute: compute() }));
  const sparks = container.querySelectorAll('[data-testid="sparkline"]');
  expect(sparks).toHaveLength(2);
  expect(container.textContent).toContain('210m');
  expect(container.textContent).toContain('/ 500m limit');
  expect(container.textContent).toContain('/ 1.3 GiB request');
  expect(container.querySelector('[data-testid="compute-starved-chip"]')).toBeNull();
  expect(container.querySelector('[data-testid="compute-throttled-chip"]')).toBeNull();
});

test('expanded: "Starved by <ns/pod>" chip when a noisy-neighbour finding names a culprit', () => {
  const f = finding();
  const { container } = renderNode(base({ isExpanded: true, compute: compute({ status: 'warning', findings: [f] }) }));
  const chip = container.querySelector('[data-testid="compute-starved-chip"]')!;
  expect(chip.textContent).toBe('Starved by batch/etl-1');
  expect(chip.getAttribute('title')).toBe(f.message);
  const dot = container.querySelector('[data-testid="compute-status-dot"]')!;
  expect(dot.className).toContain(COMPUTE_DOT_CLASS.warning);
  expect(dot.getAttribute('title')).toContain('noisy-neighbor');
});

test('Starved-by chip: an opted-out culprit (null usage) says so in the tooltip', () => {
  const f = finding();
  f.culprit = { ...f.culprit!, cpu_usage_millis: null };
  const { container } = renderNode(base({ isExpanded: true, compute: compute({ status: 'warning', findings: [f] }) }));
  const chip = container.querySelector('[data-testid="compute-starved-chip"]')!;
  expect(chip.textContent).toBe('Starved by batch/etl-1');
  expect(chip.getAttribute('title')).toBe(`${f.message} — usage unknown (opted out of sampling)`);
});

test('expanded: "Throttled NN%" chip for cpu-throttled; a critical finding paints the dot red', () => {
  const f = finding({ kind: 'cpu-throttled', severity: 'critical', culprit: null, evidence: { ...finding().evidence, throttled_ratio: 0.34 } });
  const { container } = renderNode(base({ isExpanded: true, compute: compute({ status: 'critical', findings: [f] }) }));
  expect(container.querySelector('[data-testid="compute-throttled-chip"]')!.textContent).toBe('Throttled 34%');
  expect(container.querySelector('[data-testid="compute-starved-chip"]')).toBeNull();
  expect(container.querySelector('[data-testid="compute-status-dot"]')!.className).toContain(COMPUTE_DOT_CLASS.critical);
});

// Fix #7: the sparkline ceiling follows the micro bar's denominator, except
// that a node-capacity denominator auto-scales (a 100m pod on a 32-core node
// would otherwise be a flat line on the baseline).
test('sparkline auto-scales when the denominator is node capacity, and follows the limit otherwise', () => {
  const nodeScaled = renderNode(base({ isExpanded: true, compute: compute({ cpuDenominator: 'node', cpuCapacityMillis: 32_000, sparkCpu: [{ at: NOW - 120_000, value: 100 }, { at: NOW - 60_000, value: 200 }, { at: NOW, value: 150 }] }) }));
  const cpuSpark = nodeScaled.container.querySelectorAll('[data-testid="sparkline"]')[0]; // first = CPU, second = memory
  const d = cpuSpark.querySelector('path[fill="none"]')!.getAttribute('d')!;
  const ys = [...d.matchAll(/,([\d.]+)/g)].map((m) => Number(m[1]));
  expect(Math.max(...ys) - Math.min(...ys)).toBeGreaterThan(10); // not flat
  expect(cpuSpark.querySelector('line')).toBeNull(); // no capacity line against node capacity
  cleanup();
  const limitScaled = renderNode(base({ isExpanded: true, compute: compute({ cpuDenominator: 'limit', cpuCapacityMillis: 500, sparkCpu: [{ at: NOW - 120_000, value: 100 }, { at: NOW - 60_000, value: 200 }, { at: NOW, value: 150 }] }) }));
  expect(limitScaled.container.querySelectorAll('[data-testid="sparkline"]')[0].querySelector('line')).not.toBeNull(); // limit reference line
});

// Fix #9: the dot and bars are images with an accessible name mirroring the tooltip.
test('status dot and micro bars carry role=img and an aria-label equal to their title', () => {
  const { container } = renderNode(base({ compute: compute() }));
  for (const id of ['compute-status-dot', 'compute-cpu-bar', 'compute-mem-bar']) {
    const el = container.querySelector(`[data-testid="${id}"]`)!;
    expect(el.getAttribute('role')).toBe('img');
    expect(el.getAttribute('aria-label')).toBe(el.getAttribute('title'));
    expect(el.getAttribute('aria-label')).toBeTruthy();
  }
});

test('dropped BPF inserts on the node: warning dot, tooltip names the counts', () => {
  const { container } = renderNode(base({ compute: compute({ status: 'warning', probeDrops: { hist: 3, pair: 5 } }) }));
  const dot = container.querySelector('[data-testid="compute-status-dot"]')!;
  expect(dot.className).toContain(COMPUTE_DOT_CLASS.warning);
  expect(dot.getAttribute('title')).toBe('Compute warning; probe map full: 3 histogram / 5 pair inserts dropped');
  expect(dot.getAttribute('aria-label')).toBe(dot.getAttribute('title'));
});

test('pending: muted pulsing dot, "no sample yet" tooltip, no bar', () => {
  const { container } = renderNode(base({ compute: compute({ status: 'pending', containers: [], cpuPct: null, memPct: null }) }));
  const dot = container.querySelector('[data-testid="compute-status-dot"]')!;
  expect(dot.className).toContain(COMPUTE_DOT_CLASS.pending);
  expect(dot.getAttribute('title')).toBe('No compute sample for this pod (not yet sampled, or opted out with kguardian.dev/compute: off)');
  expect(container.querySelector('[data-testid="compute-microbar"]')).toBeNull();
});

test('unsupported vs off: muted dot, no bar, tooltips read apart', () => {
  const muted = (status: PodComputeData['status']) => compute({ status, containers: [], cpuPct: null, memPct: null });
  const a = renderNode(base({ compute: muted('unsupported') }));
  const dotA = a.container.querySelector('[data-testid="compute-status-dot"]')!;
  expect(dotA.className).toContain(COMPUTE_DOT_CLASS.unsupported);
  expect(dotA.getAttribute('title')).toMatch(/cgroup v1/);
  expect(a.container.querySelector('[data-testid="compute-microbar"]')).toBeNull();
  cleanup();
  const b = renderNode(base({ compute: muted('off') }));
  const dotB = b.container.querySelector('[data-testid="compute-status-dot"]')!;
  expect(dotB.className).toContain(COMPUTE_DOT_CLASS.off);
  expect(dotB.getAttribute('title')).toMatch(/compute\.enabled is false/);
  expect(dotB.getAttribute('title')).not.toBe(dotA.getAttribute('title'));
});
