import { describe, expect, it } from 'vitest';
import type { WorkloadRow } from '../../utils/workloads';
import { applyColumnFilters, columnFilterClauses, NO_COLUMN_FILTERS, unknownRowsNote, type ColumnFilters } from './filters';

const drift = (missing: string[]) => ({ missing, extra: [], inSync: missing.length === 0 });
const capture = (complete: boolean) => ({ level: complete ? 'full' : 'high', complete, pods: [] });

function row(name: string, over: Partial<WorkloadRow>): WorkloadRow {
  return {
    key: `ns/Deployment/${name}`, namespace: 'ns', kind: 'Deployment', name, pods: [], profile: null,
    seccomp: 'none', drift: null, capture: capture(true), network: { state: 'unreported' }, ...over,
  };
}

const rows: WorkloadRow[] = [
  row('enforcing-drifted', { seccomp: 'enforcing', drift: drift(['clone3']), capture: capture(false), network: { state: 'audit', policies: ['p'], wouldDeny: 2, verdicts: 3 } }),
  row('enforcing-in-sync', { seccomp: 'enforcing', drift: drift([]), network: { state: 'audit', policies: ['p'], wouldDeny: 0, verdicts: 1 } }),
  row('audit-drifted', { seccomp: 'audit', drift: drift(['bpf']) }),
  row('no-cr', { seccomp: 'none', capture: capture(false) }),
  row('unknown', { seccomp: 'unknown', capture: null }),
];

const known = { verdictsUnknown: false };
const names = (f: Partial<ColumnFilters>, seccompMode = false, unknown = known) =>
  applyColumnFilters(rows, { ...NO_COLUMN_FILTERS, ...f }, seccompMode, unknown).rows.map((r) => r.name);

describe('column filters', () => {
  it('no filter keeps every row, unknown ones included', () => {
    expect(names({})).toEqual(rows.map((r) => r.name));
  });

  it('each filter narrows to the rows its tile counts', () => {
    expect(names({ network: 'would-deny' })).toEqual(['enforcing-drifted']);
    expect(names({ network: 'audit' })).toEqual(['enforcing-drifted', 'enforcing-in-sync']);
    expect(names({ network: 'unreported' })).toEqual(['audit-drifted', 'no-cr', 'unknown']);
    expect(names({ seccomp: 'enforcing' })).toEqual(['enforcing-drifted', 'enforcing-in-sync']);
    expect(names({ seccomp: 'audit' })).toEqual(['audit-drifted']);
    expect(names({ seccomp: 'none' })).toEqual(['no-cr']);
    expect(names({ drift: 'drifted' })).toEqual(['enforcing-drifted', 'audit-drifted']);
    expect(names({ drift: 'in-sync' })).toEqual(['enforcing-in-sync']);
    expect(names({ drift: 'no-cr' })).toEqual(['no-cr']);
    expect(names({ capture: 'partial' })).toEqual(['enforcing-drifted', 'no-cr']);
    expect(names({ capture: 'full' })).toEqual(['enforcing-in-sync', 'audit-drifted']);
  });

  it('filters combine', () => {
    expect(names({ seccomp: 'enforcing', drift: 'drifted' })).toEqual(['enforcing-drifted']);
    expect(names({ drift: 'drifted', capture: 'full' })).toEqual(['audit-drifted']);
    expect(names({ seccomp: 'audit', capture: 'partial' })).toEqual([]);
  });

  it('a row whose value is unknown is left out and counted, never read as a "no"', () => {
    const r = applyColumnFilters(rows, { ...NO_COLUMN_FILTERS, drift: 'no-cr' }, false, known);
    expect(r.rows.map((x) => x.name)).toEqual(['no-cr']);
    expect(r.unknownRows).toBe(1);
    expect(r.unknownFilters).toEqual(['drift']);
    expect(unknownRowsNote(r)).toBe('1 workload is not shown because the drift is not known for it yet.');
  });

  it('a row another filter rules out is not counted as unknown', () => {
    const r = applyColumnFilters(rows, { ...NO_COLUMN_FILTERS, seccomp: 'enforcing', network: 'would-deny' }, false, known);
    expect(r.unknownRows).toBe(0);
    expect(unknownRowsNote(r)).toBeNull();
  });

  it('while the audit verdicts are unknown, the network filter shows nothing and says why', () => {
    const r = applyColumnFilters(rows, { ...NO_COLUMN_FILTERS, network: 'unreported' }, false, { verdictsUnknown: true });
    expect(r.rows).toEqual([]);
    expect(unknownRowsNote(r)).toBe('5 workloads are not shown because the network policy state is not known for them yet.');
  });

  it('the seccomp table has no network column, so the network filter does not apply there', () => {
    expect(names({ network: 'would-deny' }, true)).toEqual(rows.map((r) => r.name));
    expect(columnFilterClauses({ ...NO_COLUMN_FILTERS, network: 'would-deny', drift: 'drifted' }, true)).toEqual(['syscall drift from its CR']);
  });
});
