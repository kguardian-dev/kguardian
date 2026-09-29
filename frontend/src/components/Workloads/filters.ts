import { hasBlockingDrift, type WorkloadRow } from '../../utils/workloads';

/**
 * The Workloads table's column filters. Each option selects the same rows its
 * summary tile counts (Would-deny, Seccomp enforcing, Drifted, Partial
 * capture), so a tile's number is the row count with that filter on.
 */
export interface ColumnFilters {
  network: '' | 'would-deny' | 'audit' | 'unreported';
  seccomp: '' | 'enforcing' | 'audit' | 'none';
  drift: '' | 'drifted' | 'in-sync' | 'no-cr';
  capture: '' | 'partial' | 'full';
}

export type ColumnFilterKey = keyof ColumnFilters;

export const NO_COLUMN_FILTERS: ColumnFilters = { network: '', seccomp: '', drift: '', capture: '' };

export const COLUMN_FILTER_OPTIONS: { [K in ColumnFilterKey]: { label: string; options: Array<{ value: Exclude<ColumnFilters[K], ''>; label: string; clause: string }> } } = {
  network: {
    label: 'Network',
    options: [
      { value: 'would-deny', label: 'Would-deny', clause: 'a recent would-deny audit verdict' },
      { value: 'audit', label: 'Audit verdicts', clause: 'recent audit verdicts' },
      { value: 'unreported', label: 'Not reported', clause: 'no reported network policy' },
    ],
  },
  seccomp: {
    label: 'Seccomp',
    options: [
      { value: 'enforcing', label: 'Enforcing', clause: 'an enforcing seccomp CR' },
      { value: 'audit', label: 'Audit mode', clause: 'an audit-mode seccomp CR' },
      { value: 'none', label: 'No CR', clause: 'no seccomp CR' },
    ],
  },
  drift: {
    label: 'Drift',
    options: [
      { value: 'drifted', label: 'Drifted', clause: 'syscall drift from its CR' },
      { value: 'in-sync', label: 'In sync', clause: 'a CR in sync with its observed syscalls' },
      { value: 'no-cr', label: 'No CR', clause: 'no CR to drift from' },
    ],
  },
  capture: {
    label: 'Capture',
    options: [
      { value: 'partial', label: 'Partial', clause: 'partial capture' },
      { value: 'full', label: 'Full', clause: 'full capture' },
    ],
  },
};

/** Filters the seccomp columns have no column for. */
const ALL_CONTROLS_ONLY: ReadonlySet<ColumnFilterKey> = new Set(['network']);

/** The filters the table shown has a column for. */
export function shownColumnFilters(seccompMode: boolean): ColumnFilterKey[] {
  return (Object.keys(COLUMN_FILTER_OPTIONS) as ColumnFilterKey[]).filter((k) => !(seccompMode && ALL_CONTROLS_ONLY.has(k)));
}

/** The filters that are set and apply to the table shown. */
export function activeColumnFilters(filters: ColumnFilters, seccompMode: boolean): ColumnFilterKey[] {
  return shownColumnFilters(seccompMode).filter((k) => filters[k] !== '');
}

export interface UnknownInputs {
  /** The audit verdicts are loading or could not be read: no row's network state is known. */
  verdictsUnknown: boolean;
}

/** Whether `row` passes filter `key`, or null when its value is not known. */
export function matchColumn(row: WorkloadRow, key: ColumnFilterKey, filters: ColumnFilters, unknown: UnknownInputs): boolean | null {
  switch (key) {
    case 'network': {
      if (unknown.verdictsUnknown) return null;
      const n = row.network;
      if (filters.network === 'would-deny') return n.state === 'audit' && n.wouldDeny > 0;
      if (filters.network === 'audit') return n.state === 'audit';
      return n.state === 'unreported';
    }
    case 'seccomp':
      return row.seccomp === 'unknown' ? null : row.seccomp === filters.seccomp;
    case 'drift':
      // Drift is only known where the CR state is.
      if (row.seccomp === 'unknown') return null;
      if (filters.drift === 'drifted') return hasBlockingDrift(row.drift);
      if (filters.drift === 'in-sync') return row.drift !== null && row.drift.missing.length === 0;
      return row.drift === null;
    case 'capture':
      if (row.capture === null) return null;
      return filters.capture === 'partial' ? !row.capture.complete : row.capture.complete;
  }
}

export interface ColumnFilterResult {
  rows: WorkloadRow[];
  /** Rows left out only because a filter's value is unknown for them. */
  unknownRows: number;
  /** The filters whose value was unknown for those rows. */
  unknownFilters: ColumnFilterKey[];
}

/**
 * The rows that pass every active filter. A row whose value is unknown for a
 * filter, and that no other filter rules out, is left out and counted, so the
 * table can say so rather than drop it silently or count it as a "no".
 */
export function applyColumnFilters(rows: readonly WorkloadRow[], filters: ColumnFilters, seccompMode: boolean, unknown: UnknownInputs): ColumnFilterResult {
  const keys = activeColumnFilters(filters, seccompMode);
  const unknownFilters = new Set<ColumnFilterKey>();
  let unknownRows = 0;
  const kept = rows.filter((row) => {
    const results = keys.map((key) => [key, matchColumn(row, key, filters, unknown)] as const);
    if (results.some(([, m]) => m === false)) return false;
    const unread = results.filter(([, m]) => m === null);
    if (unread.length === 0) return true;
    unknownRows += 1;
    for (const [key] of unread) unknownFilters.add(key);
    return false;
  });
  return { rows: kept, unknownRows, unknownFilters: keys.filter((k) => unknownFilters.has(k)) };
}

const UNKNOWN_LABEL: Record<ColumnFilterKey, string> = {
  network: 'the network policy state',
  seccomp: 'the seccomp CR state',
  drift: 'the drift',
  capture: 'the capture',
};

/** "a", "a and b", "a, b and c". */
export function joinClauses(clauses: string[]): string {
  return clauses.length <= 1 ? clauses.join('') : `${clauses.slice(0, -1).join(', ')} and ${clauses.at(-1)}`;
}

/** Says how many rows a filter left out for want of data, or null when none. */
export function unknownRowsNote({ unknownRows, unknownFilters }: Pick<ColumnFilterResult, 'unknownRows' | 'unknownFilters'>): string | null {
  if (unknownRows === 0) return null;
  const what = joinClauses(unknownFilters.map((k) => UNKNOWN_LABEL[k]));
  const one = unknownRows === 1;
  return `${unknownRows} ${one ? 'workload is' : 'workloads are'} not shown because ${what} ${unknownFilters.length === 1 ? 'is' : 'are'} not known for ${one ? 'it' : 'them'} yet.`;
}

/** The active filters as clauses for the empty state ("an enforcing seccomp CR"). */
export function columnFilterClauses(filters: ColumnFilters, seccompMode: boolean): string[] {
  return activeColumnFilters(filters, seccompMode).map((k) => {
    const opt = (COLUMN_FILTER_OPTIONS[k].options as Array<{ value: string; clause: string }>).find((o) => o.value === filters[k]);
    return opt?.clause ?? '';
  });
}
