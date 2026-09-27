import type { ContainerCapabilities } from '../types/profile';

/** `kg_runtime_coverage` reasons in words (shared with drift's not-evaluated reasons). */
const RUNTIME_COVERAGE_TEXT: Record<string, string> = {
  no_runtime_data: 'no runtime capture heartbeat for this container',
  probes_missing: 'the exec probe was off on at least one instance',
  libraries_not_tracked: 'the runtime inventory runs in exec mode on at least one instance (full mode is needed)',
  events_dropped: 'the capture lost events in the window',
  events_pending: 'events were still waiting to reach the Broker',
  incomplete_paths: 'some captured paths are incomplete',
  capture_gap: 'the capture has a gap in the window (or began inside it)',
};

/** A `kg_runtime_coverage` reason in words, or null for a reason it does not return. */
export function runtimeCoverageText(reason: string): string | null {
  return RUNTIME_COVERAGE_TEXT[reason] ?? null;
}

/**
 * Why capability evidence is insufficient (contract section 2.9): a
 * `kg_runtime_coverage` reason or one of the capability checks. An unknown
 * reason is shown as itself, never dropped.
 */
export function capabilityEvidenceText(reason: string | null | undefined): string {
  if (reason && RUNTIME_COVERAGE_TEXT[reason]) return RUNTIME_COVERAGE_TEXT[reason];
  switch (reason) {
    case null:
    case undefined:
      return 'not stated';
    case 'capabilities_not_tracked':
      return 'the capability probe was off on at least one instance';
    case 'capabilities_partial_hook':
      return 'the capability probe ran on the security_capable fallback, which misses some checks';
    case 'capabilities_not_seen_since_start':
      return 'the container was already running when the probe attached: capabilities used at startup were not seen. It becomes evidence once it restarts under the probe';
    case 'no_current_digest':
      return 'the container runs no current digest';
    case 'coverage_unavailable':
      return 'runtime coverage cannot be read (the coverage function is missing from the database)';
    case 'retention_shorter_than_window':
      return 'runtime data is kept for less time than the evidence window, so the window cannot be covered';
    case 'rows_truncated':
      return 'more capability rows than one read covers';
    default:
      return `reason "${reason}"`;
  }
}

/** "7 d" / "36 h": the evidence window as the UI says it. */
export function windowText(hours: number): string {
  return hours % 24 === 0 ? `${hours / 24} d` : `${hours} h`;
}

/** Every capability this container is known to need or ask for, for a quick summary line. */
export function capabilitySummary(c: ContainerCapabilities): string {
  const parts: string[] = [];
  if (c.used.length) parts.push(`${c.used.length} used`);
  if (c.probed.length) parts.push(`${c.probed.length} probed`);
  if (c.denied.length) parts.push(`${c.denied.length} denied`);
  return parts.length ? parts.join(', ') : 'none observed';
}
