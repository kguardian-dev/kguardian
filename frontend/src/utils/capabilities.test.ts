import { expect, test } from 'vitest';
import { capabilityEvidenceText } from './capabilities';

test('every documented insufficient-evidence reason reads as words, and an unknown one as itself', () => {
  for (const r of ['no_runtime_data', 'probes_missing', 'libraries_not_tracked', 'events_dropped', 'events_pending', 'incomplete_paths', 'capture_gap', 'capabilities_not_tracked', 'capabilities_partial_hook', 'capabilities_not_seen_since_start', 'no_current_digest', 'rows_truncated', 'coverage_unavailable', 'retention_shorter_than_window']) {
    expect(capabilityEvidenceText(r)).not.toMatch(/^reason "/);
  }
  expect(capabilityEvidenceText('something_new')).toBe('reason "something_new"');
});
