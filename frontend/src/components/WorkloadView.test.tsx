// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';

afterEach(cleanup);

vi.mock('../hooks/useSeccompProfiles', () => ({
  useSeccompProfiles: () => ({ api: {}, profiles: [], loading: false, error: null, refresh: async () => {} }),
}));
vi.mock('../services/api', () => ({ default: { getAuditVerdicts: async () => [] } }));
vi.mock('./DataTable', () => ({ default: () => <div /> }));

import { WorkloadView } from './WorkloadView';

const props = {
  ns: 'payments', kind: 'Deployment', name: 'api', pods: [], allPods: [], services: [],
  onBack: () => {}, onOpenInMap: () => {},
};

// A cold deep link: profiles answered (empty) but the pod list is still in
// flight. "No workload" here would be a claim that flashes before the data lands.
test('while the pod list is loading, a missing row is not reported as "no workload"', () => {
  render(<WorkloadView {...props} podsLoading />);
  expect(screen.queryByText(/No workload/)).toBeNull();
});

test('once everything has loaded, a missing row says so', () => {
  render(<WorkloadView {...props} podsLoading={false} />);
  expect(screen.getByText('No workload payments/api')).not.toBeNull();
});
