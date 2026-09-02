// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { useClusterEnvironment } from './useClusterEnvironment';
import api from '../services/api';
import { UNKNOWN_CLUSTER_ENVIRONMENT } from '../types';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function Probe() {
  const { cni } = useClusterEnvironment();
  return <span data-testid="cni">{cni}</span>;
}

// Contract: starts 'unknown' (never gates rendering), resolves to the
// broker's answer, and any failure stays 'unknown' — "behave exactly
// as before".

test('starts unknown and resolves to the broker value', async () => {
  vi.spyOn(api, 'getClusterEnvironment').mockResolvedValue({
    ...UNKNOWN_CLUSTER_ENVIRONMENT,
    cni: 'calico',
    nodes: 3,
  });
  render(<Probe />);
  expect(screen.getByTestId('cni').textContent).toBe('unknown');
  await waitFor(() => expect(screen.getByTestId('cni').textContent).toBe('calico'));
});

test('stays unknown when the service resolves the fallback', async () => {
  vi.spyOn(api, 'getClusterEnvironment').mockResolvedValue(UNKNOWN_CLUSTER_ENVIRONMENT);
  render(<Probe />);
  await waitFor(() => expect(screen.getByTestId('cni').textContent).toBe('unknown'));
});
