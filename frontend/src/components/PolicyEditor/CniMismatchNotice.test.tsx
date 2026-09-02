// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { CniMismatchNotice } from './CniMismatchNotice';

afterEach(cleanup);

// The notice backs CNI-aligned policy generation (issue #1413): shown
// only on a REAL mismatch (callers gate on cni !== unknown/cilium), it
// names the detected CNI, warns about both failure modes (CRD absent →
// apply fails; CRD present but unenforced → silently inert), and is
// dismissible without disabling export.

test('names the detected CNI and both failure modes', () => {
  render(<CniMismatchNotice cni="calico" />);
  expect(screen.getByRole('note').textContent).toContain('calico');
  expect(screen.getByRole('note').textContent).toContain('CiliumNetworkPolicy CRD');
  expect(screen.getByRole('note').textContent).toContain('only Cilium enforces it');
});

test('dismiss removes the notice', () => {
  render(<CniMismatchNotice cni="flannel" />);
  fireEvent.click(screen.getByLabelText('Dismiss CNI notice'));
  expect(screen.queryByRole('note')).toBeNull();
});
