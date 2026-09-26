// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { FindingsTable } from './FindingsTable';
import { vulnCapture } from '../../fixtures/vulns';
import type { ImageVulnsPage } from '../../types/vulns';

afterEach(cleanup);

const captured = vulnCapture<ImageVulnsPage>('image-checkout-vulnerabilities').body;
// Test-local: busybox as a Broker with runtime data (P1-2, not on main yet)
// would send it, installed but not seen running over a 24h window.
const checkout = {
  ...captured,
  items: captured.items.map((f) =>
    f.id === 'CVE-2099-0004'
      ? { ...f, tier: 'Background', tierFactors: ['in_use:installed_not_observed', 'severity:low', 'exposed'], inUseState: 'installed_not_observed', inUse: false, inUseDetail: { ...f.inUseDetail!, state: 'installed_not_observed', reason: null, windowHours: 24 } }
      : f,
  ),
};

test('a Background finding shows the caveat as text, with its covered window', () => {
  render(<FindingsTable items={checkout.items} onOpenCve={() => {}} />);
  expect(screen.getByTestId('background-caveat').textContent).toBe('Background: installed, not seen running over the covered window (1d). Not proof it is unreachable.');
});

test('no Background finding, no caveat', () => {
  render(<FindingsTable items={checkout.items.filter((f) => f.tier !== 'Background')} onOpenCve={() => {}} />);
  expect(screen.queryByTestId('background-caveat')).toBeNull();
});
