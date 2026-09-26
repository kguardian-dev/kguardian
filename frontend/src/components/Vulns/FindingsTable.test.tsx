// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { FindingsTable } from './FindingsTable';
import { tierFixture } from '../../fixtures/vulns';
import type { ImageVulnsPage } from '../../types/vulns';

afterEach(cleanup);

const checkout = tierFixture<ImageVulnsPage>('image-checkout-vulnerabilities').body;

test('a Background finding shows the caveat as text, with its covered window', () => {
  render(<FindingsTable items={checkout.items} onOpenCve={() => {}} />);
  expect(screen.getByTestId('background-caveat').textContent).toBe('Background: installed, not seen running over the covered window (1d). Not proof it is unreachable.');
});

test('no Background finding, no caveat', () => {
  render(<FindingsTable items={checkout.items.filter((f) => f.tier !== 'Background')} onOpenCve={() => {}} />);
  expect(screen.queryByTestId('background-caveat')).toBeNull();
});
