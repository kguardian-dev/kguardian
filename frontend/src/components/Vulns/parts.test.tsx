// @vitest-environment jsdom
import { afterEach, describe, expect, test } from 'vitest';
import { cleanup, render } from '@testing-library/react';

afterEach(cleanup);
import { TierBadge } from './parts';

/** Text a sighted user sees: everything except sr-only spans. */
const seen = (el: Element): string =>
  [...el.childNodes].map((n) => (n instanceof HTMLElement ? (n.classList.contains('sr-only') ? '' : seen(n)) : n.textContent ?? '')).join('');
/** Text a screen reader gets: everything except aria-hidden spans. */
const heard = (el: Element): string =>
  [...el.childNodes].map((n) => (n instanceof HTMLElement ? (n.getAttribute('aria-hidden') === 'true' ? '' : heard(n)) : n.textContent ?? '')).join('');

const badge = (props: Parameters<typeof TierBadge>[0]) => render(<TierBadge {...props} />).container.querySelector('[data-tier]')!;

describe('TierBadge floor', () => {
  test('a floor shows "≥P2" and reads "at least P2"', () => {
    const b = badge({ tier: 'P2', atLeast: true, unknownRows: 3 });
    expect(seen(b)).toBe('≥P2');
    expect(heard(b)).toBe('at least P2; 3 unknown');
    expect(b.getAttribute('title')).toBe('at least P2; 3 rows unknown');
  });

  test('a Background floor is spelled out, not "≥Bkg"', () => {
    const b = badge({ tier: 'Background', atLeast: true, unknownRows: 2 });
    expect(seen(b)).toBe('Background + 2 unknown');
    expect(heard(b)).toBe('Background + 2 unknown');
    expect(b.textContent).not.toContain('≥');
  });

  test('a floor with no row count says "some"', () => {
    expect(seen(badge({ tier: 'Background', atLeast: true }))).toBe('Background + some unknown');
  });

  test('P0 cannot be exceeded, so it is never a floor', () => {
    const b = badge({ tier: 'P0', atLeast: true, unknownRows: 1 });
    expect(b.textContent).toBe('P0');
    expect(b.hasAttribute('data-at-least')).toBe(false);
  });

  test('without a floor: plain tier, "Bkg" for Background', () => {
    expect(badge({ tier: 'P1' }).textContent).toBe('P1');
    expect(badge({ tier: 'Background' }).textContent).toBe('Bkg');
  });
});
