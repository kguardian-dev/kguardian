// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { act, cleanup, render } from '@testing-library/react';
import { useMediaQuery } from './useMediaQuery';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function stubMatchMedia(initial: boolean) {
  let matches = initial;
  const listeners = new Set<() => void>();
  vi.stubGlobal('matchMedia', (query: string) => ({
    get matches() { return matches; },
    media: query,
    addEventListener: (_: string, cb: () => void) => listeners.add(cb),
    removeEventListener: (_: string, cb: () => void) => listeners.delete(cb),
  }));
  return (next: boolean) => {
    matches = next;
    listeners.forEach((cb) => cb());
  };
}

function Probe() {
  return <span data-testid="p">{String(useMediaQuery('(max-width: 767px)'))}</span>;
}

test('follows the media query live (resize / rotation), not just on first render', () => {
  const set = stubMatchMedia(false);
  const { getByTestId } = render(<Probe />);
  expect(getByTestId('p').textContent).toBe('false');
  act(() => set(true));
  expect(getByTestId('p').textContent).toBe('true');
  act(() => set(false));
  expect(getByTestId('p').textContent).toBe('false');
});
