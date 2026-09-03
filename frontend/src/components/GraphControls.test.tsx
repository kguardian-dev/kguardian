// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { DAEMONSET_TOGGLE_TOOLTIP, GraphControls } from './GraphControls';

afterEach(cleanup);

const props = (over: Partial<Parameters<typeof GraphControls>[0]> = {}) => ({
  showTraffic: true, onToggleTraffic: vi.fn(),
  showExternalNodes: true, onToggleExternalNodes: vi.fn(), externalCount: 3,
  showDaemonSetNodes: false, onToggleDaemonSetNodes: vi.fn(), daemonSetCount: 5,
  layoutDirection: 'LR' as const, onToggleLayoutDirection: vi.fn(),
  ...over,
});

test('DaemonSets toggle sits next to External, off by default, reports the hidden count, and fires its callback', () => {
  const p = props();
  render(<GraphControls {...p} />);
  const btn = screen.getByTitle(DAEMONSET_TOGGLE_TOOLTIP);
  expect(btn.textContent).toBe('DaemonSets (5 hidden)');
  expect(btn.getAttribute('aria-pressed')).toBe('false');
  // Ordering: Traffic, External, DaemonSets, Layout.
  const labels = screen.getAllByRole('button').map((b) => b.textContent);
  expect(labels).toEqual(['Traffic', 'External (3)', 'DaemonSets (5 hidden)', 'Layout']);
  fireEvent.click(btn);
  expect(p.onToggleDaemonSetNodes).toHaveBeenCalledTimes(1);
  expect(p.onToggleExternalNodes).not.toHaveBeenCalled();
});

test('when on, the count is shown without the hidden hint', () => {
  render(<GraphControls {...props({ showDaemonSetNodes: true })} />);
  const btn = screen.getByTitle(DAEMONSET_TOGGLE_TOOLTIP);
  expect(btn.textContent).toBe('DaemonSets (5)');
  expect(btn.getAttribute('aria-pressed')).toBe('true');
});

test('no count suffix when there is nothing to hide', () => {
  render(<GraphControls {...props({ daemonSetCount: 0 })} />);
  expect(screen.getByTitle(DAEMONSET_TOGGLE_TOOLTIP).textContent).toBe('DaemonSets');
});

test('the toggle is only offered while external nodes are shown', () => {
  render(<GraphControls {...props({ showExternalNodes: false })} />);
  expect(screen.queryByTitle(DAEMONSET_TOGGLE_TOOLTIP)).toBeNull();
});
