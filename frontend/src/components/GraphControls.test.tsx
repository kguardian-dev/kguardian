// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { DAEMONSET_ACTIVE, DAEMONSET_TOGGLE_TOOLTIP, EXTERNAL_ACTIVE, GraphControls, TRAFFIC_ACTIVE } from './GraphControls';

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

test('each toggle has its own hue: Traffic indigo, External amber, DaemonSets teal', () => {
  render(<GraphControls {...props({ showDaemonSetNodes: true })} />);
  const [traffic, external, daemonSets] = screen.getAllByRole('button');
  expect(traffic.className).toContain(TRAFFIC_ACTIVE);
  expect(external.className).toContain(EXTERNAL_ACTIVE);
  expect(daemonSets.className).toContain(DAEMONSET_ACTIVE);
  // Three distinct tokens — none shares another's colour.
  expect(DAEMONSET_ACTIVE).toContain('hubble-info');
  expect(DAEMONSET_ACTIVE).not.toContain('hubble-warning');
  expect(DAEMONSET_ACTIVE).not.toContain('hubble-accent');
  expect(EXTERNAL_ACTIVE).not.toContain('hubble-info');
  expect(TRAFFIC_ACTIVE).not.toContain('hubble-info');
  expect(daemonSets.className).not.toContain('hubble-warning');
});

test('while off, the hidden-count hint still carries the DaemonSets hue', () => {
  render(<GraphControls {...props()} />);
  const btn = screen.getByTitle(DAEMONSET_TOGGLE_TOOLTIP);
  expect(btn.className).not.toContain('hubble-info');
  expect(btn.querySelector('span.text-hubble-info')?.textContent).toBe('(5 hidden)');
});

test('no count suffix when there is nothing to hide', () => {
  render(<GraphControls {...props({ daemonSetCount: 0 })} />);
  expect(screen.getByTitle(DAEMONSET_TOGGLE_TOOLTIP).textContent).toBe('DaemonSets');
});

test('the toggle is only offered while external nodes are shown', () => {
  render(<GraphControls {...props({ showExternalNodes: false })} />);
  expect(screen.queryByTitle(DAEMONSET_TOGGLE_TOOLTIP)).toBeNull();
});
