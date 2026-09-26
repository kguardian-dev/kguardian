// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { CONTENTION_ACTIVE, CONTENTION_TOGGLE_TOOLTIP, DAEMONSET_ACTIVE, DAEMONSET_TOGGLE_TOOLTIP, EXTERNAL_ACTIVE, GraphControls, TRAFFIC_ACTIVE } from './GraphControls';

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

// Contention toggle (design D8): on by default, offered only when there is a
// contention edge to control, its own hue (error red, shared with the edges).

test('Contention toggle is not offered when there are no contention edges', () => {
  render(<GraphControls {...props({ onToggleContention: vi.fn(), contentionCount: 0 })} />);
  expect(screen.queryByTitle(CONTENTION_TOGGLE_TOOLTIP)).toBeNull();
});

test('Contention toggle: on by default, shows the edge count, fires its callback', () => {
  const onToggleContention = vi.fn();
  render(<GraphControls {...props({ onToggleContention, contentionCount: 2 })} />);
  const btn = screen.getByTitle(CONTENTION_TOGGLE_TOOLTIP);
  expect(btn.textContent).toBe('Contention (2)');
  expect(btn.getAttribute('aria-pressed')).toBe('true');
  expect(btn.className).toContain(CONTENTION_ACTIVE);
  // Ordering: Traffic, External, DaemonSets, Contention, Layout.
  const labels = screen.getAllByRole('button').map((b) => b.textContent);
  expect(labels).toEqual(['Traffic', 'External (3)', 'DaemonSets (5 hidden)', 'Contention (2)', 'Layout']);
  fireEvent.click(btn);
  expect(onToggleContention).toHaveBeenCalledTimes(1);
});

test('while off, the Contention hidden-count hint carries the contention hue', () => {
  render(<GraphControls {...props({ showContention: false, onToggleContention: vi.fn(), contentionCount: 2 })} />);
  const btn = screen.getByTitle(CONTENTION_TOGGLE_TOOLTIP);
  expect(btn.textContent).toBe('Contention (2 hidden)');
  expect(btn.getAttribute('aria-pressed')).toBe('false');
  expect(btn.className).not.toContain('hubble-error');
  expect(btn.querySelector('span.text-hubble-error')?.textContent).toBe('(2 hidden)');
});

test('the Contention hue is distinct from the other three toggles', () => {
  expect(CONTENTION_ACTIVE).toContain('hubble-error');
  for (const other of [TRAFFIC_ACTIVE, EXTERNAL_ACTIVE, DAEMONSET_ACTIVE]) expect(other).not.toContain('hubble-error');
});

test('lens control: four lenses, the active one pressed, a pick reports the lens', () => {
  const onLensChange = vi.fn();
  render(<GraphControls {...props({ lens: 'vulns', onLensChange })} />);
  const group = screen.getByRole('group', { name: 'Map lens' });
  const buttons = [...group.querySelectorAll('button')];
  expect(buttons.map((b) => b.textContent)).toEqual(['None', 'Vulnerabilities', 'Supply chain', 'Coverage']);
  // Only the edges toggle is called Traffic.
  expect(screen.getAllByRole('button').filter((b) => b.textContent === 'Traffic')).toHaveLength(1);
  expect(buttons.map((b) => b.getAttribute('aria-pressed'))).toEqual(['false', 'true', 'false', 'false']);
  fireEvent.click(buttons[3]);
  expect(onLensChange).toHaveBeenCalledWith('coverage');
  // Narrow screens get the same choice as a select.
  fireEvent.change(screen.getByRole('combobox', { name: 'Map lens' }), { target: { value: 'supply' } });
  expect(onLensChange).toHaveBeenLastCalledWith('supply');
});
