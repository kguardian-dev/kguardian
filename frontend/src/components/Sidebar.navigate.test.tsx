// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { Share2 } from 'lucide-react';
import { Sidebar } from './Sidebar';

afterEach(cleanup);

test('a nav item runs its action, then onNavigate (the narrow-screen overlay closes on it)', () => {
  const order: string[] = [];
  const onClick = vi.fn(() => order.push('item'));
  const onNavigate = vi.fn(() => order.push('navigate'));
  render(<Sidebar version="t" items={[{ id: 'map', label: 'Network Map', icon: Share2, group: 'Views', onClick }]} onNavigate={onNavigate} />);
  fireEvent.click(screen.getByText('Network Map'));
  expect(order).toEqual(['item', 'navigate']);
});

test('both toggles say whether the rail is expanded', () => {
  const items = [{ id: 'map', label: 'Network Map', icon: Share2, group: 'Views', onClick: () => {} }];
  const { rerender } = render(<Sidebar version="t" items={items} collapsed onToggleCollapse={() => {}} />);
  expect(screen.getByRole('button', { name: 'Expand sidebar' }).getAttribute('aria-expanded')).toBe('false');
  rerender(<Sidebar version="t" items={items} collapsed={false} onToggleCollapse={() => {}} />);
  expect(screen.getByRole('button', { name: 'Collapse sidebar' }).getAttribute('aria-expanded')).toBe('true');
});
