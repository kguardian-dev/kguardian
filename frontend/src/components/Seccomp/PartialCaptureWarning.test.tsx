// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { PartialCaptureWarning } from './PartialCaptureWarning';
import { CaptureBadge } from './CaptureBadge';

afterEach(cleanup);

test('renders nothing when capture is complete', () => {
  render(<PartialCaptureWarning capture={{ level: 'full', complete: true, pods: [{ name: 'a', level: 'full' }] }} />);
  expect(screen.queryByRole('alert')).toBeNull();
});

test('names the tier, pods, consequence, and both fixes', () => {
  render(
    <PartialCaptureWarning
      capture={{ level: 'low', complete: false, pods: [{ name: 'web-1', level: 'low' }, { name: 'web-2', level: 'full' }] }}
    />,
  );
  const alert = screen.getByRole('alert');
  expect(alert.textContent).toContain('Partial capture — low tier, 1 pod');
  expect(alert.textContent).toContain('Profile is incomplete and will block syscalls the app uses.');
  expect(alert.textContent).toContain('kguardian.dev/syscall-capture: full');
  expect(alert.textContent).toContain('syscalls.captureLevel=full');
  expect(screen.getByText('web-1')).toBeTruthy();
  expect(screen.queryByText('web-2')).toBeNull();
});

test('missing capture is treated as partial, never full', () => {
  render(<PartialCaptureWarning capture={null} />);
  expect(screen.queryByRole('alert')).toBeNull();
  render(<PartialCaptureWarning capture={{ level: 'unknown', complete: false, pods: [] }} />);
  expect(screen.getByRole('alert').textContent).toContain('unknown tier');
});

test('badge flips between full and partial', () => {
  const { rerender } = render(<CaptureBadge capture={{ level: 'full', complete: true, pods: [] }} />);
  expect(screen.getByText('full')).toBeTruthy();
  rerender(<CaptureBadge capture={{ level: 'medium', complete: false, pods: [{ name: 'p', level: 'medium' }] }} />);
  expect(screen.getByRole('status').textContent).toContain('medium');
  expect(screen.getByRole('status').textContent).toContain('partial');
});
