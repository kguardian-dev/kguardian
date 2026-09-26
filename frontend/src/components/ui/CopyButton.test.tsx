// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { CopyButton } from './CopyButton';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

test('copies the exact text and confirms, then resets', async () => {
  vi.useFakeTimers();
  const writeText = vi.fn(async () => {});
  vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } });
  render(<CopyButton text={'securityContext:\n  runAsNonRoot: true\n'} ariaLabel="Copy patch" />);
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Copy patch' }));
  });
  expect(writeText).toHaveBeenCalledWith('securityContext:\n  runAsNonRoot: true\n');
  expect(screen.getByText('Copied')).not.toBeNull();
  await act(async () => {
    vi.advanceTimersByTime(2100);
  });
  expect(screen.queryByText('Copied')).toBeNull();
});

test('a failed copy says so instead of claiming success', async () => {
  vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText: vi.fn(async () => Promise.reject(new Error('denied'))) } });
  // jsdom has no execCommand; the fallback throws too.
  document.execCommand = vi.fn(() => {
    throw new Error('unsupported');
  });
  render(<CopyButton text="x" />);
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Copy' }));
  });
  expect(screen.queryByText('Copied')).toBeNull();
  expect(screen.getByText(/Copy failed/)).not.toBeNull();
});
