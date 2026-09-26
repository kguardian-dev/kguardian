// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { CommandPalette } from './CommandPalette';

afterEach(cleanup);

test('the command palette dialog has an accessible name', () => {
  render(<CommandPalette onClose={() => {}} commands={[]} />);
  expect(screen.getByRole('dialog', { name: 'Search and commands' })).toBeTruthy();
});
