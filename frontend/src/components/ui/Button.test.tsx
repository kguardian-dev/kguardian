// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { createRef } from 'react';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { Search } from 'lucide-react';
import { Button } from './Button';

// @testing-library's auto-cleanup only self-registers under `globals: true`.
afterEach(cleanup);

// The point of this primitive is that height and padding can never drift again
// (they had, across ~14 inline signatures). So the tests worth having are the
// ones that fail when a variant or size silently stops routing through the
// shared tables, plus the defaults every call site relies on.

test('defaults to a secondary, medium, type="button" control', () => {
  // type matters: an untyped button inside a form submits it. Several of these
  // live inside the policy editor's form.
  render(<Button>Save</Button>);
  const btn = screen.getByRole('button', { name: 'Save' });
  expect(btn.getAttribute('type')).toBe('button');
  expect(btn.className).toContain('h-9');
});

test('each size maps to exactly one height', () => {
  render(
    <>
      <Button size="sm">small</Button>
      <Button size="md">medium</Button>
    </>,
  );
  expect(screen.getByRole('button', { name: 'small' }).className).toContain('h-8');
  expect(screen.getByRole('button', { name: 'medium' }).className).toContain('h-9');
});

test('icon-only collapses to a square of the same height', () => {
  // A square icon button must match the height of the text buttons beside it,
  // which is what kept breaking when each call site rolled its own padding.
  render(
    <>
      <Button iconOnly size="sm" leftIcon={Search} aria-label="search small" />
      <Button iconOnly size="md" leftIcon={Search} aria-label="search medium" />
    </>,
  );
  const sm = screen.getByRole('button', { name: 'search small' }).className;
  const md = screen.getByRole('button', { name: 'search medium' }).className;
  expect(sm).toContain('h-8');
  expect(sm).toContain('w-8');
  expect(md).toContain('h-9');
  expect(md).toContain('w-9');
});

test('every variant resolves to a token class, never an undefined lookup', () => {
  // A typo'd variant would render the literal string "undefined" into class,
  // which looks like an unstyled button rather than an error.
  for (const variant of ['primary', 'secondary', 'ghost', 'danger', 'success'] as const) {
    const { unmount } = render(<Button variant={variant}>{variant}</Button>);
    const cls = screen.getByRole('button', { name: variant }).className;
    expect(cls).not.toContain('undefined');
    expect(cls).toContain('border');
    unmount();
  }
});

test('caller className is appended, not swapped in', () => {
  render(<Button className="w-full">wide</Button>);
  const cls = screen.getByRole('button', { name: 'wide' }).className;
  expect(cls).toContain('w-full');
  expect(cls).toContain('h-9'); // base sizing survives
});

test('forwards refs and click handlers, and respects disabled', () => {
  const ref = createRef<HTMLButtonElement>();
  const onClick = vi.fn();
  render(
    <>
      <Button ref={ref} onClick={onClick}>go</Button>
      <Button disabled onClick={onClick}>nope</Button>
    </>,
  );

  expect(ref.current).toBeInstanceOf(HTMLButtonElement);
  fireEvent.click(screen.getByRole('button', { name: 'go' }));
  expect(onClick).toHaveBeenCalledTimes(1);

  const disabled = screen.getByRole('button', { name: 'nope' }) as HTMLButtonElement;
  expect(disabled.disabled).toBe(true);
  fireEvent.click(disabled);
  expect(onClick).toHaveBeenCalledTimes(1);
});
