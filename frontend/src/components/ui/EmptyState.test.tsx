// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { Inbox } from 'lucide-react';
import { Button } from './Button';
import { EmptyState } from './EmptyState';
import { GraphSkeleton, Skeleton } from './Skeleton';

// @testing-library's auto-cleanup only self-registers under `globals: true`.
afterEach(cleanup);

test('renders the title as a heading so empty screens keep a document outline', () => {
  render(<EmptyState icon={Inbox} title="No workloads" />);
  expect(screen.getByRole('heading', { name: 'No workloads' })).toBeTruthy();
});

test('omits description and action containers when not supplied', () => {
  // The optional slots must collapse rather than leaving empty padded divs that
  // push the layout around.
  const { container } = render(<EmptyState icon={Inbox} title="No workloads" />);
  expect(container.querySelector('p')).toBeNull();
  expect(screen.queryByRole('button')).toBeNull();
});

test('renders description and action when supplied', () => {
  render(
    <EmptyState
      icon={Inbox}
      title="No verdicts yet"
      description="Policies are evaluated as traffic arrives."
      action={<Button>Create a policy</Button>}
    />,
  );
  expect(screen.getByText('Policies are evaluated as traffic arrives.')).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Create a policy' })).toBeTruthy();
});

test('compact reduces padding rather than changing the content', () => {
  const { container: full } = render(<EmptyState icon={Inbox} title="a" />);
  const fullCls = (full.firstChild as HTMLElement).className;
  cleanup();
  const { container: compact } = render(<EmptyState icon={Inbox} title="a" compact />);
  const compactCls = (compact.firstChild as HTMLElement).className;

  expect(fullCls).toContain('py-16');
  expect(compactCls).toContain('py-10');
});

test('Skeleton merges caller classes onto the pulse block', () => {
  const { container } = render(<Skeleton className="h-3 w-1/2" />);
  const cls = (container.firstChild as HTMLElement).className;
  expect(cls).toContain('animate-pulse');
  expect(cls).toContain('h-3');
  expect(cls).toContain('w-1/2');
});

test('GraphSkeleton is hidden from assistive tech', () => {
  // It is decorative scaffolding; announcing its placeholder boxes while the
  // real graph loads would be noise.
  const { container } = render(<GraphSkeleton />);
  expect((container.firstChild as HTMLElement).getAttribute('aria-hidden')).toBe('true');
});
