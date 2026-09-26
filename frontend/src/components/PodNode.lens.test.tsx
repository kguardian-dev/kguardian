// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { cleanup, render } from '@testing-library/react';
import { ReactFlowProvider } from 'reactflow';
import PodNode from './PodNode';
import type { LensBadge, PodInfo } from '../types';

// Map lens badge: absent under Traffic (the card is the pre-lens card),
// present with its tone and full-sentence label otherwise.

afterEach(cleanup);

const pod: PodInfo = { pod_name: 'checkout-1', pod_ip: '10.0.0.1', pod_namespace: 'payments', time_stamp: 't', node_name: 'worker-1', is_dead: false };
const renderNode = (lensBadge?: LensBadge) =>
  render(
    <ReactFlowProvider>
      <PodNode
        data={{ id: 'payments-checkout', label: 'checkout', pod, pods: [pod], traffic: [], isExpanded: false, isExternal: false, onToggle: () => {}, onFocus: () => {}, lensBadge } as never}
        selected={false}
      />
    </ReactFlowProvider>,
  );

test('no badge without a lens', () => {
  const { queryByTestId } = renderNode();
  expect(queryByTestId('lens-badge')).toBeNull();
});

test('the badge carries its tone, short text and full label', () => {
  const badge: LensBadge = { lens: 'vulns', tone: 'p0', text: 'P0 · 2', label: '2 P0/P1 vulnerabilities on running images, worst P0: CVE-2099-0001, CVE-2099-0002.' };
  const { getByTestId } = renderNode(badge);
  const el = getByTestId('lens-badge');
  expect(el.textContent).toBe('P0 · 2');
  expect(el.getAttribute('data-tone')).toBe('p0');
  expect(el.getAttribute('aria-label')).toBe(badge.label);
  expect(el.className).toContain('text-tier-p0');
});

test('unknown is dashed and muted, never the good tone', () => {
  const { getByTestId } = renderNode({ lens: 'vulns', tone: 'unknown', text: 'no data', label: 'No source has reported on the images this workload runs.' });
  const el = getByTestId('lens-badge');
  expect(el.className).toContain('border-dashed');
  expect(el.className).not.toContain('state-enforcing');
});
