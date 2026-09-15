// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { ReactFlowProvider } from 'reactflow';
import PodNode from './PodNode';
import type { NetworkTraffic, PodInfo, PodNodeData } from '../types';

// A denied flow is the signal this tool exists to surface, and until now the
// card said nothing about it: the count was in the namespace summary and the
// individual flows were red edges, so answering "which workload is being
// denied" meant tracing the graph by eye. The badge puts it on the card, which
// is what an operator actually scans.

afterEach(cleanup);

const pod: PodInfo = {
  pod_name: 'api-1', pod_ip: '10.0.0.1', pod_namespace: 'payments',
  time_stamp: 't', node_name: 'worker-1', is_dead: false,
};

const flow = (decision: string | null): NetworkTraffic =>
  ({ traffic_in_out_ip: '10.0.0.9', traffic_type: 'EGRESS', decision }) as unknown as NetworkTraffic;

const card = (traffic: NetworkTraffic[]): PodNodeData =>
  ({ id: 'payments-api', label: 'api', pod, pods: [pod], traffic }) as unknown as PodNodeData;

const render1 = (data: PodNodeData) =>
  render(
    <ReactFlowProvider>
      <PodNode data={data} selected={false} />
    </ReactFlowProvider>,
  );

test('a card with denied flows shows the count', () => {
  render1(card([flow('DROP'), flow('ALLOW'), flow('DROP')]));
  const badge = screen.getByTestId('denied-badge');
  expect(badge.textContent).toContain('2');
  // Read on the accessible name rather than the colour, which is the whole
  // point of pairing the number with an icon and a label.
  expect(badge.getAttribute('aria-label')).toBe('2 denied flows');
});

test('the count is singular for one denial', () => {
  render1(card([flow('DROP'), flow('ALLOW')]));
  expect(screen.getByTestId('denied-badge').getAttribute('aria-label')).toBe('1 denied flow');
});

test('decision casing from the broker does not change the count', () => {
  // The column is free text ("ALLOW or DROP"); rows have arrived lowercase.
  render1(card([flow('drop'), flow('Drop')]));
  expect(screen.getByTestId('denied-badge').textContent).toContain('2');
});

test('a card with no denied flows shows no badge at all', () => {
  render1(card([flow('ALLOW'), flow(null)]));
  expect(screen.queryByTestId('denied-badge')).toBeNull();
});

test('a card with no traffic shows no badge', () => {
  render1(card([]));
  expect(screen.queryByTestId('denied-badge')).toBeNull();
});

// The badge sits on the collapsed card: an operator should not have to open a
// workload to find out it is being denied.
test('the badge is visible without expanding the card', () => {
  const data = card([flow('DROP')]);
  expect(data.isExpanded).toBeFalsy();
  render1(data);
  expect(screen.getByTestId('denied-badge')).toBeTruthy();
});
