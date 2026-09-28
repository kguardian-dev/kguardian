// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { cleanup, render } from '@testing-library/react';
import { ReactFlowProvider } from 'reactflow';
import PodNode from './PodNode';
import type { PodInfo, PodNodeData } from '../types';

// F-08 (MAP-03): a workload whose traffic read timed out used to look
// flow-less and vanish. It keeps its card and says what happened.

afterEach(cleanup);

const pod: PodInfo = { pod_name: 'rollouts-1', pod_ip: '10.0.0.1', pod_namespace: 'argocd', time_stamp: 't', node_name: 'worker-1', is_dead: false };
const renderNode = (over: Partial<PodNodeData>) =>
  render(
    <ReactFlowProvider>
      <PodNode
        data={{ id: 'argocd-rollouts', label: 'argo-rollouts', pod, pods: [pod], traffic: [], isExpanded: false, isExternal: false, ...over } as never}
        selected={false}
      />
    </ReactFlowProvider>,
  );

test('no badge when every read answered', () => {
  const { queryByTestId, container } = renderNode({ trafficError: false, syscallsError: false });
  expect(queryByTestId('read-failed-badge')).toBeNull();
  expect(container.textContent).not.toMatch(/read failed/);
});

test('a failed traffic read is a visible badge that says so and how to retry', () => {
  const { getByTestId } = renderNode({ trafficError: true });
  const badge = getByTestId('read-failed-badge');
  expect(badge.textContent).toBe('traffic read failed');
  expect(badge.getAttribute('title')).toMatch(/Refresh to retry/);
  expect(badge.getAttribute('aria-label')).toMatch(/traffic read failed/);
  expect(badge.className).toContain('hubble-warning'); // an event, not the lens "unknown" tone
});

test('the badge names whichever reads failed', () => {
  expect(renderNode({ syscallsError: true }).getByTestId('read-failed-badge').textContent).toBe('syscall read failed');
  cleanup();
  expect(renderNode({ trafficError: true, syscallsError: true }).getByTestId('read-failed-badge').textContent).toBe('traffic and syscall reads failed');
});

test('the open card does not claim "no traffic recorded" for a read that failed', () => {
  const { container } = renderNode({ trafficError: true, isExpanded: true });
  expect(container.textContent).toMatch(/Traffic unknown: the read failed/);
  expect(container.textContent).not.toMatch(/No traffic or syscalls recorded yet/);
  cleanup();
  const honest = renderNode({ trafficError: false, isExpanded: true });
  expect(honest.container.textContent).toMatch(/No traffic or syscalls recorded yet/);
});
