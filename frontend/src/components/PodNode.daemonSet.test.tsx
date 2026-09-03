// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { cleanup, render } from '@testing-library/react';
import { ReactFlowProvider } from 'reactflow';
import PodNode from './PodNode';
import type { PodInfo } from '../types';

// DaemonSet / host-network peer cards carry the DaemonSets hue on their spine
// and icon — and nothing else: the operator asked for no tag text on the node,
// the colour alone ties the toggle, the node and its edges together.

afterEach(cleanup);

const pod = (name: string, extra: Partial<PodInfo> = {}): PodInfo => ({
  pod_name: name, pod_ip: '192.168.50.101', pod_namespace: 'observability', time_stamp: 't', node_name: 'worker-1', is_dead: false, ...extra,
});
const renderNode = (pods: PodInfo[], isExternal = true) => {
  const data = { id: 'n', label: 'node-exporter', pod: pods[0], pods, traffic: [], isExpanded: false, isExternal, externalNamespace: 'observability', onToggle: () => {}, onFocus: () => {} };
  return render(
    <ReactFlowProvider>
      <PodNode id="n" data={data as never} selected={false} type="podNode" xPos={0} yPos={0} zIndex={0} isConnectable={false} dragging={false} />
    </ReactFlowProvider>,
  );
};

test('DaemonSet peer: teal spine, no badge text', () => {
  const { container } = renderNode([pod('node-exporter-abc', { workload_kind: 'DaemonSet', host_network: true })]);
  expect(container.querySelector('.border-l-hubble-info')).not.toBeNull();
  expect(container.querySelector('.border-l-hubble-warning')).toBeNull();
  expect(container.textContent).not.toMatch(/DaemonSet|host-network/);
});

test('ordinary external peer keeps the amber spine', () => {
  const { container } = renderNode([pod('grafana-0', { workload_kind: 'Deployment', host_network: false })]);
  expect(container.querySelector('.border-l-hubble-warning')).not.toBeNull();
  expect(container.querySelector('.border-l-hubble-info')).toBeNull();
});
