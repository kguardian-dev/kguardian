import { describe, expect, test } from 'vitest';
import type { PodInfo, PodNodeData } from '../types';
import { isHostNetworkTarget } from './hostNetwork';

// isHostNetworkTarget looks at the whole identity group, not just the primary
// pod: during a rollout that flips hostNetwork, old and new pods coexist and
// the WARNING must still be emitted. null/absent (old broker) never counts.

const pod = (name: string, host_network: boolean | null | undefined): PodInfo => ({
  pod_name: name, pod_ip: '10.0.0.1', pod_namespace: 'ns', time_stamp: 't', node_name: 'n', is_dead: false,
  ...(host_network !== undefined && { host_network }),
});
const group = (primary: PodInfo, ...rest: PodInfo[]): PodNodeData =>
  ({ id: primary.pod_name, label: primary.pod_name, pod: primary, pods: [primary, ...rest], traffic: [], isExpanded: false }) as PodNodeData;

describe('isHostNetworkTarget', () => {
  test('primary false, one group member true ⇒ host-network (mid-rollout flip warns)', () => {
    expect(isHostNetworkTarget(group(pod('a', false), pod('b', false), pod('c', true)))).toBe(true);
  });
  test('primary true ⇒ host-network regardless of the group', () => {
    expect(isHostNetworkTarget(group(pod('a', true), pod('b', false)))).toBe(true);
  });
  test('all false ⇒ not host-network', () => {
    expect(isHostNetworkTarget(group(pod('a', false), pod('b', false)))).toBe(false);
  });
  test('all null / absent (old broker) ⇒ not host-network', () => {
    expect(isHostNetworkTarget(group(pod('a', null), pod('b', undefined)))).toBe(false);
  });
  test('group missing entirely ⇒ falls back to the primary pod only', () => {
    const single = { ...group(pod('a', false)), pods: undefined } as unknown as PodNodeData;
    expect(isHostNetworkTarget(single)).toBe(false);
  });
});
