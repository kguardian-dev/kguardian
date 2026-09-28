import { describe, expect, it } from 'vitest';
import { EXTERNAL_SCOPE, ipBlockScope } from './ipBlockScope';
import { hostNetworkPeerComment, hostNetworkServiceComment } from './hostNetwork';
import { selectorlessServiceComment, unattributedPeerComment } from './peerComments';

// The visual editor used to label every ipBlock "External (IP Block)" with
// the hint "External traffic outside the cluster", including node IPs of
// host-network peers and Service ClusterIPs, all of them inside the VPC.
describe('ipBlockScope', () => {
  it('reads the host-network peer comment as a node IP, with no outside-the-cluster hint', () => {
    expect(ipBlockScope([hostNetworkPeerComment('standard', 'monitoring', 'node-exporter', 'worker-1')]))
      .toEqual({ label: 'Node IP (host-network peer)', hint: null });
    expect(ipBlockScope([hostNetworkServiceComment('standard', 'monitoring', 'node-exporter', [], '10.96.0.20')]).label)
      .toBe('Node IP (host-network peer)');
  });

  it('reads the selector-less Service comment as a cluster Service IP', () => {
    expect(ipBlockScope([selectorlessServiceComment('default', 'kubernetes', '10.100.0.1', 'ipBlock')]))
      .toEqual({ label: 'Cluster Service IP', hint: null });
  });

  it('reads the unattributed comment as a former holder, still in-cluster', () => {
    expect(ipBlockScope([unattributedPeerComment('10.244.12.199', '2026-07-23T10:00:00')]))
      .toEqual({ label: 'Unattributed peer IP', hint: null });
    expect(ipBlockScope([unattributedPeerComment('10.244.12.199', undefined)]).label).toBe('Unattributed peer IP');
  });

  it('keeps the external label and hint for a rule with no comment', () => {
    expect(ipBlockScope(undefined)).toBe(EXTERNAL_SCOPE);
    expect(ipBlockScope([])).toBe(EXTERNAL_SCOPE);
    expect(ipBlockScope(['some other note'])).toBe(EXTERNAL_SCOPE);
    expect(EXTERNAL_SCOPE).toEqual({ label: 'External (IP Block)', hint: 'External traffic outside the cluster' });
  });
});
