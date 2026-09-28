/**
 * What an ipBlock peer stands for, read from the rule's comment line: the
 * generators pin in-cluster addresses (node IPs, selector-less ClusterIPs,
 * former holders of a pod IP) as ipBlocks, and they are not "external".
 */
export interface IpBlockScope {
  label: string;
  /** Italic line under the CIDR field; null when the comment already says what the address is. */
  hint: string | null;
}

export const EXTERNAL_SCOPE: IpBlockScope = {
  label: 'External (IP Block)',
  hint: 'External traffic outside the cluster',
};

// Prefixes of the comment builders in utils/hostNetwork.ts and
// utils/peerComments.ts, pinned byte-for-byte by the generator goldens.
const HOST_NETWORK_PEER = /^host-network peer /;
const SELECTORLESS_SERVICE = /^Service \S+\/\S+ has no selector/;
const UNATTRIBUTED_PEER = /^unattributed peer /;

export function ipBlockScope(comments?: readonly string[]): IpBlockScope {
  for (const c of comments ?? []) {
    if (HOST_NETWORK_PEER.test(c)) return { label: 'Node IP (host-network peer)', hint: null };
    if (SELECTORLESS_SERVICE.test(c)) return { label: 'Cluster Service IP', hint: null };
    if (UNATTRIBUTED_PEER.test(c)) return { label: 'Unattributed peer IP', hint: null };
  }
  return EXTERNAL_SCOPE;
}
