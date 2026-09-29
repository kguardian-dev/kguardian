// @vitest-environment jsdom
import { describe, expect, test, vi } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { parse } from 'yaml';
import type { PodNodeData } from '../../types';
import type { NetworkPolicy, NetworkPolicyPeer } from '../../types/networkPolicy';

// The editor starts from a generated policy; stub the generator so each test
// controls the peers it edits.
let generated: NetworkPolicy;
vi.mock('../../utils/networkPolicyGenerator', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../utils/networkPolicyGenerator')>()),
  generateNetworkPolicy: vi.fn(async () => structuredClone(generated)),
}));

import { policyToYAML } from '../../utils/networkPolicyGenerator';
import { useNetworkPolicyEditor } from './useNetworkPolicyEditor';

const pod = { id: 'web', pod: { pod_name: 'web', pod_namespace: 'prod' } } as PodNodeData;
const withIngressPeer = (peer: NetworkPolicyPeer): NetworkPolicy => ({
  apiVersion: 'networking.k8s.io/v1', kind: 'NetworkPolicy', metadata: { name: 'web-policy', namespace: 'prod' },
  spec: {
    podSelector: { matchLabels: { app: 'web' } }, policyTypes: ['Ingress'],
    ingress: [{ id: 'r1', peers: [peer], ports: [{ protocol: 'TCP', port: 8080 }] }],
  },
});

const editorFor = async (policy: NetworkPolicy) => {
  generated = policy;
  const hook = renderHook(() => useNetworkPolicyEditor({ pod, isOpen: true }));
  await waitFor(() => expect(hook.result.current.policy).not.toBeNull());
  return hook;
};

// The label editor's hint reads "Leave empty to match all pods in namespace"
// (and "... all namespaces"). Removing the last label used to delete the
// selector, and a same-namespace peer left with nothing rendered as a bare
// `-`: a null NetworkPolicyPeer, which the API server rejects ("must specify
// a peer"), failing the whole policy. An empty selector is what the hint
// promises and what the API means by it.
describe('removeLabelFromPeer — the last label leaves an empty selector, never an empty peer', () => {
  test('same-namespace peer: podSelector {} (every pod in the namespace), a valid peer in the YAML', async () => {
    const { result } = await editorFor(withIngressPeer({ podSelector: { matchLabels: { app: 'api' } } }));
    act(() => result.current.removeLabelFromPeer('r1', 0, 'podSelector', 'app', 'ingress'));
    expect(result.current.policy!.spec.ingress![0].peers).toEqual([{ podSelector: { matchLabels: {} } }]);
    const yaml = policyToYAML(result.current.policy!);
    expect(parse(yaml).spec.ingress[0].from).toEqual([{ podSelector: {} }]);
    expect(yaml).toContain('  - from:\n    -\n      podSelector: {}\n');
  });

  test('namespace-only peer: namespaceSelector {} (every namespace), not an empty peer', async () => {
    const { result } = await editorFor(withIngressPeer({ namespaceSelector: { matchLabels: { team: 'a' } } }));
    act(() => result.current.removeLabelFromPeer('r1', 0, 'namespaceSelector', 'team', 'ingress'));
    expect(result.current.policy!.spec.ingress![0].peers).toEqual([{ namespaceSelector: { matchLabels: {} } }]);
    expect(parse(policyToYAML(result.current.policy!)).spec.ingress[0].from).toEqual([{ namespaceSelector: {} }]);
  });

  test('cross-namespace peer: removing the last namespace label keeps "all namespaces", not the policy namespace', async () => {
    const { result } = await editorFor(withIngressPeer({
      podSelector: { matchLabels: { app: 'api' } },
      namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'backend' } },
    }));
    act(() => result.current.removeLabelFromPeer('r1', 0, 'namespaceSelector', 'kubernetes.io/metadata.name', 'ingress'));
    expect(result.current.policy!.spec.ingress![0].peers).toEqual([
      { podSelector: { matchLabels: { app: 'api' } }, namespaceSelector: { matchLabels: {} } },
    ]);
  });

  test('other labels stay when one of several is removed', async () => {
    const { result } = await editorFor(withIngressPeer({ podSelector: { matchLabels: { app: 'api', tier: 'be' } } }));
    act(() => result.current.removeLabelFromPeer('r1', 0, 'podSelector', 'tier', 'ingress'));
    expect(result.current.policy!.spec.ingress![0].peers).toEqual([{ podSelector: { matchLabels: { app: 'api' } } }]);
  });
});
