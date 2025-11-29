import { useState, useEffect, useRef } from 'react';
import type { PodNodeData } from '../../types';
import type { NetworkPolicy, NetworkPolicyRule, NetworkPolicyPort, NetworkPolicyPeer } from '../../types/networkPolicy';
import { generateNetworkPolicy } from '../../utils/networkPolicyGenerator';

interface UseNetworkPolicyEditorProps {
  pod: PodNodeData | null;
  allPods: PodNodeData[];
  isOpen: boolean;
}

export const useNetworkPolicyEditor = ({ pod, allPods, isOpen }: UseNetworkPolicyEditorProps) => {
  const [policy, setPolicy] = useState<NetworkPolicy | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isIngressExpanded, setIsIngressExpanded] = useState(true);
  const [isEgressExpanded, setIsEgressExpanded] = useState(true);
  const [labelInputs, setLabelInputs] = useState<{ [key: string]: { key: string; value: string } }>({});

  // Track which pod we've generated policy for to avoid regeneration
  const lastGeneratedPodId = useRef<string | null>(null);

  useEffect(() => {
    const currentPodId = pod?.id || null;

    // Only generate if we have a pod and haven't generated for this pod yet
    if (isOpen && pod && currentPodId !== lastGeneratedPodId.current) {
      lastGeneratedPodId.current = currentPodId;
      setIsLoading(true);
      generateNetworkPolicy(pod, allPods)
        .then((generatedPolicy) => {
          setPolicy(generatedPolicy);
        })
        .finally(() => {
          setIsLoading(false);
        });
    }
  }, [isOpen, pod, allPods]);

  const addIngressRule = () => {
    if (!policy) return;
    const newRule: NetworkPolicyRule = {
      id: `ingress-${Date.now()}`,
      peers: [],
      ports: [],
    };
    setPolicy({
      ...policy,
      spec: {
        ...policy.spec,
        ingress: [...(policy.spec.ingress || []), newRule],
        policyTypes: policy.spec.policyTypes.includes('Ingress')
          ? policy.spec.policyTypes
          : [...policy.spec.policyTypes, 'Ingress'],
      },
    });
  };

  const addEgressRule = () => {
    if (!policy) return;
    const newRule: NetworkPolicyRule = {
      id: `egress-${Date.now()}`,
      peers: [],
      ports: [],
    };
    setPolicy({
      ...policy,
      spec: {
        ...policy.spec,
        egress: [...(policy.spec.egress || []), newRule],
        policyTypes: policy.spec.policyTypes.includes('Egress')
          ? policy.spec.policyTypes
          : [...policy.spec.policyTypes, 'Egress'],
      },
    });
  };

  const removeIngressRule = (ruleId: string) => {
    if (!policy) return;
    setPolicy({
      ...policy,
      spec: {
        ...policy.spec,
        ingress: policy.spec.ingress?.filter(r => r.id !== ruleId),
      },
    });
  };

  const removeEgressRule = (ruleId: string) => {
    if (!policy) return;
    setPolicy({
      ...policy,
      spec: {
        ...policy.spec,
        egress: policy.spec.egress?.filter(r => r.id !== ruleId),
      },
    });
  };

  const addPortToRule = (ruleId: string, type: 'ingress' | 'egress') => {
    if (!policy) return;
    const newPort: NetworkPolicyPort = {
      protocol: 'TCP',
      port: 80,
    };

    if (type === 'ingress') {
      setPolicy({
        ...policy,
        spec: {
          ...policy.spec,
          ingress: policy.spec.ingress?.map(rule =>
            rule.id === ruleId
              ? { ...rule, ports: [...rule.ports, newPort] }
              : rule
          ),
        },
      });
    } else {
      setPolicy({
        ...policy,
        spec: {
          ...policy.spec,
          egress: policy.spec.egress?.map(rule =>
            rule.id === ruleId
              ? { ...rule, ports: [...rule.ports, newPort] }
              : rule
          ),
        },
      });
    }
  };

  const removePortFromRule = (ruleId: string, portIndex: number, type: 'ingress' | 'egress') => {
    if (!policy) return;
    if (type === 'ingress') {
      setPolicy({
        ...policy,
        spec: {
          ...policy.spec,
          ingress: policy.spec.ingress?.map(rule =>
            rule.id === ruleId
              ? { ...rule, ports: rule.ports.filter((_, i) => i !== portIndex) }
              : rule
          ),
        },
      });
    } else {
      setPolicy({
        ...policy,
        spec: {
          ...policy.spec,
          egress: policy.spec.egress?.map(rule =>
            rule.id === ruleId
              ? { ...rule, ports: rule.ports.filter((_, i) => i !== portIndex) }
              : rule
          ),
        },
      });
    }
  };

  const removePeerFromRule = (ruleId: string, peerIndex: number, type: 'ingress' | 'egress') => {
    if (!policy) return;
    if (type === 'ingress') {
      setPolicy({
        ...policy,
        spec: {
          ...policy.spec,
          ingress: policy.spec.ingress?.map(rule =>
            rule.id === ruleId
              ? { ...rule, peers: rule.peers.filter((_, i) => i !== peerIndex) }
              : rule
          ),
        },
      });
    } else {
      setPolicy({
        ...policy,
        spec: {
          ...policy.spec,
          egress: policy.spec.egress?.map(rule =>
            rule.id === ruleId
              ? { ...rule, peers: rule.peers.filter((_, i) => i !== peerIndex) }
              : rule
          ),
        },
      });
    }
  };

  const updatePeerCIDR = (ruleId: string, peerIndex: number, cidr: string, type: 'ingress' | 'egress') => {
    if (!policy) return;
    if (type === 'ingress') {
      setPolicy({
        ...policy,
        spec: {
          ...policy.spec,
          ingress: policy.spec.ingress?.map(rule =>
            rule.id === ruleId
              ? {
                  ...rule,
                  peers: rule.peers.map((peer, i) =>
                    i === peerIndex && peer.ipBlock
                      ? { ...peer, ipBlock: { ...peer.ipBlock, cidr } }
                      : peer
                  ),
                }
              : rule
          ),
        },
      });
    } else {
      setPolicy({
        ...policy,
        spec: {
          ...policy.spec,
          egress: policy.spec.egress?.map(rule =>
            rule.id === ruleId
              ? {
                  ...rule,
                  peers: rule.peers.map((peer, i) =>
                    i === peerIndex && peer.ipBlock
                      ? { ...peer, ipBlock: { ...peer.ipBlock, cidr } }
                      : peer
                  ),
                }
              : rule
          ),
        },
      });
    }
  };

  const updatePort = (
    ruleId: string,
    portIndex: number,
    field: 'protocol' | 'port',
    value: string | number,
    type: 'ingress' | 'egress'
  ) => {
    if (!policy) return;
    if (type === 'ingress') {
      setPolicy({
        ...policy,
        spec: {
          ...policy.spec,
          ingress: policy.spec.ingress?.map(rule =>
            rule.id === ruleId
              ? {
                  ...rule,
                  ports: rule.ports.map((port, i) =>
                    i === portIndex ? { ...port, [field]: value } : port
                  ),
                }
              : rule
          ),
        },
      });
    } else {
      setPolicy({
        ...policy,
        spec: {
          ...policy.spec,
          egress: policy.spec.egress?.map(rule =>
            rule.id === ruleId
              ? {
                  ...rule,
                  ports: rule.ports.map((port, i) =>
                    i === portIndex ? { ...port, [field]: value } : port
                  ),
                }
              : rule
          ),
        },
      });
    }
  };

  const addPeerToRule = (ruleId: string, type: 'ingress' | 'egress') => {
    if (!policy) return;
    const newPeer: NetworkPolicyPeer = {
      ipBlock: {
        cidr: '0.0.0.0/0',
      },
    };

    if (type === 'ingress') {
      setPolicy({
        ...policy,
        spec: {
          ...policy.spec,
          ingress: policy.spec.ingress?.map(rule =>
            rule.id === ruleId
              ? { ...rule, peers: [...rule.peers, newPeer] }
              : rule
          ),
        },
      });
    } else {
      setPolicy({
        ...policy,
        spec: {
          ...policy.spec,
          egress: policy.spec.egress?.map(rule =>
            rule.id === ruleId
              ? { ...rule, peers: [...rule.peers, newPeer] }
              : rule
          ),
        },
      });
    }
  };

  const changePeerType = (
    ruleId: string,
    peerIndex: number,
    peerType: 'external' | 'inNamespace' | 'inCluster',
    type: 'ingress' | 'egress'
  ) => {
    if (!policy) return;
    let newPeer: NetworkPolicyPeer;

    if (peerType === 'external') {
      newPeer = { ipBlock: { cidr: '0.0.0.0/0' } };
    } else if (peerType === 'inNamespace') {
      newPeer = { podSelector: { matchLabels: {} } };
    } else {
      newPeer = { namespaceSelector: { matchLabels: {} } };
    }

    if (type === 'ingress') {
      setPolicy({
        ...policy,
        spec: {
          ...policy.spec,
          ingress: policy.spec.ingress?.map(rule =>
            rule.id === ruleId
              ? {
                  ...rule,
                  peers: rule.peers.map((peer, i) => (i === peerIndex ? newPeer : peer)),
                }
              : rule
          ),
        },
      });
    } else {
      setPolicy({
        ...policy,
        spec: {
          ...policy.spec,
          egress: policy.spec.egress?.map(rule =>
            rule.id === ruleId
              ? {
                  ...rule,
                  peers: rule.peers.map((peer, i) => (i === peerIndex ? newPeer : peer)),
                }
              : rule
          ),
        },
      });
    }
  };

  const updatePeerLabel = (
    ruleId: string,
    peerIndex: number,
    selectorType: 'podSelector' | 'namespaceSelector',
    labelKey: string,
    labelValue: string,
    type: 'ingress' | 'egress'
  ) => {
    if (!policy) return;
    if (type === 'ingress') {
      setPolicy({
        ...policy,
        spec: {
          ...policy.spec,
          ingress: policy.spec.ingress?.map(rule =>
            rule.id === ruleId
              ? {
                  ...rule,
                  peers: rule.peers.map((peer, i) => {
                    if (i !== peerIndex) return peer;

                    if (selectorType === 'podSelector' && peer.podSelector) {
                      return {
                        ...peer,
                        podSelector: {
                          matchLabels: {
                            ...peer.podSelector.matchLabels,
                            [labelKey]: labelValue,
                          },
                        },
                      };
                    } else if (selectorType === 'namespaceSelector' && peer.namespaceSelector) {
                      return {
                        ...peer,
                        namespaceSelector: {
                          matchLabels: {
                            ...peer.namespaceSelector.matchLabels,
                            [labelKey]: labelValue,
                          },
                        },
                      };
                    }
                    return peer;
                  }),
                }
              : rule
          ),
        },
      });
    } else {
      setPolicy({
        ...policy,
        spec: {
          ...policy.spec,
          egress: policy.spec.egress?.map(rule =>
            rule.id === ruleId
              ? {
                  ...rule,
                  peers: rule.peers.map((peer, i) => {
                    if (i !== peerIndex) return peer;

                    if (selectorType === 'podSelector' && peer.podSelector) {
                      return {
                        ...peer,
                        podSelector: {
                          matchLabels: {
                            ...peer.podSelector.matchLabels,
                            [labelKey]: labelValue,
                          },
                        },
                      };
                    } else if (selectorType === 'namespaceSelector' && peer.namespaceSelector) {
                      return {
                        ...peer,
                        namespaceSelector: {
                          matchLabels: {
                            ...peer.namespaceSelector.matchLabels,
                            [labelKey]: labelValue,
                          },
                        },
                      };
                    }
                    return peer;
                  }),
                }
              : rule
          ),
        },
      });
    }
  };

  const addLabelToPeer = (
    ruleId: string,
    peerIndex: number,
    selectorType: 'podSelector' | 'namespaceSelector',
    key: string,
    value: string,
    type: 'ingress' | 'egress'
  ) => {
    if (!policy || !key.trim()) return;

    const updateFn = (rule: NetworkPolicyRule) => {
      if (rule.id !== ruleId) return rule;

      return {
        ...rule,
        peers: rule.peers.map((peer, i) => {
          if (i !== peerIndex) return peer;

          if (selectorType === 'podSelector') {
            if (!peer.podSelector) {
              return { ...peer, podSelector: { matchLabels: { [key]: value } } };
            }
            return {
              ...peer,
              podSelector: {
                matchLabels: {
                  ...peer.podSelector.matchLabels,
                  [key]: value,
                },
              },
            };
          } else {
            if (!peer.namespaceSelector) {
              return { ...peer, namespaceSelector: { matchLabels: { [key]: value } } };
            }
            return {
              ...peer,
              namespaceSelector: {
                matchLabels: {
                  ...peer.namespaceSelector.matchLabels,
                  [key]: value,
                },
              },
            };
          }
        }),
      };
    };

    if (type === 'ingress') {
      setPolicy({
        ...policy,
        spec: {
          ...policy.spec,
          ingress: policy.spec.ingress?.map(updateFn),
        },
      });
    } else {
      setPolicy({
        ...policy,
        spec: {
          ...policy.spec,
          egress: policy.spec.egress?.map(updateFn),
        },
      });
    }
  };

  const removeLabelFromPeer = (
    ruleId: string,
    peerIndex: number,
    selectorType: 'podSelector' | 'namespaceSelector',
    labelKey: string,
    type: 'ingress' | 'egress'
  ) => {
    if (!policy) return;
    const updateFn = (rule: NetworkPolicyRule) => {
      if (rule.id !== ruleId) return rule;

      return {
        ...rule,
        peers: rule.peers.map((peer, i) => {
          if (i !== peerIndex) return peer;

          if (selectorType === 'podSelector' && peer.podSelector) {
            const newLabels = { ...peer.podSelector.matchLabels };
            delete newLabels[labelKey];

            if (Object.keys(newLabels).length === 0) {
              const { podSelector, ...rest } = peer;
              return rest;
            }

            return {
              ...peer,
              podSelector: { matchLabels: newLabels },
            };
          } else if (selectorType === 'namespaceSelector' && peer.namespaceSelector) {
            const newLabels = { ...peer.namespaceSelector.matchLabels };
            delete newLabels[labelKey];

            if (Object.keys(newLabels).length === 0) {
              const { namespaceSelector, ...rest } = peer;
              return rest;
            }

            return {
              ...peer,
              namespaceSelector: { matchLabels: newLabels },
            };
          }

          return peer;
        }),
      };
    };

    if (type === 'ingress') {
      setPolicy({
        ...policy,
        spec: {
          ...policy.spec,
          ingress: policy.spec.ingress?.map(updateFn),
        },
      });
    } else {
      setPolicy({
        ...policy,
        spec: {
          ...policy.spec,
          egress: policy.spec.egress?.map(updateFn),
        },
      });
    }
  };

  const togglePodSelector = (ruleId: string, peerIndex: number, type: 'ingress' | 'egress') => {
    if (!policy) return;
    const updateFn = (rule: NetworkPolicyRule) => {
      if (rule.id !== ruleId) return rule;

      return {
        ...rule,
        peers: rule.peers.map((peer, i) => {
          if (i !== peerIndex) return peer;

          if (peer.podSelector) {
            const { podSelector, ...rest } = peer;
            return rest;
          } else {
            return {
              ...peer,
              podSelector: {
                matchLabels: {},
              },
            };
          }
        }),
      };
    };

    if (type === 'ingress') {
      setPolicy({
        ...policy,
        spec: {
          ...policy.spec,
          ingress: policy.spec.ingress?.map(updateFn),
        },
      });
    } else {
      setPolicy({
        ...policy,
        spec: {
          ...policy.spec,
          egress: policy.spec.egress?.map(updateFn),
        },
      });
    }
  };

  return {
    policy,
    setPolicy,
    isLoading,
    isIngressExpanded,
    setIsIngressExpanded,
    isEgressExpanded,
    setIsEgressExpanded,
    labelInputs,
    setLabelInputs,
    addIngressRule,
    addEgressRule,
    removeIngressRule,
    removeEgressRule,
    addPortToRule,
    removePortFromRule,
    removePeerFromRule,
    updatePeerCIDR,
    updatePort,
    addPeerToRule,
    changePeerType,
    updatePeerLabel,
    addLabelToPeer,
    removeLabelFromPeer,
    togglePodSelector,
  };
};
