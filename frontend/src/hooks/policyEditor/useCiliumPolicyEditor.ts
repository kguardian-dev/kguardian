import { useState, useEffect, useRef } from 'react';
import type { PodNodeData } from '../../types';
import type {
  CiliumNetworkPolicy,
  CiliumIngressRule,
  CiliumEgressRule,
  EndpointSelector,
  PortProtocol,
  CiliumPortRule,
} from '../../types/ciliumPolicy';
import { generateCiliumNetworkPolicy } from '../../utils/ciliumPolicyGenerator';

interface UseCiliumPolicyEditorProps {
  pod: PodNodeData | null;
  isOpen: boolean;
}

export const useCiliumPolicyEditor = ({ pod, isOpen }: UseCiliumPolicyEditorProps) => {
  const [ciliumPolicy, setCiliumPolicy] = useState<CiliumNetworkPolicy | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isIngressExpanded, setIsIngressExpanded] = useState(true);
  const [isEgressExpanded, setIsEgressExpanded] = useState(true);
  const [labelInputs, setLabelInputs] = useState<{ [key: string]: { key: string; value: string } }>({});

  const lastGeneratedPodId = useRef<string | null>(null);

  useEffect(() => {
    const currentPodId = pod?.id || null;

    if (isOpen && pod && currentPodId !== lastGeneratedPodId.current) {
      lastGeneratedPodId.current = currentPodId;
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setIsLoading(true);
      generateCiliumNetworkPolicy(pod)
        .then((generatedPolicy) => {
          setCiliumPolicy(generatedPolicy);
        })
        .finally(() => {
          setIsLoading(false);
        });
    }
  }, [isOpen, pod]);

  const toggleDefaultDeny = (direction: 'ingress' | 'egress') => {
    if (!ciliumPolicy) return;
    setCiliumPolicy({
      ...ciliumPolicy,
      spec: {
        ...ciliumPolicy.spec,
        defaultDeny: {
          ...ciliumPolicy.spec.defaultDeny,
          [direction]: !ciliumPolicy.spec.defaultDeny[direction],
        },
      },
    });
  };

  const updateEndpointSelectorLabel = (key: string, value: string) => {
    if (!ciliumPolicy) return;
    setCiliumPolicy({
      ...ciliumPolicy,
      spec: {
        ...ciliumPolicy.spec,
        endpointSelector: {
          matchLabels: {
            ...ciliumPolicy.spec.endpointSelector.matchLabels,
            [key]: value,
          },
        },
      },
    });
  };

  const removeEndpointSelectorLabel = (key: string) => {
    if (!ciliumPolicy) return;
    const newLabels = { ...ciliumPolicy.spec.endpointSelector.matchLabels };
    delete newLabels[key];
    setCiliumPolicy({
      ...ciliumPolicy,
      spec: {
        ...ciliumPolicy.spec,
        endpointSelector: { matchLabels: newLabels },
      },
    });
  };

  const addIngressRule = () => {
    if (!ciliumPolicy) return;
    const newRule: CiliumIngressRule = {
      id: `ingress-${Date.now()}`,
      fromEndpoints: [],
      toPorts: [],
    };
    setCiliumPolicy({
      ...ciliumPolicy,
      spec: {
        ...ciliumPolicy.spec,
        ingress: [...(ciliumPolicy.spec.ingress || []), newRule],
      },
    });
  };

  const addEgressRule = () => {
    if (!ciliumPolicy) return;
    const newRule: CiliumEgressRule = {
      id: `egress-${Date.now()}`,
      toEndpoints: [],
      toPorts: [],
    };
    setCiliumPolicy({
      ...ciliumPolicy,
      spec: {
        ...ciliumPolicy.spec,
        egress: [...(ciliumPolicy.spec.egress || []), newRule],
      },
    });
  };

  const removeIngressRule = (ruleId: string) => {
    if (!ciliumPolicy) return;
    setCiliumPolicy({
      ...ciliumPolicy,
      spec: {
        ...ciliumPolicy.spec,
        ingress: ciliumPolicy.spec.ingress?.filter(r => r.id !== ruleId),
      },
    });
  };

  const removeEgressRule = (ruleId: string) => {
    if (!ciliumPolicy) return;
    setCiliumPolicy({
      ...ciliumPolicy,
      spec: {
        ...ciliumPolicy.spec,
        egress: ciliumPolicy.spec.egress?.filter(r => r.id !== ruleId),
      },
    });
  };

  // Peer management for ingress (fromEndpoints / fromCIDR)
  const addIngressEndpoint = (ruleId: string) => {
    if (!ciliumPolicy) return;
    const newEndpoint: EndpointSelector = { matchLabels: {} };
    setCiliumPolicy({
      ...ciliumPolicy,
      spec: {
        ...ciliumPolicy.spec,
        ingress: ciliumPolicy.spec.ingress?.map(rule =>
          rule.id === ruleId
            ? { ...rule, fromEndpoints: [...(rule.fromEndpoints || []), newEndpoint] }
            : rule
        ),
      },
    });
  };

  const removeIngressEndpoint = (ruleId: string, epIndex: number) => {
    if (!ciliumPolicy) return;
    setCiliumPolicy({
      ...ciliumPolicy,
      spec: {
        ...ciliumPolicy.spec,
        ingress: ciliumPolicy.spec.ingress?.map(rule =>
          rule.id === ruleId
            ? { ...rule, fromEndpoints: rule.fromEndpoints?.filter((_, i) => i !== epIndex) }
            : rule
        ),
      },
    });
  };

  const addIngressCIDR = (ruleId: string) => {
    if (!ciliumPolicy) return;
    setCiliumPolicy({
      ...ciliumPolicy,
      spec: {
        ...ciliumPolicy.spec,
        ingress: ciliumPolicy.spec.ingress?.map(rule =>
          rule.id === ruleId
            ? { ...rule, fromCIDR: [...(rule.fromCIDR || []), '0.0.0.0/0'] }
            : rule
        ),
      },
    });
  };

  const removeIngressCIDR = (ruleId: string, cidrIndex: number) => {
    if (!ciliumPolicy) return;
    setCiliumPolicy({
      ...ciliumPolicy,
      spec: {
        ...ciliumPolicy.spec,
        ingress: ciliumPolicy.spec.ingress?.map(rule =>
          rule.id === ruleId
            ? { ...rule, fromCIDR: rule.fromCIDR?.filter((_, i) => i !== cidrIndex) }
            : rule
        ),
      },
    });
  };

  const updateIngressCIDR = (ruleId: string, cidrIndex: number, value: string) => {
    if (!ciliumPolicy) return;
    setCiliumPolicy({
      ...ciliumPolicy,
      spec: {
        ...ciliumPolicy.spec,
        ingress: ciliumPolicy.spec.ingress?.map(rule =>
          rule.id === ruleId
            ? { ...rule, fromCIDR: rule.fromCIDR?.map((c, i) => i === cidrIndex ? value : c) }
            : rule
        ),
      },
    });
  };

  // Peer management for egress (toEndpoints / toCIDR)
  const addEgressEndpoint = (ruleId: string) => {
    if (!ciliumPolicy) return;
    const newEndpoint: EndpointSelector = { matchLabels: {} };
    setCiliumPolicy({
      ...ciliumPolicy,
      spec: {
        ...ciliumPolicy.spec,
        egress: ciliumPolicy.spec.egress?.map(rule =>
          rule.id === ruleId
            ? { ...rule, toEndpoints: [...(rule.toEndpoints || []), newEndpoint] }
            : rule
        ),
      },
    });
  };

  const removeEgressEndpoint = (ruleId: string, epIndex: number) => {
    if (!ciliumPolicy) return;
    setCiliumPolicy({
      ...ciliumPolicy,
      spec: {
        ...ciliumPolicy.spec,
        egress: ciliumPolicy.spec.egress?.map(rule =>
          rule.id === ruleId
            ? { ...rule, toEndpoints: rule.toEndpoints?.filter((_, i) => i !== epIndex) }
            : rule
        ),
      },
    });
  };

  const addEgressCIDR = (ruleId: string) => {
    if (!ciliumPolicy) return;
    setCiliumPolicy({
      ...ciliumPolicy,
      spec: {
        ...ciliumPolicy.spec,
        egress: ciliumPolicy.spec.egress?.map(rule =>
          rule.id === ruleId
            ? { ...rule, toCIDR: [...(rule.toCIDR || []), '0.0.0.0/0'] }
            : rule
        ),
      },
    });
  };

  const removeEgressCIDR = (ruleId: string, cidrIndex: number) => {
    if (!ciliumPolicy) return;
    setCiliumPolicy({
      ...ciliumPolicy,
      spec: {
        ...ciliumPolicy.spec,
        egress: ciliumPolicy.spec.egress?.map(rule =>
          rule.id === ruleId
            ? { ...rule, toCIDR: rule.toCIDR?.filter((_, i) => i !== cidrIndex) }
            : rule
        ),
      },
    });
  };

  const updateEgressCIDR = (ruleId: string, cidrIndex: number, value: string) => {
    if (!ciliumPolicy) return;
    setCiliumPolicy({
      ...ciliumPolicy,
      spec: {
        ...ciliumPolicy.spec,
        egress: ciliumPolicy.spec.egress?.map(rule =>
          rule.id === ruleId
            ? { ...rule, toCIDR: rule.toCIDR?.map((c, i) => i === cidrIndex ? value : c) }
            : rule
        ),
      },
    });
  };

  // Label management for endpoint selectors within rules
  const addLabelToEndpoint = (
    ruleId: string,
    epIndex: number,
    key: string,
    value: string,
    direction: 'ingress' | 'egress'
  ) => {
    if (!ciliumPolicy || !key.trim()) return;

    if (direction === 'ingress') {
      setCiliumPolicy({
        ...ciliumPolicy,
        spec: {
          ...ciliumPolicy.spec,
          ingress: ciliumPolicy.spec.ingress?.map(rule =>
            rule.id === ruleId
              ? {
                  ...rule,
                  fromEndpoints: rule.fromEndpoints?.map((ep, i) =>
                    i === epIndex
                      ? { matchLabels: { ...ep.matchLabels, [key]: value } }
                      : ep
                  ),
                }
              : rule
          ),
        },
      });
    } else {
      setCiliumPolicy({
        ...ciliumPolicy,
        spec: {
          ...ciliumPolicy.spec,
          egress: ciliumPolicy.spec.egress?.map(rule =>
            rule.id === ruleId
              ? {
                  ...rule,
                  toEndpoints: rule.toEndpoints?.map((ep, i) =>
                    i === epIndex
                      ? { matchLabels: { ...ep.matchLabels, [key]: value } }
                      : ep
                  ),
                }
              : rule
          ),
        },
      });
    }
  };

  const removeLabelFromEndpoint = (
    ruleId: string,
    epIndex: number,
    labelKey: string,
    direction: 'ingress' | 'egress'
  ) => {
    if (!ciliumPolicy) return;

    const updateEndpoint = (ep: EndpointSelector, i: number): EndpointSelector => {
      if (i !== epIndex) return ep;
      const newLabels = { ...ep.matchLabels };
      delete newLabels[labelKey];
      return { matchLabels: newLabels };
    };

    if (direction === 'ingress') {
      setCiliumPolicy({
        ...ciliumPolicy,
        spec: {
          ...ciliumPolicy.spec,
          ingress: ciliumPolicy.spec.ingress?.map(rule =>
            rule.id === ruleId
              ? { ...rule, fromEndpoints: rule.fromEndpoints?.map(updateEndpoint) }
              : rule
          ),
        },
      });
    } else {
      setCiliumPolicy({
        ...ciliumPolicy,
        spec: {
          ...ciliumPolicy.spec,
          egress: ciliumPolicy.spec.egress?.map(rule =>
            rule.id === ruleId
              ? { ...rule, toEndpoints: rule.toEndpoints?.map(updateEndpoint) }
              : rule
          ),
        },
      });
    }
  };

  // Port management
  const addPortToRule = (ruleId: string, direction: 'ingress' | 'egress') => {
    if (!ciliumPolicy) return;
    const newPort: PortProtocol = { port: '80', protocol: 'TCP' };

    const addPort = (toPorts: CiliumPortRule[] | undefined): CiliumPortRule[] => {
      if (!toPorts || toPorts.length === 0) {
        return [{ ports: [newPort] }];
      }
      return [{ ports: [...toPorts[0].ports, newPort] }];
    };

    if (direction === 'ingress') {
      setCiliumPolicy({
        ...ciliumPolicy,
        spec: {
          ...ciliumPolicy.spec,
          ingress: ciliumPolicy.spec.ingress?.map(rule =>
            rule.id === ruleId ? { ...rule, toPorts: addPort(rule.toPorts) } : rule
          ),
        },
      });
    } else {
      setCiliumPolicy({
        ...ciliumPolicy,
        spec: {
          ...ciliumPolicy.spec,
          egress: ciliumPolicy.spec.egress?.map(rule =>
            rule.id === ruleId ? { ...rule, toPorts: addPort(rule.toPorts) } : rule
          ),
        },
      });
    }
  };

  const removePortFromRule = (ruleId: string, portIndex: number, direction: 'ingress' | 'egress') => {
    if (!ciliumPolicy) return;

    const removePort = (toPorts: CiliumPortRule[] | undefined): CiliumPortRule[] => {
      if (!toPorts || toPorts.length === 0) return [];
      const filtered = toPorts[0].ports.filter((_, i) => i !== portIndex);
      return filtered.length > 0 ? [{ ports: filtered }] : [];
    };

    if (direction === 'ingress') {
      setCiliumPolicy({
        ...ciliumPolicy,
        spec: {
          ...ciliumPolicy.spec,
          ingress: ciliumPolicy.spec.ingress?.map(rule =>
            rule.id === ruleId ? { ...rule, toPorts: removePort(rule.toPorts) } : rule
          ),
        },
      });
    } else {
      setCiliumPolicy({
        ...ciliumPolicy,
        spec: {
          ...ciliumPolicy.spec,
          egress: ciliumPolicy.spec.egress?.map(rule =>
            rule.id === ruleId ? { ...rule, toPorts: removePort(rule.toPorts) } : rule
          ),
        },
      });
    }
  };

  const updatePort = (
    ruleId: string,
    portIndex: number,
    field: 'port' | 'protocol',
    value: string,
    direction: 'ingress' | 'egress'
  ) => {
    if (!ciliumPolicy) return;

    const updPort = (toPorts: CiliumPortRule[] | undefined): CiliumPortRule[] => {
      if (!toPorts || toPorts.length === 0) return [];
      return [{
        ports: toPorts[0].ports.map((p, i) =>
          i === portIndex ? { ...p, [field]: value } : p
        ),
      }];
    };

    if (direction === 'ingress') {
      setCiliumPolicy({
        ...ciliumPolicy,
        spec: {
          ...ciliumPolicy.spec,
          ingress: ciliumPolicy.spec.ingress?.map(rule =>
            rule.id === ruleId ? { ...rule, toPorts: updPort(rule.toPorts) } : rule
          ),
        },
      });
    } else {
      setCiliumPolicy({
        ...ciliumPolicy,
        spec: {
          ...ciliumPolicy.spec,
          egress: ciliumPolicy.spec.egress?.map(rule =>
            rule.id === ruleId ? { ...rule, toPorts: updPort(rule.toPorts) } : rule
          ),
        },
      });
    }
  };

  return {
    ciliumPolicy,
    setCiliumPolicy,
    isLoading,
    isIngressExpanded,
    setIsIngressExpanded,
    isEgressExpanded,
    setIsEgressExpanded,
    labelInputs,
    setLabelInputs,
    toggleDefaultDeny,
    updateEndpointSelectorLabel,
    removeEndpointSelectorLabel,
    addIngressRule,
    addEgressRule,
    removeIngressRule,
    removeEgressRule,
    addIngressEndpoint,
    removeIngressEndpoint,
    addIngressCIDR,
    removeIngressCIDR,
    updateIngressCIDR,
    addEgressEndpoint,
    removeEgressEndpoint,
    addEgressCIDR,
    removeEgressCIDR,
    updateEgressCIDR,
    addLabelToEndpoint,
    removeLabelFromEndpoint,
    addPortToRule,
    removePortFromRule,
    updatePort,
  };
};
