import React, { useState, useEffect, useRef } from 'react';
import { X, Plus, Trash2, Copy, Download, FileCode, ChevronDown, ChevronRight, Shield, Lock, AlertCircle } from 'lucide-react';
import type { PodNodeData } from '../types';
import type { NetworkPolicy, NetworkPolicyRule, NetworkPolicyPort, NetworkPolicyPeer } from '../types/networkPolicy';
import type { SeccompProfile, SeccompSyscall, SeccompAction } from '../types/seccompProfile';
import { generateNetworkPolicy, policyToYAML } from '../utils/networkPolicyGenerator';
import { generateSeccompProfile, profileToYAML, profileToJSON } from '../utils/seccompProfileGenerator';
import { SECCOMP_ACTIONS, ARCHITECTURES } from '../types/seccompProfile';
import { isValidSyscall, getSyscallSuggestions } from '../utils/syscalls';

interface NetworkPolicyEditorProps {
  isOpen: boolean;
  onClose: () => void;
  pod: PodNodeData | null;
  allPods?: PodNodeData[];
}

type PolicyType = 'network' | 'seccomp';

const NetworkPolicyEditor: React.FC<NetworkPolicyEditorProps> = ({ isOpen, onClose, pod, allPods = [] }) => {
  const [policyType, setPolicyType] = useState<PolicyType>('network');
  const [policy, setPolicy] = useState<NetworkPolicy | null>(null);
  const [seccompProfile, setSeccompProfile] = useState<SeccompProfile | null>(null);
  const [yamlView, setYamlView] = useState(true); // Default to YAML view
  const [copiedToClipboard, setCopiedToClipboard] = useState(false);
  const [isIngressExpanded, setIsIngressExpanded] = useState(true);
  const [isEgressExpanded, setIsEgressExpanded] = useState(true);
  const [isSyscallsExpanded, setIsSyscallsExpanded] = useState(true);

  // Syscall autocomplete state
  const [syscallInputValues, setSyscallInputValues] = useState<{ [key: number]: string }>({});
  const [syscallSuggestions, setSyscallSuggestions] = useState<{ [key: number]: string[] }>({});
  const [syscallErrors, setSyscallErrors] = useState<{ [key: number]: string }>({});
  const [activeSuggestionIndex, setActiveSuggestionIndex] = useState<{ [key: number]: number }>({});

  useEffect(() => {
    if (isOpen && pod) {
      if (policyType === 'network') {
        const generatedPolicy = generateNetworkPolicy(pod, allPods);
        setPolicy(generatedPolicy);
      } else {
        const generatedProfile = generateSeccompProfile(pod);
        setSeccompProfile(generatedProfile);
      }
    }
  }, [isOpen, pod, allPods, policyType]);

  if (!isOpen || !pod) return null;
  if (policyType === 'network' && !policy) return null;
  if (policyType === 'seccomp' && !seccompProfile) return null;

  const handleCopyYAML = () => {
    let content: string;
    if (policyType === 'network' && policy) {
      content = policyToYAML(policy);
    } else if (policyType === 'seccomp' && seccompProfile) {
      content = yamlView
        ? profileToYAML(seccompProfile, pod.pod.pod_name, pod.pod.pod_namespace || 'default')
        : profileToJSON(seccompProfile);
    } else {
      return;
    }
    navigator.clipboard.writeText(content);
    setCopiedToClipboard(true);
    setTimeout(() => setCopiedToClipboard(false), 2000);
  };

  const handleDownloadYAML = () => {
    let content: string;
    let filename: string;
    let mimeType: string;

    if (policyType === 'network' && policy) {
      content = policyToYAML(policy);
      filename = `${policy.metadata.name}.yaml`;
      mimeType = 'text/yaml';
    } else if (policyType === 'seccomp' && seccompProfile) {
      if (yamlView) {
        content = profileToYAML(seccompProfile, pod.pod.pod_name, pod.pod.pod_namespace || 'default');
        filename = `${pod.pod.pod_name}-seccomp.yaml`;
        mimeType = 'text/yaml';
      } else {
        content = profileToJSON(seccompProfile);
        filename = `${pod.pod.pod_name}-seccomp.json`;
        mimeType = 'application/json';
      }
    } else {
      return;
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const addIngressRule = () => {
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
    setPolicy({
      ...policy,
      spec: {
        ...policy.spec,
        ingress: policy.spec.ingress?.filter(r => r.id !== ruleId),
      },
    });
  };

  const removeEgressRule = (ruleId: string) => {
    setPolicy({
      ...policy,
      spec: {
        ...policy.spec,
        egress: policy.spec.egress?.filter(r => r.id !== ruleId),
      },
    });
  };

  const addPortToRule = (ruleId: string, type: 'ingress' | 'egress') => {
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

  const updatePort = (ruleId: string, portIndex: number, field: 'protocol' | 'port', value: string | number, type: 'ingress' | 'egress') => {
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

  // Seccomp profile handlers
  const addSyscallRule = () => {
    if (!seccompProfile) return;
    const newRule: SeccompSyscall = {
      names: [],
      action: 'SCMP_ACT_ALLOW',
    };
    setSeccompProfile({
      ...seccompProfile,
      syscalls: [...(seccompProfile.syscalls || []), newRule],
    });
  };

  const removeSyscallRule = (index: number) => {
    if (!seccompProfile) return;
    setSeccompProfile({
      ...seccompProfile,
      syscalls: seccompProfile.syscalls?.filter((_, i) => i !== index),
    });
  };

  const addSyscallToRule = (ruleIndex: number, syscall: string) => {
    if (!seccompProfile || !syscall.trim()) return;

    const trimmedSyscall = syscall.trim().toLowerCase();

    // Validate syscall name
    if (!isValidSyscall(trimmedSyscall)) {
      setSyscallErrors({
        ...syscallErrors,
        [ruleIndex]: `"${trimmedSyscall}" is not a valid Linux syscall name`,
      });
      return;
    }

    // Check if syscall already exists in this rule
    const rule = seccompProfile.syscalls?.[ruleIndex];
    if (rule && rule.names.includes(trimmedSyscall)) {
      setSyscallErrors({
        ...syscallErrors,
        [ruleIndex]: `"${trimmedSyscall}" is already in this rule`,
      });
      return;
    }

    // Clear error and add syscall
    setSyscallErrors({
      ...syscallErrors,
      [ruleIndex]: '',
    });

    setSeccompProfile({
      ...seccompProfile,
      syscalls: seccompProfile.syscalls?.map((rule, i) =>
        i === ruleIndex
          ? { ...rule, names: [...rule.names, trimmedSyscall] }
          : rule
      ),
    });

    // Clear input value
    setSyscallInputValues({
      ...syscallInputValues,
      [ruleIndex]: '',
    });
  };

  const handleSyscallInputChange = (ruleIndex: number, value: string) => {
    setSyscallInputValues({
      ...syscallInputValues,
      [ruleIndex]: value,
    });

    // Get suggestions
    if (value.trim()) {
      const suggestions = getSyscallSuggestions(value.trim(), 10);
      setSyscallSuggestions({
        ...syscallSuggestions,
        [ruleIndex]: suggestions,
      });
      setActiveSuggestionIndex({
        ...activeSuggestionIndex,
        [ruleIndex]: -1,
      });
    } else {
      setSyscallSuggestions({
        ...syscallSuggestions,
        [ruleIndex]: [],
      });
    }

    // Clear error when user starts typing
    if (syscallErrors[ruleIndex]) {
      setSyscallErrors({
        ...syscallErrors,
        [ruleIndex]: '',
      });
    }
  };

  const handleSyscallKeyDown = (ruleIndex: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    const suggestions = syscallSuggestions[ruleIndex] || [];
    const activeIndex = activeSuggestionIndex[ruleIndex] ?? -1;

    if (e.key === 'Enter') {
      e.preventDefault();
      if (activeIndex >= 0 && activeIndex < suggestions.length) {
        // User selected a suggestion
        addSyscallToRule(ruleIndex, suggestions[activeIndex]);
        setSyscallSuggestions({
          ...syscallSuggestions,
          [ruleIndex]: [],
        });
      } else {
        // User pressed Enter on their typed value
        const value = syscallInputValues[ruleIndex] || e.currentTarget.value;
        if (value.trim()) {
          addSyscallToRule(ruleIndex, value);
          setSyscallSuggestions({
            ...syscallSuggestions,
            [ruleIndex]: [],
          });
        }
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (suggestions.length > 0) {
        setActiveSuggestionIndex({
          ...activeSuggestionIndex,
          [ruleIndex]: activeIndex < suggestions.length - 1 ? activeIndex + 1 : 0,
        });
      }
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (suggestions.length > 0) {
        setActiveSuggestionIndex({
          ...activeSuggestionIndex,
          [ruleIndex]: activeIndex > 0 ? activeIndex - 1 : suggestions.length - 1,
        });
      }
    } else if (e.key === 'Escape') {
      setSyscallSuggestions({
        ...syscallSuggestions,
        [ruleIndex]: [],
      });
    }
  };

  const removeSyscallFromRule = (ruleIndex: number, syscallIndex: number) => {
    if (!seccompProfile) return;
    setSeccompProfile({
      ...seccompProfile,
      syscalls: seccompProfile.syscalls?.map((rule, i) =>
        i === ruleIndex
          ? { ...rule, names: rule.names.filter((_, j) => j !== syscallIndex) }
          : rule
      ),
    });
  };

  const updateSyscallAction = (ruleIndex: number, action: SeccompAction) => {
    if (!seccompProfile) return;
    setSeccompProfile({
      ...seccompProfile,
      syscalls: seccompProfile.syscalls?.map((rule, i) =>
        i === ruleIndex ? { ...rule, action } : rule
      ),
    });
  };

  const updateDefaultAction = (action: SeccompAction) => {
    if (!seccompProfile) return;
    setSeccompProfile({
      ...seccompProfile,
      defaultAction: action,
    });
  };

  const toggleArchitecture = (arch: string) => {
    if (!seccompProfile) return;
    const currentArchs = seccompProfile.architectures || [];
    const hasArch = currentArchs.includes(arch);

    setSeccompProfile({
      ...seccompProfile,
      architectures: hasArch
        ? currentArchs.filter(a => a !== arch)
        : [...currentArchs, arch],
    });
  };

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/50 backdrop-blur-sm z-40 transition-opacity"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 pointer-events-none">
        <div
          className="bg-hubble-card border border-hubble-border rounded-lg shadow-2xl w-full max-w-7xl h-[90vh] flex flex-col pointer-events-auto"
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div className="flex items-center justify-between px-6 py-4 border-b border-hubble-border">
            <div className="flex items-center gap-3">
              <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-hubble-success/20">
                {policyType === 'network' ? (
                  <Shield className="w-5 h-5 text-hubble-success" />
                ) : (
                  <Lock className="w-5 h-5 text-hubble-success" />
                )}
              </div>
              <div>
                <h2 className="text-lg font-semibold text-primary">
                  {policyType === 'network' ? 'Network Policy Builder' : 'Seccomp Profile Builder'}
                </h2>
                <p className="text-xs text-tertiary">
                  {pod.pod.pod_name} • {pod.pod.pod_namespace}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {/* Policy Type Selector */}
              <div className="flex bg-hubble-dark rounded-lg p-1 mr-2">
                <button
                  onClick={() => setPolicyType('network')}
                  className={`px-3 py-1.5 text-xs rounded transition-all flex items-center gap-1 ${
                    policyType === 'network'
                      ? 'bg-hubble-accent text-white'
                      : 'text-secondary hover:text-primary'
                  }`}
                >
                  <Shield className="w-3 h-3" />
                  Network Policy
                </button>
                <button
                  onClick={() => setPolicyType('seccomp')}
                  className={`px-3 py-1.5 text-xs rounded transition-all flex items-center gap-1 ${
                    policyType === 'seccomp'
                      ? 'bg-hubble-accent text-white'
                      : 'text-secondary hover:text-primary'
                  }`}
                >
                  <Lock className="w-3 h-3" />
                  Seccomp Profile
                </button>
              </div>
              <button
                onClick={() => setYamlView(!yamlView)}
                className={`px-3 py-1.5 text-xs rounded-lg transition-colors ${
                  yamlView
                    ? 'bg-hubble-accent text-white'
                    : 'text-secondary hover:text-primary hover:bg-hubble-dark'
                }`}
              >
                {yamlView ? 'Visual Editor' : (policyType === 'seccomp' ? 'YAML/JSON View' : 'YAML View')}
              </button>
              <button
                onClick={handleCopyYAML}
                className="px-3 py-1.5 text-xs text-secondary hover:text-primary hover:bg-hubble-dark rounded-lg transition-colors flex items-center gap-1"
                title="Copy YAML"
              >
                <Copy className="w-3 h-3" />
                {copiedToClipboard ? 'Copied!' : 'Copy'}
              </button>
              <button
                onClick={handleDownloadYAML}
                className="px-3 py-1.5 text-xs text-secondary hover:text-primary hover:bg-hubble-dark rounded-lg transition-colors flex items-center gap-1"
                title="Download YAML"
              >
                <Download className="w-3 h-3" />
                Download
              </button>
              <button
                onClick={onClose}
                className="p-2 text-tertiary hover:text-primary hover:bg-hubble-dark rounded-lg transition-colors"
                aria-label="Close"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
          </div>

          {/* Content */}
          <div className="flex-1 overflow-hidden flex">
            {yamlView ? (
              /* YAML View */
              <div className="flex-1 p-6 overflow-auto">
                <pre className="bg-hubble-dark text-secondary p-4 rounded-lg font-mono text-sm overflow-x-auto">
                  {policyType === 'network' && policy
                    ? policyToYAML(policy)
                    : policyType === 'seccomp' && seccompProfile
                    ? profileToYAML(seccompProfile, pod.pod.pod_name, pod.pod.pod_namespace || 'default')
                    : ''}
                </pre>
              </div>
            ) : (
              /* Visual Editor */
              <div className="flex-1 p-6 overflow-auto space-y-6">
                {policyType === 'network' && policy ? (
                  /* Network Policy Visual Editor */
                  <>
                {/* Metadata Section */}
                <div className="bg-hubble-dark p-4 rounded-lg border border-hubble-border">
                  <h3 className="text-sm font-semibold text-primary mb-3">Policy Metadata</h3>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs text-tertiary mb-1">Name</label>
                      <input
                        type="text"
                        value={policy.metadata.name}
                        onChange={(e) =>
                          setPolicy({
                            ...policy,
                            metadata: { ...policy.metadata, name: e.target.value },
                          })
                        }
                        className="w-full bg-hubble-card text-primary px-3 py-2 rounded border border-hubble-border
                                   focus:outline-none focus:ring-2 focus:ring-hubble-accent focus:border-transparent text-sm"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-tertiary mb-1">Namespace</label>
                      <input
                        type="text"
                        value={policy.metadata.namespace}
                        onChange={(e) =>
                          setPolicy({
                            ...policy,
                            metadata: { ...policy.metadata, namespace: e.target.value },
                          })
                        }
                        className="w-full bg-hubble-card text-primary px-3 py-2 rounded border border-hubble-border
                                   focus:outline-none focus:ring-2 focus:ring-hubble-accent focus:border-transparent text-sm"
                      />
                    </div>
                  </div>
                </div>

                {/* Ingress Rules */}
                <div className="bg-hubble-dark p-4 rounded-lg border border-hubble-border">
                  <div className="flex items-center justify-between mb-3">
                    <button
                      onClick={() => setIsIngressExpanded(!isIngressExpanded)}
                      className="flex items-center gap-2 text-sm font-semibold text-primary hover:text-hubble-accent transition-colors"
                    >
                      {isIngressExpanded ? (
                        <ChevronDown className="w-4 h-4 text-hubble-success" />
                      ) : (
                        <ChevronRight className="w-4 h-4 text-hubble-success" />
                      )}
                      Ingress Rules
                      {policy.spec.ingress && ` (${policy.spec.ingress.length})`}
                    </button>
                    {isIngressExpanded && (
                      <button
                        onClick={addIngressRule}
                        className="px-3 py-1.5 text-xs bg-hubble-success text-white rounded-lg hover:bg-green-600
                                   transition-colors flex items-center gap-1"
                      >
                        <Plus className="w-3 h-3" />
                        Add Rule
                      </button>
                    )}
                  </div>
                  {isIngressExpanded && (
                    <div className="space-y-3">
                    {policy.spec.ingress && policy.spec.ingress.length > 0 ? (
                      policy.spec.ingress.map((rule, index) => (
                        <div key={rule.id} className="bg-hubble-card p-3 rounded-lg border border-hubble-border">
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-xs font-medium text-secondary">Rule {index + 1}</span>
                            <button
                              onClick={() => removeIngressRule(rule.id)}
                              className="p-1 text-hubble-error hover:bg-hubble-error/20 rounded transition-colors"
                              title="Remove rule"
                            >
                              <Trash2 className="w-3 h-3" />
                            </button>
                          </div>
                          <div className="space-y-3">
                            <div>
                              <div className="flex items-center justify-between mb-2">
                                <label className="text-xs font-medium text-secondary">From (Sources)</label>
                                <button
                                  onClick={() => addPeerToRule(rule.id, 'ingress')}
                                  className="text-xs text-hubble-accent hover:text-blue-400 flex items-center gap-1"
                                >
                                  <Plus className="w-3 h-3" />
                                  Add Source
                                </button>
                              </div>
                              <div className="space-y-2">
                                {rule.peers.length > 0 ? (
                                  rule.peers.map((peer, peerIndex) => (
                                    <div key={peerIndex} className="bg-hubble-dark p-2 rounded border border-hubble-border">
                                      <div className="flex items-center gap-2">
                                        {peer.ipBlock && (
                                          <>
                                            <span className="text-xs text-tertiary min-w-[60px]">IP Block:</span>
                                            <input
                                              type="text"
                                              value={peer.ipBlock.cidr}
                                              onChange={(e) => updatePeerCIDR(rule.id, peerIndex, e.target.value, 'ingress')}
                                              className="flex-1 bg-hubble-card text-secondary px-2 py-1 rounded border border-hubble-border
                                                         focus:outline-none focus:ring-1 focus:ring-hubble-accent text-xs font-mono"
                                              placeholder="0.0.0.0/0"
                                            />
                                          </>
                                        )}
                                        {peer.podSelector && (
                                          <div className="flex-1 flex flex-col gap-1">
                                            <div className="flex items-center gap-2">
                                              <span className="text-xs text-tertiary min-w-[60px]">Pod Selector:</span>
                                              <div className="flex flex-wrap gap-1">
                                                {Object.entries(peer.podSelector.matchLabels).map(([key, value]) => (
                                                  <span key={key} className="text-xs bg-hubble-success/20 text-hubble-success px-2 py-0.5 rounded">
                                                    {key}: {value}
                                                  </span>
                                                ))}
                                              </div>
                                            </div>
                                            {peer.namespaceSelector && (
                                              <div className="flex items-center gap-2">
                                                <span className="text-xs text-tertiary min-w-[60px]">Namespace:</span>
                                                <div className="flex flex-wrap gap-1">
                                                  {Object.entries(peer.namespaceSelector.matchLabels).map(([key, value]) => (
                                                    <span key={key} className="text-xs bg-hubble-accent/20 text-hubble-accent px-2 py-0.5 rounded">
                                                      {key}: {value}
                                                    </span>
                                                  ))}
                                                </div>
                                              </div>
                                            )}
                                          </div>
                                        )}
                                        {!peer.podSelector && peer.namespaceSelector && (
                                          <div className="flex items-center gap-2">
                                            <span className="text-xs text-tertiary min-w-[60px]">Namespace:</span>
                                            <div className="flex flex-wrap gap-1">
                                              {Object.entries(peer.namespaceSelector.matchLabels).map(([key, value]) => (
                                                <span key={key} className="text-xs bg-hubble-accent/20 text-hubble-accent px-2 py-0.5 rounded">
                                                  {key}: {value}
                                                </span>
                                              ))}
                                            </div>
                                          </div>
                                        )}
                                        <button
                                          onClick={() => removePeerFromRule(rule.id, peerIndex, 'ingress')}
                                          className="p-1 text-hubble-error hover:bg-hubble-error/20 rounded transition-colors"
                                          title="Remove source"
                                        >
                                          <Trash2 className="w-3 h-3" />
                                        </button>
                                      </div>
                                    </div>
                                  ))
                                ) : (
                                  <p className="text-xs text-tertiary italic">No sources defined</p>
                                )}
                              </div>
                            </div>
                            <div>
                              <div className="flex items-center justify-between mb-2">
                                <label className="text-xs font-medium text-secondary">Ports</label>
                                <button
                                  onClick={() => addPortToRule(rule.id, 'ingress')}
                                  className="text-xs text-hubble-accent hover:text-blue-400 flex items-center gap-1"
                                >
                                  <Plus className="w-3 h-3" />
                                  Add Port
                                </button>
                              </div>
                              <div className="space-y-2">
                                {rule.ports.length > 0 ? (
                                  rule.ports.map((port, portIndex) => (
                                    <div key={portIndex} className="bg-hubble-dark p-2 rounded border border-hubble-border">
                                      <div className="flex items-center gap-2">
                                        <select
                                          value={port.protocol}
                                          onChange={(e) => updatePort(rule.id, portIndex, 'protocol', e.target.value, 'ingress')}
                                          className="bg-hubble-card text-secondary px-2 py-1 rounded border border-hubble-border
                                                     focus:outline-none focus:ring-1 focus:ring-hubble-accent text-xs"
                                        >
                                          <option value="TCP">TCP</option>
                                          <option value="UDP">UDP</option>
                                          <option value="SCTP">SCTP</option>
                                        </select>
                                        <span className="text-xs text-tertiary">/</span>
                                        <input
                                          type="number"
                                          value={port.port}
                                          onChange={(e) => updatePort(rule.id, portIndex, 'port', parseInt(e.target.value) || 0, 'ingress')}
                                          className="w-20 bg-hubble-card text-secondary px-2 py-1 rounded border border-hubble-border
                                                     focus:outline-none focus:ring-1 focus:ring-hubble-accent text-xs font-mono"
                                          placeholder="80"
                                          min="1"
                                          max="65535"
                                        />
                                        <button
                                          onClick={() => removePortFromRule(rule.id, portIndex, 'ingress')}
                                          className="p-1 text-hubble-error hover:bg-hubble-error/20 rounded transition-colors ml-auto"
                                          title="Remove port"
                                        >
                                          <Trash2 className="w-3 h-3" />
                                        </button>
                                      </div>
                                    </div>
                                  ))
                                ) : (
                                  <p className="text-xs text-tertiary italic">No ports defined</p>
                                )}
                              </div>
                            </div>
                          </div>
                        </div>
                      ))
                    ) : (
                      <p className="text-xs text-tertiary text-center py-4">
                        No ingress rules defined. Click "Add Rule" to create one.
                      </p>
                    )}
                    </div>
                  )}
                </div>

                {/* Egress Rules */}
                <div className="bg-hubble-dark p-4 rounded-lg border border-hubble-border">
                  <div className="flex items-center justify-between mb-3">
                    <button
                      onClick={() => setIsEgressExpanded(!isEgressExpanded)}
                      className="flex items-center gap-2 text-sm font-semibold text-primary hover:text-hubble-accent transition-colors"
                    >
                      {isEgressExpanded ? (
                        <ChevronDown className="w-4 h-4 text-hubble-warning" />
                      ) : (
                        <ChevronRight className="w-4 h-4 text-hubble-warning" />
                      )}
                      Egress Rules
                      {policy.spec.egress && ` (${policy.spec.egress.length})`}
                    </button>
                    {isEgressExpanded && (
                      <button
                        onClick={addEgressRule}
                        className="px-3 py-1.5 text-xs bg-hubble-warning text-white rounded-lg hover:bg-orange-600
                                   transition-colors flex items-center gap-1"
                      >
                        <Plus className="w-3 h-3" />
                        Add Rule
                      </button>
                    )}
                  </div>
                  {isEgressExpanded && (
                    <div className="space-y-3">
                    {policy.spec.egress && policy.spec.egress.length > 0 ? (
                      policy.spec.egress.map((rule, index) => (
                        <div key={rule.id} className="bg-hubble-card p-3 rounded-lg border border-hubble-border">
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-xs font-medium text-secondary">Rule {index + 1}</span>
                            <button
                              onClick={() => removeEgressRule(rule.id)}
                              className="p-1 text-hubble-error hover:bg-hubble-error/20 rounded transition-colors"
                              title="Remove rule"
                            >
                              <Trash2 className="w-3 h-3" />
                            </button>
                          </div>
                          <div className="space-y-3">
                            <div>
                              <div className="flex items-center justify-between mb-2">
                                <label className="text-xs font-medium text-secondary">To (Destinations)</label>
                                <button
                                  onClick={() => addPeerToRule(rule.id, 'egress')}
                                  className="text-xs text-hubble-accent hover:text-blue-400 flex items-center gap-1"
                                >
                                  <Plus className="w-3 h-3" />
                                  Add Destination
                                </button>
                              </div>
                              <div className="space-y-2">
                                {rule.peers.length > 0 ? (
                                  rule.peers.map((peer, peerIndex) => (
                                    <div key={peerIndex} className="bg-hubble-dark p-2 rounded border border-hubble-border">
                                      <div className="flex items-center gap-2">
                                        {peer.ipBlock && (
                                          <>
                                            <span className="text-xs text-tertiary min-w-[60px]">IP Block:</span>
                                            <input
                                              type="text"
                                              value={peer.ipBlock.cidr}
                                              onChange={(e) => updatePeerCIDR(rule.id, peerIndex, e.target.value, 'egress')}
                                              className="flex-1 bg-hubble-card text-secondary px-2 py-1 rounded border border-hubble-border
                                                         focus:outline-none focus:ring-1 focus:ring-hubble-accent text-xs font-mono"
                                              placeholder="0.0.0.0/0"
                                            />
                                          </>
                                        )}
                                        {peer.podSelector && (
                                          <div className="flex-1 flex flex-col gap-1">
                                            <div className="flex items-center gap-2">
                                              <span className="text-xs text-tertiary min-w-[60px]">Pod Selector:</span>
                                              <div className="flex flex-wrap gap-1">
                                                {Object.entries(peer.podSelector.matchLabels).map(([key, value]) => (
                                                  <span key={key} className="text-xs bg-hubble-success/20 text-hubble-success px-2 py-0.5 rounded">
                                                    {key}: {value}
                                                  </span>
                                                ))}
                                              </div>
                                            </div>
                                            {peer.namespaceSelector && (
                                              <div className="flex items-center gap-2">
                                                <span className="text-xs text-tertiary min-w-[60px]">Namespace:</span>
                                                <div className="flex flex-wrap gap-1">
                                                  {Object.entries(peer.namespaceSelector.matchLabels).map(([key, value]) => (
                                                    <span key={key} className="text-xs bg-hubble-accent/20 text-hubble-accent px-2 py-0.5 rounded">
                                                      {key}: {value}
                                                    </span>
                                                  ))}
                                                </div>
                                              </div>
                                            )}
                                          </div>
                                        )}
                                        {!peer.podSelector && peer.namespaceSelector && (
                                          <div className="flex items-center gap-2">
                                            <span className="text-xs text-tertiary min-w-[60px]">Namespace:</span>
                                            <div className="flex flex-wrap gap-1">
                                              {Object.entries(peer.namespaceSelector.matchLabels).map(([key, value]) => (
                                                <span key={key} className="text-xs bg-hubble-accent/20 text-hubble-accent px-2 py-0.5 rounded">
                                                  {key}: {value}
                                                </span>
                                              ))}
                                            </div>
                                          </div>
                                        )}
                                        <button
                                          onClick={() => removePeerFromRule(rule.id, peerIndex, 'egress')}
                                          className="p-1 text-hubble-error hover:bg-hubble-error/20 rounded transition-colors"
                                          title="Remove destination"
                                        >
                                          <Trash2 className="w-3 h-3" />
                                        </button>
                                      </div>
                                    </div>
                                  ))
                                ) : (
                                  <p className="text-xs text-tertiary italic">No destinations defined</p>
                                )}
                              </div>
                            </div>
                            <div>
                              <div className="flex items-center justify-between mb-2">
                                <label className="text-xs font-medium text-secondary">Ports</label>
                                <button
                                  onClick={() => addPortToRule(rule.id, 'egress')}
                                  className="text-xs text-hubble-accent hover:text-blue-400 flex items-center gap-1"
                                >
                                  <Plus className="w-3 h-3" />
                                  Add Port
                                </button>
                              </div>
                              <div className="space-y-2">
                                {rule.ports.length > 0 ? (
                                  rule.ports.map((port, portIndex) => (
                                    <div key={portIndex} className="bg-hubble-dark p-2 rounded border border-hubble-border">
                                      <div className="flex items-center gap-2">
                                        <select
                                          value={port.protocol}
                                          onChange={(e) => updatePort(rule.id, portIndex, 'protocol', e.target.value, 'egress')}
                                          className="bg-hubble-card text-secondary px-2 py-1 rounded border border-hubble-border
                                                     focus:outline-none focus:ring-1 focus:ring-hubble-accent text-xs"
                                        >
                                          <option value="TCP">TCP</option>
                                          <option value="UDP">UDP</option>
                                          <option value="SCTP">SCTP</option>
                                        </select>
                                        <span className="text-xs text-tertiary">/</span>
                                        <input
                                          type="number"
                                          value={port.port}
                                          onChange={(e) => updatePort(rule.id, portIndex, 'port', parseInt(e.target.value) || 0, 'egress')}
                                          className="w-20 bg-hubble-card text-secondary px-2 py-1 rounded border border-hubble-border
                                                     focus:outline-none focus:ring-1 focus:ring-hubble-accent text-xs font-mono"
                                          placeholder="80"
                                          min="1"
                                          max="65535"
                                        />
                                        <button
                                          onClick={() => removePortFromRule(rule.id, portIndex, 'egress')}
                                          className="p-1 text-hubble-error hover:bg-hubble-error/20 rounded transition-colors ml-auto"
                                          title="Remove port"
                                        >
                                          <Trash2 className="w-3 h-3" />
                                        </button>
                                      </div>
                                    </div>
                                  ))
                                ) : (
                                  <p className="text-xs text-tertiary italic">No ports defined</p>
                                )}
                              </div>
                            </div>
                          </div>
                        </div>
                      ))
                    ) : (
                      <p className="text-xs text-tertiary text-center py-4">
                        No egress rules defined. Click "Add Rule" to create one.
                      </p>
                    )}
                    </div>
                  )}
                </div>
                  </>
                ) : policyType === 'seccomp' && seccompProfile ? (
                  /* Seccomp Profile Visual Editor */
                  <>
                    {/* Default Action */}
                    <div className="bg-hubble-dark p-4 rounded-lg border border-hubble-border">
                      <h3 className="text-sm font-semibold text-primary mb-3">Default Action</h3>
                      <div className="flex items-center gap-3">
                        <label className="text-xs text-tertiary">Action for syscalls not explicitly allowed:</label>
                        <select
                          value={seccompProfile.defaultAction}
                          onChange={(e) => updateDefaultAction(e.target.value as SeccompAction)}
                          className="bg-hubble-card text-primary px-3 py-2 rounded border border-hubble-border
                                     focus:outline-none focus:ring-2 focus:ring-hubble-accent focus:border-transparent text-sm"
                        >
                          {SECCOMP_ACTIONS.map(action => (
                            <option key={action} value={action}>{action}</option>
                          ))}
                        </select>
                      </div>
                    </div>

                    {/* Architectures */}
                    <div className="bg-hubble-dark p-4 rounded-lg border border-hubble-border">
                      <h3 className="text-sm font-semibold text-primary mb-3">Architectures</h3>
                      <div className="flex flex-wrap gap-2">
                        {ARCHITECTURES.map(arch => (
                          <button
                            key={arch}
                            onClick={() => toggleArchitecture(arch)}
                            className={`px-3 py-1.5 text-xs rounded-lg border transition-all ${
                              seccompProfile.architectures?.includes(arch)
                                ? 'bg-hubble-accent/20 border-hubble-accent text-hubble-accent'
                                : 'border-hubble-border text-secondary hover:border-hubble-accent/50'
                            }`}
                          >
                            {arch.replace('SCMP_ARCH_', '')}
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* Syscall Rules */}
                    <div className="bg-hubble-dark p-4 rounded-lg border border-hubble-border">
                      <div className="flex items-center justify-between mb-3">
                        <button
                          onClick={() => setIsSyscallsExpanded(!isSyscallsExpanded)}
                          className="flex items-center gap-2 text-sm font-semibold text-primary hover:text-hubble-accent transition-colors"
                        >
                          {isSyscallsExpanded ? (
                            <ChevronDown className="w-4 h-4 text-hubble-success" />
                          ) : (
                            <ChevronRight className="w-4 h-4 text-hubble-success" />
                          )}
                          Syscall Rules
                          {seccompProfile.syscalls && ` (${seccompProfile.syscalls.length})`}
                        </button>
                        {isSyscallsExpanded && (
                          <button
                            onClick={addSyscallRule}
                            className="px-3 py-1.5 text-xs bg-hubble-success text-white rounded-lg hover:bg-green-600
                                       transition-colors flex items-center gap-1"
                          >
                            <Plus className="w-3 h-3" />
                            Add Rule
                          </button>
                        )}
                      </div>
                      {isSyscallsExpanded && (
                        <div className="space-y-3">
                          {seccompProfile.syscalls && seccompProfile.syscalls.length > 0 ? (
                            seccompProfile.syscalls.map((rule, index) => (
                              <div key={index} className="bg-hubble-card p-3 rounded-lg border border-hubble-border">
                                <div className="flex items-center justify-between mb-3">
                                  <div className="flex items-center gap-3">
                                    <span className="text-xs font-medium text-secondary">Rule {index + 1}</span>
                                    <select
                                      value={rule.action}
                                      onChange={(e) => updateSyscallAction(index, e.target.value as SeccompAction)}
                                      className="bg-hubble-dark text-secondary px-2 py-1 rounded border border-hubble-border
                                                 focus:outline-none focus:ring-1 focus:ring-hubble-accent text-xs"
                                    >
                                      {SECCOMP_ACTIONS.map(action => (
                                        <option key={action} value={action}>{action}</option>
                                      ))}
                                    </select>
                                  </div>
                                  <button
                                    onClick={() => removeSyscallRule(index)}
                                    className="p-1 text-hubble-error hover:bg-hubble-error/20 rounded transition-colors"
                                    title="Remove rule"
                                  >
                                    <Trash2 className="w-3 h-3" />
                                  </button>
                                </div>
                                <div>
                                  <label className="text-xs font-medium text-secondary mb-2 block">Syscalls ({rule.names.length})</label>
                                  <div className="flex flex-wrap gap-2 mb-2">
                                    {rule.names.map((syscall, syscallIndex) => (
                                      <div
                                        key={syscallIndex}
                                        className="flex items-center gap-1 bg-hubble-dark px-2 py-1 rounded border border-hubble-border"
                                      >
                                        <span className="text-xs text-secondary font-mono">{syscall}</span>
                                        <button
                                          onClick={() => removeSyscallFromRule(index, syscallIndex)}
                                          className="text-hubble-error hover:text-red-400 transition-colors"
                                          title="Remove syscall"
                                        >
                                          <X className="w-3 h-3" />
                                        </button>
                                      </div>
                                    ))}
                                  </div>
                                  <div className="relative">
                                    <div className="flex items-center gap-1">
                                      <input
                                        type="text"
                                        placeholder="Type syscall name..."
                                        value={syscallInputValues[index] || ''}
                                        onChange={(e) => handleSyscallInputChange(index, e.target.value)}
                                        onKeyDown={(e) => handleSyscallKeyDown(index, e)}
                                        className={`w-48 bg-hubble-dark text-secondary px-2 py-1 rounded border text-xs font-mono
                                                   focus:outline-none focus:ring-1 focus:ring-hubble-accent ${
                                                     syscallErrors[index]
                                                       ? 'border-hubble-error'
                                                       : 'border-hubble-border'
                                                   }`}
                                      />
                                      <span className="text-xs text-tertiary">↑↓ to navigate, Enter to add</span>
                                    </div>

                                    {/* Autocomplete dropdown */}
                                    {syscallSuggestions[index] && syscallSuggestions[index].length > 0 && (
                                      <div className="absolute z-10 mt-1 w-48 bg-hubble-dark border border-hubble-border rounded-lg shadow-lg max-h-48 overflow-y-auto">
                                        {syscallSuggestions[index].map((suggestion, suggestionIndex) => (
                                          <button
                                            key={suggestionIndex}
                                            type="button"
                                            onClick={() => {
                                              addSyscallToRule(index, suggestion);
                                              setSyscallSuggestions({
                                                ...syscallSuggestions,
                                                [index]: [],
                                              });
                                            }}
                                            className={`w-full text-left px-3 py-1.5 text-xs font-mono hover:bg-hubble-card transition-colors ${
                                              (activeSuggestionIndex[index] ?? -1) === suggestionIndex
                                                ? 'bg-hubble-accent text-white'
                                                : 'text-secondary'
                                            }`}
                                          >
                                            {suggestion}
                                          </button>
                                        ))}
                                      </div>
                                    )}

                                    {/* Validation error */}
                                    {syscallErrors[index] && (
                                      <div className="flex items-center gap-1 mt-1 text-hubble-error">
                                        <AlertCircle className="w-3 h-3" />
                                        <span className="text-xs">{syscallErrors[index]}</span>
                                      </div>
                                    )}
                                  </div>
                                </div>
                              </div>
                            ))
                          ) : (
                            <p className="text-xs text-tertiary text-center py-4">
                              No syscall rules defined. Click "Add Rule" to create one.
                            </p>
                          )}
                        </div>
                      )}
                    </div>
                  </>
                ) : null}
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="border-t border-hubble-border px-6 py-4">
            <div className="flex items-center justify-between">
              <p className="text-xs text-tertiary">
                {policyType === 'network'
                  ? 'This policy was generated from observed network traffic. Review and customize before applying.'
                  : 'This profile was generated from observed syscalls. Review and customize before applying.'}
              </p>
              <div className="flex gap-2">
                <button
                  onClick={onClose}
                  className="px-4 py-2 text-sm text-secondary hover:text-primary hover:bg-hubble-dark rounded-lg transition-colors"
                >
                  Close
                </button>
                <button
                  onClick={handleDownloadYAML}
                  className="px-4 py-2 text-sm bg-hubble-accent text-white rounded-lg hover:bg-blue-600 transition-colors"
                >
                  {policyType === 'network' ? 'Save Policy' : 'Save Profile'}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default NetworkPolicyEditor;
