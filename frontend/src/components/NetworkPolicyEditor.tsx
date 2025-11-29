import React, { useState } from 'react';
import { Plus, Trash2, X, ChevronDown, ChevronRight, AlertCircle, RefreshCw } from 'lucide-react';
import type { PodNodeData } from '../types';
import type { SeccompAction } from '../types/seccompProfile';
import { policyToYAML } from '../utils/networkPolicyGenerator';
import { profileToYAML } from '../utils/seccompProfileGenerator';
import { SECCOMP_ACTIONS, ARCHITECTURES, SECCOMP_ACTION_DESCRIPTIONS } from '../types/seccompProfile';
import { PolicyHeader } from './PolicyEditor';
import {
  useNetworkPolicyEditor,
  useSeccompProfileEditor,
  useSyscallAutocomplete,
  usePolicyExport,
  type PolicyType,
} from '../hooks/policyEditor';

interface NetworkPolicyEditorProps {
  isOpen: boolean;
  onClose: () => void;
  pod: PodNodeData | null;
  allPods?: PodNodeData[];
}

const NetworkPolicyEditor: React.FC<NetworkPolicyEditorProps> = ({ isOpen, onClose, pod, allPods = [] }) => {
  const [policyType, setPolicyType] = useState<PolicyType>('network');
  const [yamlView, setYamlView] = useState(true); // Default to YAML view

  // Network policy management
  const {
    policy,
    setPolicy,
    isLoading: isNetworkPolicyLoading,
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
    addLabelToPeer,
    removeLabelFromPeer,
    togglePodSelector,
  } = useNetworkPolicyEditor({ pod, allPods, isOpen: isOpen && policyType === 'network' });

  // Seccomp profile management
  const {
    seccompProfile,
    isSyscallsExpanded,
    setIsSyscallsExpanded,
    syscallErrors,
    addSyscallRule,
    removeSyscallRule,
    addSyscallToRule,
    removeSyscallFromRule,
    updateSyscallAction,
    updateDefaultAction,
    toggleArchitecture,
    clearSyscallError,
  } = useSeccompProfileEditor({ pod, isOpen: isOpen && policyType === 'seccomp' });

  // Syscall autocomplete
  const {
    syscallInputValues,
    syscallSuggestions,
    activeSuggestionIndex,
    handleInputChange: handleSyscallInputChange,
    handleKeyDown: handleSyscallKeyDown,
    clearInput: clearSyscallInput,
  } = useSyscallAutocomplete();

  // Export functionality
  const { copiedToClipboard, handleCopy, handleDownload } = usePolicyExport({
    policyType,
    policy,
    seccompProfile,
    podName: pod?.pod.pod_name || '',
    podIdentity: pod?.pod.pod_identity || undefined,
    podNamespace: pod?.pod.pod_namespace || 'default',
    yamlView,
  });

  if (!isOpen || !pod) return null;

  // Show loading state while generating policy
  const isLoading = (policyType === 'network' && isNetworkPolicyLoading) ||
                     (policyType === 'network' && !policy) ||
                     (policyType === 'seccomp' && !seccompProfile);

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
          <PolicyHeader
            policyType={policyType}
            onPolicyTypeChange={setPolicyType}
            yamlView={yamlView}
            onYamlViewToggle={() => setYamlView(!yamlView)}
            copiedToClipboard={copiedToClipboard}
            onCopy={handleCopy}
            onDownload={handleDownload}
            onClose={onClose}
            podName={pod.pod.pod_name}
            podNamespace={pod.pod.pod_namespace}
          />

          {/* Content */}
          <div className="flex-1 overflow-hidden flex">
            {isLoading ? (
              /* Loading State */
              <div className="flex-1 flex items-center justify-center">
                <div className="text-center">
                  <RefreshCw className="w-12 h-12 text-hubble-accent animate-spin mx-auto mb-4" />
                  <p className="text-lg font-semibold text-primary mb-2">
                    Generating {policyType === 'network' ? 'Network Policy' : 'Seccomp Profile'}
                  </p>
                  <p className="text-sm text-tertiary">
                    Analyzing traffic patterns and building policy rules...
                  </p>
                </div>
              </div>
            ) : yamlView ? (
              /* YAML View */
              <div className="flex-1 p-6 overflow-auto">
                <pre className="bg-hubble-dark text-secondary p-4 rounded-lg font-mono text-sm overflow-x-auto">
                  {policyType === 'network' && policy
                    ? policyToYAML(policy)
                    : policyType === 'seccomp' && seccompProfile
                    ? profileToYAML(seccompProfile, pod.pod.pod_identity || pod.pod.pod_name, pod.pod.pod_namespace || 'default')
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
                                    <div key={peerIndex} className="bg-hubble-dark p-3 rounded border border-hubble-border space-y-2">
                                      {/* Peer Type Selector */}
                                      <div className="flex items-center gap-2">
                                        <span className="text-xs text-tertiary min-w-[60px]">Scope:</span>
                                        <select
                                          value={
                                            peer.ipBlock
                                              ? 'external'
                                              : peer.podSelector && !peer.namespaceSelector
                                              ? 'inNamespace'
                                              : 'inCluster'
                                          }
                                          onChange={(e) => changePeerType(rule.id, peerIndex, e.target.value as any, 'ingress')}
                                          className="bg-hubble-card text-secondary px-2 py-1 rounded border border-hubble-border
                                                     focus:outline-none focus:ring-1 focus:ring-hubble-accent text-xs"
                                        >
                                          <option value="external">External (IP Block)</option>
                                          <option value="inNamespace">In Namespace (Same Namespace)</option>
                                          <option value="inCluster">In Cluster (Any Namespace)</option>
                                        </select>
                                      </div>

                                      {/* IP Block Editor */}
                                      {peer.ipBlock && (
                                        <div className="flex items-center gap-2">
                                          <span className="text-xs text-tertiary min-w-[60px]">CIDR:</span>
                                          <input
                                            type="text"
                                            value={peer.ipBlock.cidr}
                                            onChange={(e) => updatePeerCIDR(rule.id, peerIndex, e.target.value, 'ingress')}
                                            className="flex-1 bg-hubble-card text-secondary px-2 py-1 rounded border border-hubble-border
                                                       focus:outline-none focus:ring-1 focus:ring-hubble-accent text-xs font-mono"
                                            placeholder="0.0.0.0/0 or 10.0.0.0/8"
                                          />
                                        </div>
                                      )}

                                      {/* In Namespace: Pod Selector Only */}
                                      {peer.podSelector && !peer.namespaceSelector && (
                                        <div className="space-y-2">
                                          <div>
                                            <div className="flex items-center justify-between mb-1">
                                              <span className="text-xs font-medium text-secondary">Pod Labels (Same Namespace)</span>
                                            </div>
                                            {/* Show existing labels */}
                                            {Object.entries(peer.podSelector.matchLabels).length > 0 && (
                                              <div className="flex flex-wrap gap-1 mb-2">
                                                {Object.entries(peer.podSelector.matchLabels).map(([key, value]) => (
                                                  <div key={key} className="flex items-center gap-1 bg-hubble-success/20 text-hubble-success px-2 py-1 rounded text-xs">
                                                    <span className="font-mono">{key}={value}</span>
                                                    <button
                                                      onClick={() => removeLabelFromPeer(rule.id, peerIndex, 'podSelector', key, 'ingress')}
                                                      className="hover:text-red-400 transition-colors"
                                                      title="Remove label"
                                                    >
                                                      <X className="w-3 h-3" />
                                                    </button>
                                                  </div>
                                                ))}
                                              </div>
                                            )}
                                            {/* Add new label inputs */}
                                            <div className="flex items-center gap-2">
                                              <input
                                                type="text"
                                                value={labelInputs[`${rule.id}-${peerIndex}-podSelector`]?.key || ''}
                                                onChange={(e) => setLabelInputs({
                                                  ...labelInputs,
                                                  [`${rule.id}-${peerIndex}-podSelector`]: {
                                                    ...labelInputs[`${rule.id}-${peerIndex}-podSelector`],
                                                    key: e.target.value
                                                  }
                                                })}
                                                className="flex-1 bg-hubble-card text-secondary px-2 py-1 rounded border border-hubble-border
                                                           focus:outline-none focus:ring-1 focus:ring-hubble-accent text-xs"
                                                placeholder="app"
                                              />
                                              <span className="text-xs text-tertiary">=</span>
                                              <input
                                                type="text"
                                                value={labelInputs[`${rule.id}-${peerIndex}-podSelector`]?.value || ''}
                                                onChange={(e) => setLabelInputs({
                                                  ...labelInputs,
                                                  [`${rule.id}-${peerIndex}-podSelector`]: {
                                                    ...labelInputs[`${rule.id}-${peerIndex}-podSelector`],
                                                    value: e.target.value
                                                  }
                                                })}
                                                onKeyDown={(e) => {
                                                  if (e.key === 'Enter') {
                                                    const input = labelInputs[`${rule.id}-${peerIndex}-podSelector`];
                                                    if (input?.key) {
                                                      addLabelToPeer(rule.id, peerIndex, 'podSelector', input.key, input.value || '', 'ingress');
                                                      setLabelInputs({
                                                        ...labelInputs,
                                                        [`${rule.id}-${peerIndex}-podSelector`]: { key: '', value: '' }
                                                      });
                                                    }
                                                  }
                                                }}
                                                className="flex-1 bg-hubble-card text-secondary px-2 py-1 rounded border border-hubble-border
                                                           focus:outline-none focus:ring-1 focus:ring-hubble-accent text-xs"
                                                placeholder="nginx"
                                              />
                                              <button
                                                onClick={() => {
                                                  const input = labelInputs[`${rule.id}-${peerIndex}-podSelector`];
                                                  if (input?.key) {
                                                    addLabelToPeer(rule.id, peerIndex, 'podSelector', input.key, input.value || '', 'ingress');
                                                    setLabelInputs({
                                                      ...labelInputs,
                                                      [`${rule.id}-${peerIndex}-podSelector`]: { key: '', value: '' }
                                                    });
                                                  }
                                                }}
                                                className="px-2 py-1 bg-hubble-success text-white rounded text-xs hover:bg-green-600 transition-colors"
                                              >
                                                <Plus className="w-3 h-3" />
                                              </button>
                                            </div>
                                          </div>
                                        </div>
                                      )}

                                      {/* In Cluster: Namespace Selector + Optional Pod Selector */}
                                      {peer.namespaceSelector && (
                                        <div className="space-y-2">
                                          {/* Namespace Selector */}
                                          <div>
                                            <div className="flex items-center justify-between mb-1">
                                              <span className="text-xs font-medium text-secondary">Namespace Labels</span>
                                              <span className="text-xs text-tertiary italic">Leave empty to match all namespaces</span>
                                            </div>
                                            {/* Show existing labels */}
                                            {Object.entries(peer.namespaceSelector.matchLabels).length > 0 && (
                                              <div className="flex flex-wrap gap-1 mb-2">
                                                {Object.entries(peer.namespaceSelector.matchLabels).map(([key, value]) => (
                                                  <div key={key} className="flex items-center gap-1 bg-hubble-accent/20 text-hubble-accent px-2 py-1 rounded text-xs">
                                                    <span className="font-mono">{key}={value}</span>
                                                    <button
                                                      onClick={() => removeLabelFromPeer(rule.id, peerIndex, 'namespaceSelector', key, 'ingress')}
                                                      className="hover:text-red-400 transition-colors"
                                                      title="Remove label"
                                                    >
                                                      <X className="w-3 h-3" />
                                                    </button>
                                                  </div>
                                                ))}
                                              </div>
                                            )}
                                            {/* Add new label inputs */}
                                            <div className="flex items-center gap-2">
                                              <input
                                                type="text"
                                                value={labelInputs[`${rule.id}-${peerIndex}-namespaceSelector`]?.key || ''}
                                                onChange={(e) => setLabelInputs({
                                                  ...labelInputs,
                                                  [`${rule.id}-${peerIndex}-namespaceSelector`]: {
                                                    ...labelInputs[`${rule.id}-${peerIndex}-namespaceSelector`],
                                                    key: e.target.value
                                                  }
                                                })}
                                                className="flex-1 bg-hubble-card text-secondary px-2 py-1 rounded border border-hubble-border
                                                           focus:outline-none focus:ring-1 focus:ring-hubble-accent text-xs"
                                                placeholder="kubernetes.io/metadata.name"
                                              />
                                              <span className="text-xs text-tertiary">=</span>
                                              <input
                                                type="text"
                                                value={labelInputs[`${rule.id}-${peerIndex}-namespaceSelector`]?.value || ''}
                                                onChange={(e) => setLabelInputs({
                                                  ...labelInputs,
                                                  [`${rule.id}-${peerIndex}-namespaceSelector`]: {
                                                    ...labelInputs[`${rule.id}-${peerIndex}-namespaceSelector`],
                                                    value: e.target.value
                                                  }
                                                })}
                                                onKeyDown={(e) => {
                                                  if (e.key === 'Enter') {
                                                    const input = labelInputs[`${rule.id}-${peerIndex}-namespaceSelector`];
                                                    if (input?.key) {
                                                      addLabelToPeer(rule.id, peerIndex, 'namespaceSelector', input.key, input.value || '', 'ingress');
                                                      setLabelInputs({
                                                        ...labelInputs,
                                                        [`${rule.id}-${peerIndex}-namespaceSelector`]: { key: '', value: '' }
                                                      });
                                                    }
                                                  }
                                                }}
                                                className="flex-1 bg-hubble-card text-secondary px-2 py-1 rounded border border-hubble-border
                                                           focus:outline-none focus:ring-1 focus:ring-hubble-accent text-xs"
                                                placeholder="production"
                                              />
                                              <button
                                                onClick={() => {
                                                  const input = labelInputs[`${rule.id}-${peerIndex}-namespaceSelector`];
                                                  if (input?.key) {
                                                    addLabelToPeer(rule.id, peerIndex, 'namespaceSelector', input.key, input.value || '', 'ingress');
                                                    setLabelInputs({
                                                      ...labelInputs,
                                                      [`${rule.id}-${peerIndex}-namespaceSelector`]: { key: '', value: '' }
                                                    });
                                                  }
                                                }}
                                                className="px-2 py-1 bg-hubble-success text-white rounded text-xs hover:bg-green-600 transition-colors"
                                              >
                                                <Plus className="w-3 h-3" />
                                              </button>
                                            </div>
                                          </div>

                                          {/* Pod Selector (optional, to narrow down which pods) */}
                                          {peer.podSelector && (
                                            <div>
                                              <div className="flex items-center justify-between mb-1">
                                                <span className="text-xs font-medium text-secondary">Pod Labels (Optional)</span>
                                                <button
                                                  onClick={() => togglePodSelector(rule.id, peerIndex, 'ingress')}
                                                  className="text-xs text-hubble-error hover:text-red-400"
                                                >
                                                  Remove
                                                </button>
                                              </div>
                                              <span className="text-xs text-tertiary italic block mb-2">Leave empty to match all pods in namespace</span>
                                              {/* Show existing labels */}
                                              {Object.entries(peer.podSelector.matchLabels).length > 0 && (
                                                <div className="flex flex-wrap gap-1 mb-2">
                                                  {Object.entries(peer.podSelector.matchLabels).map(([key, value]) => (
                                                    <div key={key} className="flex items-center gap-1 bg-hubble-success/20 text-hubble-success px-2 py-1 rounded text-xs">
                                                      <span className="font-mono">{key}={value}</span>
                                                      <button
                                                        onClick={() => removeLabelFromPeer(rule.id, peerIndex, 'podSelector', key, 'ingress')}
                                                        className="hover:text-red-400 transition-colors"
                                                        title="Remove label"
                                                      >
                                                        <X className="w-3 h-3" />
                                                      </button>
                                                    </div>
                                                  ))}
                                                </div>
                                              )}
                                              {/* Add new label inputs */}
                                              <div className="flex items-center gap-2">
                                                <input
                                                  type="text"
                                                  value={labelInputs[`${rule.id}-${peerIndex}-podSelector-incluster`]?.key || ''}
                                                  onChange={(e) => setLabelInputs({
                                                    ...labelInputs,
                                                    [`${rule.id}-${peerIndex}-podSelector-incluster`]: {
                                                      ...labelInputs[`${rule.id}-${peerIndex}-podSelector-incluster`],
                                                      key: e.target.value
                                                    }
                                                  })}
                                                  className="flex-1 bg-hubble-card text-secondary px-2 py-1 rounded border border-hubble-border
                                                             focus:outline-none focus:ring-1 focus:ring-hubble-accent text-xs"
                                                  placeholder="app"
                                                />
                                                <span className="text-xs text-tertiary">=</span>
                                                <input
                                                  type="text"
                                                  value={labelInputs[`${rule.id}-${peerIndex}-podSelector-incluster`]?.value || ''}
                                                  onChange={(e) => setLabelInputs({
                                                    ...labelInputs,
                                                    [`${rule.id}-${peerIndex}-podSelector-incluster`]: {
                                                      ...labelInputs[`${rule.id}-${peerIndex}-podSelector-incluster`],
                                                      value: e.target.value
                                                    }
                                                  })}
                                                  onKeyDown={(e) => {
                                                    if (e.key === 'Enter') {
                                                      const input = labelInputs[`${rule.id}-${peerIndex}-podSelector-incluster`];
                                                      if (input?.key) {
                                                        addLabelToPeer(rule.id, peerIndex, 'podSelector', input.key, input.value || '', 'ingress');
                                                        setLabelInputs({
                                                          ...labelInputs,
                                                          [`${rule.id}-${peerIndex}-podSelector-incluster`]: { key: '', value: '' }
                                                        });
                                                      }
                                                    }
                                                  }}
                                                  className="flex-1 bg-hubble-card text-secondary px-2 py-1 rounded border border-hubble-border
                                                             focus:outline-none focus:ring-1 focus:ring-hubble-accent text-xs"
                                                  placeholder="nginx"
                                                />
                                                <button
                                                  onClick={() => {
                                                    const input = labelInputs[`${rule.id}-${peerIndex}-podSelector-incluster`];
                                                    if (input?.key) {
                                                      addLabelToPeer(rule.id, peerIndex, 'podSelector', input.key, input.value || '', 'ingress');
                                                      setLabelInputs({
                                                        ...labelInputs,
                                                        [`${rule.id}-${peerIndex}-podSelector-incluster`]: { key: '', value: '' }
                                                      });
                                                    }
                                                  }}
                                                  className="px-2 py-1 bg-hubble-success text-white rounded text-xs hover:bg-green-600 transition-colors"
                                                >
                                                  <Plus className="w-3 h-3" />
                                                </button>
                                              </div>
                                            </div>
                                          )}

                                          {/* Add Pod Selector button */}
                                          {!peer.podSelector && (
                                            <button
                                              onClick={() => togglePodSelector(rule.id, peerIndex, 'ingress')}
                                              className="text-xs text-hubble-accent hover:text-blue-400"
                                            >
                                              + Add Pod Selector (Optional)
                                            </button>
                                          )}
                                        </div>
                                      )}


                                      {/* Remove button */}
                                      <div className="flex justify-end">
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
                                    <div key={peerIndex} className="bg-hubble-dark p-3 rounded border border-hubble-border space-y-2">
                                      {/* Peer Type Selector */}
                                      <div className="flex items-center gap-2">
                                        <span className="text-xs text-tertiary min-w-[60px]">Scope:</span>
                                        <select
                                          value={
                                            peer.ipBlock
                                              ? 'external'
                                              : peer.podSelector && !peer.namespaceSelector
                                              ? 'inNamespace'
                                              : 'inCluster'
                                          }
                                          onChange={(e) => changePeerType(rule.id, peerIndex, e.target.value as any, 'egress')}
                                          className="bg-hubble-card text-secondary px-2 py-1 rounded border border-hubble-border
                                                     focus:outline-none focus:ring-1 focus:ring-hubble-accent text-xs"
                                        >
                                          <option value="external">External (IP Block)</option>
                                          <option value="inNamespace">In Namespace (Same Namespace)</option>
                                          <option value="inCluster">In Cluster (Any Namespace)</option>
                                        </select>
                                      </div>

                                      {/* External: IP Block Editor */}
                                      {peer.ipBlock && (
                                        <div className="space-y-2">
                                          <div className="flex items-center gap-2">
                                            <span className="text-xs text-tertiary min-w-[60px]">CIDR:</span>
                                            <input
                                              type="text"
                                              value={peer.ipBlock.cidr}
                                              onChange={(e) => updatePeerCIDR(rule.id, peerIndex, e.target.value, 'egress')}
                                              className="flex-1 bg-hubble-card text-secondary px-2 py-1 rounded border border-hubble-border
                                                         focus:outline-none focus:ring-1 focus:ring-hubble-accent text-xs font-mono"
                                              placeholder="0.0.0.0/0 or 10.0.0.0/8"
                                            />
                                          </div>
                                          <p className="text-xs text-tertiary italic">
                                            External traffic outside the cluster
                                          </p>
                                        </div>
                                      )}

                                      {/* In Namespace: Pod Selector Only */}
                                      {peer.podSelector && !peer.namespaceSelector && (
                                        <div className="space-y-2">
                                          <div>
                                            <div className="flex items-center justify-between mb-1">
                                              <span className="text-xs font-medium text-secondary">Pod Labels (Same Namespace)</span>
                                            </div>
                                            {/* Show existing labels as chips */}
                                            {Object.entries(peer.podSelector.matchLabels).length > 0 && (
                                              <div className="flex flex-wrap gap-1 mb-2">
                                                {Object.entries(peer.podSelector.matchLabels).map(([key, value]) => (
                                                  <div key={key} className="flex items-center gap-1 bg-hubble-success/20 text-hubble-success px-2 py-1 rounded text-xs">
                                                    <span className="font-mono">{key}={value}</span>
                                                    <button
                                                      onClick={() => removeLabelFromPeer(rule.id, peerIndex, 'podSelector', key, 'egress')}
                                                      className="hover:text-red-400 transition-colors"
                                                      title="Remove label"
                                                    >
                                                      <X className="w-3 h-3" />
                                                    </button>
                                                  </div>
                                                ))}
                                              </div>
                                            )}
                                            <span className="text-xs text-tertiary italic block mb-2">
                                              Leave empty to match all pods in the same namespace
                                            </span>
                                            {/* Add new label inputs */}
                                            <div className="flex items-center gap-2">
                                              <input
                                                type="text"
                                                value={labelInputs[`${rule.id}-${peerIndex}-podSelector-egress`]?.key || ''}
                                                onChange={(e) => {
                                                  const currentInputs = labelInputs[`${rule.id}-${peerIndex}-podSelector-egress`] || { key: '', value: '' };
                                                  setLabelInputs({
                                                    ...labelInputs,
                                                    [`${rule.id}-${peerIndex}-podSelector-egress`]: {
                                                      ...currentInputs,
                                                      key: e.target.value
                                                    }
                                                  });
                                                }}
                                                className="flex-1 bg-hubble-card text-secondary px-2 py-1 rounded border border-hubble-border
                                                           focus:outline-none focus:ring-1 focus:ring-hubble-accent text-xs"
                                                placeholder="app"
                                              />
                                              <span className="text-xs text-tertiary">=</span>
                                              <input
                                                type="text"
                                                value={labelInputs[`${rule.id}-${peerIndex}-podSelector-egress`]?.value || ''}
                                                onChange={(e) => {
                                                  const currentInputs = labelInputs[`${rule.id}-${peerIndex}-podSelector-egress`] || { key: '', value: '' };
                                                  setLabelInputs({
                                                    ...labelInputs,
                                                    [`${rule.id}-${peerIndex}-podSelector-egress`]: {
                                                      ...currentInputs,
                                                      value: e.target.value
                                                    }
                                                  });
                                                }}
                                                onKeyDown={(e) => {
                                                  if (e.key === 'Enter') {
                                                    const input = labelInputs[`${rule.id}-${peerIndex}-podSelector-egress`];
                                                    if (input?.key) {
                                                      addLabelToPeer(rule.id, peerIndex, 'podSelector', input.key, input.value || '', 'egress');
                                                      setLabelInputs({
                                                        ...labelInputs,
                                                        [`${rule.id}-${peerIndex}-podSelector-egress`]: { key: '', value: '' }
                                                      });
                                                    }
                                                  }
                                                }}
                                                className="flex-1 bg-hubble-card text-secondary px-2 py-1 rounded border border-hubble-border
                                                           focus:outline-none focus:ring-1 focus:ring-hubble-accent text-xs"
                                                placeholder="nginx"
                                              />
                                              <button
                                                onClick={() => {
                                                  const input = labelInputs[`${rule.id}-${peerIndex}-podSelector-egress`];
                                                  if (input?.key) {
                                                    addLabelToPeer(rule.id, peerIndex, 'podSelector', input.key, input.value || '', 'egress');
                                                    setLabelInputs({
                                                      ...labelInputs,
                                                      [`${rule.id}-${peerIndex}-podSelector-egress`]: { key: '', value: '' }
                                                    });
                                                  }
                                                }}
                                                className="px-2 py-1 bg-hubble-success text-white rounded text-xs hover:bg-green-600 transition-colors"
                                                title="Add label"
                                              >
                                                <Plus className="w-3 h-3" />
                                              </button>
                                            </div>
                                          </div>
                                        </div>
                                      )}

                                      {/* In Cluster: Namespace Selector + Optional Pod Selector */}
                                      {peer.namespaceSelector && (
                                        <div className="space-y-2">
                                          {/* Namespace Selector */}
                                          <div>
                                            <div className="flex items-center justify-between mb-1">
                                              <span className="text-xs font-medium text-secondary">Namespace Labels</span>
                                              <span className="text-xs text-tertiary italic">Leave empty to match all namespaces</span>
                                            </div>
                                            {/* Show existing namespace labels as chips */}
                                            {Object.entries(peer.namespaceSelector.matchLabels).length > 0 && (
                                              <div className="flex flex-wrap gap-1 mb-2">
                                                {Object.entries(peer.namespaceSelector.matchLabels).map(([key, value]) => (
                                                  <div key={key} className="flex items-center gap-1 bg-hubble-accent/20 text-hubble-accent px-2 py-1 rounded text-xs">
                                                    <span className="font-mono">{key}={value}</span>
                                                    <button
                                                      onClick={() => removeLabelFromPeer(rule.id, peerIndex, 'namespaceSelector', key, 'egress')}
                                                      className="hover:text-red-400 transition-colors"
                                                      title="Remove label"
                                                    >
                                                      <X className="w-3 h-3" />
                                                    </button>
                                                  </div>
                                                ))}
                                              </div>
                                            )}
                                            {/* Add new namespace label inputs */}
                                            <div className="flex items-center gap-2">
                                              <input
                                                type="text"
                                                value={labelInputs[`${rule.id}-${peerIndex}-namespaceSelector-egress`]?.key || ''}
                                                onChange={(e) => {
                                                  const currentInputs = labelInputs[`${rule.id}-${peerIndex}-namespaceSelector-egress`] || { key: '', value: '' };
                                                  setLabelInputs({
                                                    ...labelInputs,
                                                    [`${rule.id}-${peerIndex}-namespaceSelector-egress`]: {
                                                      ...currentInputs,
                                                      key: e.target.value
                                                    }
                                                  });
                                                }}
                                                className="flex-1 bg-hubble-card text-secondary px-2 py-1 rounded border border-hubble-border
                                                           focus:outline-none focus:ring-1 focus:ring-hubble-accent text-xs"
                                                placeholder="env"
                                              />
                                              <span className="text-xs text-tertiary">=</span>
                                              <input
                                                type="text"
                                                value={labelInputs[`${rule.id}-${peerIndex}-namespaceSelector-egress`]?.value || ''}
                                                onChange={(e) => {
                                                  const currentInputs = labelInputs[`${rule.id}-${peerIndex}-namespaceSelector-egress`] || { key: '', value: '' };
                                                  setLabelInputs({
                                                    ...labelInputs,
                                                    [`${rule.id}-${peerIndex}-namespaceSelector-egress`]: {
                                                      ...currentInputs,
                                                      value: e.target.value
                                                    }
                                                  });
                                                }}
                                                onKeyDown={(e) => {
                                                  if (e.key === 'Enter') {
                                                    const input = labelInputs[`${rule.id}-${peerIndex}-namespaceSelector-egress`];
                                                    if (input?.key) {
                                                      addLabelToPeer(rule.id, peerIndex, 'namespaceSelector', input.key, input.value || '', 'egress');
                                                      setLabelInputs({
                                                        ...labelInputs,
                                                        [`${rule.id}-${peerIndex}-namespaceSelector-egress`]: { key: '', value: '' }
                                                      });
                                                    }
                                                  }
                                                }}
                                                className="flex-1 bg-hubble-card text-secondary px-2 py-1 rounded border border-hubble-border
                                                           focus:outline-none focus:ring-1 focus:ring-hubble-accent text-xs"
                                                placeholder="production"
                                              />
                                              <button
                                                onClick={() => {
                                                  const input = labelInputs[`${rule.id}-${peerIndex}-namespaceSelector-egress`];
                                                  if (input?.key) {
                                                    addLabelToPeer(rule.id, peerIndex, 'namespaceSelector', input.key, input.value || '', 'egress');
                                                    setLabelInputs({
                                                      ...labelInputs,
                                                      [`${rule.id}-${peerIndex}-namespaceSelector-egress`]: { key: '', value: '' }
                                                    });
                                                  }
                                                }}
                                                className="px-2 py-1 bg-hubble-accent text-white rounded text-xs hover:bg-blue-600 transition-colors"
                                                title="Add namespace label"
                                              >
                                                <Plus className="w-3 h-3" />
                                              </button>
                                            </div>
                                          </div>

                                          {/* Pod Selector (optional, to narrow down which pods) */}
                                          {peer.podSelector && (
                                            <div>
                                              <div className="flex items-center justify-between mb-1">
                                                <span className="text-xs font-medium text-secondary">Pod Labels (Optional)</span>
                                                <button
                                                  onClick={() => togglePodSelector(rule.id, peerIndex, 'egress')}
                                                  className="text-xs text-hubble-error hover:text-red-400"
                                                >
                                                  Remove
                                                </button>
                                              </div>
                                              <span className="text-xs text-tertiary italic block mb-2">
                                                Leave empty to match all pods in namespace
                                              </span>
                                              {/* Show existing pod labels as chips */}
                                              {Object.entries(peer.podSelector.matchLabels).length > 0 && (
                                                <div className="flex flex-wrap gap-1 mb-2">
                                                  {Object.entries(peer.podSelector.matchLabels).map(([key, value]) => (
                                                    <div key={key} className="flex items-center gap-1 bg-hubble-success/20 text-hubble-success px-2 py-1 rounded text-xs">
                                                      <span className="font-mono">{key}={value}</span>
                                                      <button
                                                        onClick={() => removeLabelFromPeer(rule.id, peerIndex, 'podSelector', key, 'egress')}
                                                        className="hover:text-red-400 transition-colors"
                                                        title="Remove label"
                                                      >
                                                        <X className="w-3 h-3" />
                                                      </button>
                                                    </div>
                                                  ))}
                                                </div>
                                              )}
                                              {/* Add new pod label inputs */}
                                              <div className="flex items-center gap-2">
                                                <input
                                                  type="text"
                                                  value={labelInputs[`${rule.id}-${peerIndex}-podSelector-incluster-egress`]?.key || ''}
                                                  onChange={(e) => {
                                                    const currentInputs = labelInputs[`${rule.id}-${peerIndex}-podSelector-incluster-egress`] || { key: '', value: '' };
                                                    setLabelInputs({
                                                      ...labelInputs,
                                                      [`${rule.id}-${peerIndex}-podSelector-incluster-egress`]: {
                                                        ...currentInputs,
                                                        key: e.target.value
                                                      }
                                                    });
                                                  }}
                                                  className="flex-1 bg-hubble-card text-secondary px-2 py-1 rounded border border-hubble-border
                                                             focus:outline-none focus:ring-1 focus:ring-hubble-accent text-xs"
                                                  placeholder="app"
                                                />
                                                <span className="text-xs text-tertiary">=</span>
                                                <input
                                                  type="text"
                                                  value={labelInputs[`${rule.id}-${peerIndex}-podSelector-incluster-egress`]?.value || ''}
                                                  onChange={(e) => {
                                                    const currentInputs = labelInputs[`${rule.id}-${peerIndex}-podSelector-incluster-egress`] || { key: '', value: '' };
                                                    setLabelInputs({
                                                      ...labelInputs,
                                                      [`${rule.id}-${peerIndex}-podSelector-incluster-egress`]: {
                                                        ...currentInputs,
                                                        value: e.target.value
                                                      }
                                                    });
                                                  }}
                                                  onKeyDown={(e) => {
                                                    if (e.key === 'Enter') {
                                                      const input = labelInputs[`${rule.id}-${peerIndex}-podSelector-incluster-egress`];
                                                      if (input?.key) {
                                                        addLabelToPeer(rule.id, peerIndex, 'podSelector', input.key, input.value || '', 'egress');
                                                        setLabelInputs({
                                                          ...labelInputs,
                                                          [`${rule.id}-${peerIndex}-podSelector-incluster-egress`]: { key: '', value: '' }
                                                        });
                                                      }
                                                    }
                                                  }}
                                                  className="flex-1 bg-hubble-card text-secondary px-2 py-1 rounded border border-hubble-border
                                                             focus:outline-none focus:ring-1 focus:ring-hubble-accent text-xs"
                                                  placeholder="nginx"
                                                />
                                                <button
                                                  onClick={() => {
                                                    const input = labelInputs[`${rule.id}-${peerIndex}-podSelector-incluster-egress`];
                                                    if (input?.key) {
                                                      addLabelToPeer(rule.id, peerIndex, 'podSelector', input.key, input.value || '', 'egress');
                                                      setLabelInputs({
                                                        ...labelInputs,
                                                        [`${rule.id}-${peerIndex}-podSelector-incluster-egress`]: { key: '', value: '' }
                                                      });
                                                    }
                                                  }}
                                                  className="px-2 py-1 bg-hubble-success text-white rounded text-xs hover:bg-green-600 transition-colors"
                                                  title="Add pod label"
                                                >
                                                  <Plus className="w-3 h-3" />
                                                </button>
                                              </div>
                                            </div>
                                          )}

                                          {/* Add Pod Selector button */}
                                          {!peer.podSelector && (
                                            <button
                                              onClick={() => togglePodSelector(rule.id, peerIndex, 'egress')}
                                              className="text-xs text-hubble-accent hover:text-blue-400"
                                            >
                                              + Add Pod Selector (Optional)
                                            </button>
                                          )}
                                        </div>
                                      )}

                                      {/* Remove button */}
                                      <div className="flex justify-end">
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
                      <div className="space-y-2">
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
                        <div className="flex items-start gap-2 mt-2 p-2 bg-hubble-card/50 rounded border border-hubble-border/50">
                          <span className="text-hubble-accent text-xs">ℹ️</span>
                          <p className="text-xs text-tertiary">
                            <span className="text-secondary font-medium">{seccompProfile.defaultAction}:</span>{' '}
                            {SECCOMP_ACTION_DESCRIPTIONS[seccompProfile.defaultAction]}
                          </p>
                        </div>
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
                                <div className="flex items-start gap-2 mb-3 p-2 bg-hubble-dark/50 rounded border border-hubble-border/30">
                                  <span className="text-hubble-accent text-xs">ℹ️</span>
                                  <p className="text-xs text-tertiary">
                                    {SECCOMP_ACTION_DESCRIPTIONS[rule.action]}
                                  </p>
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
                                        onChange={(e) => {
                                          handleSyscallInputChange(index, e.target.value);
                                          clearSyscallError(index);
                                        }}
                                        onKeyDown={(e) => handleSyscallKeyDown(index, e, (syscall) => {
                                          const success = addSyscallToRule(index, syscall);
                                          if (success) {
                                            clearSyscallInput(index);
                                          }
                                        })}
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
                                              const success = addSyscallToRule(index, suggestion);
                                              if (success) {
                                                clearSyscallInput(index);
                                              }
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
                  onClick={handleDownload}
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
