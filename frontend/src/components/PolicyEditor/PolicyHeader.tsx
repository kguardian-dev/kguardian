import React from 'react';
import { X, Copy, Download, Shield, Lock, AlertTriangle } from 'lucide-react';
import type { NetworkExportFormat, PolicyType, SeccompExportFormat } from '../../hooks/policyEditor';

interface PolicyHeaderProps {
  policyType: PolicyType;
  onPolicyTypeChange: (type: PolicyType) => void;
  yamlView: boolean;
  onYamlViewToggle: () => void;
  copiedToClipboard: boolean;
  onCopy: () => void;
  onDownload: () => void;
  onClose: () => void;
  podName: string;
  podNamespace: string | null;
  /** Non-null when the cluster CNI makes CiliumNetworkPolicy unlikely
   *  to be applicable; shown as a badge on the Cilium tab. */
  ciliumWarning?: string | null;
  /** Seccomp export format (kguardian CR by default). */
  seccompFormat?: SeccompExportFormat;
  onSeccompFormatChange?: (format: SeccompExportFormat) => void;
  /** Network export format (plain NetworkPolicy by default); names the title. */
  networkFormat?: NetworkExportFormat;
}

// All three are network policies picked from one format switch, so the titles
// stay in one family. "Cilium Policy Builder" dropped the "Network" the other
// two carry, which read as a different tool rather than a different format.
const NETWORK_FORMAT_TITLE: Record<NetworkExportFormat, string> = {
  audit: 'Audit Network Policy Builder',
  network: 'Network Policy Builder',
  cilium: 'Cilium Network Policy Builder',
};

const SECCOMP_FORMAT_LABEL: Record<SeccompExportFormat, string> = {
  kguardian: 'kguardian CR',
  spo: 'Security Profiles Operator CR',
  json: 'raw seccomp JSON',
};

export const PolicyHeader: React.FC<PolicyHeaderProps> = ({
  policyType,
  onPolicyTypeChange,
  yamlView,
  onYamlViewToggle,
  copiedToClipboard,
  onCopy,
  onDownload,
  onClose,
  podName,
  podNamespace,
  ciliumWarning,
  seccompFormat = 'kguardian',
  networkFormat = 'network',
}) => {
  const seccompLabel = SECCOMP_FORMAT_LABEL[seccompFormat];
  // Cilium is a FORMAT of the network tab (picked next to Audit and
  // NetworkPolicy in the YAML view, like the seccomp formats), not a tab of
  // its own, so the tab strip is Network / Seccomp.
  const networkTab = policyType === 'network' || policyType === 'cilium';
  const networkTitle = NETWORK_FORMAT_TITLE[policyType === 'cilium' ? 'cilium' : networkFormat];
  return (
    <div className="flex items-center justify-between px-6 py-4 border-b border-hubble-border">
      <div className="flex items-center gap-3">
        <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-hubble-success/20">
          {/* The icon tracks the TAB, not the export format. Cilium is a
              format of the network tab like Audit and NetworkPolicy are, so
              swapping the icon for it made picking a format look like
              switching tools. Seccomp is a different tab and keeps its own. */}
          {networkTab ? (
            <Shield className="w-5 h-5 text-hubble-success" />
          ) : (
            <Lock className="w-5 h-5 text-hubble-success" />
          )}
        </div>
        <div>
          <h2 className="text-lg font-semibold text-primary">
            {networkTab ? networkTitle : 'Seccomp Profile Builder'}
          </h2>
          <p className="text-xs text-tertiary">
            {podName} • {podNamespace}
          </p>
        </div>
      </div>
      <div className="flex items-center gap-2">
        {/* Policy Type Selector */}
        <div className="flex bg-hubble-dark rounded-lg p-1 mr-2" role="tablist" aria-label="Policy type">
          <button
            role="tab"
            aria-selected={networkTab}
            onClick={() => onPolicyTypeChange(policyType === 'cilium' ? 'cilium' : 'network')}
            className={`px-3 py-1.5 text-xs rounded transition-all flex items-center gap-1 ${
              networkTab
                ? 'bg-hubble-accent text-white'
                : 'text-secondary hover:text-primary'
            }`}
          >
            <Shield className="w-3 h-3" />
            Network Policy
            {policyType === 'cilium' && ciliumWarning && (
              <span title={ciliumWarning} aria-label={ciliumWarning}>
                <AlertTriangle className="w-3 h-3 text-hubble-warning" />
              </span>
            )}
          </button>
          <button
            role="tab"
            aria-selected={policyType === 'seccomp'}
            onClick={() => onPolicyTypeChange('seccomp')}
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
          onClick={onYamlViewToggle}
          className={`px-3 py-1.5 text-xs rounded-lg transition-colors ${
            yamlView
              ? 'bg-hubble-accent text-white'
              : 'text-secondary hover:text-primary hover:bg-hubble-dark'
          }`}
        >
          {yamlView ? 'Visual Editor' : (policyType === 'seccomp' ? 'Export View' : 'YAML View')}
        </button>
        <button
          onClick={onCopy}
          className="px-3 py-1.5 text-xs text-secondary hover:text-primary hover:bg-hubble-dark rounded-lg transition-colors flex items-center gap-1"
          title={policyType === 'seccomp' ? `Copy ${seccompLabel}` : 'Copy YAML'}
        >
          <Copy className="w-3 h-3" />
          {copiedToClipboard ? 'Copied!' : 'Copy'}
        </button>
        <button
          onClick={onDownload}
          className="px-3 py-1.5 text-xs text-secondary hover:text-primary hover:bg-hubble-dark rounded-lg transition-colors flex items-center gap-1"
          title={policyType === 'seccomp' ? `Download ${seccompLabel}` : 'Download YAML'}
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
  );
};
