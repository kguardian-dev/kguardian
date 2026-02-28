import { useState } from 'react';
import type { NetworkPolicy } from '../../types/networkPolicy';
import type { CiliumNetworkPolicy } from '../../types/ciliumPolicy';
import type { SeccompProfile } from '../../types/seccompProfile';
import { policyToYAML } from '../../utils/networkPolicyGenerator';
import { ciliumPolicyToYAML } from '../../utils/ciliumPolicyGenerator';
import { profileToYAML, profileToJSON } from '../../utils/seccompProfileGenerator';

export type PolicyType = 'network' | 'cilium' | 'seccomp';

interface UsePolicyExportProps {
  policyType: PolicyType;
  policy: NetworkPolicy | null;
  ciliumPolicy: CiliumNetworkPolicy | null;
  seccompProfile: SeccompProfile | null;
  podName: string;
  podIdentity?: string;
  podNamespace: string;
  yamlView: boolean;
}

export const usePolicyExport = ({
  policyType,
  policy,
  ciliumPolicy,
  seccompProfile,
  podName,
  podIdentity,
  podNamespace,
  yamlView,
}: UsePolicyExportProps) => {
  const [copiedToClipboard, setCopiedToClipboard] = useState(false);

  const getExportContent = (): string | null => {
    if (policyType === 'network' && policy) {
      return policyToYAML(policy);
    } else if (policyType === 'cilium' && ciliumPolicy) {
      return ciliumPolicyToYAML(ciliumPolicy);
    } else if (policyType === 'seccomp' && seccompProfile) {
      // Use pod identity for resource name, fallback to pod name
      const resourceName = podIdentity || podName;
      return yamlView
        ? profileToYAML(seccompProfile, resourceName, podNamespace)
        : profileToJSON(seccompProfile);
    }
    return null;
  };

  const handleCopy = async () => {
    const content = getExportContent();
    if (!content) return;

    try {
      await navigator.clipboard.writeText(content);
    } catch {
      // Fallback: use a temporary textarea for copy
      try {
        const textarea = document.createElement('textarea');
        textarea.value = content;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
      } catch (fallbackErr) {
        console.error('Failed to copy to clipboard:', fallbackErr);
        return;
      }
    }
    setCopiedToClipboard(true);
    setTimeout(() => setCopiedToClipboard(false), 2000);
  };

  const handleDownload = () => {
    const content = getExportContent();
    if (!content) return;

    let filename: string;
    let mimeType: string;

    if (policyType === 'network' && policy) {
      filename = `${policy.metadata.name}.yaml`;
      mimeType = 'text/yaml';
    } else if (policyType === 'cilium' && ciliumPolicy) {
      filename = `${ciliumPolicy.metadata.name}.yaml`;
      mimeType = 'text/yaml';
    } else if (policyType === 'seccomp') {
      if (yamlView) {
        filename = `${podName}-seccomp.yaml`;
        mimeType = 'text/yaml';
      } else {
        filename = `${podName}-seccomp.json`;
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
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return {
    copiedToClipboard,
    handleCopy,
    handleDownload,
  };
};
