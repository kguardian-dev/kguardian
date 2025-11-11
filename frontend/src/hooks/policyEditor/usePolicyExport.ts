import { useState } from 'react';
import type { NetworkPolicy } from '../../types/networkPolicy';
import type { SeccompProfile } from '../../types/seccompProfile';
import { policyToYAML } from '../../utils/networkPolicyGenerator';
import { profileToYAML, profileToJSON } from '../../utils/seccompProfileGenerator';

export type PolicyType = 'network' | 'seccomp';

interface UsePolicyExportProps {
  policyType: PolicyType;
  policy: NetworkPolicy | null;
  seccompProfile: SeccompProfile | null;
  podName: string;
  podIdentity?: string;
  podNamespace: string;
  yamlView: boolean;
}

export const usePolicyExport = ({
  policyType,
  policy,
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
    } else if (policyType === 'seccomp' && seccompProfile) {
      // Use pod identity for resource name, fallback to pod name
      const resourceName = podIdentity || podName;
      return yamlView
        ? profileToYAML(seccompProfile, resourceName, podNamespace)
        : profileToJSON(seccompProfile);
    }
    return null;
  };

  const handleCopy = () => {
    const content = getExportContent();
    if (!content) return;

    navigator.clipboard.writeText(content);
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
    a.click();
    URL.revokeObjectURL(url);
  };

  return {
    copiedToClipboard,
    handleCopy,
    handleDownload,
  };
};
