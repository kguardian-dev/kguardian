import { useState } from 'react';
import type { NetworkPolicy } from '../../types/networkPolicy';
import type { CiliumNetworkPolicy } from '../../types/ciliumPolicy';
import type { SeccompProfile } from '../../types/seccompProfile';
import { policyToYAML } from '../../utils/networkPolicyGenerator';
import { ciliumPolicyToYAML } from '../../utils/ciliumPolicyGenerator';
import { profileToYAML, profileToJSON } from '../../utils/seccompProfileGenerator';
import { podProfileToKguardianCR, suggestedCrName } from '../../utils/seccompCr';
import type { PodNodeData } from '../../types';
import type { CaptureInfo } from '../../types/seccompWorkload';

export type PolicyType = 'network' | 'cilium' | 'seccomp';

/**
 * Seccomp export formats. `kguardian` (default) is the kguardian.dev/v1alpha1
 * SeccompProfile CR the docs describe and the controller reconciles; `spo` is
 * the Security Profiles Operator CR for shops running SPO; `json` is the raw
 * seccomp document.
 */
export type SeccompExportFormat = 'kguardian' | 'spo' | 'json';

export const SECCOMP_EXPORT_FORMATS: { id: SeccompExportFormat; label: string; hint: string }[] = [
  { id: 'kguardian', label: 'kguardian CR', hint: 'kguardian.dev/v1alpha1 SeccompProfile — commit and apply; the controller writes the node file' },
  { id: 'spo', label: 'Security Profiles Operator CR', hint: 'security-profiles-operator.x-k8s.io/v1beta1 SeccompProfile — requires SPO' },
  { id: 'json', label: 'Raw JSON', hint: 'Plain seccomp document (what the kubelet loads from disk)' },
];

interface UsePolicyExportProps {
  policyType: PolicyType;
  policy: NetworkPolicy | null;
  ciliumPolicy: CiliumNetworkPolicy | null;
  seccompProfile: SeccompProfile | null;
  podName: string;
  podIdentity?: string;
  podNamespace: string;
  /** Network/Cilium always export YAML; seccomp is driven by `seccompFormat`. Kept for callers. */
  yamlView?: boolean;
  /** Seccomp only; defaults to the kguardian CR. */
  seccompFormat?: SeccompExportFormat;
  /** Seccomp only; needed for the kguardian CR (workloadRef + capture header). */
  pod?: PodNodeData | null;
  capture?: CaptureInfo;
}

export const usePolicyExport = ({
  policyType,
  policy,
  ciliumPolicy,
  seccompProfile,
  podName,
  podIdentity,
  podNamespace,
  seccompFormat = 'kguardian',
  pod = null,
  capture = { level: 'unknown', complete: false, pods: [] },
}: UsePolicyExportProps) => {
  const [copiedToClipboard, setCopiedToClipboard] = useState(false);

  const getExportContent = (): string | null => {
    if (policyType === 'network' && policy) {
      return policyToYAML(policy);
    } else if (policyType === 'cilium' && ciliumPolicy) {
      return ciliumPolicyToYAML(ciliumPolicy);
    } else if (policyType === 'seccomp' && seccompProfile) {
      if (seccompFormat === 'json') return profileToJSON(seccompProfile);
      if (seccompFormat === 'spo') {
        // Use pod identity for resource name, fallback to pod name
        return profileToYAML(seccompProfile, podIdentity || podName, podNamespace);
      }
      if (!pod) return null;
      return podProfileToKguardianCR(pod, seccompProfile, capture);
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
      if (seccompFormat === 'json') {
        filename = `${podName}-seccomp.json`;
        mimeType = 'application/json';
      } else if (seccompFormat === 'spo') {
        // A Security Profiles Operator SeccompProfile CR, not a raw seccomp
        // document — name it so.
        filename = `${podName}-seccompprofile-spo.yaml`;
        mimeType = 'text/yaml';
      } else {
        filename = `${pod ? suggestedCrName(pod) : podName}.yaml`;
        mimeType = 'text/yaml';
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
    getExportContent,
  };
};
