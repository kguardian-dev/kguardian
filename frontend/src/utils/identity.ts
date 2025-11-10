import type { PodInfo } from '../types';

/**
 * Derive identity name from pod labels following Cilium Hubble conventions
 * Priority:
 * 1. app.kubernetes.io/name
 * 2. app
 * 3. k8s-app
 * 4. app.kubernetes.io/component
 * 5. gateway.networking.k8s.io/gateway-name (for gateway pods)
 * 6. pod_name (fallback)
 *
 * @param pod - Pod information including pod_obj with labels
 * @returns Identity name in format "namespace/app-name"
 */
export function deriveIdentityName(pod: PodInfo): string {
  const namespace = pod.pod_namespace || 'default';

  // Extract labels from pod_obj if available
  if (pod.pod_obj?.metadata?.labels) {
    const labels = pod.pod_obj.metadata.labels;

    // Debug logging to help investigate label extraction
    console.log(`[Identity] Pod: ${pod.pod_name}, Labels:`, labels);

    // Priority 1: app.kubernetes.io/name
    if (labels['app.kubernetes.io/name']) {
      console.log(`[Identity] Using app.kubernetes.io/name: ${labels['app.kubernetes.io/name']}`);
      return `${namespace}/${labels['app.kubernetes.io/name']}`;
    }

    // Priority 2: app
    if (labels.app) {
      console.log(`[Identity] Using app label: ${labels.app}`);
      return `${namespace}/${labels.app}`;
    }

    // Priority 3: k8s-app
    if (labels['k8s-app']) {
      console.log(`[Identity] Using k8s-app label: ${labels['k8s-app']}`);
      return `${namespace}/${labels['k8s-app']}`;
    }

    // Priority 4: app.kubernetes.io/component
    if (labels['app.kubernetes.io/component']) {
      console.log(`[Identity] Using app.kubernetes.io/component label: ${labels['app.kubernetes.io/component']}`);
      return `${namespace}/${labels['app.kubernetes.io/component']}`;
    }

    // Priority 5: gateway.networking.k8s.io/gateway-name (for gateway pods)
    if (labels['gateway.networking.k8s.io/gateway-name']) {
      console.log(`[Identity] Using gateway.networking.k8s.io/gateway-name: ${labels['gateway.networking.k8s.io/gateway-name']}`);
      return `${namespace}/${labels['gateway.networking.k8s.io/gateway-name']}`;
    }

    console.log(`[Identity] No matching labels found for pod ${pod.pod_name}, using pod name as fallback`);
  } else {
    console.log(`[Identity] No labels found in pod_obj for pod: ${pod.pod_name}`);
  }

  // Fallback: namespace/pod_name
  return `${namespace}/${pod.pod_name}`;
}

/**
 * Get a display-friendly short name from identity
 * Extracts just the app portion from "namespace/app"
 *
 * @param identityName - Full identity name "namespace/app"
 * @returns Short app name
 */
export function getShortIdentityName(identityName: string): string {
  const parts = identityName.split('/');
  return parts.length > 1 ? parts[1] : identityName;
}
