import { apiClient } from '../services/api';

export interface TrafficIdentity {
  podName?: string;
  podNamespace?: string;
  podLabels?: Record<string, string>;
  svcName?: string;
  svcNamespace?: string;
  svcSelector?: Record<string, string>;
  isExternal: boolean;
}

// Helper to resolve traffic identity following advisor priority
export async function resolveTrafficIdentity(ip: string): Promise<TrafficIdentity> {
  if (!ip) {
    return { isExternal: true };
  }

  // Priority 1: Try to get service info from API
  try {
    const serviceInfo = await apiClient.getServiceByIP(ip);
    if (serviceInfo && serviceInfo.svc_name) {
      const svcSpec = (serviceInfo.service_spec as Record<string, unknown>)?.spec as Record<string, unknown> | undefined;
      const svcSelector = svcSpec?.selector as Record<string, string> | undefined;
      return {
        svcName: serviceInfo.svc_name,
        svcNamespace: serviceInfo.svc_namespace || undefined,
        svcSelector: svcSelector && Object.keys(svcSelector).length > 0 ? svcSelector : undefined,
        isExternal: false,
      };
    }
  } catch {
    // Service lookup failed, continue to pod lookup
  }

  // Priority 2: Try to get pod info from API (checks all namespaces)
  try {
    const podInfo = await apiClient.getPodDetailsByIP(ip);
    if (podInfo && podInfo.pod_name) {
      let podLabels: Record<string, string> | undefined;
      if (podInfo.workload_selector_labels && Object.keys(podInfo.workload_selector_labels).length > 0) {
        podLabels = podInfo.workload_selector_labels;
      } else if (podInfo.pod_obj?.metadata?.labels) {
        podLabels = podInfo.pod_obj.metadata.labels as Record<string, string>;
      }
      return {
        podName: podInfo.pod_name,
        podNamespace: podInfo.pod_namespace || undefined,
        podLabels,
        isExternal: false,
      };
    }
  } catch {
    // Pod lookup failed, continue to external
  }

  // Priority 3: External traffic
  return { isExternal: true };
}
