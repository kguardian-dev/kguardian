import axios from 'axios';
import type { AxiosInstance } from 'axios';
import type { PodInfo, NetworkTraffic, SyscallInfo, ServiceInfo, AuditVerdict, ClusterEnvironment } from '../types';
import { UNKNOWN_CLUSTER_ENVIRONMENT } from '../types';

class BrokerAPIClient {
  private client: AxiosInstance;

  constructor(baseURL?: string) {
    // Use provided baseURL or default to relative /api path
    // The /api path is proxied by Vite preview server to the broker service
    const apiURL = baseURL || '/api';

    this.client = axios.create({
      baseURL: apiURL,
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  /**
   * Get recent audit-mode verdicts — flows the evaluator decided on
   * for an AuditNetworkPolicy / AuditClusterNetworkPolicy. Returns
   * both `Allow` and `WouldDeny` rows so operators can preview both
   * sides of policy impact. Optional filters: policy, namespace,
   * verdict, direction, row limit.
   *
   * The verdict and direction filters are server-side and index-backed
   * (idx_audit_verdicts_verdict_time). Prefer them over client-side
   * filtering when narrowing, especially with large policies, to avoid
   * burning the row limit on rows you'll discard.
   */
  async getAuditVerdicts(opts: {
    policy?: string;
    namespace?: string;
    verdict?: 'Allow' | 'WouldDeny';
    direction?: 'Ingress' | 'Egress';
    limit?: number;
  } = {}): Promise<AuditVerdict[]> {
    try {
      const params: Record<string, string | number> = {};
      if (opts.policy) params.policy = opts.policy;
      if (opts.namespace) params.namespace = opts.namespace;
      if (opts.verdict) params.verdict = opts.verdict;
      if (opts.direction) params.direction = opts.direction;
      if (opts.limit) params.limit = opts.limit;
      const response = await this.client.get('/audit/verdicts', { params });
      return response.data || [];
    } catch (error) {
      console.error('Error fetching audit verdicts:', error);
      return [];
    }
  }

  /**
   * Get all pod traffic
   */
  async getAllPodTraffic(): Promise<NetworkTraffic[]> {
    try {
      const response = await this.client.get('/pod/traffic');
      return response.data || [];
    } catch (error) {
      console.error('Error fetching all pod traffic:', error);
      return [];
    }
  }

  /**
   * Get pod traffic by pod name
   */
  async getPodTrafficByName(podName: string): Promise<NetworkTraffic[]> {
    try {
      const response = await this.client.get(`/pod/traffic/${podName}`);
      return response.data || [];
    } catch (error) {
      console.error('Error fetching pod traffic by name:', error);
      return [];
    }
  }

  /**
   * Get pod details by pod name
   */
  async getPodDetailsByName(podName: string): Promise<PodInfo | null> {
    try {
      const response = await this.client.get(`/pod/name/${podName}`);
      return response.data;
    } catch (error) {
      console.error('Error fetching pod details by name:', error);
      return null;
    }
  }

  /**
   * Get pod details by IP address. `at` (a traffic row's `time_stamp`) asks
   * the broker for the pod that held the IP AT that time — it excludes pods
   * started later and prefers one alive then (`GET /pod/ip/{ip}?at=`). A
   * broker predating the parameter ignores it and returns the current
   * holder, so callers apply the same start-time guard themselves
   * (utils/peerResolution). 404 (no holder at that time) resolves to null.
   */
  async getPodDetailsByIP(podIP: string, at?: string): Promise<PodInfo | null> {
    try {
      const response = await this.client.get(`/pod/ip/${podIP}`, at !== undefined ? { params: { at } } : undefined);
      return response.data;
    } catch (error) {
      console.error('Error fetching pod details by IP:', error);
      return null;
    }
  }

  /**
   * Get syscalls for a pod by pod name
   */
  async getPodSyscalls(podName: string): Promise<SyscallInfo[]> {
    try {
      const response = await this.client.get(`/pod/syscalls/${podName}`);
      return response.data || [];
    } catch (error) {
      console.error('Error fetching pod syscalls:', error);
      return [];
    }
  }

  /**
   * Get all service details
   */
  async getAllServices(): Promise<ServiceInfo[]> {
    try {
      const response = await this.client.get('/svc/info');
      return response.data || [];
    } catch (error) {
      console.error('Error fetching all services:', error);
      return [];
    }
  }

  /**
   * Get service details by IP address
   */
  async getServiceByIP(serviceIP: string): Promise<ServiceInfo | null> {
    try {
      const response = await this.client.get(`/svc/ip/${serviceIP}`);
      return response.data;
    } catch (error) {
      console.error('Error fetching service by IP:', error);
      return null;
    }
  }

  /**
   * Cluster environment (coarse CNI/IP-family/platform aggregates from
   * the broker's node_facts). Memoized for the page lifetime — the CNI
   * cannot change mid-session — and every failure path degrades to
   * all-'unknown', which consumers MUST treat as "behave exactly as
   * before" (older brokers 404 this endpoint).
   */
  private clusterEnvPromise: Promise<ClusterEnvironment> | null = null;

  async getClusterEnvironment(): Promise<ClusterEnvironment> {
    if (!this.clusterEnvPromise) {
      this.clusterEnvPromise = this.client
        .get<ClusterEnvironment>('/cluster/environment')
        .then((r) => r.data)
        .catch(() => UNKNOWN_CLUSTER_ENVIRONMENT);
    }
    return this.clusterEnvPromise;
  }

  /** Test hook: clear the memoized environment. */
  resetClusterEnvironmentCache(): void {
    this.clusterEnvPromise = null;
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<boolean> {
    try {
      const response = await this.client.get('/health');
      return response.status === 200;
    } catch (error) {
      console.error('Health check failed:', error);
      return false;
    }
  }

  /**
   * Get all pod details
   */
  async getAllPods(): Promise<PodInfo[]> {
    try {
      const response = await this.client.get('/pod/info');
      // Ensure we always return an array
      if (Array.isArray(response.data)) {
        return response.data;
      }
      console.warn('API returned non-array data for /pod/info:', response.data);
      return [];
    } catch (error) {
      console.error('Error fetching all pods:', error);
      return [];
    }
  }

  /**
   * Get all unique namespaces from pods
   */
  async getNamespaces(): Promise<string[]> {
    try {
      const pods = await this.getAllPods();

      // Ensure pods is an array
      if (!Array.isArray(pods)) {
        console.error('getAllPods() did not return an array:', pods);
        return ['default'];
      }

      const namespaces = new Set<string>();

      pods.forEach(pod => {
        if (pod.pod_namespace) {
          namespaces.add(pod.pod_namespace);
        }
      });

      // Convert to array and sort, with "default" always first
      const namespaceArray = Array.from(namespaces).sort();
      const defaultIndex = namespaceArray.indexOf('default');

      if (defaultIndex > 0) {
        // Move "default" to the front
        namespaceArray.splice(defaultIndex, 1);
        namespaceArray.unshift('default');
      } else if (defaultIndex === -1 && namespaceArray.length > 0) {
        // If no "default" namespace exists, still sort alphabetically
        return namespaceArray;
      }

      return namespaceArray;
    } catch (error) {
      console.error('Error fetching namespaces:', error);
      return ['default'];
    }
  }

  /**
   * Set the base URL for the API client (for configuration)
   */
  setBaseURL(baseURL: string) {
    this.client.defaults.baseURL = baseURL;
  }

  /** The broker base path every other broker module must build on (the
   *  `/api` proxy in dev/preview). Exposed so fetch-based modules that need
   *  structured error bodies (see services/seccompApi.ts) share one origin. */
  get baseURL(): string {
    return this.client.defaults.baseURL ?? '/api';
  }
}

// Export a singleton instance
export const apiClient = new BrokerAPIClient();
export default apiClient;
