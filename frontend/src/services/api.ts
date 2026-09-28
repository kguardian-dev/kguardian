import axios from 'axios';
import type { AxiosInstance } from 'axios';
import type { PodInfo, NetworkTraffic, SyscallInfo, ServiceInfo, AuditVerdict, ClusterEnvironment } from '../types';
import { UNKNOWN_CLUSTER_ENVIRONMENT } from '../types';
import type {
  ComputeFindingsResponse,
  ComputeHistoryRow,
  ComputeLatestResponse,
  ComputeNode,
  ContentionPair,
} from '../types/compute';

/**
 * The broker has no compute endpoints (404 / 501): a broker predating the
 * feature. Consumers stop polling for the session instead of retrying.
 */
export class ComputeUnsupportedError extends Error {
  constructor(path: string) {
    super(`compute endpoints unsupported by this broker (${path})`);
    this.name = 'ComputeUnsupportedError';
  }
}

function rethrowCompute(error: unknown, path: string): never {
  if (axios.isAxiosError(error) && (error.response?.status === 404 || error.response?.status === 501)) {
    throw new ComputeUnsupportedError(path);
  }
  throw error;
}

/** Sorted namespace list with "default" moved to the front when present. */
export function orderNamespaces(namespaces: string[]): string[] {
  const sorted = Array.from(new Set(namespaces)).sort();
  const defaultIndex = sorted.indexOf('default');
  if (defaultIndex > 0) {
    sorted.splice(defaultIndex, 1);
    sorted.unshift('default');
  }
  return sorted;
}

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
   *
   * Rejects on failure, like the compute getters, so a caller can show an
   * error instead of an empty "no verdicts" state.
   */
  async getAuditVerdicts(opts: {
    policy?: string;
    namespace?: string;
    verdict?: 'Allow' | 'WouldDeny';
    direction?: 'Ingress' | 'Egress';
    limit?: number;
  } = {}): Promise<AuditVerdict[]> {
    const params: Record<string, string | number> = {};
    if (opts.policy) params.policy = opts.policy;
    if (opts.namespace) params.namespace = opts.namespace;
    if (opts.verdict) params.verdict = opts.verdict;
    if (opts.direction) params.direction = opts.direction;
    if (opts.limit) params.limit = opts.limit;
    const response = await this.client.get('/audit/verdicts', { params });
    return response.data || [];
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
   * Get pod traffic by pod name. A failed read (timeout, 5xx, network) is
   * rethrown, never returned as `[]`: an empty array means the broker holds
   * no flows for the pod, and a pod whose read failed must not look flow-less
   * (the map would hide it and the Policy Builder would read it as 0 conns).
   */
  async getPodTrafficByName(podName: string): Promise<NetworkTraffic[]> {
    try {
      const response = await this.client.get(`/pod/traffic/${podName}`);
      return response.data || [];
    } catch (error) {
      console.error('Error fetching pod traffic by name:', error);
      throw error;
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
   * Get syscalls for a pod by pod name. Rethrows on failure, as
   * `getPodTrafficByName` does and for the same reason.
   */
  async getPodSyscalls(podName: string): Promise<SyscallInfo[]> {
    try {
      const response = await this.client.get(`/pod/syscalls/${podName}`);
      return response.data || [];
    } catch (error) {
      console.error('Error fetching pod syscalls:', error);
      throw error;
    }
  }

  /**
   * In-flight `/svc/info` request, shared like `podsInFlight` below: the
   * service listing is the second-heaviest response the broker produces (2 MB
   * on a mid-sized cluster) and overlapping loads used to fetch it twice.
   */
  private servicesInFlight: Promise<ServiceInfo[]> | null = null;

  /**
   * Get all service details
   */
  async getAllServices(): Promise<ServiceInfo[]> {
    if (this.servicesInFlight) return this.servicesInFlight;

    const request = (async () => {
      try {
        const response = await this.client.get('/svc/info');
        return response.data || [];
      } catch (error) {
        console.error('Error fetching all services:', error);
        return [];
      }
    })();

    this.servicesInFlight = request;
    try {
      return await request;
    } finally {
      this.servicesInFlight = null;
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
  /**
   * In-flight `/pod/info` request, shared by every concurrent caller.
   *
   * The whole pod inventory is the single heaviest response the broker
   * produces, and a page load asks for it more than once: `usePodData` wants
   * the listing, `useNamespaces` derives the namespace list from the same
   * listing, and the policy generators ask again when opened. Un-coalesced
   * those overlap, and the broker pays to serialise the entire inventory once
   * per caller. On a 43k-pod cluster that was two concurrent 72 MB responses
   * per page load, which OOM-killed the broker at a 4 GiB limit.
   *
   * Only IN-FLIGHT requests are shared, with no time-based cache: a request
   * that has already returned is not reused, so `refreshData` and a namespace
   * change still fetch genuinely fresh data. The entry is cleared as soon as
   * the request settles, failures included, so a failed load does not poison
   * the next attempt.
   */
  private podsInFlight: Promise<PodInfo[]> | null = null;

  async getAllPods(): Promise<PodInfo[]> {
    if (this.podsInFlight) return this.podsInFlight;

    const request = (async () => {
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
    })();

    this.podsInFlight = request;
    try {
      return await request;
    } finally {
      this.podsInFlight = null;
    }
  }

  /**
   * Namespaces with at least one running pod, "default" first.
   *
   * Reads `GET /pod/namespaces`, one DISTINCT over the live rows. Deriving
   * the list from the whole `/pod/info` listing, as this did before, meant
   * the picker depended on the heaviest response the broker produces: on a
   * cluster with heavy pod churn the dead rows made that listing outgrow the
   * client timeout, and the picker silently fell back to just "default". A
   * broker older than the endpoint answers 404; then the old derivation runs.
   * Any other failure is rethrown: a transient error is not a list of one
   * `default`, and the caller keeps the namespace it already had (the URL's).
   */
  async getNamespaces(): Promise<string[]> {
    try {
      const response = await this.client.get('/pod/namespaces');
      if (Array.isArray(response.data)) {
        return orderNamespaces(response.data.filter((ns): ns is string => typeof ns === 'string'));
      }
      console.warn('API returned non-array data for /pod/namespaces:', response.data);
    } catch (error) {
      if (!(axios.isAxiosError(error) && error.response?.status === 404)) {
        console.error('Error fetching namespaces:', error);
        throw error;
      }
    }
    return this.namespacesFromPods();
  }

  /** Pre-`/pod/namespaces` brokers: derive the list from the pod inventory. */
  private async namespacesFromPods(): Promise<string[]> {
    try {
      const pods = await this.getAllPods();

      // Ensure pods is an array
      if (!Array.isArray(pods)) {
        console.error('getAllPods() did not return an array:', pods);
        return ['default'];
      }

      const namespaces = new Set<string>();
      pods.forEach(pod => {
        if (pod.pod_namespace && !pod.is_dead) {
          namespaces.add(pod.pod_namespace);
        }
      });
      return orderNamespaces(Array.from(namespaces));
    } catch (error) {
      console.error('Error fetching namespaces:', error);
      return ['default'];
    }
  }

  // ── Compute gauges / contention (docs/design/compute-contention-monitoring.md) ──
  // Unlike the traffic getters these do NOT swallow failures: a 404/501
  // becomes ComputeUnsupportedError (the hook stops polling for the
  // session, so an older broker is not hammered every 5 s) and anything else
  // propagates so the hook can surface a real error and retry next tick.

  /** Live per-container rows + node rows for the namespace (`GET /compute/latest`). */
  async getComputeLatest(namespace: string): Promise<ComputeLatestResponse> {
    try {
      const response = await this.client.get<ComputeLatestResponse>('/compute/latest', { params: { namespace } });
      const data = response.data;
      return {
        containers: Array.isArray(data?.containers) ? data.containers : [],
        nodes: Array.isArray(data?.nodes) ? data.nodes : [],
      };
    } catch (error) {
      return rethrowCompute(error, '/compute/latest');
    }
  }

  /** Minute / 5-minute history rows for a pod, oldest first (`GET /compute/history/{pod_uid}`). */
  async getComputeHistory(podUid: string, minutes = 60): Promise<ComputeHistoryRow[]> {
    try {
      const response = await this.client.get<{ rows: ComputeHistoryRow[] }>(
        `/compute/history/${encodeURIComponent(podUid)}`,
        { params: { minutes } },
      );
      return Array.isArray(response.data?.rows) ? response.data.rows : [];
    } catch (error) {
      return rethrowCompute(error, '/compute/history');
    }
  }

  /** Victim ↔ culprit pairs for a namespace or node (`GET /compute/contention`). */
  async getComputeContention(opts: { namespace?: string; node?: string; minutes?: number }): Promise<ContentionPair[]> {
    try {
      const params: Record<string, string | number> = {};
      if (opts.namespace) params.namespace = opts.namespace;
      if (opts.node) params.node = opts.node;
      if (opts.minutes) params.minutes = opts.minutes;
      const response = await this.client.get<{ pairs: ContentionPair[] }>('/compute/contention', { params });
      return Array.isArray(response.data?.pairs) ? response.data.pairs : [];
    } catch (error) {
      return rethrowCompute(error, '/compute/contention');
    }
  }

  /** Broker-computed compute findings + metadata (`GET /compute/findings`); no filter = cluster. */
  async getComputeFindings(opts: { namespace?: string; node?: string } = {}): Promise<ComputeFindingsResponse> {
    try {
      const params: Record<string, string> = {};
      if (opts.namespace) params.namespace = opts.namespace;
      if (opts.node) params.node = opts.node;
      const response = await this.client.get<ComputeFindingsResponse>('/compute/findings', { params });
      const data = response.data;
      return {
        findings: Array.isArray(data?.findings) ? data.findings : [],
        truncated: data?.truncated === true,
        victims_evaluated: typeof data?.victims_evaluated === 'number' ? data.victims_evaluated : undefined,
        history_disabled: data?.history_disabled === true,
      };
    } catch (error) {
      return rethrowCompute(error, '/compute/findings');
    }
  }

  /** Every node's compute / contention support row (`GET /compute/nodes`). */
  async getComputeNodes(): Promise<ComputeNode[]> {
    try {
      const response = await this.client.get<{ nodes: ComputeNode[] }>('/compute/nodes');
      return Array.isArray(response.data?.nodes) ? response.data.nodes : [];
    } catch (error) {
      return rethrowCompute(error, '/compute/nodes');
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
