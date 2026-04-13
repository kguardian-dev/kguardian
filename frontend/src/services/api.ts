import axios from 'axios';
import type { AxiosInstance } from 'axios';
import type { PodInfo, NetworkTraffic, SyscallInfo, ServiceInfo } from '../types';

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
   * Get all pod traffic
   */
  async getAllPodTraffic(signal?: AbortSignal): Promise<NetworkTraffic[]> {
    const response = await this.client.get('/pod/traffic', { signal });
    return response.data || [];
  }

  /**
   * Get pod traffic by pod name
   */
  async getPodTrafficByName(podName: string, signal?: AbortSignal): Promise<NetworkTraffic[]> {
    const response = await this.client.get(`/pod/traffic/${podName}`, { signal });
    return response.data || [];
  }

  /**
   * Get pod details by pod name
   */
  async getPodDetailsByName(podName: string, signal?: AbortSignal): Promise<PodInfo | null> {
    const response = await this.client.get(`/pod/name/${podName}`, { signal });
    return response.data;
  }

  /**
   * Get pod details by IP address
   */
  async getPodDetailsByIP(podIP: string, signal?: AbortSignal): Promise<PodInfo | null> {
    const response = await this.client.get(`/pod/ip/${podIP}`, { signal });
    return response.data;
  }

  /**
   * Get syscalls for a pod by pod name
   */
  async getPodSyscalls(podName: string, signal?: AbortSignal): Promise<SyscallInfo[]> {
    const response = await this.client.get(`/pod/syscalls/${podName}`, { signal });
    return response.data || [];
  }

  /**
   * Get all service details
   */
  async getAllServices(signal?: AbortSignal): Promise<ServiceInfo[]> {
    const response = await this.client.get('/svc/info', { signal });
    return response.data || [];
  }

  /**
   * Get service details by IP address
   */
  async getServiceByIP(serviceIP: string, signal?: AbortSignal): Promise<ServiceInfo | null> {
    const response = await this.client.get(`/svc/ip/${serviceIP}`, { signal });
    return response.data;
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
  async getAllPods(signal?: AbortSignal): Promise<PodInfo[]> {
    const response = await this.client.get('/pod/info', { signal });
    // Ensure we always return an array
    if (Array.isArray(response.data)) {
      return response.data;
    }
    console.warn('API returned non-array data for /pod/info:', response.data);
    return [];
  }

  /**
   * Get all unique namespaces from pods
   */
  async getNamespaces(signal?: AbortSignal): Promise<string[]> {
    const pods = await this.getAllPods(signal);

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
  }

  /**
   * Set the base URL for the API client (for configuration)
   */
  setBaseURL(baseURL: string) {
    this.client.defaults.baseURL = baseURL;
  }
}

// Export a singleton instance
export const apiClient = new BrokerAPIClient();
export default apiClient;
