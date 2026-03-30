import axios from 'axios';
import type { AxiosInstance, AxiosError, InternalAxiosRequestConfig } from 'axios';
import type { PodInfo, NetworkTraffic, SyscallInfo, ServiceInfo } from '../types';

interface RetryConfig extends InternalAxiosRequestConfig {
  _retryCount?: number;
}

const MAX_RETRIES = 3;
const RETRY_BASE_DELAY_MS = 1000;

function isRetryable(error: AxiosError): boolean {
  // Retry on network errors (ECONNREFUSED, ECONNRESET, etc.)
  if (!error.response) return true;
  // Retry on 502, 503, 504 (broker temporarily unavailable)
  const status = error.response.status;
  return status === 502 || status === 503 || status === 504;
}

function retryDelay(retryCount: number): number {
  // Exponential backoff: 1s, 2s, 4s + jitter
  const delay = RETRY_BASE_DELAY_MS * Math.pow(2, retryCount);
  const jitter = delay * 0.2 * Math.random();
  return delay + jitter;
}

class BrokerAPIClient {
  private client: AxiosInstance;
  private _connected = false;
  private _onConnectionChange?: (connected: boolean) => void;

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

    // Retry interceptor for transient failures
    this.client.interceptors.response.use(
      (response) => {
        this.setConnected(true);
        return response;
      },
      async (error: AxiosError) => {
        const config = error.config as RetryConfig | undefined;
        if (!config || !isRetryable(error)) {
          this.setConnected(false);
          return Promise.reject(error);
        }

        const retryCount = config._retryCount ?? 0;
        if (retryCount >= MAX_RETRIES) {
          this.setConnected(false);
          return Promise.reject(error);
        }

        config._retryCount = retryCount + 1;
        const delay = retryDelay(retryCount);
        await new Promise((resolve) => setTimeout(resolve, delay));
        return this.client(config);
      },
    );
  }

  private setConnected(connected: boolean) {
    if (this._connected !== connected) {
      this._connected = connected;
      this._onConnectionChange?.(connected);
    }
  }

  get connected(): boolean {
    return this._connected;
  }

  onConnectionChange(callback: (connected: boolean) => void) {
    this._onConnectionChange = callback;
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
   * Get pod details by IP address
   */
  async getPodDetailsByIP(podIP: string): Promise<PodInfo | null> {
    try {
      const response = await this.client.get(`/pod/ip/${podIP}`);
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
}

// Export a singleton instance
export const apiClient = new BrokerAPIClient();
export default apiClient;
