import axios from 'axios';
import type { AxiosInstance } from 'axios';
import type { PodInfo, NetworkTraffic, SyscallInfo } from '../types';

class BrokerAPIClient {
  private client: AxiosInstance;

  constructor(baseURL: string = '/api') {
    this.client = axios.create({
      baseURL,
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json',
      },
    });
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
   * Get service details by IP address
   */
  async getServiceByIP(serviceIP: string): Promise<any> {
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
      return response.data || [];
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
