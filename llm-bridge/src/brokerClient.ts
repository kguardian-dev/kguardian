import axios, { AxiosInstance } from "axios";
import type { ToolCall, ToolResult } from "./types/index.js";

export class BrokerClient {
  private client: AxiosInstance;
  private brokerUrl: string;

  constructor(brokerUrl: string) {
    this.brokerUrl = brokerUrl;
    this.client = axios.create({
      baseURL: brokerUrl,
      timeout: 10000,
      headers: {
        "Content-Type": "application/json",
      },
    });
  }

  /**
   * Execute a tool call by routing to the appropriate broker endpoint
   */
  async executeTool(toolCall: ToolCall): Promise<ToolResult> {
    try {
      const { name, arguments: args } = toolCall;

      switch (name) {
        case "get_pod_network_traffic":
          return await this.getPodNetworkTraffic(
            args.namespace,
            args.pod_name
          );

        case "get_pod_syscalls":
          return await this.getPodSyscalls(args.namespace, args.pod_name);

        case "get_pod_packet_drops":
          return await this.getPodPacketDrops(args.namespace, args.pod_name);

        default:
          return {
            data: null,
            error: `Unknown tool: ${name}`,
          };
      }
    } catch (error) {
      return {
        data: null,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  private async getPodNetworkTraffic(
    namespace: string,
    podName: string
  ): Promise<ToolResult> {
    try {
      const response = await this.client.get(
        `/pod/traffic/name/${namespace}/${podName}`
      );
      return { data: response.data };
    } catch (error) {
      if (axios.isAxiosError(error)) {
        return {
          data: null,
          error: `Failed to fetch network traffic: ${error.response?.status} - ${error.message}`,
        };
      }
      return {
        data: null,
        error: `Failed to fetch network traffic: ${error}`,
      };
    }
  }

  private async getPodSyscalls(
    namespace: string,
    podName: string
  ): Promise<ToolResult> {
    try {
      const response = await this.client.get(
        `/pod/syscalls/name/${namespace}/${podName}`
      );
      return { data: response.data };
    } catch (error) {
      if (axios.isAxiosError(error)) {
        return {
          data: null,
          error: `Failed to fetch syscalls: ${error.response?.status} - ${error.message}`,
        };
      }
      return {
        data: null,
        error: `Failed to fetch syscalls: ${error}`,
      };
    }
  }

  private async getPodPacketDrops(
    namespace: string,
    podName: string
  ): Promise<ToolResult> {
    try {
      const response = await this.client.get(
        `/pod/packet_drop/name/${namespace}/${podName}`
      );
      return { data: response.data };
    } catch (error) {
      if (axios.isAxiosError(error)) {
        return {
          data: null,
          error: `Failed to fetch packet drops: ${error.response?.status} - ${error.message}`,
        };
      }
      return {
        data: null,
        error: `Failed to fetch packet drops: ${error}`,
      };
    }
  }

  /**
   * Get available tools definition for LLMs
   */
  static getToolDefinitions() {
    return [
      {
        name: "get_pod_network_traffic",
        description:
          "Get network traffic data for a specific pod by namespace and pod name. Returns source/destination IPs, ports, protocols, and connection counts.",
        parameters: {
          type: "object",
          properties: {
            namespace: {
              type: "string",
              description: "The Kubernetes namespace of the pod",
            },
            pod_name: {
              type: "string",
              description: "The name of the pod",
            },
          },
          required: ["namespace", "pod_name"],
        },
      },
      {
        name: "get_pod_syscalls",
        description:
          "Get system call data for a specific pod. Returns the syscalls made by the pod with their frequencies. Useful for security analysis and seccomp profile generation.",
        parameters: {
          type: "object",
          properties: {
            namespace: {
              type: "string",
              description: "The Kubernetes namespace of the pod",
            },
            pod_name: {
              type: "string",
              description: "The name of the pod",
            },
          },
          required: ["namespace", "pod_name"],
        },
      },
      {
        name: "get_pod_packet_drops",
        description:
          "Get packet drop events for a specific pod. Returns information about dropped network packets including reasons and statistics. Useful for debugging network issues.",
        parameters: {
          type: "object",
          properties: {
            namespace: {
              type: "string",
              description: "The Kubernetes namespace of the pod",
            },
            pod_name: {
              type: "string",
              description: "The name of the pod",
            },
          },
          required: ["namespace", "pod_name"],
        },
      },
    ];
  }

  /**
   * Get system prompt for kguardian AI assistant
   */
  static getSystemPrompt(): string {
    return `You are an AI assistant for kguardian, a Kubernetes security monitoring tool.

Your role is to help users understand their cluster's network traffic, security events, and system calls.

You have access to these tools:
- get_pod_network_traffic: Query network connections for a pod
- get_pod_syscalls: Get system calls made by a pod
- get_pod_packet_drops: Get packet drop information

When answering questions:
1. Be concise and technical
2. Use the available tools to fetch real data when needed
3. Provide actionable insights about security and networking
4. Suggest network policies or seccomp profiles when relevant
5. Format data in readable tables or lists when appropriate

Available data includes:
- Pod network traffic (source/dest IPs, ports, protocols)
- Syscall usage patterns
- Packet drop events
- Service mappings

Remember to ask for specific pod names and namespaces when you need to query data.`;
  }
}
