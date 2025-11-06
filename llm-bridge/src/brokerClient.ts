import axios, { AxiosInstance } from "axios";
import type { ToolCall, ToolResult } from "./types/index.js";

export class BrokerClient {
  private mcpClient: AxiosInstance;
  private brokerClient: AxiosInstance;
  private mcpUrl: string;
  private brokerUrl: string;

  constructor(brokerUrl: string, mcpUrl?: string) {
    this.brokerUrl = brokerUrl;
    this.mcpUrl = mcpUrl || process.env.MCP_SERVER_URL || "http://kguardian-mcp-server.kguardian.svc.cluster.local:8081";

    // MCP server client for tool calls
    this.mcpClient = axios.create({
      baseURL: this.mcpUrl,
      timeout: 30000,
      headers: {
        "Content-Type": "application/json",
      },
    });

    // Keep broker client for backward compatibility if needed
    this.brokerClient = axios.create({
      baseURL: brokerUrl,
      timeout: 10000,
      headers: {
        "Content-Type": "application/json",
      },
    });
  }

  /**
   * Execute a tool call by routing to the MCP server
   */
  async executeTool(toolCall: ToolCall): Promise<ToolResult> {
    try {
      const { name, arguments: args } = toolCall;

      // All tools are now handled by MCP server via HTTP POST
      const response = await this.mcpClient.post("/", {
        jsonrpc: "2.0",
        id: Date.now(),
        method: "tools/call",
        params: {
          name,
          arguments: args,
        },
      });

      if (response.data.error) {
        return {
          data: null,
          error: response.data.error.message || "MCP server returned an error",
        };
      }

      // MCP server returns result in response.data.result.content
      const result = response.data.result;
      if (result && result.content) {
        // Parse the JSON data from the content
        const contentText = Array.isArray(result.content)
          ? result.content[0].text
          : result.content.text;

        try {
          const parsedData = JSON.parse(contentText);
          return { data: parsedData };
        } catch {
          // If not JSON, return as-is
          return { data: contentText };
        }
      }

      return { data: result };
    } catch (error) {
      if (axios.isAxiosError(error)) {
        return {
          data: null,
          error: `MCP server error: ${error.response?.status} - ${error.response?.data?.error?.message || error.message}`,
        };
      }
      return {
        data: null,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  // Keeping these methods for backward compatibility but they now use MCP server
  private async getPodNetworkTraffic(
    namespace: string,
    podName: string
  ): Promise<ToolResult> {
    return this.executeTool({
      name: "get_pod_network_traffic",
      arguments: { namespace, pod_name: podName },
    });
  }

  private async getPodSyscalls(
    namespace: string,
    podName: string
  ): Promise<ToolResult> {
    return this.executeTool({
      name: "get_pod_syscalls",
      arguments: { namespace, pod_name: podName },
    });
  }

  /**
   * Get available tools definition for LLMs
   */
  static getToolDefinitions() {
    return [
      {
        name: "get_pod_network_traffic",
        description:
          "Get network traffic data for a specific pod by namespace and pod name. Returns source/destination IPs, ports, protocols, traffic types (ingress/egress), and packet decisions (allowed/dropped). Essential for generating network policies and understanding pod communication patterns.",
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
          "Get system call (syscall) data for a specific pod. Returns the syscalls made by the pod with their frequencies and architecture. Critical for security analysis, generating seccomp profiles, and identifying suspicious behavior.",
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
        name: "get_pod_details",
        description:
          "Get detailed information about a pod by its IP address. Returns pod name, namespace, IP, and full Kubernetes pod object. Useful for correlating IP addresses to pod identities.",
        parameters: {
          type: "object",
          properties: {
            ip: {
              type: "string",
              description: "The IP address of the pod to query",
            },
          },
          required: ["ip"],
        },
      },
      {
        name: "get_service_details",
        description:
          "Get detailed information about a Kubernetes service by its cluster IP. Returns service name, namespace, IP, ports, and full service object. Essential for understanding service-to-service communication.",
        parameters: {
          type: "object",
          properties: {
            ip: {
              type: "string",
              description: "The IP address of the service to query",
            },
          },
          required: ["ip"],
        },
      },
      {
        name: "get_cluster_traffic",
        description:
          "Get all network traffic data across the entire cluster. Returns comprehensive traffic information for all monitored pods. Use this for cluster-wide network analysis, identifying communication patterns, and detecting anomalies. WARNING: This returns large datasets.",
        parameters: {
          type: "object",
          properties: {},
          required: [],
        },
      },
      {
        name: "get_cluster_pods",
        description:
          "Get detailed information about all pods in the cluster. Returns pod names, namespaces, IPs, and full Kubernetes objects. Useful for cluster inventory and identifying monitored workloads. WARNING: This returns large datasets.",
        parameters: {
          type: "object",
          properties: {},
          required: [],
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

IMPORTANT: You have access to 6 powerful tools that can fetch real-time data from the cluster. ALWAYS USE THESE TOOLS when users ask questions:

**Pod-Specific Tools:**
- get_pod_network_traffic: Query network connections for a pod (requires namespace and pod_name)
- get_pod_syscalls: Get system calls made by a pod (requires namespace and pod_name)

**Lookup Tools:**
- get_pod_details: Find pod info by IP address (requires ip)
- get_service_details: Find service info by cluster IP (requires ip)

**Cluster-Wide Tools:**
- get_cluster_traffic: Get ALL network traffic in the cluster (no parameters) - use for comprehensive analysis
- get_cluster_pods: Get ALL pod information in the cluster (no parameters) - use for inventory/discovery

When a user provides namespace and pod name (in ANY format), immediately use the appropriate tool. Do NOT ask for clarification if you have the information.

Examples:
- "Show syscalls for nginx-123 in default" → USE get_pod_syscalls immediately
- "What pods are running?" → USE get_cluster_pods immediately
- "Show all network traffic" → USE get_cluster_traffic immediately
- "What is pod 10.1.2.3?" → USE get_pod_details with ip="10.1.2.3"

When presenting results:
1. Be concise and technical
2. Format data in readable tables or lists
3. Highlight security concerns or anomalies
4. Suggest network policies or seccomp profiles when relevant
5. For large datasets, summarize key findings first

If you don't have required information, ask ONCE, then use the tool immediately.`;
  }
}
