import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { ToolCall, ToolResult } from "./types/index.js";

export class BrokerClient {
  private mcpClient: Client | null = null;
  private mcpUrl: string;
  private mcpInitialized: boolean = false;

  constructor(brokerUrl: string, mcpUrl?: string) {
    this.mcpUrl = mcpUrl || process.env.MCP_SERVER_URL || "http://kguardian-mcp-server.kguardian.svc.cluster.local:8081";
  }

  /**
   * Initialize MCP client connection
   */
  private async initializeMCPClient(): Promise<void> {
    if (this.mcpInitialized && this.mcpClient) {
      return;
    }

    try {
      // Create Streamable HTTP transport (MCP spec 2025-03-26)
      const transport = new StreamableHTTPClientTransport(new URL(this.mcpUrl));

      // Create MCP client
      this.mcpClient = new Client(
        {
          name: "kguardian-llm-bridge",
          version: "1.1.0",
        },
        {
          capabilities: {},
        }
      );

      // Connect to MCP server
      await this.mcpClient.connect(transport);
      this.mcpInitialized = true;

      console.log(`✓ Connected to MCP server at ${this.mcpUrl}`);
    } catch (error) {
      console.error("Failed to initialize MCP client:", error);
      throw new Error(
        `Failed to connect to MCP server at ${this.mcpUrl}: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /**
   * Execute a tool call by routing to the MCP server
   */
  async executeTool(toolCall: ToolCall): Promise<ToolResult> {
    try {
      // Ensure MCP client is initialized
      await this.initializeMCPClient();

      if (!this.mcpClient) {
        throw new Error("MCP client not initialized");
      }

      const { name, arguments: args } = toolCall;

      console.log(`Calling MCP tool: ${name} with args:`, args);

      // Call the tool using MCP SDK
      const result = await this.mcpClient.callTool({
        name,
        arguments: args || {},
      });

      console.log(`MCP tool ${name} returned:`, result);

      // MCP SDK returns result with content array
      if (result.content && Array.isArray(result.content)) {
        // Extract text content from the response
        const textContent = result.content.find((item) => item.type === "text");
        if (textContent && "text" in textContent) {
          try {
            // Try to parse as JSON
            const parsedData = JSON.parse(textContent.text);
            return { data: parsedData };
          } catch {
            // If not JSON, return as-is
            return { data: textContent.text };
          }
        }
      }

      // If we get here, return the raw result
      return { data: result };
    } catch (error) {
      console.error(`Error calling MCP tool ${toolCall.name}:`, error);
      return {
        data: null,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Get available tools from MCP server
   */
  async getAvailableTools(): Promise<any[]> {
    try {
      await this.initializeMCPClient();

      if (!this.mcpClient) {
        throw new Error("MCP client not initialized");
      }

      const response = await this.mcpClient.listTools();
      return response.tools || [];
    } catch (error) {
      console.error("Error fetching tools from MCP server:", error);
      return [];
    }
  }

  /**
   * Get tool definitions for LLMs
   * This fetches the actual tools from the MCP server dynamically
   */
  static async getToolDefinitionsFromMCP(mcpUrl?: string): Promise<any[]> {
    const client = new BrokerClient("", mcpUrl);
    try {
      const tools = await client.getAvailableTools();

      // Convert MCP tool format to LLM provider format
      return tools.map((tool: any) => ({
        name: tool.name,
        description: tool.description || "",
        parameters: tool.inputSchema || {
          type: "object",
          properties: {},
          required: [],
        },
      }));
    } catch (error) {
      console.error("Failed to fetch tools from MCP server, using fallback:", error);
      // Fallback to static definitions if MCP server is unavailable
      return BrokerClient.getToolDefinitions();
    }
  }

  /**
   * Get available tools definition for LLMs (static fallback)
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

  /**
   * Close the MCP client connection
   */
  async close(): Promise<void> {
    if (this.mcpClient) {
      await this.mcpClient.close();
      this.mcpClient = null;
      this.mcpInitialized = false;
      console.log("MCP client connection closed");
    }
  }
}
