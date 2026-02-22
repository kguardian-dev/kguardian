import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { ToolCall, ToolResult } from "./types/index.js";

export interface ParsedContext {
  namespace?: string;
  podNames?: string[];
}

export class BrokerClient {
  private mcpClient: Client | null = null;
  private mcpUrl: string;
  private mcpInitialized: boolean = false;
  private initPromise: Promise<void> | null = null;
  private static toolDefsCache: any[] | null = null;

  constructor(brokerUrl: string, mcpUrl?: string) {
    this.mcpUrl = mcpUrl || process.env.MCP_SERVER_URL || "http://kguardian-mcp-server.kguardian.svc.cluster.local:8081";
  }

  /**
   * Initialize MCP client connection (with mutex to prevent race conditions)
   */
  async initializeMCPClient(): Promise<void> {
    if (this.mcpInitialized) return;
    if (!this.initPromise) {
      this.initPromise = this._doInit();
    }
    return this.initPromise;
  }

  private async _doInit(): Promise<void> {
    try {
      // Create Streamable HTTP transport (MCP spec 2025-03-26)
      const transport = new StreamableHTTPClientTransport(new URL(this.mcpUrl));

      // Create MCP client
      this.mcpClient = new Client(
        {
          name: "kguardian-llm-bridge",
          version: "1.2.1",
        },
        {
          capabilities: {},
        }
      );

      // Connect to MCP server
      await this.mcpClient.connect(transport);
      this.mcpInitialized = true;

      console.log(`Connected to MCP server at ${this.mcpUrl}`);
    } catch (error) {
      // Reset the promise so future calls can retry
      this.initPromise = null;
      console.error("Failed to initialize MCP client:", error);
      throw new Error(
        `Failed to connect to MCP server at ${this.mcpUrl}: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /**
   * Reset MCP client connection state so the next call will reconnect
   */
  private resetConnection(): void {
    this.mcpClient = null;
    this.mcpInitialized = false;
    this.initPromise = null;
    console.log("MCP client connection reset — will reconnect on next call");
  }

  /**
   * Check if an error is a connection-level failure worth retrying
   */
  private isConnectionError(error: unknown): boolean {
    if (!(error instanceof Error)) return false;
    const msg = error.message.toLowerCase();
    return (
      msg.includes("econnrefused") ||
      msg.includes("econnreset") ||
      msg.includes("socket hang up") ||
      msg.includes("fetch failed") ||
      msg.includes("network error")
    );
  }

  /**
   * Execute a tool call by routing to the MCP server.
   * On connection errors, resets state and retries once.
   */
  async executeTool(toolCall: ToolCall): Promise<ToolResult> {
    return this.executeToolInner(toolCall, true);
  }

  private async executeToolInner(
    toolCall: ToolCall,
    allowRetry: boolean
  ): Promise<ToolResult> {
    try {
      // Ensure MCP client is initialized
      await this.initializeMCPClient();

      if (!this.mcpClient) {
        throw new Error("MCP client not initialized");
      }

      const { name, arguments: args } = toolCall;

      console.log(`Calling MCP tool: ${name}`);

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
      // On connection errors, reset and retry once
      if (allowRetry && this.isConnectionError(error)) {
        console.warn(
          `Connection error calling MCP tool ${toolCall.name}, resetting and retrying:`,
          error instanceof Error ? error.message : error
        );
        this.resetConnection();
        return this.executeToolInner(toolCall, false);
      }

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
    } finally {
      await client.close();
    }
  }

  /**
   * Get tool definitions with caching — tries MCP server first, falls back to static
   */
  static async getToolsCached(): Promise<any[]> {
    if (BrokerClient.toolDefsCache) return BrokerClient.toolDefsCache;
    try {
      BrokerClient.toolDefsCache = await BrokerClient.getToolDefinitionsFromMCP();
    } catch {
      BrokerClient.toolDefsCache = BrokerClient.getToolDefinitions();
    }
    return BrokerClient.toolDefsCache;
  }

  /**
   * Get available tools definition for LLMs (static fallback)
   */
  static getToolDefinitions() {
    return [
      {
        name: "get_pod_network_traffic",
        description:
          "Get network traffic for a specific pod by name. Returns source/destination IPs, ports, protocols, ingress/egress types, and packet decisions. Use when the user asks about a specific pod's connections. Requires only pod_name (not namespace-scoped).",
        parameters: {
          type: "object",
          properties: {
            pod_name: {
              type: "string",
              description: "The name of the pod to query traffic for",
            },
          },
          required: ["pod_name"],
        },
      },
      {
        name: "get_pod_syscalls",
        description:
          "Get system calls made by a specific pod. Returns syscall names, frequencies, and architecture. Use when the user asks about a pod's syscalls or seccomp profile. Requires only pod_name (not namespace-scoped).",
        parameters: {
          type: "object",
          properties: {
            pod_name: {
              type: "string",
              description: "The name of the pod to query syscalls for",
            },
          },
          required: ["pod_name"],
        },
      },
      {
        name: "get_pod_details",
        description:
          "Look up a pod by its IP address. Returns pod name, namespace, IP, and full Kubernetes pod object. Requires only ip.",
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
          "Look up a Kubernetes service by its cluster IP. Returns service name, namespace, IP, ports, and full service spec. Requires only ip.",
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
          "Get a summary of network traffic across the cluster. Returns per-pod traffic counts. Accepts optional namespace to filter. Use for overall traffic patterns.",
        parameters: {
          type: "object",
          properties: {
            namespace: {
              type: "string",
              description: "Optional namespace to filter traffic results",
            },
          },
          required: [],
        },
      },
      {
        name: "get_cluster_pods",
        description:
          "List pods in the cluster with compact metadata. Accepts optional namespace to filter. Use when the user asks what pods are running.",
        parameters: {
          type: "object",
          properties: {
            namespace: {
              type: "string",
              description: "Optional namespace to filter pod results",
            },
          },
          required: [],
        },
      },
    ];
  }

  /**
   * Get system prompt for kguardian AI assistant
   */
  static getSystemPrompt(context?: ParsedContext): string {
    let prompt = `You are an AI assistant for kguardian, a Kubernetes security monitoring tool.

Your role is to help users understand their cluster's network traffic, security events, and system calls.

IMPORTANT: You have access to 6 tools that fetch real-time data from the cluster. ALWAYS USE THESE TOOLS when users ask questions.

## Tool Selection Guide

**Pod-Specific Tools** (require only pod_name, NOT namespace):
- get_pod_network_traffic: Get traffic for a specific pod. Use when user asks about a pod's connections.
- get_pod_syscalls: Get syscalls for a specific pod. Use when user asks about a pod's behavior or seccomp.

**Lookup Tools** (require only ip):
- get_pod_details: Find pod info by IP address.
- get_service_details: Find service info by cluster IP.

**Cluster-Wide Tools** (accept optional namespace filter):
- get_cluster_traffic: Get traffic summary across pods. Returns per-pod counts, not raw records.
- get_cluster_pods: List pods with compact metadata (name, namespace, IP, node).

## Constraints
- Pod-specific tools take only pod_name — do NOT pass namespace to them.
- Cluster tools accept an optional "namespace" parameter to scope results.`;

    if (context?.namespace) {
      prompt += `\n\n## Current Context
The user is viewing namespace "${context.namespace}". ALWAYS pass namespace="${context.namespace}" to get_cluster_traffic and get_cluster_pods unless the user explicitly asks for all namespaces.`;
    }

    if (context?.podNames && context.podNames.length > 0) {
      const pods = context.podNames.slice(0, 20).join(", ");
      prompt += `\nVisible pods: ${pods}${context.podNames.length > 20 ? ` (and ${context.podNames.length - 20} more)` : ""}`;
    }

    prompt += `

## Response Format
1. Be concise and technical
2. Format data in readable tables or lists
3. Highlight security concerns or anomalies
4. Suggest network policies or seccomp profiles when relevant
5. For large datasets, summarize key findings first

When a user mentions a pod name, use the appropriate tool immediately. Do NOT ask for clarification if you have the information.`;

    return prompt;
  }

  /**
   * Parse a JSON context string from the frontend into a typed object
   */
  static parseContext(contextStr?: string): ParsedContext | undefined {
    if (!contextStr) return undefined;
    try {
      const parsed = JSON.parse(contextStr);
      return {
        namespace: typeof parsed.namespace === "string" ? parsed.namespace : undefined,
        podNames: Array.isArray(parsed.podNames) ? parsed.podNames : undefined,
      };
    } catch {
      return undefined;
    }
  }

  /**
   * Close the MCP client connection
   */
  async close(): Promise<void> {
    if (this.mcpClient) {
      await this.mcpClient.close();
      this.mcpClient = null;
      this.mcpInitialized = false;
      this.initPromise = null;
      console.log("MCP client connection closed");
    }
  }
}
