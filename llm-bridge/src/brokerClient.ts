import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { log } from "./logger.js";
import type { ToolCall, ToolResult } from "./types/index.js";

export interface ParsedContext {
  namespace?: string;
  podNames?: string[];
}

/**
 * Resolve the MCP server URL from (in priority order): an explicit
 * constructor argument, the MCP_SERVER_URL env var, or the in-cluster
 * default. Each candidate is trim-empty defended so a whitespace-only
 * value (typical Helm YAML literal artefact, or a misconfigured
 * env-from-secret with stray whitespace) doesn't pass the truthy
 * check and surface later as a cryptic `TypeError: Invalid URL` from
 * `new URL(...)` inside the transport — far from the env-var read
 * site. Same defense-in-depth class as the mcp-server's
 * NewBrokerClient TrimSpace and the broker's AuditClient::from_env
 * trim.
 *
 * Exported as a pure helper so the resolution contract can be unit-
 * tested without instantiating BrokerClient (which would also try to
 * import MCP transports just to test a string resolution).
 */
export function resolveMcpUrl(arg?: string, envUrl?: string): string {
  const argTrimmed = arg?.trim();
  const envTrimmed = envUrl?.trim();
  return argTrimmed || envTrimmed || "http://kguardian-mcp-server.kguardian.svc.cluster.local:8081";
}

export class BrokerClient {
  private mcpClient: Client | null = null;
  private mcpUrl: string;
  private mcpInitialized: boolean = false;
  private initPromise: Promise<void> | null = null;
  private static toolDefsCache: any[] | null = null;

  /**
   * The class is named BrokerClient for historical reasons — before
   * the MCP refactor it talked directly to the broker. Today all
   * tool calls route through the MCP server (this.mcpUrl), and the
   * broker is reached via the MCP server's own broker client. So
   * only `mcpUrl` is meaningful; the previous `brokerUrl` parameter
   * was declared but never stored — the static getToolDefinitionsFromMCP
   * helper already acknowledged this by passing "" for it.
   */
  constructor(mcpUrl?: string) {
    this.mcpUrl = resolveMcpUrl(mcpUrl, process.env.MCP_SERVER_URL);
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

      log.info(`Connected to MCP server at ${this.mcpUrl}`);
    } catch (error) {
      // Reset the promise so future calls can retry
      this.initPromise = null;
      log.error("Failed to initialize MCP client:", error);
      throw new Error(
        `Failed to connect to MCP server at ${this.mcpUrl}: ${error instanceof Error ? error.message : String(error)}`,
        { cause: error }
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
    log.info("MCP client connection reset — will reconnect on next call");
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

      // Per-tool-call entry + exit logs at debug level. A chatty LLM
      // can call tools dozens of times per session and the exit log
      // (with the full result body) is multi-KB per call — far too
      // verbose for steady-state INFO. Operators wanting per-call
      // tracing run with LOG_LEVEL=debug.
      log.debug(`Calling MCP tool: ${name}`);

      // Call the tool using MCP SDK
      const result = await this.mcpClient.callTool({
        name,
        arguments: args || {},
      });

      log.debug(`MCP tool ${name} returned:`, result);

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
        log.warn(
          `Connection error calling MCP tool ${toolCall.name}, resetting and retrying:`,
          error instanceof Error ? error.message : error
        );
        this.resetConnection();
        return this.executeToolInner(toolCall, false);
      }

      log.error(`Error calling MCP tool ${toolCall.name}:`, error);
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
      // Propagate rather than swallow. The MCP server is the single source of
      // truth for the tool surface; if discovery fails the assistant has no
      // grounded tools, and answering ungrounded is worse than failing. The
      // caller surfaces a clear "tool server unreachable" error to the user.
      log.error("Error fetching tools from MCP server:", error);
      throw error instanceof Error ? error : new Error(String(error));
    }
  }

  /**
   * Get tool definitions for LLMs
   * This fetches the actual tools from the MCP server dynamically
   */
  static async getToolDefinitionsFromMCP(mcpUrl?: string): Promise<any[]> {
    const client = new BrokerClient(mcpUrl);
    try {
      const tools = await client.getAvailableTools();

      // Convert MCP tool format to LLM provider format.
      return tools.map((tool: any) => ({
        name: tool.name,
        description: tool.description || "",
        parameters: tool.inputSchema || {
          type: "object",
          properties: {},
          required: [],
        },
      }));
    } finally {
      // Errors propagate (no static fallback) — the MCP server is the single
      // source of truth for the tool surface.
      await client.close();
    }
  }

  /**
   * Get tool definitions with caching. The MCP server is the single source of
   * truth — there is no static fallback. If discovery fails or returns nothing,
   * this throws so the request fails clearly rather than the model answering
   * without its data tools. Only a successful, non-empty result is cached, so a
   * transient MCP blip is retried on the next request.
   */
  static async getToolsCached(): Promise<any[]> {
    if (BrokerClient.toolDefsCache) return BrokerClient.toolDefsCache;
    const tools = await BrokerClient.getToolDefinitionsFromMCP();
    if (!tools.length) {
      throw new Error(
        "MCP server returned no tools — the assistant cannot answer without its data tools. Check that the MCP server is reachable (MCP_SERVER_URL).",
      );
    }
    BrokerClient.toolDefsCache = tools;
    return tools;
  }

  /**
   * Get system prompt for kguardian AI assistant
   */
  static getSystemPrompt(context?: ParsedContext): string {
    let prompt = `You are an AI assistant for kguardian, a Kubernetes security monitoring tool.

Your role is to help users understand their cluster's network traffic, security events, and system calls.

IMPORTANT: You have access to tools that fetch real-time data from the cluster. ALWAYS USE THESE TOOLS when users ask questions.

## Tool Selection Guide

**Pod-Specific Tools** (require only pod_name, NOT namespace):
- get_pod_network_traffic: Get traffic for a specific pod. Use when user asks about a pod's connections.
- get_pod_syscalls: Get syscalls for a specific pod. Use when user asks about a pod's behavior or seccomp.
- get_pod_details_by_name: Identify a pod from its name (namespace, IP, node, workload labels). Prefer this when the user names a pod.

**Lookup Tools** (require only ip):
- get_pod_details: Find pod info by IP address.
- get_service_details: Find service info by cluster IP.

**Cluster-Wide Tools** (accept optional namespace filter):
- get_cluster_traffic: Get traffic summary across pods. Returns per-pod counts, not raw records.
- get_cluster_pods: List pods with compact metadata (name, namespace, IP, node).
- list_services: List services with name, namespace, cluster IP, selector, and ports.
- get_pods_on_node: List pods on a specific node (blast-radius / "what runs on node X"). Requires node.

**Security / Policy Tools:**
- get_audit_verdicts: Get network-policy evaluation verdicts (Allow / WouldDeny) for observed flows, newest first. THE tool for "what would be denied", "why is this flow blocked", "show recent policy violations", or "summarize security events". Filter by policy, namespace, verdict ('WouldDeny' for violations), direction, and limit.

**Generation Tools** (synthesize ready-to-apply resources from observed runtime data):
- generate_network_policy: Generate a least-privilege NetworkPolicy or CiliumNetworkPolicy (YAML) for a pod. Use when the user asks to generate/create a network policy or lock down a pod. Pass policy_type 'cilium' only if the user asks for Cilium. Present the YAML in a fenced \`\`\`yaml code block so the user can copy or apply it.
- generate_seccomp_profile: Generate a least-privilege seccomp profile (JSON) for a pod. Use when the user asks to generate/create a seccomp profile. Present the JSON in a fenced \`\`\`json code block.

## Constraints
- Pod-specific tools take only pod_name — do NOT pass namespace to them.
- Cluster, service, and audit tools accept an optional "namespace" parameter to scope results.`;

    if (context?.namespace) {
      prompt += `\n\n## Current Context
The user is viewing namespace "${context.namespace}". ALWAYS pass namespace="${context.namespace}" to get_cluster_traffic, get_cluster_pods, list_services, and get_audit_verdicts unless the user explicitly asks for all namespaces.`;
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
6. Respond with your final answer only — do not narrate your reasoning or tool-selection process

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
      log.info("MCP client connection closed");
    }
  }
}
