import { log } from "./logger.js";
import type { ToolCall, ToolResult } from "./types/index.js";
import { TOOL_DEFS } from "./tools/registry.js";
import { executeInProcessTool } from "./tools/execute.js";

// the assistant's 12 tools run IN-PROCESS here — this class no
// longer talks to a separate mcp-server over MCP transport. It reaches the
// broker directly and generates network policies / seccomp profiles itself
// (src/tools/*), so neither the mcp-server nor the advisor-serve service is
// in the path. The public surface (executeTool, getToolsCached,
// getSystemPrompt, parseContext) is unchanged so the provider loops are
// untouched, and the src/tools parity test proves every tool reproduces the
// former mcp-server's outputs against the shared contract fixtures.
//
// NOTE: the class keeps the name McpClient for a focused, reviewable diff; a
// rename to `Assistant` is a trivial follow-up. The tool set is still exposed
// as MCP tools to the model — only the transport (a network hop to a Go
// service) is gone.

export interface ParsedContext {
  namespace?: string;
  podNames?: string[];
}

export class McpClient {
  private static toolDefsCache: { name: string; description: string; parameters: unknown }[] | null = null;

  /**
   * Execute a tool call in-process. Returns the same ToolResult shape the
   * providers already consume: { data } on success (parsed JSON when the tool
   * returned JSON, otherwise the raw string), or { data: null, error } on
   * failure — a failing tool never throws, so one bad call can't abort the
   * model's tool round.
   */
  async executeTool(toolCall: ToolCall): Promise<ToolResult> {
    const { name, arguments: args } = toolCall;
    log.debug(`Executing tool in-process: ${name}`);
    const result = await executeInProcessTool(name, args || {});
    if (result.isError) {
      return { data: null, error: result.text };
    }
    try {
      return { data: JSON.parse(result.text) };
    } catch {
      // Advisor tools return YAML/JSON text that is not necessarily a JSON
      // object — forward it as-is.
      return { data: result.text };
    }
  }

  /**
   * Tool definitions for the LLM providers, sourced from the single in-repo
   * registry. Kept async + cached to preserve the previous call signature.
   */
  static async getToolsCached(): Promise<{ name: string; description: string; parameters: unknown }[]> {
    if (McpClient.toolDefsCache) return McpClient.toolDefsCache;
    McpClient.toolDefsCache = TOOL_DEFS.map((t) => ({
      name: t.name,
      description: t.description,
      parameters: t.parameters,
    }));
    return McpClient.toolDefsCache;
  }

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
   * Parse a JSON context string from the frontend into a typed object.
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
}
