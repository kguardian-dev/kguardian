import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
  type ListToolsResult,
} from "@modelcontextprotocol/sdk/types.js";

import { log } from "../logger.js";
import { TOOL_DEFS } from "../tools/registry.js";
import { executeInProcessTool } from "../tools/execute.js";

/**
 * The MCP protocol layer: the same 12 tools the assistant runs in-process,
 * spoken as MCP so external clients (Claude Code, for one) can call them.
 *
 * This uses the SDK's LOW-LEVEL `Server` with raw request handlers rather
 * than `McpServer.registerTool`, and that is the whole point. `registerTool`
 * wants a zod shape and derives the JSON Schema itself, which would give the
 * MCP surface its own hand-maintained copy of every tool's parameters — a
 * second source of truth guaranteed to drift from `TOOL_DEFS` the first time
 * someone edits a description. Handling `tools/list` directly lets
 * `inputSchema` be `TOOL_DEFS[].parameters` passed through verbatim, so an
 * external client and the LLM provider loops see byte-identical definitions
 * and a tool added to the registry cannot silently skip MCP.
 */

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Version advertised in the MCP `serverInfo`. Read from package.json at
 * runtime (two levels up from both src/mcp/ under tsx and dist/mcp/ in the
 * image, where the Dockerfile copies package.json alongside dist/) so it
 * tracks the released llm-bridge version instead of a constant that goes
 * stale. serverInfo is advisory — clients display it, nothing depends on it —
 * so an unreadable package.json degrades to "0.0.0" rather than refusing to
 * start.
 */
function packageVersion(): string {
  try {
    const raw = readFileSync(resolve(__dirname, "..", "..", "package.json"), "utf8");
    const parsed = JSON.parse(raw) as { version?: string };
    return parsed.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

const SERVER_VERSION = packageVersion();

/** The MCP tool list, derived from the registry — never hand-written. */
export function mcpToolList(): ListToolsResult["tools"] {
  return TOOL_DEFS.map((tool) => ({
    name: tool.name,
    description: tool.description,
    inputSchema: tool.parameters,
  }));
}

/**
 * Run one tool and shape the MCP result.
 *
 * `executeInProcessTool` already converts a failure into
 * `{ text, isError: true }`, and that maps onto MCP's `isError` flag exactly:
 * the model sees the error text as tool output and can recover, instead of
 * the round aborting. The extra try/catch is not redundant — anything that
 * escaped that function (an unknown-tool path, an OOM stringifying a huge
 * response) would otherwise surface as a JSON-RPC -32603 protocol error,
 * which most clients treat as "the server is broken" rather than "that call
 * failed". Keeping it a tool-level error keeps the session usable.
 */
async function callTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  try {
    const result = await executeInProcessTool(name, args);
    return { content: [{ type: "text", text: result.text }], isError: result.isError };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    log.error(`MCP tool ${name} threw:`, message);
    return { content: [{ type: "text", text: `error executing ${name}: ${message}` }], isError: true };
  }
}

/**
 * Build an MCP `Server` wired to the registry. A fresh instance is created
 * per HTTP request (see router.ts) — the handlers hold no state, so this is
 * cheap and keeps the endpoint safe to load-balance across replicas.
 */
export function createMcpServer(): Server {
  const server = new Server(
    { name: "kguardian", version: SERVER_VERSION },
    {
      // Only tools. kguardian exposes no MCP resources or prompts; declaring
      // capabilities it doesn't serve would make clients issue resources/list
      // calls that can only fail.
      capabilities: { tools: {} },
      instructions:
        "kguardian exposes observed Kubernetes runtime behaviour: pod network traffic, " +
        "syscalls, service and pod inventory, network-policy audit verdicts, and generation " +
        "of least-privilege NetworkPolicy / seccomp profiles from that observed baseline. " +
        "Pod-specific tools take only pod_name, never a namespace; cluster-wide tools accept " +
        "an optional namespace filter.",
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: mcpToolList() }));

  server.setRequestHandler(CallToolRequestSchema, async (request) =>
    callTool(request.params.name, (request.params.arguments ?? {}) as Record<string, unknown>),
  );

  return server;
}
