import { Router, type Request, type Response } from "express";
import rateLimit from "express-rate-limit";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { log } from "../logger.js";
import { requireBearer } from "./auth.js";
import { createMcpServer } from "./server.js";
import type { McpConfig } from "./config.js";

/**
 * HTTP layer for the MCP endpoint: auth, rate limiting, and the
 * StreamableHTTP transport lifecycle. Mounted on the existing Express app at
 * MCP_PATH so MCP shares the service's port, Service, probes and CORS config
 * rather than adding a second listener to deploy and firewall.
 */

/**
 * Every request gets its own `Server` + transport, and the transport is
 * constructed with `sessionIdGenerator: undefined` — stateless mode. This is
 * a deployment constraint, not a preference: the chart runs llm-bridge with
 * `replicaCount: 2` behind a ClusterIP Service with no session affinity, so
 * consecutive requests from one MCP client land on different pods. A
 * server-side session created on replica A simply does not exist on replica
 * B, and the client would get a 404 "session not found" mid-conversation with
 * no way to recover. Stateless mode has no session to lose: each POST carries
 * everything needed to serve it. The cost is per-request object construction
 * (negligible — the handlers close over module-level constants) and no
 * server-initiated notifications, which this tool set does not use.
 */
async function handleMcpRequest(req: Request, res: Response): Promise<void> {
  const server = createMcpServer();
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });

  // Tear both down when the response finishes, however it finishes. Without
  // this the per-request Server/transport pair leaks for the life of the
  // process and an agentic client doing hundreds of calls would grow the heap
  // unboundedly.
  res.on("close", () => {
    void transport.close();
    void server.close();
  });

  try {
    await server.connect(transport);
    // `express.json({ limit: '100kb' })` is applied globally in index.ts, so
    // the body stream is already consumed by the time we get here and the
    // transport would hang waiting for data it will never see. Hand it the
    // parsed body explicitly — the SDK supports exactly this case.
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    log.error("MCP request failed:", message);
    // The transport writes its own status once it starts responding (and for
    // an accepted POST that response is an SSE stream), so only synthesize an
    // error when nothing has gone out yet. -32603 is JSON-RPC "internal
    // error"; the id is null because a failure this early means we may not
    // have a request id to correlate against.
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32603, message: "Internal server error" },
        id: null,
      });
    }
  }
}

/**
 * Build the /mcp router. Only called when the endpoint is enabled — when it
 * is not, index.ts never mounts anything and the path 404s like any other
 * unrouted URL, so a disabled endpoint is indistinguishable from a build that
 * never had one.
 */
export function createMcpRouter(config: McpConfig): Router {
  const router = Router();

  // Own limiter, separate from the chat route's 20/min — see the rationale on
  // DEFAULT_RATE_LIMIT_PER_MIN in config.ts. Note the counter is per-replica
  // (the default store is in-memory), so with replicaCount: 2 the cluster-wide
  // ceiling is roughly double the configured value; it is a runaway-client
  // guard, not a quota.
  router.use(
    rateLimit({
      windowMs: 60 * 1000,
      limit: config.rateLimitPerMin,
      message: { error: "Too many requests" },
    }),
  );

  router.use(requireBearer(config.authToken));

  router.post("/", handleMcpRequest);

  // Everything else — GET (the standalone server-notification stream) and
  // DELETE (session teardown) — is answered 405 without touching the
  // transport.
  //
  // This is not tidiness, it is a leak fix. Handed a GET, the SDK opens an SSE
  // stream and holds it open indefinitely waiting for server-initiated
  // messages. This server has none to send: it declares only the `tools`
  // capability, and stateless mode means nothing survives a request anyway. So
  // each GET would pin a socket plus a Server/transport pair for the life of
  // the client, for traffic that will never arrive. The spec explicitly allows
  // 405 here ("the server MUST either return Content-Type: text/event-stream
  // … or else return HTTP 405"), and the SDK's own client treats 405 on GET
  // and DELETE as "not offered" and moves on rather than erroring.
  router.all("/", (req: Request, res: Response) => {
    res.setHeader("Allow", "POST");
    res.status(405).json({
      jsonrpc: "2.0",
      error: {
        code: -32000,
        message: "Method not allowed: this endpoint is stateless and serves MCP over POST only",
      },
      id: null,
    });
  });

  return router;
}
