/**
 * Configuration for the MCP endpoint served from this process.
 *
 * SIMPLIFICATION-GOAL.md §"MCP server" anticipated this: the 12 tools that
 * used to live in the standalone Go mcp-server now run in-process
 * (src/tools/*), and the same registry is re-exposed over StreamableHTTP
 * from the same Express app for external MCP clients. There is no second
 * deployment and no second listener — just another route on port 8080.
 *
 * The endpoint is OFF by default. It surfaces cluster telemetry (pod
 * traffic, syscalls, audit verdicts) to whatever can reach the Service, so
 * turning it on is a deliberate operator decision, not a default.
 */

/** Path the MCP endpoint is mounted at when enabled. */
export const MCP_PATH = "/mcp";

/**
 * Requests/minute allowed on /mcp. Deliberately far above the chat route's
 * 20/min: that limit is sized for a human typing questions into the UI,
 * whereas one MCP client session is many HTTP round-trips — `initialize`,
 * `tools/list`, then a separate POST per tool call. An agent investigating
 * "why is this flow dropped" walks pods → traffic → verdicts → policy and
 * burns 30-60 calls in seconds, which would trip a 20/min bucket almost
 * immediately. 300/min (~5/s sustained) leaves that headroom while still
 * capping a runaway client. Every tool call is a read against the broker,
 * so the blast radius of the higher ceiling is broker load, not writes.
 */
const DEFAULT_RATE_LIMIT_PER_MIN = 300;

export interface McpConfig {
  /** Whether /mcp is routed at all. When false the path 404s. */
  enabled: boolean;
  /** Shared secret required as `Authorization: Bearer <token>`, or null for no auth. */
  authToken: string | null;
  /** Per-IP request ceiling for the endpoint's own rate limiter. */
  rateLimitPerMin: number;
}

/**
 * Parse the MCP settings out of an env-style map. Pure so it is unit-testable
 * without mutating process.env, mirroring `availableProvidersFromEnv`.
 *
 * Every read is trimmed for the same reason documented in index.ts: a value
 * pasted into a Helm value or a Secret routinely carries a trailing newline,
 * and an untrimmed `"true\n"` would silently leave the endpoint off while the
 * operator believes it is on. Whitespace-only counts as unset throughout —
 * including for the token, so `MCP_AUTH_TOKEN: "   "` disables auth rather
 * than making every request fail an impossible comparison (same rule as the
 * Broker's `AuthConfig::from_env`).
 */
export function mcpConfigFromEnv(env: Record<string, string | undefined>): McpConfig {
  const flag = env.MCP_ENABLED?.trim().toLowerCase();
  const enabled = flag === "true" || flag === "1";

  const token = env.MCP_AUTH_TOKEN?.trim();

  // A non-numeric or non-positive override falls back to the default rather
  // than producing an unlimited (NaN) or instantly-exhausted (0) bucket.
  const parsedLimit = Number.parseInt(env.MCP_RATE_LIMIT_PER_MIN?.trim() || "", 10);
  const rateLimitPerMin =
    Number.isFinite(parsedLimit) && parsedLimit > 0 ? parsedLimit : DEFAULT_RATE_LIMIT_PER_MIN;

  return { enabled, authToken: token || null, rateLimitPerMin };
}
