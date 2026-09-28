// Streaming event contract (provider -> transport). Transport-agnostic so the
// HTTP layer decides how to serialise (SSE) and every provider stays testable.
export type StreamEvent =
  | { type: "text"; delta: string }
  | { type: "thinking"; delta: string }
  | { type: "tool_use"; name: string; id: string }
  | { type: "tool_result"; name: string; ok: boolean }
  | { type: "done"; model: string }
  | { type: "error"; error: string };

export type Emit = (event: StreamEvent) => void;

/**
 * An Error that carries the upstream provider HTTP status so the transport can
 * map it (429 rate-limit / 529 overload) instead of collapsing everything to a
 * generic 500. `status` is undefined for non-API (network/other) errors.
 */
export interface ProviderError extends Error {
  status?: number;
}
