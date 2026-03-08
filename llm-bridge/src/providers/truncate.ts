import type { ToolResult } from "../types/index.js";

const MAX_TOOL_RESULT_CHARS = 50000; // ~12K tokens — keeps total payload under TPM limits
const SAMPLE_SIZE = 50;

/**
 * Serialize a tool result to a string, truncating large payloads to stay
 * within LLM context/token limits. For arrays with namespace data, produces
 * a per-namespace breakdown instead of naive slicing.
 */
export function serializeToolResult(result: ToolResult): string {
  if (result.error) {
    return `Error: ${result.error}`;
  }
  if (!result.data) {
    return "No data returned";
  }

  const raw =
    typeof result.data === "string"
      ? result.data
      : JSON.stringify(result.data);

  if (raw.length <= MAX_TOOL_RESULT_CHARS) {
    return raw;
  }

  // For arrays, produce a smart summary
  if (Array.isArray(result.data)) {
    const total = result.data.length;

    // Check if items have namespace fields for grouped summary
    const hasNamespace = total > 0 && typeof result.data[0] === "object" && result.data[0] !== null &&
      ("pod_namespace" in result.data[0] || "svc_namespace" in result.data[0]);

    if (hasNamespace) {
      const nsCounts: Record<string, number> = {};
      for (const item of result.data) {
        const ns = (item as Record<string, any>).pod_namespace ||
                   (item as Record<string, any>).svc_namespace || "unknown";
        nsCounts[ns] = (nsCounts[ns] || 0) + 1;
      }

      return JSON.stringify({
        _truncated: true,
        _total: total,
        _showing: SAMPLE_SIZE,
        _namespace_breakdown: nsCounts,
        _note: `Result too large (${total} items across ${Object.keys(nsCounts).length} namespaces). Showing first ${SAMPLE_SIZE} items. Use namespace filter or pod-specific queries for detailed data.`,
        _sample: result.data.slice(0, SAMPLE_SIZE),
      });
    }

    // Fallback for non-namespace arrays
    return JSON.stringify({
      _truncated: true,
      _total: total,
      _showing: SAMPLE_SIZE,
      _note: `Result too large (${total} items). Showing first ${SAMPLE_SIZE} items. Use more specific queries for detailed data.`,
      _sample: result.data.slice(0, SAMPLE_SIZE),
    });
  }

  return (
    raw.slice(0, MAX_TOOL_RESULT_CHARS) +
    `\n\n[TRUNCATED — result was ${raw.length} characters. Use more specific queries to get detailed data.]`
  );
}
