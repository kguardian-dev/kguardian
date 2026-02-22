import type { ToolResult } from "../types/index.js";

const MAX_TOOL_RESULT_CHARS = 50000; // ~12K tokens — keeps total payload under TPM limits

/**
 * Serialize a tool result to a string, truncating large payloads to stay
 * within LLM context/token limits.
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

  // For arrays, return a subset with metadata
  if (Array.isArray(result.data)) {
    const total = result.data.length;
    const subset = result.data.slice(0, 100);
    return JSON.stringify({
      _truncated: true,
      _total: total,
      _showing: subset.length,
      _note: `Result too large (${total} items). Showing first ${subset.length} items. Use pod-specific queries for detailed data.`,
      data: subset,
    });
  }

  return (
    raw.slice(0, MAX_TOOL_RESULT_CHARS) +
    `\n\n[TRUNCATED — result was ${raw.length} characters. Use more specific queries to get detailed data.]`
  );
}
