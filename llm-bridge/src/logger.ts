/**
 * Minimal level-aware logger for llm-bridge.
 *
 * The codebase previously used `console.log` everywhere — unfiltered,
 * unconditional, dumped to stdout. For per-request and per-tool-call
 * hot paths (the `MCP tool X returned: <full JSON body>` style line
 * being the worst offender), that's both noisy at INFO and slow when
 * the result is multi-KB. This module gates the noisy paths behind a
 * LOG_LEVEL env var so steady-state operators see only the
 * lifecycle / outcome lines.
 *
 * Levels (case-insensitive): "trace" < "debug" < "info" < "warn" < "error".
 * Default is "info". Anything below the configured level is dropped.
 *
 * Kept tiny on purpose — picking up pino or winston for four call
 * sites is overkill, and a dependency-free helper is also more
 * testable.
 */

export type Level = "trace" | "debug" | "info" | "warn" | "error";

const ORDER: Record<Level, number> = {
  trace: 10,
  debug: 20,
  info: 30,
  warn: 40,
  error: 50,
};

/**
 * Resolve the active log level from an env-style string. Trims +
 * lower-cases; unknown values fall back to `info` (same forgiving
 * pattern as the broker / controller env-trim defenses).
 */
export function resolveLevel(raw: string | undefined): Level {
  const v = raw?.trim().toLowerCase();
  if (v === "trace" || v === "debug" || v === "info" || v === "warn" || v === "error") {
    return v;
  }
  return "info";
}

const ACTIVE: Level = resolveLevel(process.env.LOG_LEVEL);
const ACTIVE_RANK = ORDER[ACTIVE];

function emit(level: Level, args: unknown[]): void {
  if (ORDER[level] < ACTIVE_RANK) return;
  // Write to stdout for trace/debug/info (matches console.log) and
  // stderr for warn/error (matches conventional logger output).
  const stream = level === "warn" || level === "error" ? console.error : console.log;
  stream(`[${level}]`, ...args);
}

export const log = {
  trace: (...args: unknown[]) => emit("trace", args),
  debug: (...args: unknown[]) => emit("debug", args),
  info: (...args: unknown[]) => emit("info", args),
  warn: (...args: unknown[]) => emit("warn", args),
  error: (...args: unknown[]) => emit("error", args),
};
