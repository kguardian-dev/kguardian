import { log } from "../logger.js";

// Direct HTTP clients to the broker and advisor. WS-B: the assistant reaches
// the data plane in-process instead of proxying through the mcp-server, so
// these replace the MCP transport hop. Same endpoints, same optional broker
// bearer token as the mcp-server used.

const BROKER_TIMEOUT_MS = 90_000; // cluster-wide queries can be large
const ADVISOR_TIMEOUT_MS = 60_000;

function trimSlash(u: string): string {
  return u.trim().replace(/\/+$/, "");
}

export function brokerURL(): string {
  return trimSlash(process.env.BROKER_URL?.trim() || "http://kguardian-broker.kguardian.svc.cluster.local:9090");
}

export function advisorURL(): string {
  return trimSlash(process.env.ADVISOR_URL?.trim() || "http://kguardian-advisor.kguardian.svc.cluster.local:8083");
}

function brokerAuthHeaders(): Record<string, string> {
  const token = process.env.BROKER_AUTH_TOKEN?.trim();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function getWithTimeout(url: string, timeoutMs: number, headers: Record<string, string>, accept: string): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { headers: { Accept: accept, ...headers }, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

/** GET a broker endpoint and parse JSON. Throws on non-2xx or abort. */
export async function brokerGetJSON(path: string): Promise<unknown> {
  const url = `${brokerURL()}${path}`;
  const resp = await getWithTimeout(url, BROKER_TIMEOUT_MS, brokerAuthHeaders(), "application/json");
  if (!resp.ok) {
    log.error(`broker GET ${path} -> ${resp.status}`);
    throw new Error(`broker returned ${resp.status} for ${path}`);
  }
  return resp.json();
}

/** GET an advisor generate endpoint and return the raw text body (YAML/JSON). */
export async function advisorGetText(path: string): Promise<string> {
  const url = `${advisorURL()}${path}`;
  const resp = await getWithTimeout(url, ADVISOR_TIMEOUT_MS, {}, "text/plain, application/json, application/yaml");
  if (!resp.ok) {
    log.error(`advisor GET ${path} -> ${resp.status}`);
    throw new Error(`advisor returned ${resp.status} for ${path}`);
  }
  return resp.text();
}

/** Build the /audit/verdicts query string, mirroring the mcp-server's three
 *  namespace modes (cluster-scoped = empty value present; single ns; or absent). */
export function auditVerdictsQuery(args: {
  policy?: string; namespace?: string; verdict?: string; direction?: string; limit?: number; cluster_scoped?: boolean;
}): string {
  const q = new URLSearchParams();
  if (args.policy) q.set("policy", args.policy);
  if (args.cluster_scoped) q.set("namespace", "");
  else if (args.namespace) q.set("namespace", args.namespace);
  if (args.verdict) q.set("verdict", args.verdict);
  if (args.direction) q.set("direction", args.direction);
  if (typeof args.limit === "number" && args.limit > 0) q.set("limit", String(args.limit));
  const s = q.toString();
  return s ? `?${s}` : "";
}
