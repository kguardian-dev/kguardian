import { log } from "../logger.js";

// Direct HTTP client to the broker. the assistant reaches the data
// plane in-process instead of proxying through the mcp-server, so this
// replaces the MCP transport hop. Same endpoints, same optional broker
// bearer token as the mcp-server used.

const BROKER_TIMEOUT_MS = 90_000; // cluster-wide queries can be large

function trimSlash(u: string): string {
  return u.trim().replace(/\/+$/, "");
}

export function brokerURL(): string {
  return trimSlash(process.env.BROKER_URL?.trim() || "http://kguardian-broker.kguardian.svc.cluster.local:9090");
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

/** A non-2xx broker answer. `status` lets a tool tell "no data" (404)
 *  from a failure; the message is unchanged from the plain Error it replaced. */
export class BrokerHTTPError extends Error {
  constructor(public readonly status: number, public readonly path: string) {
    super(`broker returned ${status} for ${path}`);
    this.name = "BrokerHTTPError";
  }
}

/** GET a broker endpoint and parse JSON. Throws on non-2xx or abort. */
export async function brokerGetJSON(path: string): Promise<unknown> {
  const url = `${brokerURL()}${path}`;
  const resp = await getWithTimeout(url, BROKER_TIMEOUT_MS, brokerAuthHeaders(), "application/json");
  if (!resp.ok) {
    log.error(`broker GET ${path} -> ${resp.status}`);
    throw new BrokerHTTPError(resp.status, path);
  }
  return resp.json();
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

// --- cluster environment -------------------------------------------

/**
 * The cluster's detected CNI and whether it enforces NetworkPolicy,
 * from GET /cluster/environment, cached (success ~5min, failure ~60s).
 * Every failure — older broker 404, timeout, junk — resolves to
 * "unknown", which callers MUST treat as "no signal, behave as
 * before". Never throws.
 *
 * The two fields answer different questions and both matter. Which CNI
 * decides whether a CiliumNetworkPolicy is even readable here;
 * enforcement decides whether ANY policy does something. AWS VPC CNI
 * supports NetworkPolicy only when explicitly enabled and ships with it
 * off, in which case it accepts the object and silently ignores it, so
 * "the CNI is X" has never been enough to tell an operator their policy
 * will take effect.
 */
const CNI_TTL_OK_MS = 5 * 60_000;
const CNI_TTL_ERR_MS = 60_000;

export interface ClusterPolicySupport {
  cni: string;
  /** 'enforced' | 'unenforced' | 'mixed' | 'unknown' */
  enforcement: string;
}

let cniCache: { value: ClusterPolicySupport; expires: number } | null = null;

export async function clusterPolicySupport(): Promise<ClusterPolicySupport> {
  const now = Date.now();
  if (cniCache && now < cniCache.expires) return cniCache.value;
  const str = (v: unknown) => (typeof v === "string" && v.length > 0 ? v : "unknown");
  try {
    const env = (await brokerGetJSON("/cluster/environment")) as {
      cni?: unknown;
      policy_enforcement?: unknown;
    };
    cniCache = {
      value: { cni: str(env.cni), enforcement: str(env.policy_enforcement) },
      expires: now + CNI_TTL_OK_MS,
    };
  } catch {
    cniCache = {
      value: { cni: "unknown", enforcement: "unknown" },
      expires: now + CNI_TTL_ERR_MS,
    };
  }
  return cniCache.value;
}


/** Test hook: clear the CNI cache. */
export function resetClusterCniCache(): void {
  cniCache = null;
}
