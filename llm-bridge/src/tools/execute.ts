import { log } from "../logger.js";
import { TOOL_DEFS } from "./registry.js";
import { brokerGetJSON, advisorGetText, auditVerdictsQuery } from "./backendClient.js";
import {
  filterByNamespace, compactTrafficSummary, compactPodsSummary, filterAlivePods, compactSvc,
} from "./compaction.js";
import { seccompFromBrokerSyscalls } from "./generators/seccomp.js";

// In-process tool execution (WS-B). Each of the 12 tools is a fetch from the
// broker or advisor followed by the exact compaction the mcp-server applied
// (tools/*.go handlers). The G1 parity test replays the shared backend
// fixtures through executeInProcessTool and asserts the results match the Go
// server's recorded outputs.

const s = (v: unknown): string => (typeof v === "string" ? v : "");
const enc = encodeURIComponent;

export interface InProcessResult {
  text: string;
  isError: boolean;
}

type Handler = (args: Record<string, unknown>) => Promise<unknown>;

const handlers: Record<string, Handler> = {
  get_pod_network_traffic: (a) => brokerGetJSON(`/pod/traffic/${enc(s(a.pod_name))}`),
  get_pod_syscalls: (a) => brokerGetJSON(`/pod/syscalls/${enc(s(a.pod_name))}`),
  get_pod_details: async (a) => compactPodsSummary(await brokerGetJSON(`/pod/ip/${enc(s(a.ip))}`)),
  get_service_details: async (a) => compactSvc(await brokerGetJSON(`/svc/ip/${enc(s(a.ip))}`)),
  get_cluster_traffic: async (a) => {
    const data = await brokerGetJSON(`/pod/traffic`);
    const summary = compactTrafficSummary(filterByNamespace(data, s(a.namespace)));
    if (s(a.namespace)) (summary as Record<string, unknown>).filtered_namespace = s(a.namespace);
    return summary;
  },
  get_cluster_pods: async (a) => {
    const data = await brokerGetJSON(`/pod/info`);
    return compactPodsSummary(filterAlivePods(filterByNamespace(data, s(a.namespace))));
  },
  get_pod_details_by_name: async (a) => compactPodsSummary(await brokerGetJSON(`/pod/name/${enc(s(a.pod_name))}`)),
  list_services: async (a) => compactSvc(filterByNamespace(await brokerGetJSON(`/svc/info`), s(a.namespace))),
  get_pods_on_node: async (a) => compactPodsSummary(filterAlivePods(await brokerGetJSON(`/pod/list/${enc(s(a.node))}`))),
  get_audit_verdicts: (a) =>
    brokerGetJSON(`/audit/verdicts${auditVerdictsQuery({
      policy: s(a.policy), namespace: s(a.namespace), verdict: s(a.verdict), direction: s(a.direction),
      limit: typeof a.limit === "number" ? a.limit : undefined, cluster_scoped: a.cluster_scoped === true,
    })}`),
  generate_network_policy: async (a) => {
    const type = s(a.policy_type) || "kubernetes";
    return advisorGetText(`/generate/networkpolicy?pod=${enc(s(a.pod_name))}&type=${enc(type)}`);
  },
  // Seccomp is generated in-process from the pod's observed syscalls — no
  // advisor hop (WS-C). Returned as pretty JSON; the profile is G2-locked to
  // the frontend and advisor-CLI generators.
  generate_seccomp_profile: async (a) => {
    const syscalls = await brokerGetJSON(`/pod/syscalls/${enc(s(a.pod_name))}`);
    return JSON.stringify(seccompFromBrokerSyscalls(syscalls), null, 2);
  },
};

const KNOWN = new Set(TOOL_DEFS.map((t) => t.name));

/** Execute a tool in-process. Advisor tools return their raw text body; broker
 *  tools return compacted JSON serialized to a string — matching what the LLM
 *  received from the mcp-server. Errors become an is-error result, not a throw,
 *  so one failing tool never aborts the model's tool round. */
export async function executeInProcessTool(name: string, args: Record<string, unknown>): Promise<InProcessResult> {
  if (!KNOWN.has(name)) {
    return { text: `unknown tool: ${name}`, isError: true };
  }
  try {
    const out = await handlers[name](args ?? {});
    const text = typeof out === "string" ? out : JSON.stringify(out);
    return { text, isError: false };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log.error(`tool ${name} failed:`, msg);
    return { text: `error executing ${name}: ${msg}`, isError: true };
  }
}
