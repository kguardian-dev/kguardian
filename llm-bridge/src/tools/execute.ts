import { log } from "../logger.js";
import { TOOL_DEFS } from "./registry.js";
import { brokerGetJSON, auditVerdictsQuery } from "./backendClient.js";
import {
  filterByNamespace, compactTrafficSummary, compactPodsSummary, filterAlivePods, compactSvc,
} from "./compaction.js";
import { seccompFromBrokerSyscalls } from "./generators/seccomp.js";
import {
  generateNetworkPolicy, generateCiliumPolicy, policyToYAML,
  type PeerResolver, type PeerIdentity, type PodInfo, type TrafficRow,
} from "./generators/networkpolicy.js";

// In-process tool execution — this IS the assistant now. Each of the 12
// tools is a broker fetch + the exact compaction the former mcp-server applied,
// or in-process policy/seccomp generation. The G1 parity test replays the
// shared backend fixtures through executeInProcessTool and asserts broker
// tools match the former Go server's outputs.

const s = (v: unknown): string => (typeof v === "string" ? v : "");
const enc = encodeURIComponent;

// Resolve a peer IP to a policy identity the way the advisor does: service
// selector first (priority 1), then pod labels (priority 2), else null →
// external CIDR. Broker lookups that 404/error resolve to null (external).
const brokerPeerResolver: PeerResolver = async (ip): Promise<PeerIdentity | null> => {
  try {
    const svc = (await brokerGetJSON(`/svc/ip/${enc(ip)}`)) as {
      svc_namespace?: string; service_spec?: { spec?: { selector?: Record<string, string> } };
    };
    const selector = svc?.service_spec?.spec?.selector;
    if (selector && Object.keys(selector).length > 0) {
      return { selector, namespace: svc.svc_namespace };
    }
  } catch { /* not a service — fall through to pod lookup */ }
  try {
    const pod = (await brokerGetJSON(`/pod/ip/${enc(ip)}`)) as {
      pod_namespace?: string; pod_obj?: { metadata?: { labels?: Record<string, string> } };
    };
    const labels = pod?.pod_obj?.metadata?.labels;
    if (labels && Object.keys(labels).length > 0) {
      return { selector: labels, namespace: pod.pod_namespace };
    }
  } catch { /* not a pod — external */ }
  return null;
};

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
  // Network policy is generated in-process from the pod's observed traffic and
  // broker-resolved peer identities — no advisor hop. Byte-semantically
  // identical to the advisor (G2 netpol fixtures lock all paths).
  generate_network_policy: async (a) => {
    const podName = s(a.pod_name);
    const traffic = (await brokerGetJSON(`/pod/traffic/${enc(podName)}`)) as TrafficRow[] & { pod_ip?: string }[];
    if (!Array.isArray(traffic) || traffic.length === 0) {
      throw new Error(`no traffic data found for pod ${podName}`);
    }
    const podIP = (traffic[0] as { pod_ip?: string }).pod_ip ?? "";
    const detail = (await brokerGetJSON(`/pod/ip/${enc(podIP)}`)) as {
      pod_name?: string; pod_namespace?: string; pod_ip?: string;
      pod_obj?: { metadata?: { labels?: Record<string, string> } };
    };
    const pod: PodInfo = {
      name: detail.pod_name ?? podName,
      namespace: detail.pod_namespace ?? "",
      ip: detail.pod_ip ?? podIP,
      labels: detail.pod_obj?.metadata?.labels ?? {},
    };
    const type = s(a.policy_type) || "kubernetes";
    const policy = type === "cilium"
      ? await generateCiliumPolicy(pod, traffic, brokerPeerResolver)
      : await generateNetworkPolicy(pod, traffic, brokerPeerResolver);
    return policyToYAML(policy);
  },
  // Seccomp is generated in-process from the pod's observed syscalls — no
  // advisor hop. Returned as pretty JSON; the profile is G2-locked to
  // the frontend and advisor-CLI generators.
  generate_seccomp_profile: async (a) => {
    const syscalls = await brokerGetJSON(`/pod/syscalls/${enc(s(a.pod_name))}`);
    return JSON.stringify(seccompFromBrokerSyscalls(syscalls), null, 2);
  },
};

const KNOWN = new Set(TOOL_DEFS.map((t) => t.name));

/** Execute a tool in-process. Generation tools return YAML/JSON text; broker
 *  tools return compacted JSON serialized to a string — matching what the LLM
 *  received when tools ran via the former mcp-server. Errors become an
 *  is-error result, not a throw, so one failing tool never aborts the
 *  model's tool round. */
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
