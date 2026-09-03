import { log } from "../logger.js";
import { TOOL_DEFS } from "./registry.js";
import { brokerGetJSON, auditVerdictsQuery, clusterCni } from "./backendClient.js";
import {
  filterByNamespace, compactTrafficSummary, compactPodsSummary, filterAlivePods, compactSvc,
} from "./compaction.js";
import { seccompFromBrokerSyscalls } from "./generators/seccomp.js";
import {
  generateNetworkPolicyWithComments, generateCiliumPolicyWithComments, policyToYAML, hostNetworkServiceIdentity,
  type PeerResolver, type PeerIdentity, type PodInfo, type TrafficRow, type BrokerPodListEntry,
} from "./generators/networkpolicy.js";

// In-process tool execution — this IS the assistant now. Each of the 12
// tools is a broker fetch + the exact compaction the former mcp-server applied,
// or in-process policy/seccomp generation. The G1 parity test replays the
// shared backend fixtures through executeInProcessTool and asserts broker
// tools match the former Go server's outputs.

const s = (v: unknown): string => (typeof v === "string" ? v : "");
const enc = encodeURIComponent;

// Broker /pod/ip record — the fields the generators read. host_network,
// node_name and workload_name are the flat columns broker-api-v3 added;
// an older broker simply omits them (⇒ pre-existing behaviour).
interface BrokerPodRecord {
  pod_name?: string; pod_namespace?: string; pod_ip?: string;
  host_network?: boolean | null; node_name?: string; workload_name?: string;
  pod_obj?: { metadata?: { labels?: Record<string, string> }; spec?: { nodeName?: string } };
}

// Resolve a peer IP to a policy identity the way the advisor does: service
// selector first (priority 1), then pod labels (priority 2), else null →
// external CIDR. Broker lookups that 404/error resolve to null (external).
// A pod with host_network === true is returned as a host-network identity
// regardless of its labels — the generators render it as the node IP. A
// Service whose alive backing pods (from /pod/info, fetched once per
// generation) are host-network is returned the same way, named by Service.
function makeBrokerPeerResolver(): PeerResolver {
  let podList: Promise<BrokerPodListEntry[]> | null = null;
  const listPods = (): Promise<BrokerPodListEntry[]> => {
    podList ??= brokerGetJSON("/pod/info")
      .then((v) => (Array.isArray(v) ? (v as BrokerPodListEntry[]) : []))
      .catch(() => [] as BrokerPodListEntry[]); // unknown ⇒ pre-existing rendering
    return podList;
  };
  return async (ip): Promise<PeerIdentity | null> => {
    try {
      const svc = (await brokerGetJSON(`/svc/ip/${enc(ip)}`)) as {
        svc_name?: string; svc_namespace?: string; service_spec?: { spec?: { selector?: Record<string, string> } };
      };
      const selector = svc?.service_spec?.spec?.selector;
      if (selector && Object.keys(selector).length > 0) {
        const host = hostNetworkServiceIdentity({ svc_name: svc.svc_name, svc_namespace: svc.svc_namespace, selector }, await listPods());
        return host ?? { selector, namespace: svc.svc_namespace };
      }
    } catch { /* not a service — fall through to pod lookup */ }
    try {
      const pod = (await brokerGetJSON(`/pod/ip/${enc(ip)}`)) as BrokerPodRecord;
      if (pod?.host_network === true) {
        return {
          hostNetwork: true, namespace: pod.pod_namespace, podName: pod.pod_name,
          workload: pod.workload_name, node: pod.node_name || pod.pod_obj?.spec?.nodeName,
        };
      }
      const labels = pod?.pod_obj?.metadata?.labels;
      if (labels && Object.keys(labels).length > 0) {
        return { selector: labels, namespace: pod.pod_namespace };
      }
    } catch { /* not a pod — external */ }
    return null;
  };
}

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
    const detail = (await brokerGetJSON(`/pod/ip/${enc(podIP)}`)) as BrokerPodRecord;
    const pod: PodInfo = {
      name: detail.pod_name ?? podName,
      namespace: detail.pod_namespace ?? "",
      ip: detail.pod_ip ?? podIP,
      labels: detail.pod_obj?.metadata?.labels ?? {},
      hostNetwork: detail.host_network ?? null,
      workload: detail.workload_name,
    };
    const type = s(a.policy_type) || "kubernetes";
    const brokerPeerResolver = makeBrokerPeerResolver();
    const { policy, comments } = type === "cilium"
      ? await generateCiliumPolicyWithComments(pod, traffic, brokerPeerResolver)
      : await generateNetworkPolicyWithComments(pod, traffic, brokerPeerResolver);
    const yaml = policyToYAML(policy, comments);
    // Align with the cluster CNI (issue #1413): never refuse and never
    // silently switch kinds — annotate, so the model (or a scripted
    // caller) sees the mismatch in the result and can self-correct.
    // clusterCni() degrades to "unknown" on any failure, which leaves
    // the output byte-identical to pre-detection behavior (the parity
    // and G2 fixtures pin exactly that).
    if (type === "cilium") {
      const cni = await clusterCni();
      if (cni !== "unknown" && cni !== "cilium") {
        return `# WARNING: cluster CNI detected as '${cni}' — the CiliumNetworkPolicy CRD is likely unavailable here, and only Cilium enforces it. Use policy_type 'kubernetes' for a policy any CNI enforces.
${yaml}`;
      }
    }
    return yaml;
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
