import { log } from "../logger.js";
import { TOOL_DEFS } from "./registry.js";
import { brokerGetJSON, auditVerdictsQuery, clusterPolicySupport, BrokerHTTPError } from "./backendClient.js";
import {
  filterByNamespace, compactTrafficSummary, compactPodsSummary, filterAlivePods, compactSvc,
} from "./compaction.js";
import { seccompFromBrokerSyscalls } from "./generators/seccomp.js";
import { computeQuery, selectPodFromLatest, summariseComputeHistory } from "./compute.js";
import {
  buildQuery, clampToolLimit, trimImagePage, trimProfile, trimProfileDiff, trimProfileList, workloadPath, POSTURE_VALUES,
} from "./posture.js";
import {
  generateNetworkPolicyWithComments, generateCiliumPolicyWithComments, policyToYAML, makePeerResolver,
  type PeerResolver, type PodInfo, type TrafficRow, type BrokerPodListEntry, type BrokerServiceRecord,
} from "./generators/networkpolicy.js";

// In-process tool execution — this IS the assistant now. Each of the original
// 12 tools is a broker fetch + the exact compaction the former mcp-server
// applied, or in-process policy/seccomp generation. The G1 parity test replays
// the shared backend fixtures through executeInProcessTool and asserts broker
// tools match the former Go server's outputs. The three compute tools
// (get_pod_compute, get_compute_findings, get_node_contention) post-date the
// mcp-server and have no golden; they are wiring-checked there and
// unit-tested in compute.test.ts.

const s = (v: unknown): string => (typeof v === "string" ? v : "");
const enc = encodeURIComponent;

/** The (namespace, kind, name) workload key every profile tool needs. */
function workloadArgs(a: Record<string, unknown>, tool: string): { namespace: string; kind: string; name: string } {
  const namespace = s(a.namespace).trim();
  const kind = s(a.kind).trim();
  const name = s(a.name).trim();
  if (!namespace || !kind || !name) throw new Error(`${tool} requires namespace, kind and name`);
  return { namespace, kind, name };
}

// Resolve a traffic row's peer to a policy identity the way the advisor
// does (networkpolicy.ts makePeerResolver, CONTRACT v4): the identity the
// broker stored on the row at ingest when present; otherwise service
// selector first, then the pod candidates holding the IP under the
// start-time guard (started_at later than the row ⇒ not the peer), else
// null → external CIDR. Broker lookups that 404/error resolve to null. The
// /pod/info listing is fetched once per generation.
function makeBrokerPeerResolver(): PeerResolver {
  const getOrNull = async <T,>(path: string): Promise<T | null> => {
    try {
      return (await brokerGetJSON(path)) as T;
    } catch {
      return null; // 404 / error ⇒ not known
    }
  };
  return makePeerResolver({
    serviceByIP: (ip) => getOrNull<BrokerServiceRecord>(`/svc/ip/${enc(ip)}`),
    podByIP: (ip) => getOrNull<BrokerPodListEntry>(`/pod/ip/${enc(ip)}`),
    pods: async () => {
      const v = await brokerGetJSON("/pod/info");
      return Array.isArray(v) ? (v as BrokerPodListEntry[]) : [];
    },
  });
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
    const detail = (await brokerGetJSON(`/pod/ip/${enc(podIP)}`)) as BrokerPodListEntry;
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
    // clusterPolicySupport() degrades to "unknown" on any failure, leaving
    // the output byte-identical to pre-detection behavior (the parity
    // and G2 fixtures pin exactly that).
    const { cni, enforcement } = await clusterPolicySupport();
    const warnings: string[] = [];
    if (type === "cilium" && cni !== "unknown" && cni !== "cilium") {
      warnings.push(
        `# WARNING: cluster CNI detected as '${cni}' — the CiliumNetworkPolicy CRD is likely unavailable here, and only Cilium reads it. A standard Kubernetes NetworkPolicy is the portable kind, but see the enforcement note below before assuming it will take effect.`,
      );
    }
    // The enforcement warning is the one that used to be missing, and
    // its absence let this tool tell an operator to switch to a
    // "policy any CNI enforces" — which does not exist. A NetworkPolicy
    // is enforced only where the CNI enforces policy, and AWS VPC CNI
    // ships with enforcement off, accepting the object and ignoring it.
    if (enforcement === "unenforced") {
      warnings.push(
        `# WARNING: this cluster is NOT enforcing NetworkPolicy (cni '${cni}'). Applying this will succeed and kubectl will show the object, but no traffic will be restricted. On AWS VPC CNI, enable it with --enable-network-policy on the node agent.`,
      );
    } else if (enforcement === "mixed") {
      warnings.push(
        `# WARNING: NetworkPolicy enforcement is inconsistent across nodes in this cluster, so this policy will restrict a pod on one node and not on another depending on where it is scheduled.`,
      );
    }
    return warnings.length > 0 ? `${warnings.join("\n")}\n${yaml}` : yaml;
  },
  // Seccomp is generated in-process from the pod's observed syscalls — no
  // advisor hop. Returned as pretty JSON; the profile is G2-locked to
  // the frontend and advisor-CLI generators.
  generate_seccomp_profile: async (a) => {
    const syscalls = await brokerGetJSON(`/pod/syscalls/${enc(s(a.pod_name))}`);
    return JSON.stringify(seccompFromBrokerSyscalls(syscalls), null, 2);
  },
  // --- compute gauges & noisy-neighbour detection ---------------------------
  // The broker computes findings (design D7); these tools only fetch and,
  // for history, summarise. /compute/latest is namespace-scoped (400
  // without a namespace), so get_pod_compute needs both args.
  get_pod_compute: async (a) => {
    const namespace = s(a.namespace);
    const podName = s(a.pod_name);
    if (!namespace || !podName) throw new Error("get_pod_compute requires both namespace and pod_name");
    const latest = await brokerGetJSON(`/compute/latest${computeQuery({ namespace })}`);
    const pod = selectPodFromLatest(latest, podName);
    if (!pod) {
      return {
        namespace, pod_name: podName, containers: [], node: null, history_60m: [],
        note: "no compute samples for this pod — compute sampling may be disabled (compute.enabled=false or the kguardian.dev/compute=off annotation), the pod may not be running, or the name/namespace may be wrong",
      };
    }
    let history: unknown = [];
    if (pod.pod_uid) {
      const h = (await brokerGetJSON(`/compute/history/${enc(pod.pod_uid)}${computeQuery({ minutes: 60 })}`)) as { rows?: unknown };
      history = h?.rows ?? [];
    }
    return {
      namespace, pod_name: podName, pod_uid: pod.pod_uid,
      node: pod.node,
      containers: pod.containers,
      history_60m: summariseComputeHistory(history),
    };
  },
  get_compute_findings: (a) => brokerGetJSON(`/compute/findings${computeQuery({ namespace: s(a.namespace), node: s(a.node) })}`),
  get_node_contention: (a) => {
    const node = s(a.node);
    if (!node) throw new Error("get_node_contention requires node");
    const minutes = typeof a.minutes === "number" && a.minutes > 0 ? a.minutes : 5;
    return brokerGetJSON(`/compute/contention${computeQuery({ node, minutes })}`);
  },
  // --- workload security profile & image inventory (#1533) -----------------
  // Every call is count-capped (clampToolLimit) before it reaches the broker
  // and size-capped (fitToBudget) before it reaches the model.
  get_workload_security_profile: async (a) => {
    const w = workloadArgs(a, "get_workload_security_profile");
    try {
      return trimProfile(await brokerGetJSON(`${workloadPath(w.namespace, w.kind, w.name)}/profile`));
    } catch (err) {
      if (err instanceof BrokerHTTPError && err.status === 404) {
        return {
          found: false, ...w,
          note: "kguardian has no data for this workload (no inventory, syscalls, live pods or stored profile). That is unknown, not safe. Check the kind and name are the workload's (e.g. the Deployment, not a pod), or that the controller runs on its nodes.",
        };
      }
      throw err;
    }
  },
  list_workload_profiles: async (a) => {
    const namespace = s(a.namespace).trim();
    const posture = s(a.posture).trim().toLowerCase();
    if (posture && !(POSTURE_VALUES as readonly string[]).includes(posture)) {
      throw new Error(`posture must be one of ${POSTURE_VALUES.join(", ")}`);
    }
    const limit = clampToolLimit(a.limit);
    const page = await brokerGetJSON(`/workloads${buildQuery({ namespace, status: posture, limit })}`);
    return trimProfileList(page, { namespace, posture });
  },
  diff_workload_profile: async (a) => {
    const w = workloadArgs(a, "diff_workload_profile");
    const rev = (v: unknown, field: string): number | undefined => {
      if (v === undefined || v === null || v === "") return undefined;
      if (typeof v !== "number" || !Number.isInteger(v) || v < 1) throw new Error(`${field} must be a revision number >= 1`);
      return v;
    };
    const from = rev(a.from, "from");
    const to = rev(a.to, "to");
    if (from !== undefined && to !== undefined && from >= to) throw new Error("from must be older than to (from < to)");
    try {
      return trimProfileDiff(await brokerGetJSON(`${workloadPath(w.namespace, w.kind, w.name)}/profile/diff${buildQuery({ from, to })}`));
    } catch (err) {
      if (err instanceof BrokerHTTPError && err.status === 404) {
        return {
          found: false, ...w, from: from ?? null, to: to ?? null,
          note: "No diff: the workload has no stored profile versions yet, or a requested revision does not exist. Call get_workload_security_profile to see the latest revision.",
        };
      }
      throw err;
    }
  },
  get_image_inventory: async (a) => {
    const namespace = s(a.namespace).trim();
    const repository = s(a.repository).trim();
    const limit = clampToolLimit(a.limit);
    const page = await brokerGetJSON(`/images${buildQuery({ namespace, repository, limit })}`);
    return trimImagePage(page, { namespace, repository });
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
