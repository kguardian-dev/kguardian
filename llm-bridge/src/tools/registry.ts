// Single source of truth for the assistant's tool set. Ported from the
// former mcp-server's tools/all_tools.go toolDefs — names and descriptions must
// stay identical (the G1 parity test pins them against the former Go server's
// goldens). The provider loops build their provider-specific tool schema from
// `parameters`; the system-prompt tool guide is generated from this list, so
// there is now exactly one place a tool is described.

export interface ToolDef {
  name: string;
  description: string;
  // JSON Schema for the tool input, as the LLM providers consume it.
  parameters: {
    type: "object";
    properties: Record<string, { type: string; description: string }>;
    required: string[];
  };
}

const str = (description: string) => ({ type: "string", description });

export const TOOL_DEFS: ToolDef[] = [
  {
    name: "get_pod_network_traffic",
    description:
      "Get network traffic for a specific pod by name. Returns source/destination IPs, ports, protocols, ingress/egress types, and packet decisions. Use when the user asks about a specific pod's connections or traffic. Requires only pod_name (not namespace-scoped — the broker resolves by name cluster-wide).",
    parameters: { type: "object", properties: { pod_name: str("The name of the pod to query traffic for") }, required: ["pod_name"] },
  },
  {
    name: "get_pod_syscalls",
    description:
      "Get system calls made by a specific pod. Returns syscall names, frequencies, and architecture. Use when the user asks about a pod's syscalls, seccomp profile, or suspicious behavior. Requires only pod_name (not namespace-scoped).",
    parameters: { type: "object", properties: { pod_name: str("The name of the pod to query syscalls for") }, required: ["pod_name"] },
  },
  {
    name: "get_pod_details",
    description:
      "Look up a pod by its IP address. Returns pod name, namespace, IP, and full Kubernetes pod object. Use when the user has an IP address and wants to identify which pod it belongs to. Requires only ip.",
    parameters: { type: "object", properties: { ip: str("The IP address of the pod to query") }, required: ["ip"] },
  },
  {
    name: "get_service_details",
    description:
      "Look up a Kubernetes service by its cluster IP. Returns service name, namespace, IP, ports, and full service spec. Use when the user has a service IP and wants to identify the service. Requires only ip.",
    parameters: { type: "object", properties: { ip: str("The IP address of the service to query") }, required: ["ip"] },
  },
  {
    name: "get_cluster_traffic",
    description:
      "Get a summary of network traffic across the cluster. Returns per-pod counts (ingress/egress, allow/drop, unique peers) plus a cluster-wide total_drop_count — not raw records. Dropped flows (decision=DROP) come from the eBPF network-policy-drop probe, so this also answers 'what traffic is being blocked/dropped'. Accepts an optional namespace filter. Use for overall traffic patterns, 'what pods are communicating', or 'where is traffic being dropped'.",
    parameters: { type: "object", properties: { namespace: str("Optional Kubernetes namespace to filter results. If omitted, returns a summary of all namespaces.") }, required: [] },
  },
  {
    name: "get_cluster_pods",
    description:
      "List pods in the cluster with compact metadata (name, namespace, IP, node, status). Heavyweight fields like pod_obj are stripped. Accepts an optional namespace parameter to filter results. Use when the user asks 'what pods are running' or needs a pod inventory.",
    parameters: { type: "object", properties: { namespace: str("Optional Kubernetes namespace to filter results. If omitted, returns pods from all namespaces.") }, required: [] },
  },
  {
    name: "get_pod_details_by_name",
    description:
      "Look up a pod by its name. Returns identity (name, namespace, IP, node, workload selector labels) with the heavyweight pod_obj stripped. Use when the user names a pod (e.g. from a traffic record) and wants its details — prefer this over get_pod_details, which requires an IP.",
    parameters: { type: "object", properties: { pod_name: str("The name of the pod to look up") }, required: ["pod_name"] },
  },
  {
    name: "list_services",
    description:
      "List Kubernetes services in the cluster with compact metadata (name, namespace, cluster IP, selector, ports). Accepts an optional namespace parameter to filter results. Use when the user asks 'what services exist' or needs a service inventory — get_service_details only resolves a single known IP.",
    parameters: { type: "object", properties: { namespace: str("Optional Kubernetes namespace to filter results. If omitted, returns services across all namespaces.") }, required: [] },
  },
  {
    name: "get_pods_on_node",
    description:
      "List the pods recorded on a specific Kubernetes node (compact metadata: name, namespace, IP, node, workload labels; live pods only). Use for blast-radius / 'what runs on node X' / 'which workloads share a node' questions. Requires node.",
    parameters: { type: "object", properties: { node: str("The name of the Kubernetes node to list pods for") }, required: ["node"] },
  },
  {
    name: "get_audit_verdicts",
    description:
      "Get network-policy evaluation verdicts — flows the AuditNetworkPolicy/AuditClusterNetworkPolicy engine evaluated as Allow or WouldDeny. Returns source/destination pod+namespace, port, protocol, direction, the human-readable reason, and observed_at, newest first. All filters optional: policy, namespace (a single namespace; omit to span all, which includes cluster-scoped), cluster_scoped (true = ONLY cluster-scoped verdicts), verdict ('Allow'|'WouldDeny'), direction ('Ingress'|'Egress'), limit (default 100, max 500). Use for security questions like 'what traffic would be denied', 'why is this flow blocked', or 'show recent policy violations'.",
    parameters: {
      type: "object",
      properties: {
        policy: str("Optional policy name to filter by (matches an AuditNetworkPolicy or AuditClusterNetworkPolicy by name)."),
        namespace: str("Optional policy namespace to filter to a single namespace's verdicts. Omit to span all namespaces."),
        cluster_scoped: { type: "boolean", description: "Set true to return ONLY cluster-scoped verdicts. Takes precedence over namespace." },
        verdict: str("Optional verdict filter: 'Allow' or 'WouldDeny'."),
        direction: str("Optional direction filter: 'Ingress' or 'Egress'."),
        limit: { type: "integer", description: "Max verdicts to return (default 100, max 500)." },
      },
      required: [],
    },
  },
  {
    name: "generate_network_policy",
    description:
      "Generate a least-privilege Kubernetes NetworkPolicy (or CiliumNetworkPolicy) for a pod from its observed traffic. Returns ready-to-apply YAML. Parameters: pod_name (required); policy_type ('kubernetes' for a standard NetworkPolicy — the default — or 'cilium'). Use when the user asks to 'generate/create a network policy', 'lock down this pod', or 'restrict traffic for X'. The policy is deterministically synthesised from captured flows, not guessed.",
    parameters: { type: "object", properties: { pod_name: str("The name of the pod to generate a least-privilege network policy for"), policy_type: str("Policy flavour: 'kubernetes' (standard NetworkPolicy, default) or 'cilium' (CiliumNetworkPolicy)") }, required: ["pod_name"] },
  },
  {
    name: "generate_seccomp_profile",
    description:
      "Generate a least-privilege seccomp profile for a pod from its observed syscalls. Returns ready-to-use seccomp JSON (allow-lists the observed syscalls, denies the rest). Parameter: pod_name (required). Use when the user asks to 'generate/create a seccomp profile' or 'restrict syscalls for X'.",
    parameters: { type: "object", properties: { pod_name: str("The name of the pod to generate a seccomp profile for") }, required: ["pod_name"] },
  },
];

/** Build the system-prompt tool guide from the registry — one source of truth. */
export function toolSelectionGuide(): string {
  return TOOL_DEFS.map((t) => `- ${t.name}: ${t.description}`).join("\n");
}
