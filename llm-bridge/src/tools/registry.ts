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
  // --- compute gauges & noisy-neighbour detection (design: compute-contention-monitoring.md) ---
  {
    name: "get_pod_compute",
    description:
      "Get live compute state for a pod: per-container CPU usage (millicores) vs request/limit, CFS throttling, cgroup PSI pressure, memory working set vs limit, OOM/refault counters, scheduler run-queue latency (p50/p95/p99) and the blame list of cgroups that pre-empted it — plus a 60-minute history summary (avg/max/p99 CPU, throttled ratio, peak pressure) per container. THE tool for 'why is pod X slow', 'is X CPU-starved or throttled', 'is X under memory pressure'. Requires namespace AND pod_name. Follow up with get_compute_findings to see if the broker has raised a finding (noisy-neighbor, cpu-throttled, ...) for it.",
    parameters: {
      type: "object",
      properties: {
        namespace: str("Kubernetes namespace of the pod (required — compute data is namespace-scoped)"),
        pod_name: str("The name of the pod to inspect"),
      },
      required: ["namespace", "pod_name"],
    },
  },
  {
    name: "get_compute_findings",
    description:
      "Get the broker's compute findings: noisy-neighbor (victim starved by a named culprit pod/system unit, with blame share), cpu-contended (starved, no dominant culprit), cpu-throttled (victim hitting its own CPU limit — raise the limit, no culprit), memory-pressure (node memory pressure with a culprit), memory-limit-thrash (victim thrashing under its own memory limit). Each finding carries victim, culprit (or null), evidence and a human-readable message. culprit.blame_share is the culprit's share of the victim's CPU wait for noisy-neighbor, or of the node's memory overage for memory-pressure. Filters optional: namespace (victim's namespace), node; omit both for the whole cluster. The response also carries truncated (true when the broker stopped after its victim budget — narrow by namespace/node), victims_evaluated, and history_disabled (true when compute history retention is off, so an empty findings list means 'not evaluated', not 'all clear'). THE tool for 'who is the noisy neighbour', 'what is starving X', 'which pods are throttled', 'any compute problems in namespace Y'.",
    parameters: {
      type: "object",
      properties: {
        namespace: str("Optional namespace filter (matches the victim's namespace; culprits may live in another namespace)"),
        node: str("Optional node name filter"),
      },
      required: [],
    },
  },
  {
    name: "get_node_contention",
    description:
      "Get raw scheduler contention pairs on a node: which cgroup (culprit pod container, system unit or kernel) pre-empted which victim container, with pre-emption count and total wait time over the window (default 5 minutes). Lower-level than get_compute_findings — use it to rank every bully on a node, check a suspected culprit that has not crossed the finding threshold, or explain the blame behind a noisy-neighbor finding. Requires node; minutes optional.",
    parameters: {
      type: "object",
      properties: {
        node: str("The Kubernetes node to inspect"),
        minutes: { type: "integer", description: "Look-back window in minutes (default 5, max 10080)." },
      },
      required: ["node"],
    },
  },
  // --- workload security profile & image inventory (#1533) -------------------
  // Every description carries the two rules the model must not break:
  // null/unknown is never "safe", and kguardian recommends but never applies.
  {
    name: "get_workload_security_profile",
    description:
      "Get a workload's security profile, computed live by the broker: posture (status ok|warn|risk|unknown derived from findings — there is no numeric score — plus coverage 0-1 = the share of the four core dimensions kguardian has data for, unknownDimensions, and one reason per dimension that is not ok), the top findings (attention) and all findings with severity, controls (NetworkPolicy audit, SeccompProfile CR), readiness checks, observed exposure, and per-dimension detail — podSecurity (Pod Security Standards level with levelConfidence, per-container securityContext and failing checks, and a recommended securityContext patch), network (observed peers, audit verdicts), syscalls (observed set, capture completeness, SeccompProfile CR sync, denials), images (running digests per container), compute (requests/limits). null anywhere means UNKNOWN (no data or not configured) — never treat it as safe, passing, zero or none; readiness ok:null means kguardian can't tell. posture.status ignores unknown dimensions, so always quote coverage and unknownDimensions with it. A podSecurity level of 'restricted' is only an upper bound (checks kguardian cannot see, such as hostPath, hostPort and AppArmor, may still lower it), so podSecurity is 'unknown' rather than 'ok' there; never call a workload PSS-restricted-compliant. kguardian only recommends: the patch and any generated policy are for the user to review and apply; nothing is applied. Requires namespace, kind (case-sensitive: Deployment, StatefulSet, DaemonSet, CronJob, Job, Pod, ...) and name (the workload name, not a pod name). found=false means kguardian has no data for the workload. Use for 'how secure is X', 'what should I fix on X', 'what PSS level does X meet', 'give me a securityContext for X'.",
    parameters: {
      type: "object",
      properties: {
        namespace: str("Namespace of the workload"),
        kind: str("Workload kind, case-sensitive: Deployment, StatefulSet, DaemonSet, CronJob, Job, ReplicaSet or Pod (for a pod with no owner)"),
        name: str("Workload name (e.g. the Deployment name, not a pod name)"),
      },
      required: ["namespace", "kind", "name"],
    },
  },
  {
    name: "list_workload_profiles",
    description:
      "List workloads with their security posture summary from the broker's profile read model: namespace, kind, name, revision, posture (status ok|warn|risk|unknown from findings — there is no numeric score — coverage, unknownDimensions), per-dimension status (podSecurity also its level and levelConfidence) and finding counts by severity. Status 'unknown' or any null means kguardian has no data to judge, never safe or fine; always mention coverage. Rows are refreshed every few minutes (computedAt). kguardian reports and recommends; it applies nothing. Filters optional: namespace, posture ('ok'|'warn'|'risk'|'unknown'), limit (default 25, max 100). truncated=true means more workloads match; narrow the filter. Use for 'which workloads are riskiest', 'posture of namespace X', 'what has no data yet'. Follow up with get_workload_security_profile for detail.",
    parameters: {
      type: "object",
      properties: {
        namespace: str("Optional namespace filter"),
        posture: str("Optional posture status filter: 'ok', 'warn', 'risk' or 'unknown'"),
        limit: { type: "integer", description: "Max workloads to return (default 25, max 100)." },
      },
      required: [],
    },
  },
  {
    name: "diff_workload_profile",
    description:
      "Compare two stored versions (revisions) of a workload's security profile: per dimension (podSecurity, images, syscalls, network) what changed — PSS level and securityContext fields, digests added/removed per container, syscalls added/removed, SeccompProfile CR changes, network rules added/removed. A version is recorded whenever the observed policy-relevant behaviour changes; it is not a record of what was applied. Defaults: to = latest revision, from = the one before it. A null scalar in the diff means unchanged; within a {from,to} pair null means unset or unknown at that revision, never 'safe'. kguardian recommends but never applies. Requires namespace, kind, name; from and to are optional revision numbers (from < to). Use for 'what changed in X since last week', 'why did X's posture drop', 'did the new release add syscalls or egress'.",
    parameters: {
      type: "object",
      properties: {
        namespace: str("Namespace of the workload"),
        kind: str("Workload kind, case-sensitive (Deployment, StatefulSet, DaemonSet, CronJob, Job, Pod, ...)"),
        name: str("Workload name"),
        from: { type: "integer", description: "Optional older revision (default: the revision before `to`)." },
        to: { type: "integer", description: "Optional newer revision (default: the latest)." },
      },
      required: ["namespace", "kind", "name"],
    },
  },
  {
    name: "get_image_inventory",
    description:
      "List the image digests workloads run, from the broker's image inventory: digest, repository, tags, digestKind, firstSeen/lastSeen and runningContainers (containers running it now; 0 = no longer running, which says nothing about safety). A null field is unknown, never safe. Inventory only — it has NO vulnerability, SBOM or signature data, so never describe an image as vulnerable, clean, signed or unsigned from this tool. Filters optional: namespace (images some workload in that namespace runs), repository (exact normalised name, e.g. docker.io/library/nginx), limit (default 25, max 100). truncated=true means more images exist than were returned; narrow by namespace or repository. Use for 'what images run in X', 'which digest of nginx is deployed', 'is image Y still running'. kguardian only reports: it never applies or changes anything.",
    parameters: {
      type: "object",
      properties: {
        namespace: str("Optional namespace: only images some workload in it runs."),
        repository: str("Optional exact normalised repository, e.g. docker.io/library/nginx."),
        limit: { type: "integer", description: "Max images to return (default 25, max 100)." },
      },
      required: [],
    },
  },
];

/** Build the system-prompt tool guide from the registry — one source of truth. */
export function toolSelectionGuide(): string {
  return TOOL_DEFS.map((t) => `- ${t.name}: ${t.description}`).join("\n");
}
