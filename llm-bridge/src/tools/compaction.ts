// Response compaction — a faithful TypeScript port of the former mcp-server's
// tools/filter.go. The assistant executes the 12 tools in-process; these
// transforms must produce data structurally identical to what filter.go
// produced, which the G1 parity test enforces by replaying the shared
// backend fixtures. Keep this in lockstep with filter.go.

type Rec = Record<string, unknown>;

function isRecord(v: unknown): v is Rec {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Filter a slice of records by a pod_namespace/svc_namespace field. */
export function filterByNamespace(data: unknown, namespace: string): unknown {
  if (!namespace) return data;
  if (!Array.isArray(data)) return data;
  return data.filter((item) => {
    if (!isRecord(item)) return false;
    return item.pod_namespace === namespace || item.svc_namespace === namespace;
  });
}

/** Aggregate traffic records into per-pod summaries (compactTrafficSummary). */
export function compactTrafficSummary(data: unknown): Rec {
  if (!Array.isArray(data)) {
    return { total_records: 0, pods: {} };
  }
  interface Stats { ingress: number; egress: number; allow: number; drop: number; peers: Set<string>; }
  const pods = new Map<string, Stats>();
  let totalDrop = 0;

  for (const item of data) {
    if (!isRecord(item)) continue;
    const podName = typeof item.pod_name === "string" ? item.pod_name : "";
    if (!podName) continue;
    let s = pods.get(podName);
    if (!s) { s = { ingress: 0, egress: 0, allow: 0, drop: 0, peers: new Set() }; pods.set(podName, s); }

    const trafficType = typeof item.traffic_type === "string" ? item.traffic_type.toUpperCase() : "";
    if (trafficType === "INGRESS") s.ingress++;
    else if (trafficType === "EGRESS") s.egress++;

    if (typeof item.traffic_in_out_ip === "string" && item.traffic_in_out_ip) s.peers.add(item.traffic_in_out_ip);

    const decision = typeof item.decision === "string" ? item.decision.toUpperCase() : "";
    if (decision === "DROP") { s.drop++; totalDrop++; }
    else if (decision === "ALLOW") s.allow++;
  }

  const podSummaries: Rec = {};
  for (const [name, s] of pods) {
    podSummaries[name] = {
      ingress_count: s.ingress,
      egress_count: s.egress,
      allow_count: s.allow,
      drop_count: s.drop,
      unique_peer_count: s.peers.size,
    };
  }
  return {
    total_records: data.length,
    pod_count: pods.size,
    total_drop_count: totalDrop,
    pods: podSummaries,
  };
}

const POD_KEEP = new Set([
  "pod_name", "pod_namespace", "pod_ip", "node_name", "is_dead", "pod_identity", "workload_selector_labels",
]);

function compactPodRecord(m: Rec): Rec {
  const slim: Rec = {};
  for (const k of Object.keys(m)) if (POD_KEEP.has(k)) slim[k] = m[k];
  return slim;
}

/** Strip heavyweight fields from a pod record or array of them. */
export function compactPodsSummary(data: unknown): unknown {
  if (isRecord(data)) return compactPodRecord(data);
  if (!Array.isArray(data)) return data;
  return data.map((item) => (isRecord(item) ? compactPodRecord(item) : item));
}

/** Drop pod records with is_dead === true (absent/non-bool treated as alive). */
export function filterAlivePods(data: unknown): unknown {
  if (!Array.isArray(data)) return data;
  return data.filter((item) => !(isRecord(item) && item.is_dead === true));
}

function compactSvcRecord(m: Rec): Rec {
  const keep = new Set(["svc_name", "svc_namespace", "svc_ip", "time_stamp"]);
  const slim: Rec = {};
  for (const k of Object.keys(m)) if (keep.has(k)) slim[k] = m[k];
  const spec = m.service_spec;
  if (isRecord(spec) && isRecord(spec.spec)) {
    if ("selector" in spec.spec) slim.service_selector = spec.spec.selector;
    if ("ports" in spec.spec) slim.service_ports = spec.spec.ports;
  }
  return slim;
}

/** Strip service_spec to selector/ports; single record or array. */
export function compactSvc(data: unknown): unknown {
  if (isRecord(data)) return compactSvcRecord(data);
  if (!Array.isArray(data)) return data;
  return data.map((item) => (isRecord(item) ? compactSvcRecord(item) : item));
}
