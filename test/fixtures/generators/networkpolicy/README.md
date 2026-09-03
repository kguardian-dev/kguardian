# G2 generator golden fixtures — network policy

Language-neutral goldens for the NetworkPolicy / CiliumNetworkPolicy generators.
The advisor Go generators are the reference; each `*.golden.yaml` is their exact
output for one scenario, and the other two implementations must reproduce it:

- advisor Go — `advisor/pkg/network` (`fixture_golden_test.go`; regenerate deliberately
  with `UPDATE_GOLDEN=1 go test ./pkg/network -run FixtureGolden`)
- llm-bridge TS — `llm-bridge/src/tools/generators/networkpolicy.ts`
  (`networkpolicy.fixture.test.ts`)
- frontend TS — `frontend/src/utils/` (fixture tests alongside)

## How to compare

YAML serialisation differs harmlessly between emitters, so the reimplementations
compare the **parsed** policy (deep-equal, key order immaterial), never the bytes.

Some goldens carry `#` comments, which every parser drops. Those are part of the
contract too: also compare the ordered list of comment lines,
`lines.map(trim).filter(startsWith("#"))`, between output and golden. Indentation
and blank lines around comments are not compared.

## Scenarios

Inputs are defined in `fixture_golden_test.go`; the host-network ones are also
spelled out (with the resolver identities and expected YAML) in the generators
handoff so the TS ports can be written from it.

| Golden | Scenario |
|---|---|
| `standard_with_traffic`, `cilium_with_traffic` | one CIDR ingress peer, one CIDR egress peer |
| `standard_default_deny`, `cilium_default_deny` | no traffic |
| `cilium_endpoint_resolved` | peers resolve to a Service selector / pod labels |
| `standard_dualstack`, `cilium_dualstack` | IPv6 pod, mixed-family peers (/128 beside /32) |
| `standard_hostnetwork_egress_peer`, `cilium_hostnetwork_egress_peer` | Prometheus → node-exporter on two nodes (peers are `host_network: true`) + one CIDR peer |
| `standard_hostnetwork_ingress_peer`, `cilium_hostnetwork_ingress_peer` | hostNetwork ingress-nginx and a normal pod both reach web:8080 |
| `standard_hostnetwork_target`, `cilium_hostnetwork_target` | the target pod itself is `host_network: true` |
| `standard_cross_namespace_peer`, `cilium_cross_namespace_peer` | peers (a pod, a Service, ingress + egress) in namespaces other than the target's |
| `standard_hostnetwork_service_peer`, `cilium_hostnetwork_service_peer` | Prometheus → node-exporter ClusterIP whose backing pods are `host_network: true`, plus a normally-backed db ClusterIP |
| `standard_stale_ip_peer`, `cilium_stale_ip_peer` | legacy rows (no `peer_*`) from an IP whose only known holder started AFTER the flows ⇒ unattributed ipBlock/CIDR + comment, never that pod's selector |
| `standard_stored_peer_identity`, `cilium_stored_peer_identity` | rows carry `peer_kind` pod / service / node; the pod IP is NOW held by another pod ⇒ the stored identity wins |

## Peer attribution (stored identity + start-time guard)

Pod IPs are recycled, so resolving a row's peer IP against today's pod table
names whoever holds the IP now. Every row is attributed on its own and rules are
grouped by `(peer IP, identity)`:

- `peer_kind` set (broker resolved the peer at ingest): used verbatim. `pod`/`node`
  are looked up in `/pod/info` by namespace + name (+ uid when both sides have
  one); `service` must still be the Service `/svc/ip` returns. An identity that
  no longer exists is **unattributed** — the IP is never re-resolved.
- `peer_kind` null: `/svc/ip` first; else every pod record holding the IP is a
  candidate, but only one with a KNOWN `started_at` that is not after the row
  `time_stamp` qualifies — a NULL `started_at` is a ghost or Pending row and is
  never chosen (every live pod has a start within a minute of the broker
  upgrade). Alive first, then newest `started_at`, then newest record.
  Candidates existed but none qualified ⇒ **unattributed**; none at all ⇒ plain
  CIDR as before. A row with no `time_stamp` (bare-IP callers) has nothing to
  compare and keeps the pre-v4 by-IP behaviour.
- **Unattributed** renders as `ipBlock` / `fromCIDR`/`toCIDR` of the observed IP
  with the comment `# unattributed peer <ip> at <time>` (`<time>` = the newest row
  `time_stamp` in the group, verbatim; omitted with " at" when none parses).

Sibling rules for one IP are ordered by identity key (`cidr`, `unattributed`,
`host:<ns>/<who>`, `sel:<ns>:k=v,...`); with one identity per IP the order is
the pre-existing IP order. Full algorithm and inputs: the v4 generators handoff.

## Cross-namespace peers

A CiliumNetworkPolicy endpoint selector with no namespace label is scoped to
the policy's own namespace, so a peer in another namespace rendered from its
labels alone matches nothing (the flow is denied). Whenever the resolved peer's
namespace (pod, Service, or backing pod) differs from the target's, the Cilium
`from/toEndpoints` selector carries `k8s:io.kubernetes.pod.namespace: <peer ns>`
beside the `k8s:`-prefixed labels. Same-namespace peers are unchanged
(`cilium_endpoint_resolved` is same-namespace and untouched); an unknown peer
namespace is left as before and logged. The NetworkPolicy generator already
emitted the `namespaceSelector` for every resolved peer.

## Host-network rendering

A pod with `spec.hostNetwork: true` shares the node IP, so a `podSelector` /
`endpointSelector` built from its labels never matches its traffic. When the
broker's `/pod/ip` record says `host_network: true` (checked before labels;
`false`/`null` ⇒ unchanged behaviour):

- **NetworkPolicy**: `ipBlock` of the observed IP (`/32`, `/128` for IPv6), no
  namespaceSelector, ports kept; comment above the rule
  `# host-network peer <ns>/<workload-or-pod> on node <node> — podSelector cannot match host traffic`.
- **Cilium**: `fromEntities`/`toEntities: [host, remote-node]` + `toPorts`. One
  entities rule per distinct port list — later peers with the same ports only add
  their comment line to it. Comment wording says `endpointSelector`.
- **Target is host-network**: body unchanged, three `# WARNING:` header lines
  pointing at CiliumClusterwideNetworkPolicy + nodeSelector.
- **Service backed by host-network pods**: after `/svc/ip` resolves a selector,
  the alive pods from `/pod/info` in the Service's namespace whose labels contain
  the selector are inspected; if any is `host_network: true` the Service is a
  host-network peer. NetworkPolicy is evaluated post-DNAT, so the rule carries
  one `ipBlock` per distinct backend pod IP (= node IP), sorted — never the
  ClusterIP — with the ports on the rule; Cilium emits the usual entities rule.
  Comment (once, above the rule) names the Service `<ns>/svc/<name>`; `<node>` is
  the sorted, deduplicated `node_name` list of those pods (`worker-1,worker-2`),
  falling back to the observed IP. No broker field is involved.

`<workload-or-pod>` is `workload_name` falling back to `pod_name`; `<node>` is
`node_name`, then `pod_obj.spec.nodeName`, then the peer IP.
