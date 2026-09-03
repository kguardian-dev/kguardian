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
| `standard_hostnetwork_service_peer`, `cilium_hostnetwork_service_peer` | Prometheus → node-exporter ClusterIP whose backing pods are `host_network: true`, plus a normally-backed db ClusterIP |

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
