import { test } from "node:test";
import assert from "node:assert/strict";
import { generateNetworkPolicy, generateCiliumPolicy, type PeerResolver, type PodInfo } from "./networkpolicy.js";

// Peer CIDR behavior, exercised through the public generators because peerCIDR
// is module-private. This file guards llm-bridge's OWN copy of the address
// parser: frontend/src/utils/ipCidr.ts holds a logically identical one, and the
// two packages cannot share a module, so nothing but a test on each side catches
// one copy drifting from the other.
//
// The contract is the advisor's Go reference, common.HostCIDR (net.ParseIP ->
// To4 -> String): family-dependent mask, RFC 5952 canonical text, and an error
// (here, null -> drop the rule) for anything unparseable.

const pod: PodInfo = { name: "web", namespace: "prod", ip: "10.0.0.1", labels: { app: "web" } };
const noResolve: PeerResolver = async () => null;

const egressTo = (...ips: string[]) =>
  ips.map((ip) => ({ traffic_type: "EGRESS", traffic_in_out_ip: ip, traffic_in_out_port: "5432", ip_protocol: "TCP" }));

const standardCIDRs = async (ip: string): Promise<string[]> => {
  const policy = await generateNetworkPolicy(pod, egressTo(ip), noResolve) as any;
  return (policy.spec.egress ?? []).map((r: any) => r.to[0].ipBlock.cidr);
};

test("peer CIDR: host mask follows the address family", async () => {
  assert.deepEqual(await standardCIDRs("10.96.0.10"), ["10.96.0.10/32"]);
  assert.deepEqual(await standardCIDRs("fd00:96::a"), ["fd00:96::a/128"]);
});

test("peer CIDR: the emitted address is canonicalized, not passed through", async () => {
  // Uppercase hex, an uncompressed zero run, and leading zeros all normalize to
  // the same canonical text the Controller and Broker already emit.
  assert.deepEqual(await standardCIDRs("FD00::7"), ["fd00::7/128"]);
  assert.deepEqual(await standardCIDRs("fd00:0:0:0:0:0:0:7"), ["fd00::7/128"]);
  assert.deepEqual(await standardCIDRs("fd00:0000::0007"), ["fd00::7/128"]);
  assert.deepEqual(await standardCIDRs("2001:0db8:0000:0000:0000:ff00:0042:8329"), ["2001:db8::ff00:42:8329/128"]);
  // Leftmost of two equal-length zero runs is the one compressed.
  assert.deepEqual(await standardCIDRs("1:0:0:2:0:0:3:4"), ["1::2:0:0:3:4/128"]);
});

test("peer CIDR: IPv4-mapped addresses unwrap to a dotted-quad /32", async () => {
  assert.deepEqual(await standardCIDRs("::ffff:10.0.0.1"), ["10.0.0.1/32"]);
  assert.deepEqual(await standardCIDRs("::ffff:0a00:0001"), ["10.0.0.1/32"]);
  // IPv4-compatible (no ffff marker) is not unwrapped and keeps its /128.
  assert.deepEqual(await standardCIDRs("::10.0.0.1"), ["::a00:1/128"]);
});

test("standard policy: an unparseable peer drops its rule, not the whole policy", async () => {
  // A malformed ipBlock makes kube-apiserver reject the entire policy, so the
  // bad peer is dropped and the good one still gets its rule.
  const policy = await generateNetworkPolicy(
    pod,
    [...egressTo("fd00::xyz"), ...egressTo("10.96.0.10")],
    noResolve,
  ) as any;
  assert.deepEqual(policy.spec.egress.map((r: any) => r.to[0].ipBlock.cidr), ["10.96.0.10/32"]);
});

test("standard policy: a direction stays default-denied when every peer drops out", async () => {
  // policyTypes still names Egress - the direction WAS observed - but the empty
  // rule list is omitted, matching the advisor's omitempty serialization.
  const policy = await generateNetworkPolicy(pod, egressTo("fe80::1%eth0"), noResolve) as any;
  assert.deepEqual(policy.spec.policyTypes, ["Egress"]);
  assert.equal(policy.spec.egress, undefined);
});

test("cilium policy: an unparseable peer drops the rule rather than widening it", async () => {
  // A Cilium rule carrying neither toEndpoints nor toCIDR selects ALL peers, so
  // dropping is the only safe response - emitting the rule would fail open.
  const policy = await generateCiliumPolicy(pod, egressTo("fd00::xyz"), noResolve) as any;
  assert.equal(policy.spec.egress, undefined);
});

test("cilium policy: canonical CIDR peers", async () => {
  const policy = await generateCiliumPolicy(pod, egressTo("FD00:0000::0007"), noResolve) as any;
  assert.deepEqual(policy.spec.egress[0].toCIDR, ["fd00::7/128"]);
});

// Peer ORDER is part of the golden contract and is not something the committed
// goldens can police on their own: their inputs are already canonical and each
// direction has at most one IPv6 peer, so both a correct and an incorrect
// comparator produce the same file. These two cases cover what the goldens
// cannot.

test("peer order: sorted on the RAW observed string, canonicalized only at emit", async () => {
  // Sorting after canonicalization would move this peer: raw "FD00::7" sorts
  // after "10.96.0.10" on 'F' (0x46) vs '1' (0x31), and so does canonical
  // "fd00::7" on 'f' (0x66) — but the two disagree for other inputs, and the
  // advisor sorts raw. The emitted text is canonical either way.
  const policy = await generateNetworkPolicy(pod, egressTo("FD00::7", "10.96.0.10"), noResolve) as any;
  assert.deepEqual(
    policy.spec.egress.map((r: any) => r.to[0].ipBlock.cidr),
    ["10.96.0.10/32", "fd00::7/128"],
  );
});

test("peer order: bytewise, matching Go's sort.Strings, not locale collation", async () => {
  // Regression guard for a real divergence, on entirely canonical lowercase
  // input. Bytewise, "fd00:96::a" precedes "fd00::7" because '9' (0x39) < ':'
  // (0x3a). localeCompare treats ':' as ignorable punctuation and yields the
  // reverse — silently desyncing rule order from the advisor's goldens.
  const policy = await generateCiliumPolicy(
    pod, egressTo("fd00:96::a", "10.96.0.10", "fd00::7"), noResolve,
  ) as any;
  assert.deepEqual(
    policy.spec.egress.map((r: any) => r.toCIDR[0]),
    ["10.96.0.10/32", "fd00:96::a/128", "fd00::7/128"],
  );
});
