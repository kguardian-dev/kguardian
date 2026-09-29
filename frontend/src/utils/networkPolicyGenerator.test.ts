import { describe, it, expect, vi } from 'vitest';

// resolveTrafficIdentity reaches the broker; stub it so an unresolvable peer
// falls through to the CIDR path, which is the branch under test.
vi.mock('../services/api', () => ({
  apiClient: {
    getServiceByIP: vi.fn().mockResolvedValue(null),
    getPodDetailsByIP: vi.fn().mockResolvedValue(null),
  },
}));

import { parse } from 'yaml';
import { generateNetworkPolicy, invalidPolicyCidrs, invalidPolicyPorts, isValidPolicyPort, policyToYAML, quoteYamlValue, ruleHasPeers } from './networkPolicyGenerator';
import { generateCiliumNetworkPolicy, ciliumPolicyToYAML, ciliumRuleHasPeers, invalidCiliumCidrs, invalidCiliumPorts } from './ciliumPolicyGenerator';
import type { NetworkPolicy, NetworkPolicyRule } from '../types/networkPolicy';
import type { CiliumEgressRule, CiliumIngressRule, CiliumNetworkPolicy } from '../types/ciliumPolicy';

// An observed direction whose every peer is unparseable must stay DENIED, not
// become unrestricted.
//
// Dropping unparseable peers is correct on its own — a malformed ipBlock makes
// kube-apiserver reject the whole policy, so one bad row would cost every
// legitimate rule. But the rule list and the policyType are different
// questions. `policyTypes: []` does not mean "deny", it means the policy stops
// governing that direction at all, so gating the type on the surviving rule
// list turns a dropped peer into an ALLOW. The type must therefore key off the
// direction being observed. Both reference generators (advisor
// standard_policy.go, llm-bridge networkpolicy.ts) do exactly this.
//
// Reaching it takes one row: peer IPs come from traffic_in_out_ip unvalidated.

const podWith = (traffic: unknown[]) =>
  ({
    pod: {
      pod_name: 'web',
      pod_namespace: 'prod',
      pod_ip: '10.0.0.1',
      pod_obj: { metadata: { labels: { app: 'web' } } },
    },
    traffic,
  }) as never;

const badIngress = [
  { traffic_type: 'INGRESS', pod_port: '8080', traffic_in_out_ip: 'not-an-ip', ip_protocol: 'TCP' },
];
const badEgress = [
  { traffic_type: 'EGRESS', traffic_in_out_port: '5432', traffic_in_out_ip: 'not-an-ip', ip_protocol: 'TCP' },
];

describe('generateNetworkPolicy — unparseable peers must not open a direction', () => {
  it('keeps the Ingress policyType when every ingress peer is dropped', async () => {
    const policy = await generateNetworkPolicy(podWith(badIngress));
    expect(policy.spec.policyTypes).toContain('Ingress');
    // No rules survived, and an absent ingress key alongside the policyType is
    // the canonical default-deny form.
    expect(policy.spec.ingress ?? []).toEqual([]);
  });

  it('keeps the Egress policyType when every egress peer is dropped', async () => {
    const policy = await generateNetworkPolicy(podWith(badEgress));
    expect(policy.spec.policyTypes).toContain('Egress');
    expect(policy.spec.egress ?? []).toEqual([]);
  });

  it('still emits a rule for a parseable peer', async () => {
    const policy = await generateNetworkPolicy(
      podWith([
        { traffic_type: 'INGRESS', pod_port: '8080', traffic_in_out_ip: 'fd00::7', ip_protocol: 'TCP' },
      ]),
    );
    expect(policy.spec.policyTypes).toContain('Ingress');
    expect(policy.spec.ingress?.[0]?.peers?.[0]).toEqual({ ipBlock: { cidr: 'fd00::7/128' } });
  });

  it('does not claim a direction that was never observed', async () => {
    const policy = await generateNetworkPolicy(podWith(badIngress));
    expect(policy.spec.policyTypes).not.toContain('Egress');
  });
});

describe('generateCiliumPolicy — unparseable peers must not disable defaultDeny', () => {
  it('keeps defaultDeny.ingress when every ingress peer is dropped', async () => {
    const policy = await generateCiliumNetworkPolicy(podWith(badIngress));
    // false here would turn "deny everything not listed" into "restrict
    // nothing" for a pod that demonstrably received traffic.
    expect(policy.spec.defaultDeny.ingress).toBe(true);
    expect(policy.spec.ingress ?? []).toEqual([]);
  });

  it('keeps defaultDeny.egress when every egress peer is dropped', async () => {
    const policy = await generateCiliumNetworkPolicy(podWith(badEgress));
    expect(policy.spec.defaultDeny.egress).toBe(true);
    expect(policy.spec.egress ?? []).toEqual([]);
    // Cilium's CRD needs an ingress or egress section, so the denied,
    // rule-less direction is written as one empty rule; the other is absent.
    const yaml = ciliumPolicyToYAML(policy);
    expect(yaml).toContain('  egress:\n  - {}');
    expect(yaml).not.toContain('\n  ingress:');
  });

  it('leaves an unobserved direction undefended rather than inventing a rule', async () => {
    const policy = await generateCiliumNetworkPolicy(podWith(badIngress));
    expect(policy.spec.defaultDeny.egress).toBe(false);
  });
});

// quoteYamlValue used to test only for unsafe PUNCTUATION, which misses
// every value YAML reinterprets because of what it resolves to. kubectl
// converts YAML to JSON through a YAML 1.1 parser and matchLabels is
// map[string]string, so an unquoted `version: 2` is rejected at apply
// time with a type error. All the values below are legal Kubernetes
// label values.
describe('quoteYamlValue — values YAML 1.1 resolves to a non-string', () => {
  it.each([
    ['123', 'plain integer'],
    ['0', 'zero'],
    ['007', 'leading-zero octal'],
    ['0x1f', 'hex'],
    ['0b1010', 'binary'],
    ['1.2', 'float'],
    ['1e5', 'exponent'],
    ['-1', 'negative'],
    ['1:30', 'sexagesimal'],
    ['true', 'boolean'],
    ['false', 'boolean'],
    ['yes', 'YAML 1.1 boolean'],
    ['no', 'YAML 1.1 boolean'],
    ['on', 'YAML 1.1 boolean'],
    ['off', 'YAML 1.1 boolean'],
    ['null', 'null'],
    ['Null', 'null, capitalised'],
    ['~', 'null shorthand'],
    ['', 'empty string'],
  ])('quotes %s (%s)', (value) => {
    expect(quoteYamlValue(value)).toBe(`"${value}"`);
  });

  // The fix must only ever TIGHTEN quoting. These were emitted plain
  // before and must stay plain, or every golden fixture churns for a
  // cosmetic reason.
  it.each([
    ['web'],
    ['networking.k8s.io/v1'],
    ['app.kubernetes.io/name'],
    ['10.0.0.20/32'],
    ['v1.2.3'],
    ['2001:db8::1/128'.replace(/:/g, 'x')], // colons are punctuation-quoted; shape only
  ])('leaves %s unquoted', (value) => {
    expect(quoteYamlValue(value)).toBe(value);
  });

  // Punctuation-quoting is retained, so hyphenated names keep their
  // existing quoted form.
  it('still quotes hyphenated names as before', () => {
    expect(quoteYamlValue('deployment-web')).toBe('"deployment-web"');
  });

  it('escapes backslashes before quotes', () => {
    expect(quoteYamlValue('a"b')).toBe('"a\\"b"');
    expect(quoteYamlValue('a\\b')).toBe('"a\\\\b"');
  });
});

// Label KEYS go through the same helper as values (the emitter writes
// `${quoteYamlValue(key)}: ${quoteYamlValue(value)}`), and `2: web` fails
// at apply time exactly as `version: 2` does. Nothing pinned that, so a
// future change that quoted only the value side would pass every other
// test in this file.
describe('quoteYamlValue — keys need the same treatment as values', () => {
  it.each([['123'], ['true'], ['no'], ['1.2'], ['null']])(
    'quotes %s used as a label key',
    (key) => {
      expect(quoteYamlValue(key)).toBe(`"${key}"`);
    },
  );

  it('leaves an ordinary label key unquoted', () => {
    expect(quoteYamlValue('app.kubernetes.io/name')).toBe('app.kubernetes.io/name');
  });
});

// What the editor can hand the renderers. An empty `from` / `to` (standard)
// or a Cilium rule with no from*/to* selector matches EVERY peer, so a rule
// the editor shows with no sources must not reach the YAML as one: the user
// clicks "Add Rule", or deletes the last source of a generated rule, and the
// export used to read `- from:` (allow all ingress, on all ports).
describe('policyToYAML / ciliumPolicyToYAML — a rule with no peers is left out, never allow-all', () => {
  const standard = (ingress: NetworkPolicyRule[], egress?: NetworkPolicyRule[]): NetworkPolicy => ({
    apiVersion: 'networking.k8s.io/v1', kind: 'NetworkPolicy', metadata: { name: 'web-policy', namespace: 'prod' },
    spec: { podSelector: { matchLabels: { app: 'web' } }, policyTypes: egress ? ['Ingress', 'Egress'] : ['Ingress'], ingress, ...(egress && { egress }) },
  });
  const peerless = (id: string, ports: NetworkPolicyRule['ports'] = []): NetworkPolicyRule => ({ id, peers: [], ports });
  const fromApi: NetworkPolicyRule = { id: 'r1', peers: [{ podSelector: { matchLabels: { app: 'api' } } }], ports: [{ protocol: 'TCP', port: 8080 }] };

  it('drops the peerless rule and keeps the others', () => {
    const doc = parse(policyToYAML(standard([fromApi, peerless('r2', [{ protocol: 'TCP', port: 22 }])])));
    expect(doc.spec.ingress).toEqual([{ from: [{ podSelector: { matchLabels: { app: 'api' } } }], ports: [{ protocol: 'TCP', port: 8080 }] }]);
  });

  it('a direction left with only peerless rules keeps its policyType and no rules: deny, not allow-all', () => {
    const yaml = policyToYAML(standard([peerless('r1')], [peerless('r2', [{ protocol: 'UDP', port: 53 }])]));
    const doc = parse(yaml);
    expect(doc.spec.policyTypes).toEqual(['Ingress', 'Egress']);
    expect(doc.spec.ingress).toBeUndefined();
    expect(doc.spec.egress).toBeUndefined();
    expect(yaml).not.toContain('- from:');
    expect(yaml).not.toContain('- to:');
  });

  it('ruleHasPeers is the test the renderer applies', () => {
    expect(ruleHasPeers(fromApi)).toBe(true);
    expect(ruleHasPeers(peerless('r'))).toBe(false);
  });

  const cilium = (ingress: CiliumIngressRule[], egress: CiliumEgressRule[], defaultDeny = { ingress: true, egress: true }): CiliumNetworkPolicy => ({
    apiVersion: 'cilium.io/v2', kind: 'CiliumNetworkPolicy', metadata: { name: 'web-cilium-policy', namespace: 'prod' },
    spec: { endpointSelector: { matchLabels: { app: 'web' } }, defaultDeny, ingress, egress },
  });
  const ports = (port: string, protocol = 'TCP') => [{ ports: [{ port, protocol }] }];

  it('cilium: a rule with ports but no endpoint, CIDR or entity (L4-only, open to every peer) is left out', () => {
    const doc = parse(ciliumPolicyToYAML(cilium(
      [{ id: 'i1', fromEndpoints: [{ matchLabels: { app: 'api' } }], toPorts: ports('8080') }, { id: 'i2', fromEndpoints: [], fromCIDR: [], toPorts: ports('22') }],
      [{ id: 'e1', toEndpoints: [], toPorts: ports('53', 'UDP') }],
    )));
    expect(doc.spec.ingress).toEqual([{ fromEndpoints: [{ matchLabels: { app: 'api' } }], toPorts: ports('8080') }]);
    // The only egress rule was peerless: the denied direction keeps Cilium's
    // deny form (one empty rule), never a ports-only rule.
    expect(doc.spec.egress).toEqual([{}]);
  });

  it('cilium: a freshly added rule (no peers, no ports) never renders as a null rule', () => {
    const doc = parse(ciliumPolicyToYAML(cilium([{ id: 'i1', fromEndpoints: [], toPorts: [] }], [], { ingress: false, egress: true })));
    expect(doc.spec.ingress).toBeUndefined();
    expect(doc.spec.egress).toEqual([{}]);
  });

  it('ciliumRuleHasPeers counts endpoints, CIDRs and entities, not ports', () => {
    expect(ciliumRuleHasPeers({ id: 'x', fromCIDR: ['10.0.0.0/8'] })).toBe(true);
    expect(ciliumRuleHasPeers({ id: 'x', toEntities: ['kube-apiserver'] })).toBe(true);
    // An empty selector is an explicit peer: every endpoint in the namespace.
    expect(ciliumRuleHasPeers({ id: 'x', fromEndpoints: [{ matchLabels: {} }] })).toBe(true);
    expect(ciliumRuleHasPeers({ id: 'x', toEndpoints: [], toPorts: ports('53') })).toBe(false);
  });
});

// A NetworkPolicy port is a number 1-65535 or a named container port (an
// IANA service name: at most 15 lowercase letters, digits and inner hyphens,
// with at least one letter). Clearing the editor's port field used to store
// 0, exported as `port: 0`, which the API server rejects.
describe('isValidPolicyPort / invalidPolicyPorts / port rendering', () => {
  it.each([[80], [1], [65535], ['8080'], ['http'], ['metrics-9'], ['a'], ['dns-tcp']])('accepts %s', (port) => {
    expect(isValidPolicyPort(port)).toBe(true);
  });

  it.each([[0], [65536], [-1], [1.5], [''], ['0'], ['99999'], ['HTTP'], ['-http'], ['http-'], ['h--p'], ['123-456'], ['averyveryverylongname'], ['8080 ']])(
    'rejects %j',
    (port) => {
      expect(isValidPolicyPort(port)).toBe(false);
    },
  );

  const policyWithPorts = (ports: NetworkPolicyRule['ports']): NetworkPolicy => ({
    apiVersion: 'networking.k8s.io/v1', kind: 'NetworkPolicy', metadata: { name: 'web-policy', namespace: 'prod' },
    spec: {
      podSelector: { matchLabels: { app: 'web' } }, policyTypes: ['Ingress', 'Egress'],
      ingress: [{ id: 'i', peers: [{ podSelector: { matchLabels: { app: 'api' } } }], ports }],
      egress: [{ id: 'e', peers: [{ ipBlock: { cidr: '10.0.0.0/8' } }], ports: [{ protocol: 'UDP', port: 53 }] }],
    },
  });

  it('invalidPolicyPorts names each bad port by direction and rule', () => {
    expect(invalidPolicyPorts(policyWithPorts([{ protocol: 'TCP', port: 8080 }]))).toEqual([]);
    expect(invalidPolicyPorts(policyWithPorts([{ protocol: 'TCP', port: '' }, { protocol: 'TCP', port: 0 }]))).toEqual([
      'ingress rule 1: port ""',
      'ingress rule 1: port "0"',
    ]);
  });

  it('a peerless rule is not exported, so its ports are not checked', () => {
    const policy = policyWithPorts([{ protocol: 'TCP', port: 8080 }]);
    policy.spec.egress = [{ id: 'e', peers: [], ports: [{ protocol: 'TCP', port: '' }] }];
    expect(invalidPolicyPorts(policy)).toEqual([]);
  });

  it('a named port renders as a string, a numeric one as a number', () => {
    const doc = parse(policyToYAML(policyWithPorts([{ protocol: 'TCP', port: 'http' }, { protocol: 'TCP', port: '8443' }, { protocol: 'TCP', port: 'no' }])));
    // `no` is a YAML 1.1 boolean unless quoted.
    expect(doc.spec.ingress[0].ports).toEqual([
      { protocol: 'TCP', port: 'http' },
      { protocol: 'TCP', port: 8443 },
      { protocol: 'TCP', port: 'no' },
    ]);
  });
});

// Observed rows whose port is not 1-65535 (ICMP carries pod_port "0") or is
// missing are skipped, as the advisor's parsePort does
// (advisor/pkg/network/standard_policy.go): they used to render `port: 0`,
// which the API server rejects, and which the editor's port check would now
// hold back from export. A protocol NetworkPolicy does not know maps to TCP,
// as the advisor's protocolPtr does.
describe('generators — observed rows with no usable port are skipped, as the advisor skips them', () => {
  const icmpIngress = { traffic_type: 'INGRESS', pod_port: '0', traffic_in_out_ip: '10.9.0.1', ip_protocol: 'ICMP' };
  const tcpIngress = { traffic_type: 'INGRESS', pod_port: '8080', traffic_in_out_ip: '10.9.0.2', ip_protocol: 'TCP' };
  const portlessEgress = { traffic_type: 'EGRESS', traffic_in_out_port: '', traffic_in_out_ip: '10.9.0.3', ip_protocol: 'UDP' };
  const outOfRangeEgress = { traffic_type: 'EGRESS', traffic_in_out_port: '70000', traffic_in_out_ip: '10.9.0.4', ip_protocol: 'TCP' };
  const dnsEgress = { traffic_type: 'EGRESS', traffic_in_out_port: '53', traffic_in_out_ip: '10.9.0.5', ip_protocol: 'udp' };

  it('standard: only the rows with a real port become rules, and the document exports', async () => {
    const policy = await generateNetworkPolicy(podWith([icmpIngress, tcpIngress, portlessEgress, outOfRangeEgress, dnsEgress]));
    expect(invalidPolicyPorts(policy)).toEqual([]);
    const doc = parse(policyToYAML(policy));
    expect(doc.spec.policyTypes).toEqual(['Ingress', 'Egress']);
    expect(doc.spec.ingress).toEqual([{ from: [{ ipBlock: { cidr: '10.9.0.2/32' } }], ports: [{ protocol: 'TCP', port: 8080 }] }]);
    expect(doc.spec.egress).toEqual([{ to: [{ ipBlock: { cidr: '10.9.0.5/32' } }], ports: [{ protocol: 'UDP', port: 53 }] }]);
  });

  it('cilium: the same rows, no empty or zero port', async () => {
    const yaml = ciliumPolicyToYAML(await generateCiliumNetworkPolicy(podWith([icmpIngress, tcpIngress, portlessEgress, outOfRangeEgress, dnsEgress])));
    const doc = parse(yaml);
    expect(doc.spec.ingress).toEqual([{ fromCIDR: ['10.9.0.2/32'], toPorts: [{ ports: [{ port: '8080', protocol: 'TCP' }] }] }]);
    expect(doc.spec.egress).toEqual([{ toCIDR: ['10.9.0.5/32'], toPorts: [{ ports: [{ port: '53', protocol: 'UDP' }] }] }]);
  });

  it('only ICMP observed: no direction has a usable row, so the reference deny-all, as the advisor', async () => {
    const policy = await generateNetworkPolicy(podWith([icmpIngress]));
    expect(invalidPolicyPorts(policy)).toEqual([]);
    expect(parse(policyToYAML(policy)).spec).toEqual({ podSelector: { matchLabels: { app: 'web' } }, policyTypes: ['Ingress', 'Egress'] });
    const cilium = parse(ciliumPolicyToYAML(await generateCiliumNetworkPolicy(podWith([icmpIngress]))));
    expect(cilium.spec.enableDefaultDeny).toEqual({ ingress: true, egress: true });
  });

  it('an unknown protocol with a real port maps to TCP, as the advisor', async () => {
    const policy = await generateNetworkPolicy(podWith([{ ...tcpIngress, ip_protocol: 'ICMP' }]));
    expect(policy.spec.ingress?.[0].ports).toEqual([{ protocol: 'TCP', port: 8080 }]);
  });
});

// The Cilium editor's port field is free text. Empty, it used to export
// `port: ""`, which the CRD rejects; nothing in the editor says an empty
// field means "any port", so it is flagged rather than guessed.
describe('invalidCiliumPorts', () => {
  const cnp = (port: string): CiliumNetworkPolicy => ({
    apiVersion: 'cilium.io/v2', kind: 'CiliumNetworkPolicy', metadata: { name: 'web-cilium-policy', namespace: 'prod' },
    spec: {
      endpointSelector: { matchLabels: { app: 'web' } }, defaultDeny: { ingress: false, egress: true },
      egress: [{ id: 'e', toCIDR: ['10.0.0.0/8'], toPorts: [{ ports: [{ port, protocol: 'TCP' }] }] }],
    },
  });

  it.each([['80'], ['0'], ['65535'], ['http']])('accepts %j (Cilium: 0 is any port)', (port) => {
    expect(invalidCiliumPorts(cnp(port))).toEqual([]);
  });

  it.each([[''], ['65536'], ['-1'], ['8080 ']])('flags %j', (port) => {
    expect(invalidCiliumPorts(cnp(port))).toEqual([`egress rule 1: port "${port}"`]);
  });

  it('a digit string with a leading zero is written as its number', () => {
    expect(ciliumPolicyToYAML(cnp('0080'))).toContain('      - port: "80"');
  });

  it('invalidCiliumCidrs names an empty or malformed typed CIDR', () => {
    const policy = cnp('80');
    policy.spec.egress![0].toCIDR = ['', '10.0.0.0/8', '10.0.0.0'];
    expect(invalidCiliumCidrs(policy)).toEqual(['egress rule 1: cidr ""', 'egress rule 1: cidr "10.0.0.0"']);
  });
});

// A digit string with a leading zero, written bare, is octal to a YAML 1.1
// decoder (kubectl uses go-yaml v2): `port: 0100` is read as 64.
describe('policyToYAML — numeric ports are written as plain decimals', () => {
  it('0080 is written 80, 0100 is written 100', () => {
    const policy: NetworkPolicy = {
      apiVersion: 'networking.k8s.io/v1', kind: 'NetworkPolicy', metadata: { name: 'web-policy', namespace: 'prod' },
      spec: {
        podSelector: { matchLabels: { app: 'web' } }, policyTypes: ['Ingress'],
        ingress: [{ id: 'i', peers: [{ ipBlock: { cidr: '10.0.0.0/8' } }], ports: [{ protocol: 'TCP', port: '0080' }, { protocol: 'TCP', port: '0100' }] }],
      },
    };
    const yaml = policyToYAML(policy);
    expect(yaml).toContain('      port: 80\n');
    expect(yaml).not.toContain('0100');
    expect(parse(yaml).spec.ingress[0].ports).toEqual([{ protocol: 'TCP', port: 80 }, { protocol: 'TCP', port: 100 }]);
  });
});

describe('invalidPolicyCidrs — a typed ipBlock CIDR must parse', () => {
  const withCidr = (cidr: string, except?: string[]): NetworkPolicy => ({
    apiVersion: 'networking.k8s.io/v1', kind: 'NetworkPolicy', metadata: { name: 'web-policy', namespace: 'prod' },
    spec: {
      podSelector: { matchLabels: { app: 'web' } }, policyTypes: ['Egress'],
      egress: [{ id: 'e', peers: [{ podSelector: { matchLabels: { app: 'api' } } }, { ipBlock: { cidr, ...(except && { except }) } }], ports: [] }],
    },
  });

  it('accepts IPv4 and IPv6 CIDRs', () => {
    expect(invalidPolicyCidrs(withCidr('10.0.0.0/8'))).toEqual([]);
    expect(invalidPolicyCidrs(withCidr('fd00::/64', ['fd00::1/128']))).toEqual([]);
  });

  it('names an empty cidr, a bare address, and a bad except entry', () => {
    expect(invalidPolicyCidrs(withCidr(''))).toEqual(['egress rule 1: cidr ""']);
    expect(invalidPolicyCidrs(withCidr('10.0.0.1'))).toEqual(['egress rule 1: cidr "10.0.0.1"']);
    expect(invalidPolicyCidrs(withCidr('10.0.0.0/8', ['10.1.0.0/33']))).toEqual(['egress rule 1: except "10.1.0.0/33"']);
  });
});
