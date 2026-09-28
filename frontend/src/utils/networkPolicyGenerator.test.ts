import { describe, it, expect, vi } from 'vitest';

// resolveTrafficIdentity reaches the broker; stub it so an unresolvable peer
// falls through to the CIDR path, which is the branch under test.
vi.mock('../services/api', () => ({
  apiClient: {
    getServiceByIP: vi.fn().mockResolvedValue(null),
    getPodDetailsByIP: vi.fn().mockResolvedValue(null),
  },
}));

import { generateNetworkPolicy, quoteYamlValue } from './networkPolicyGenerator';
import { generateCiliumNetworkPolicy, ciliumPolicyToYAML } from './ciliumPolicyGenerator';

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
