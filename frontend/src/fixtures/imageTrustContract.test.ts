import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, test } from 'vitest';
import { VULN_CAPTURES } from './vulns';
import type { WorkloadProfile } from '../types/profile';

/**
 * Ties the image trust fixtures to the evaluator's Go source, so a fixture
 * cannot carry a field, verdict or reason the evaluator does not have.
 * Reads the Go files as text: the Result struct's json tags
 * (evaluator/pkg/imagetrust/runner.go), the verdict constants
 * (evaluator/pkg/v1alpha1/imagetrust.go), the evaluator's reason constants
 * (evaluator/pkg/imagetrust/eval.go) and, because an Unknown result passes
 * the discovery reason through unchanged, the Broker's attestation reason
 * codes (broker/src/attestation.rs). Every parse must find something, so a
 * moved file or a changed layout fails here instead of passing vacuously.
 */
const REPO = resolve(__dirname, '../../..');
const src = (rel: string): string => {
  const p = resolve(REPO, rel);
  try {
    return readFileSync(p, 'utf8');
  } catch (e) {
    throw new Error(`contract source ${rel} not readable at ${p}: ${(e as Error).message}`, { cause: e });
  }
};
const nonEmpty = <T>(what: string, xs: T[]): T[] => {
  if (xs.length === 0) throw new Error(`parsed no ${what}: the Go/Rust source moved or changed shape`);
  return xs;
};

/** json tag names of `type <name> struct { ... }` in a Go file. */
function goJsonTags(file: string, struct: string): string[] {
  const text = src(file);
  const m = text.match(new RegExp(`type ${struct} struct \\{([\\s\\S]*?)\\n\\}`));
  if (!m) throw new Error(`struct ${struct} not found in ${file}`);
  return nonEmpty(`json tags in ${struct}`, [...m[1].matchAll(/`json:"([^",]+)[^"]*"`/g)].map((x) => x[1]));
}

/** String values of Go constants whose names match `prefix`. */
function goStringConsts(file: string, prefix: RegExp): string[] {
  const text = src(file);
  return nonEmpty(`${prefix} constants in ${file}`, [...text.matchAll(/^\s*([A-Za-z_]\w*)\s*=\s*"([^"]*)"/gm)].filter((x) => prefix.test(x[1])).map((x) => x[2]));
}

const RESULT_TAGS = goJsonTags('evaluator/pkg/imagetrust/runner.go', 'Result');
const VERDICTS = goStringConsts('evaluator/pkg/v1alpha1/imagetrust.go', /^Image(Trusted|WouldDeny|Unknown)$/);
const EVALUATOR_REASONS = goStringConsts('evaluator/pkg/imagetrust/eval.go', /^Reason[A-Z]/);
const DISCOVERY_REASONS = (() => {
  const rs = src('broker/src/attestation.rs');
  const block = rs.match(/pub const REASONS: \[&str; \d+\] = \[([\s\S]*?)\];/);
  if (!block) throw new Error('REASONS not found in broker/src/attestation.rs');
  const unrec = rs.match(/pub const UNRECOGNISED_REASON: &str = "([^"]+)";/);
  if (!unrec) throw new Error('UNRECOGNISED_REASON not found in broker/src/attestation.rs');
  return [...nonEmpty('discovery reasons', [...block[1].matchAll(/"([^"]+)"/g)].map((x) => x[1])), unrec[1]];
})();

/** Every imageTrust result in the captured profiles, with the fixture it came from. */
const RESULTS = VULN_CAPTURES.flatMap((c) => {
  const body = c.body as Partial<WorkloadProfile> | null;
  const results = body && typeof body === 'object' ? body.dimensions?.images?.supplyChain?.imageTrust?.results : undefined;
  return (results ?? []).map((r) => ({ from: c.request, r: r as unknown as Record<string, unknown> }));
});

test('the Go and Rust sources parse to the expected sets (never vacuous)', () => {
  expect(RESULT_TAGS).toEqual(['policy', 'namespace', 'workload', 'container', 'digest', 'image', 'verdict', 'reason']);
  expect([...VERDICTS].sort()).toEqual(['Trusted', 'Unknown', 'WouldDeny']);
  expect(EVALUATOR_REASONS).toContain('untrusted-signer');
  expect(DISCOVERY_REASONS).toContain('rate_limited');
  // The fixtures must actually carry results, or the checks below prove nothing.
  expect(RESULTS.length).toBeGreaterThanOrEqual(8);
  expect(new Set(RESULTS.map((x) => x.r.verdict))).toEqual(new Set(['Trusted', 'WouldDeny', 'Unknown']));
});

test('every key of every captured image trust result is a json tag of the evaluator\'s Result', () => {
  for (const { from, r } of RESULTS) {
    for (const k of Object.keys(r)) expect(RESULT_TAGS, `${from}: key "${k}"`).toContain(k);
  }
});

test('every verdict is an evaluator verdict constant, and every reason an evaluator or discovery reason', () => {
  for (const { from, r } of RESULTS) {
    expect(VERDICTS, `${from}: verdict ${String(r.verdict)}`).toContain(r.verdict);
    if (r.reason != null) expect([...EVALUATOR_REASONS, ...DISCOVERY_REASONS], `${from}: reason ${String(r.reason)}`).toContain(r.reason);
  }
});

/** Every imageTrust `reason` in the captured profiles (unavailable answers and per-result reasons). */
const REASONS_SHOWN = VULN_CAPTURES.flatMap((c) => {
  const body = c.body as Partial<WorkloadProfile> | null;
  const t = body && typeof body === 'object' ? body.dimensions?.images?.supplyChain?.imageTrust : undefined;
  if (!t) return [];
  return [t.reason, ...(t.results ?? []).map((r) => r.reason)].filter((r): r is string => typeof r === 'string').map((reason) => ({ from: c.request, reason }));
});

/**
 * What an internal address looks like in a reason. Tuned so an address is
 * caught however it is written, and ordinary reason text is not:
 * sha256:<hex> digests, clock times (12:35:00) and key:number text
 * (status:404, timeout:30) pass. Known limit: an unhyphenated single-label
 * host with a 2-3 digit port ("evaluator:80") reads like "status:404" and
 * is not caught.
 */
const ADDRESS: Record<string, RegExp> = {
  url: /:\/\//,
  dottedOrIpv4HostPort: /\b(?:\d{1,3}(?:\.\d{1,3}){3}|localhost|[a-z0-9-]+(?:\.[a-z0-9-]+)+):\d{2,5}\b/i,
  // A single-label host (a Kubernetes service name): hyphenated, or with a 4-5 digit port.
  serviceHostPort: /\b(?:[a-z][a-z0-9]*-[a-z0-9-]*[a-z0-9]:\d{2,5}|[a-z][a-z0-9-]*:\d{4,5})\b/i,
  bracketedIpv6: /\[[0-9a-f]*:[0-9a-f:.]*\](?::\d{1,5})?/i,
  // Bare IPv6: a "::" with at least one hex group, or all 8 groups (a clock time has 3 and no "::").
  bareIpv6: /(?<![0-9a-z:])(?:(?:[0-9a-f]{1,4}:){1,7}:|(?:[0-9a-f]{1,4}:){0,6}(?::[0-9a-f]{1,4}){1,7}|:(?::[0-9a-f]{1,4}){1,7}|(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4})(?![0-9a-z:])/i,
};
const addressIn = (s: string) => Object.entries(ADDRESS).filter(([, re]) => re.test(s)).map(([name]) => name);

test.each([
  ['kguardian-evaluator:8080 refused', 'serviceHostPort'],
  ['evaluator:8080 refused', 'serviceHostPort'],
  ['kguardian-evaluator:80', 'serviceHostPort'],
  ['[fd00::1]:8080 timed out', 'bracketedIpv6'],
  ['fd00::1 unreachable', 'bareIpv6'],
  ['::1 refused', 'bareIpv6'],
  ['2001:db8:0:0:0:0:0:1 down', 'bareIpv6'],
  ['dial 127.0.0.1:56431', 'dottedOrIpv4HostPort'],
  ['evaluator.kguardian.svc:8080', 'dottedOrIpv4HostPort'],
  ['http://evaluator/image-trust', 'url'],
])('the address guard catches %s', (text, pattern) => {
  expect(addressIn(text)).toContain(pattern);
});

test.each([
  'the evaluator could not be reached: connection failed',
  'digest sha256:f48949f11f15c0e2b8fa2132d1ab201cf50e80dea612783e5c3ac78c6b378235',
  'sha256:1234567890123456',
  'checked at 12:35:00',
  '2026-09-27T12:35:00Z',
  'status:404',
  'timeout:30',
  'code:500',
  'reason: 42 checks',
  'std::io::Error',
  "the Broker's counts do not add up (2 counted, total 1)",
  'no evaluator is configured (EVALUATOR_URL): ImageTrustPolicy results are not available',
])('the address guard leaves ordinary text alone: %s', (text) => {
  expect(addressIn(text)).toEqual([]);
});

test('no image trust reason the UI shows carries an internal address (URL, host:port, service:port, IPv6)', () => {
  // The evaluator-down fixtures must be among them, or this proves nothing.
  expect(REASONS_SHOWN.some((x) => /evaluator/i.test(x.reason))).toBe(true);
  for (const { from, reason } of REASONS_SHOWN) {
    expect(addressIn(reason), `${from}: ${reason}`).toEqual([]);
  }
});
