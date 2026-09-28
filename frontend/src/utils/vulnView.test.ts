import { describe, expect, test } from 'vitest';
import { busyReadMessage, cveAiPrompt, groupNotCovered, impactCounts, PROMPT_WORKLOADS_MAX, sbomFromMatcher } from './vulnView';
import { exposureOf, imageVulns } from '../fixtures/vulns';
import type { ExposedVia, ExposedWorkload, Report } from '../types/vulns';
import type { Factor } from './tiers';

const exposure = exposureOf('CVE-2099-0001');
const row = (over: Partial<ExposedWorkload>): ExposedWorkload => ({ ...exposure.workloads[0], ...over });
const net = (exposed: boolean | null, via: ExposedVia[] = []) => ({ ...exposure.workloads[0].network!, exposed, exposedVia: via });

describe('impactCounts', () => {
  test('captured: three containers, two running workloads, one exposed; the finished CronJob is not a running workload', () => {
    expect(impactCounts(exposure)).toEqual({ images: 3, containers: 3, running: 2, exposed: 1, beyondNodes: 1, nodeOnly: 0, unknownExposure: 0 });
  });

  test('IMG-06: workloads whose only outside ingress came from nodes are counted apart from outside ingress, whichever way the Broker flags them', () => {
    // Captured from Broker 1.19.3 (CVE-2099-0006): grafana via another namespace, prometheus via a node with exposed: true.
    expect(impactCounts(exposureOf('CVE-2099-0006'))).toMatchObject({ running: 2, exposed: 2, beyondNodes: 1, nodeOnly: 1 });
    const oldShape = row({ container: 'app', running: true, network: net(true, ['node']) });
    expect(impactCounts({ ...exposure, workloads: [oldShape] })).toMatchObject({ exposed: 1, beyondNodes: 0, nodeOnly: 1, unknownExposure: 0 });
    // Broker #1780 and later: node-only ingress is exposed: false with node still in exposedVia.
    const newShape = row({ container: 'app', running: true, network: net(false, ['node']) });
    expect(impactCounts({ ...exposure, workloads: [newShape] })).toMatchObject({ exposed: 0, beyondNodes: 0, nodeOnly: 1, unknownExposure: 0 });
    // A workload with a node-only row and another row exposed beyond nodes is exposed, not node only.
    const mixed = [row({ container: 'a', running: true, network: net(true, ['node']) }), row({ container: 'b', running: true, network: net(true, ['public_ip']) })];
    expect(impactCounts({ ...exposure, workloads: mixed })).toMatchObject({ exposed: 1, beyondNodes: 1, nodeOnly: 0 });
  });

  test('IMG-04: a finished init container of a running, exposed Deployment is a row, not a second exposed workload', () => {
    const app = row({ container: 'app', running: true, network: net(true, ['node']) });
    const init = row({ container: 'config-init', running: false, network: net(true, ['node']) });
    const c = impactCounts({ ...exposure, workloads: [app, init] });
    expect(c).toMatchObject({ containers: 2, running: 1, exposed: 1, unknownExposure: 0 });
    expect(c.exposed).toBeLessThanOrEqual(c.running);
  });

  test('two running containers of one workload count once; unknown exposure counts running workloads that are not exposed', () => {
    const a = row({ container: 'a', running: true, network: net(true, ['public_ip']) });
    const b = row({ container: 'b', running: true, network: net(true, ['public_ip']) });
    const quiet = row({ name: 'other', container: 'c', running: true, network: null });
    const stopped = row({ name: 'gone', container: 'd', running: false, network: null });
    expect(impactCounts({ ...exposure, workloads: [a, b, quiet, stopped] })).toMatchObject({ containers: 4, running: 2, exposed: 1, unknownExposure: 1 });
  });
});

describe('cveAiPrompt', () => {
  const finding = imageVulns('checkout').items.find((x) => x.id === exposure.id)!;

  test("IMG-16: states the headline factors it is given, not the first image's own", () => {
    const factors: Factor[] = [
      { key: 'inuse', tone: 'risk', label: 'Executed' },
      { key: 'exposure', tone: 'neutral', label: 'Node ingress only' },
      { key: 'kev', tone: 'risk', label: 'KEV' },
    ];
    const p = cveAiPrompt(exposure, finding, 'P0', factors);
    expect(p).toContain('kguardian tier P0 from Executed, Node ingress only, KEV');
    expect(p).not.toContain('in_use:');
    // Without headline factors the finding's own factors stand in.
    expect(cveAiPrompt(exposure, finding, 'P0')).toContain(`from ${finding.tierFactors!.join(', ')}`);
  });

  test('IMG-16: names at most PROMPT_WORKLOADS_MAX exposed workloads and counts the rest', () => {
    const many = Array.from({ length: 25 }, (_, i) => row({ name: `svc-${i}`, container: 'app', running: true, network: net(true, ['public_ip']) }));
    const p = cveAiPrompt({ ...exposure, workloads: many }, null, 'P1');
    expect(p).toContain('Observed outside ingress on 25 running workload(s): payments/svc-0');
    expect(p).toContain(`payments/svc-${PROMPT_WORKLOADS_MAX - 1}, +15 more`);
    expect(p).not.toContain(`payments/svc-${PROMPT_WORKLOADS_MAX},`);
    expect(p.length).toBeLessThan(1500);
  });

  test('counts the funnel in workloads: a stopped container is not a running workload', () => {
    const p = cveAiPrompt(exposure, null);
    expect(p).toContain('3 workload container(s); 2 distinct workload(s) running.');
    expect(p).toContain('Observed outside ingress on 1 running workload(s): payments/checkout;');
    expect(p).not.toContain('Ingress from nodes only');
  });

  test('IMG-06: node-only ingress is reported on its own line, not as outside ingress, under either Broker shape', () => {
    const both = exposureOf('CVE-2099-0006');
    const p = cveAiPrompt(both, null, 'P1');
    expect(p).toContain('Observed outside ingress on 1 running workload(s): observability/grafana;');
    expect(p).toContain('Ingress from nodes only (kubelet probes, or NodePort traffic after SNAT) on 1 running workload(s): observability/prometheus.');
    const newShape = { ...both, workloads: both.workloads.map((w) => (w.name === 'prometheus' ? { ...w, network: { ...w.network!, exposed: false } } : w)) };
    expect(cveAiPrompt(newShape, null, 'P1')).toBe(p);
  });
});

test('IMG-11: a report that names the SBOM it matched from stands in when /sbom lists none', () => {
  const grype: Report = { ...imageVulns('checkout').reports[0], source: 'grype', sbomSources: ['registry'], sbomTrust: 'unverified' };
  expect(sbomFromMatcher([grype])).toEqual([{ matcher: 'grype', sbomSource: 'registry', trust: 'unverified' }]);
  expect(sbomFromMatcher([{ ...grype, sbomSources: [] }])).toEqual([]);
  expect(sbomFromMatcher(null)).toEqual([]);
});

test('IMG-14: up to ten "not covered" lines stay inline; more are set aside behind a count', () => {
  const few = ['identity: a', ...Array.from({ length: 10 }, (_, i) => `not covered: repo-${i} (a running digest is unknown)`)];
  expect(groupNotCovered(few)).toEqual({ lines: few, notCovered: [] });
  const many = ['identity: a', ...Array.from({ length: 11 }, (_, i) => `not covered: repo-${i} (a running digest is unknown)`), 'trailer'];
  const g = groupNotCovered(many);
  expect(g.lines).toEqual(['identity: a', 'trailer']);
  expect(g.notCovered).toHaveLength(11);
});

describe('busyReadMessage', () => {
  const body = (needs: number, total: number) =>
    `broker read memory budget exhausted: this request needs ${needs} KiB of a ${total} KiB budget and waited 5000 ms without getting it. The request was REFUSED, not truncated — retry. Raise BROKER_READ_MEMORY_BUDGET_MB (and the container memory limit with it) if this is persistent.`;

  test('IMG-02: a read that needs the whole budget is told so, not "try again in a few seconds"', () => {
    const m = busyReadMessage(body(262144, 262144));
    expect(m).toMatch(/whole read memory budget \(256 MiB\)/);
    expect(m).toContain('BROKER_READ_MEMORY_BUDGET_MB');
    expect(m).not.toMatch(/few seconds/);
  });

  test('a partial reservation is a transient shed, with its numbers', () => {
    expect(busyReadMessage(body(51200, 262144))).toBe('The Broker is shedding reads right now (read budget: this read needs 50 MiB of 256 MiB). Try again in a few seconds.');
    expect(busyReadMessage(body(512, 262144))).toMatch(/needs 512 KiB of 256 MiB/);
  });

  test('an unrecognised body keeps the generic message', () => {
    expect(busyReadMessage('')).toMatch(/Try again in a few seconds/);
  });
});
