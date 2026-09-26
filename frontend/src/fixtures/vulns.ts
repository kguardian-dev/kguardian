/**
 * Supply-chain fixtures. Both sets are raw Broker responses, stored verbatim
 * as `{request, status, body}`; nothing here is written by hand.
 *
 *  - ./vuln-captures (default): a Broker at current main with in-use tiers
 *    (#1678), seeded through its real ingest routes by
 *    ./vuln-captures/capture.py. Every file carries `provenance: "captured
 *    from broker <sha> ..."`. The runtime inventory (P1-2) is not on main
 *    yet, so every finding's in-use state is `unknown` (no_runtime_data):
 *    Loaded / Executed / Background come only from tests that say so.
 *  - ./vuln-captures-1671: the same world captured from a Broker at #1671
 *    (f3595b640), before tiers: no `tier`, `tierFactors` or `inUseDetail`.
 *    It stands in for an older Broker.
 *
 * The seeded world (neutral names, fictional CVE-2099-* ids):
 *  - payments/Deployment/checkout: index report joined by platform
 *    manifest, trivy-operator + grype (KEV, EPSS, two fixed versions for
 *    express); ingress from ingress-nginx and a public IP -> exposed.
 *  - payments/Deployment/ledger: exact image_id join; ingress only from its
 *    own namespace -> exposed false.
 *  - payments/CronJob/reports: not running (Completed), no flows -> exposure unknown.
 *  - observability/Deployment/grafana: exact join, a bare registry SBOM
 *    (attached-unbound); ingress from another namespace.
 *  - observability/StatefulSet/prometheus: tag-only join (workload_tag),
 *    scraped from a node -> exposed via node.
 *  - observability/DaemonSet/node-exporter: no report at all (unknown).
 *  - flux-system/Deployment/source-controller: scanned, zero findings, a
 *    verified registry SBOM; egress only -> exposure unknown.
 */
import { VulnApi } from '../services/vulnApi';
import type { CvePage, Exposure, ImageDetail, ImagePage, ImageVulnsPage, SbomPage } from '../types/vulns';

export interface Capture<T = unknown> {
  request: string;
  status: number;
  body: T;
  /** Where the response came from (current captures). */
  provenance?: string;
}

/** Which Broker the responses come from: current main (tiers) or #1671 (no tiers). */
export type CaptureSet = 'current' | '1671';

const index = (raw: Record<string, Capture>) => new Map(Object.entries(raw).map(([path, c]) => [path.replace(/^.*\/(.+)\.json$/, '$1'), c]));
const SETS: Record<CaptureSet, Map<string, Capture>> = {
  current: index(import.meta.glob('./vuln-captures/*.json', { eager: true, import: 'default' }) as Record<string, Capture>),
  '1671': index(import.meta.glob('./vuln-captures-1671/*.json', { eager: true, import: 'default' }) as Record<string, Capture>),
};

export function vulnCapture<T>(name: string, set: CaptureSet = 'current'): Capture<T> {
  const c = SETS[set].get(name);
  if (!c) throw new Error(`no ${set} vuln capture named ${name}`);
  return c as Capture<T>;
}

export const VULN_CAPTURES: Capture[] = [...SETS.current.values()];
export const PRE_TIER_CAPTURES: Capture[] = [...SETS['1671'].values()];

export const cvePage = vulnCapture<CvePage>('vulnerabilities').body;
export const imagesPage = vulnCapture<ImagePage>('images').body;
export const exposureOf = (id: string, set: CaptureSet = 'current') => vulnCapture<Exposure>(`exposure-${id}`, set).body;
export const imageDetail = (name: string, set: CaptureSet = 'current') => vulnCapture<ImageDetail>(`image-${name}`, set).body;
export const imageVulns = (name: string, set: CaptureSet = 'current') => vulnCapture<ImageVulnsPage>(`image-${name}-vulnerabilities`, set).body;
export const imageSbom = (name: string, set: CaptureSet = 'current') => vulnCapture<SbomPage>(`image-${name}-sbom`, set).body;

/** The inventory digest of a seeded workload's image, from its capture. */
export const digestOf = (name: string) => imageDetail(name).digest;

/**
 * A VulnApi whose fetch replays one capture set by request line
 * (URL-decoded; `extra` first; a request with `limit=` falls back to the
 * capture without it, since every captured list is shorter than the UI's
 * page sizes). Unmatched requests are an empty 404, which is what a Broker
 * without the route sends. `broker: '1671'` replays the Broker before tiers.
 */
export function replayVulnApi(extra: Capture[] = [], opts: { broker?: CaptureSet } = {}) {
  const calls: string[] = [];
  const all = [...extra, ...SETS[opts.broker ?? 'current'].values()];
  const norm = (r: string) => decodeURIComponent(r.replace(/\+/g, ' '));
  const fetchImpl = (async (input: RequestInfo | URL) => {
    const url = new URL(String(input), 'http://x');
    const line = `GET ${url.pathname.replace(/^\/api/, '')}${url.search}`;
    calls.push(line);
    const noLimit = (() => {
      const u = new URL(line.slice(4), 'http://x');
      u.searchParams.delete('limit');
      return `GET ${u.pathname}${u.search}`;
    })();
    const hit = all.find((c) => norm(c.request) === norm(line)) ?? all.find((c) => norm(c.request) === norm(noLimit));
    if (!hit) return new Response('', { status: 404 });
    return new Response(typeof hit.body === 'string' ? hit.body : JSON.stringify(hit.body), { status: hit.status });
  }) as typeof fetch;
  return { api: new VulnApi({ fetchImpl }), calls };
}
