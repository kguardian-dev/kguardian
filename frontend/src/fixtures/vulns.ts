/**
 * Supply-chain fixtures: raw responses captured from a local Broker built
 * from main after #1671 merged (f3595b640), seeded only through its real
 * ingest routes (POST /pod/spec, /pod/traffic/batch,
 * /images/{digest}/vulnerabilities, /images/{digest}/sbom). Stored verbatim
 * in ./vuln-captures as `{request, status, body}`; nothing here is written
 * by hand. The seed script lives outside the repo (scratchpad).
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
}

const raw = import.meta.glob('./vuln-captures/*.json', { eager: true, import: 'default' }) as Record<string, Capture>;
const byName = new Map(Object.entries(raw).map(([path, c]) => [path.replace(/^.*\/(.+)\.json$/, '$1'), c]));

export function vulnCapture<T>(name: string): Capture<T> {
  const c = byName.get(name);
  if (!c) throw new Error(`no vuln capture named ${name}`);
  return c as Capture<T>;
}

export const VULN_CAPTURES: Capture[] = [...byName.values()];

export const cvePage = vulnCapture<CvePage>('vulnerabilities').body;
export const imagesPage = vulnCapture<ImagePage>('images').body;
export const exposureOf = (id: string) => vulnCapture<Exposure>(`exposure-${id}`).body;
export const imageDetail = (name: string) => vulnCapture<ImageDetail>(`image-${name}`).body;
export const imageVulns = (name: string) => vulnCapture<ImageVulnsPage>(`image-${name}-vulnerabilities`).body;
export const imageSbom = (name: string) => vulnCapture<SbomPage>(`image-${name}-sbom`).body;

/** The inventory digest of a seeded workload's image, from its capture. */
export const digestOf = (name: string) => imageDetail(name).digest;

/**
 * A VulnApi whose fetch replays the captures by request line (URL-decoded;
 * `extra` first; a request with `limit=` falls back to the capture without
 * it). Unmatched requests are an empty 404, which is what a Broker without
 * the route sends.
 */
export function replayVulnApi(extra: Capture[] = []) {
  const calls: string[] = [];
  const all = [...extra, ...VULN_CAPTURES];
  const norm = (r: string) => decodeURIComponent(r.replace(/\+/g, ' '));
  const fetchImpl = (async (input: RequestInfo | URL) => {
    const url = new URL(String(input), 'http://x');
    const line = `GET ${url.pathname.replace(/^\/api/, '')}${url.search}`;
    calls.push(line);
    // The UI pages with `limit=`; most captures were taken without it. Every
    // captured list is shorter than the UI's page sizes, so the unlimited
    // capture is the same answer. Exact matches win.
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
