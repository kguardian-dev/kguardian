import apiClient from './api';
import { isTimeout, READ_TIMEOUT_MS, timeoutMessage, timeoutSignal } from './readTimeout';
import type { CvePage, Exposure, ImageDetail, ImagePage, ImageVulnsPage, SbomPage, VulnSeverity } from '../types/vulns';
import type { AdmissionFormat, ExportManifest, RunningSignaturePage } from '../types/attestations';
import { busyMessage, retryAfterMs } from './brokerBusy';

/**
 * Typed read-only client for the supply-chain reads (#1671) and the image
 * inventory (#1655). `fetch`-based, like ProfileApi, so status codes and
 * bodies survive for honest error states.
 */

/**
 *  - `not_found`: 404 on an exposure / image read (no affected image, or
 *    the digest is not in the inventory);
 *  - `unsupported`: 404 on a list route: a Broker without these endpoints;
 *  - `busy`: 503, the read budget shed the request or the database cancelled
 *    the statement; the message follows the body and `retryAfterMs` the
 *    Broker's `Retry-After`;
 *  - `bad_request`: 400;
 *  - `auth`: 401 / 403, the Broker wants a token the UI's proxy did not
 *    present (or one without the read scope);
 *  - `timeout`: no answer within READ_TIMEOUT_MS (retryable);
 *  - `error`: anything else (network, 5xx).
 */
export type VulnErrorKind = 'not_found' | 'unsupported' | 'busy' | 'bad_request' | 'auth' | 'timeout' | 'error';

export class VulnApiError extends Error {
  readonly status: number;
  readonly kind: VulnErrorKind;
  /** The Broker's `Retry-After` on a 503, in ms; null when it sent none. */
  readonly retryAfterMs: number | null;
  constructor(status: number, kind: VulnErrorKind, message: string, retryAfterMs: number | null = null) {
    super(message);
    this.name = 'VulnApiError';
    this.status = status;
    this.kind = kind;
    this.retryAfterMs = retryAfterMs;
  }
}

export const vulnErrorKind = (e: unknown): VulnErrorKind => (e instanceof VulnApiError ? e.kind : 'error');
export const vulnErrorMessage = (e: unknown): string => (e instanceof Error ? e.message : String(e));

/**
 * One path segment. `:` and `@` stay literal (RFC 3986 pchar): digests are
 * `sha256:…`, and the frontend's /api proxy refuses any `%` in a path
 * (vite.config.ts brokerProxyDecision), so an encoded `%3A` would be a 400.
 */
export const seg = (s: string) => encodeURIComponent(s).replace(/%3A/gi, ':').replace(/%40/g, '@');

/** #1678 filters; an older Broker ignores them, so callers check `tier` is present before trusting a filtered page. */
export interface TierFilters {
  tier?: string[];
  kev?: boolean;
  epssMin?: number;
  inUse?: string[];
}

export interface CveListQuery extends TierFilters {
  severity?: VulnSeverity[];
  fixable?: boolean;
  namespace?: string;
  running?: boolean;
  limit?: number;
  after?: string;
}

/** The read's own timeout, and the caller's abort when it passes one. */
function readSignal(timeoutMs: number, external?: AbortSignal): AbortSignal {
  const timeout = timeoutSignal(timeoutMs);
  if (!external) return timeout;
  if (typeof AbortSignal.any === 'function') return AbortSignal.any([timeout, external]);
  const c = new AbortController();
  for (const s of [timeout, external]) {
    if (s.aborted) c.abort(s.reason);
    else s.addEventListener('abort', () => c.abort(s.reason), { once: true });
  }
  return c.signal;
}

function tierParams(q: TierFilters): Record<string, string | number | boolean | undefined> {
  return {
    tier: q.tier?.length ? q.tier.join(',') : undefined,
    kev: q.kev,
    epss_min: q.epssMin,
    in_use: q.inUse?.length ? q.inUse.join(',') : undefined,
  };
}

export class VulnApi {
  private readonly fetchImpl: typeof fetch;

  private readonly timeoutMs: number;

  constructor(opts: { fetchImpl?: typeof fetch; timeoutMs?: number } = {}) {
    this.fetchImpl = opts.fetchImpl ?? ((...args) => fetch(...args));
    this.timeoutMs = opts.timeoutMs ?? READ_TIMEOUT_MS;
  }

  private get base(): string {
    return (apiClient?.baseURL ?? '/api').replace(/\/$/, '');
  }

  private async json<T>(path: string, query: Record<string, string | number | boolean | undefined> = {}, listRoute: boolean | string = false, signal?: AbortSignal): Promise<T> {
    return JSON.parse(await this.read(path, query, listRoute, 'application/json', signal)) as T;
  }

  /**
   * One read. `listRoute`: a 404 means the Broker lacks the route
   * (`unsupported`); a string is the message to show for it. `signal` lets
   * the caller drop a read it no longer wants (a modal that closed or moved on).
   */
  private async read(path: string, query: Record<string, string | number | boolean | undefined>, listRoute: boolean | string, accept: string, signal?: AbortSignal): Promise<string> {
    const sp = new URLSearchParams();
    for (const [k, v] of Object.entries(query)) if (v !== undefined && v !== '') sp.set(k, String(v));
    const q = sp.toString();
    let res: Response;
    let text: string;
    try {
      res = await this.fetchImpl(`${this.base}${path}${q ? `?${q}` : ''}`, {
        headers: { Accept: accept },
        credentials: 'same-origin',
        signal: readSignal(this.timeoutMs, signal),
      });
      text = await res.text();
    } catch (err) {
      if (signal?.aborted) throw new VulnApiError(0, 'error', 'The read was cancelled.');
      if (isTimeout(err)) throw new VulnApiError(0, 'timeout', timeoutMessage(this.timeoutMs));
      throw new VulnApiError(0, 'error', `Could not reach the Broker: ${vulnErrorMessage(err)}`);
    }
    if (res.ok) return text;
    const msg = text.trim() || `request failed with ${res.status}`;
    if (res.status === 404) {
      throw listRoute
        ? new VulnApiError(404, 'unsupported', typeof listRoute === 'string' ? listRoute : 'This Broker does not serve vulnerability data. Upgrade the Broker to a release with the supply-chain endpoints.')
        : new VulnApiError(404, 'not_found', msg);
    }
    if (res.status === 401 || res.status === 403) {
      throw new VulnApiError(
        res.status,
        'auth',
        res.status === 401
          ? 'The Broker requires a token for vulnerability reads and none was presented. Set the frontend read token (BROKER_AUTH_TOKEN) in the chart.'
          : 'The token the frontend presents does not have the Broker read scope.',
      );
    }
    if (res.status === 503) throw new VulnApiError(503, 'busy', busyMessage(text), retryAfterMs(res.headers));
    if (res.status === 400) throw new VulnApiError(400, 'bad_request', msg);
    if (res.status === 409 || res.status === 422) throw new VulnApiError(res.status, 'bad_request', msg);
    throw new VulnApiError(res.status, 'error', msg);
  }

  /** `GET /vulnerabilities`: CVEs grouped by id, most severe first. */
  listCves(q: CveListQuery = {}): Promise<CvePage> {
    return this.json<CvePage>(
      '/vulnerabilities',
      {
        severity: q.severity?.length ? q.severity.join(',') : undefined,
        fixable: q.fixable,
        namespace: q.namespace,
        running: q.running,
        ...tierParams(q),
        limit: q.limit,
        after: q.after,
      },
      true,
    );
  }

  /** `GET /vulnerabilities/{id}/exposure`. 404 = no inventory digest affected. */
  getExposure(id: string, windowHours?: number, signal?: AbortSignal): Promise<Exposure> {
    return this.json<Exposure>(`/vulnerabilities/${seg(id)}/exposure`, { window_hours: windowHours }, false, signal);
  }

  /** `GET /images`: inventory digests (cluster-wide unless `namespace`). */
  listImages(q: { namespace?: string; limit?: number; after?: string } = {}): Promise<ImagePage> {
    return this.json<ImagePage>('/images', q, true);
  }

  /** `GET /images/{digest}`: the image and the workloads that run it. */
  getImage(digest: string): Promise<ImageDetail> {
    return this.json<ImageDetail>(`/images/${seg(digest)}`);
  }

  /** `GET /images/{digest}/vulnerabilities`: deduplicated findings + the reports behind them. */
  getImageVulns(digest: string, q: { limit?: number; after?: string; source?: string } & TierFilters = {}, signal?: AbortSignal): Promise<ImageVulnsPage> {
    const { tier, kev, epssMin, inUse, ...rest } = q;
    return this.json<ImageVulnsPage>(`/images/${seg(digest)}/vulnerabilities`, { ...rest, ...tierParams({ tier, kev, epssMin, inUse }) }, false, signal);
  }

  /** `GET /images/{digest}/sbom`: every source's SBOM (reports) and one's components. */
  getImageSbom(digest: string, q: { limit?: number; after?: number; source?: string } = {}): Promise<SbomPage> {
    return this.json<SbomPage>(`/images/${seg(digest)}/sbom`, q);
  }

  /** `GET /attestations/running`: running workload containers with their image's verdict (null = not checked). */
  listRunningSignatures(q: { namespace?: string; limit?: number; after?: string } = {}): Promise<RunningSignaturePage> {
    return this.json<RunningSignaturePage>('/attestations/running', q, NO_SIGNATURES);
  }

  /** `GET /attestations/policy`: an audit-mode admission policy (YAML) from the signers verified on running images. */
  admissionPolicy(q: { format?: AdmissionFormat; namespace?: string } = {}, signal?: AbortSignal): Promise<string> {
    return this.read('/attestations/policy', { format: q.format, mode: 'audit', namespace: q.namespace }, NO_SIGNATURES, 'application/yaml', signal);
  }

  /** The `admission` artifact of a workload's export bundle, in audit mode (`GET …/export`, read-only). */
  async workloadAdmission(ns: string, kind: string, name: string, signal?: AbortSignal): Promise<ExportManifest> {
    return this.json<ExportManifest>(`/workloads/${seg(ns)}/${seg(kind)}/${seg(name)}/export`, { artifacts: 'admission', mode: 'audit', format: 'zip-manifest' }, false, signal);
  }
}

const NO_SIGNATURES = 'This Broker does not serve signature results. Upgrade the Broker to a release with signature discovery.';

export const vulnApi = new VulnApi();
