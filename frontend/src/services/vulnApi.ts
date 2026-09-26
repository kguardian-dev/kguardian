import apiClient from './api';
import { isTimeout, READ_TIMEOUT_MS, timeoutMessage, timeoutSignal } from './readTimeout';
import type { CvePage, Exposure, ImageDetail, ImagePage, ImageVulnsPage, SbomPage, VulnSeverity } from '../types/vulns';

/**
 * Typed read-only client for the supply-chain reads (#1671) and the image
 * inventory (#1655). `fetch`-based, like ProfileApi, so status codes and
 * bodies survive for honest error states.
 */

/**
 *  - `not_found`: 404 on an exposure / image read (no affected image, or
 *    the digest is not in the inventory);
 *  - `unsupported`: 404 on a list route: a Broker without these endpoints;
 *  - `busy`: 503, the read budget shed the request;
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
  constructor(status: number, kind: VulnErrorKind, message: string) {
    super(message);
    this.name = 'VulnApiError';
    this.status = status;
    this.kind = kind;
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

  private async json<T>(path: string, query: Record<string, string | number | boolean | undefined> = {}, listRoute = false): Promise<T> {
    const sp = new URLSearchParams();
    for (const [k, v] of Object.entries(query)) if (v !== undefined && v !== '') sp.set(k, String(v));
    const q = sp.toString();
    let res: Response;
    let text: string;
    try {
      res = await this.fetchImpl(`${this.base}${path}${q ? `?${q}` : ''}`, {
        headers: { Accept: 'application/json' },
        credentials: 'same-origin',
        signal: timeoutSignal(this.timeoutMs),
      });
      text = await res.text();
    } catch (err) {
      if (isTimeout(err)) throw new VulnApiError(0, 'timeout', timeoutMessage(this.timeoutMs));
      throw new VulnApiError(0, 'error', `Could not reach the Broker: ${vulnErrorMessage(err)}`);
    }
    if (res.ok) return JSON.parse(text) as T;
    const msg = text.trim() || `request failed with ${res.status}`;
    if (res.status === 404) {
      throw listRoute
        ? new VulnApiError(404, 'unsupported', 'This Broker does not serve vulnerability data. Upgrade the Broker to a release with the supply-chain endpoints.')
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
    if (res.status === 503) throw new VulnApiError(503, 'busy', 'The Broker is shedding reads right now (read budget). Try again in a few seconds.');
    if (res.status === 400) throw new VulnApiError(400, 'bad_request', msg);
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
  getExposure(id: string, windowHours?: number): Promise<Exposure> {
    return this.json<Exposure>(`/vulnerabilities/${seg(id)}/exposure`, { window_hours: windowHours });
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
  getImageVulns(digest: string, q: { limit?: number; after?: string; source?: string } & TierFilters = {}): Promise<ImageVulnsPage> {
    const { tier, kev, epssMin, inUse, ...rest } = q;
    return this.json<ImageVulnsPage>(`/images/${seg(digest)}/vulnerabilities`, { ...rest, ...tierParams({ tier, kev, epssMin, inUse }) });
  }

  /** `GET /images/{digest}/sbom`: every source's SBOM (reports) and one's components. */
  getImageSbom(digest: string, q: { limit?: number; after?: number; source?: string } = {}): Promise<SbomPage> {
    return this.json<SbomPage>(`/images/${seg(digest)}/sbom`, q);
  }
}

export const vulnApi = new VulnApi();
