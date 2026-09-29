import apiClient from './api';
import { busyMessage, errorBodyText, retryAfterMs } from './brokerBusy';
import { isTimeout, PROFILE_READ_TIMEOUT_MS, timeoutMessage, timeoutSignal } from './readTimeout';
import type { PostureStatus, ProfileDiff, VersionList, WorkloadListPage, WorkloadProfile } from '../types/profile';

/**
 * Typed read-only client for the broker's workload security profile
 * endpoints (contract v1). `fetch`-based like SeccompApi so the broker's
 * structured error codes survive.
 */

/**
 * What a failure means for the UI:
 *  - `workload_not_found` / `revision_not_found`: the broker's own 404 codes;
 *  - `unsupported`: a 404 with no contract error code — a Broker that
 *    predates the profile endpoints (the route itself does not exist);
 *  - `busy`: 503, the read budget shed the request or the database cancelled
 *    the statement; the message follows the body and `retryAfterMs` the
 *    Broker's `Retry-After`; retry later;
 *  - `bad_request`: 400;
 *  - `auth`: 401 / 403, no token presented, or one without the read scope
 *    (also what a sign-in proxy answers once the session has expired);
 *  - `timeout`: no answer within PROFILE_READ_TIMEOUT_MS (retryable);
 *  - `error`: anything else (network, 500).
 */
export type ProfileErrorKind = 'workload_not_found' | 'revision_not_found' | 'unsupported' | 'busy' | 'bad_request' | 'auth' | 'timeout' | 'error';

export class ProfileApiError extends Error {
  readonly status: number;
  readonly kind: ProfileErrorKind;
  /** The Broker's `Retry-After` on a 503, in ms; null when it sent none. */
  readonly retryAfterMs: number | null;

  constructor(status: number, kind: ProfileErrorKind, message: string, retryAfterMs: number | null = null) {
    super(message);
    this.name = 'ProfileApiError';
    this.status = status;
    this.kind = kind;
    this.retryAfterMs = retryAfterMs;
  }
}

export function errorKind(err: unknown): ProfileErrorKind {
  return err instanceof ProfileApiError ? err.kind : 'error';
}

export function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

function classify(status: number, text: string, headers?: Headers): ProfileApiError {
  let code: string | undefined;
  let message: string | undefined;
  try {
    const body = JSON.parse(text) as { error?: unknown; message?: unknown };
    if (typeof body.error === 'string') code = body.error;
    if (typeof body.message === 'string') message = body.message;
  } catch {
    /* plain-text body */
  }
  const msg = message ?? (errorBodyText(text) || `request failed with ${status}`);
  if (status === 404 && (code === 'workload_not_found' || code === 'revision_not_found')) return new ProfileApiError(status, code, msg);
  if (status === 404) return new ProfileApiError(status, 'unsupported', 'This Broker does not serve workload profiles. Upgrade the Broker to a release with the profile API.');
  if (status === 401) return new ProfileApiError(status, 'auth', 'The Broker requires a token for profile reads and none was presented. Set the frontend read token (BROKER_AUTH_TOKEN) in the chart, or sign in again if the UI is behind a sign-in proxy.');
  if (status === 403) return new ProfileApiError(status, 'auth', 'The token the frontend presents does not have the Broker read scope.');
  if (status === 503) return new ProfileApiError(status, 'busy', busyMessage(text), headers ? retryAfterMs(headers) : null);
  if (status === 400) return new ProfileApiError(status, 'bad_request', msg);
  return new ProfileApiError(status, 'error', msg);
}

const seg = encodeURIComponent;

export interface ListWorkloadsQuery {
  namespace?: string;
  /** Case-insensitive substring of the workload name (server-side). */
  search?: string;
  kind?: string;
  status?: PostureStatus;
  limit?: number;
  after?: string;
}

export class ProfileApi {
  private readonly fetchImpl: typeof fetch;

  private readonly timeoutMs: number;

  constructor(opts: { fetchImpl?: typeof fetch; timeoutMs?: number } = {}) {
    this.fetchImpl = opts.fetchImpl ?? ((...args) => fetch(...args));
    this.timeoutMs = opts.timeoutMs ?? PROFILE_READ_TIMEOUT_MS;
  }

  private get base(): string {
    return (apiClient?.baseURL ?? '/api').replace(/\/$/, '');
  }

  private async json<T>(path: string, query: Record<string, string | number | undefined> = {}): Promise<T> {
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
      if (isTimeout(err)) throw new ProfileApiError(0, 'timeout', timeoutMessage(this.timeoutMs));
      throw new ProfileApiError(0, 'error', `Could not reach the Broker: ${errorMessage(err)}`);
    }
    if (!res.ok) throw classify(res.status, text, res.headers);
    return JSON.parse(text) as T;
  }

  private workloadPath(ns: string, kind: string, name: string): string {
    return `/workloads/${seg(ns)}/${seg(kind)}/${seg(name)}`;
  }

  /** `GET /workloads` — one page. */
  listWorkloads(query: ListWorkloadsQuery = {}): Promise<WorkloadListPage> {
    return this.json<WorkloadListPage>('/workloads', { ...query });
  }

  /** `GET /workloads/{ns}/{kind}/{name}/profile` — computed live. */
  getProfile(ns: string, kind: string, name: string): Promise<WorkloadProfile> {
    return this.json<WorkloadProfile>(`${this.workloadPath(ns, kind, name)}/profile`);
  }

  /** `GET …/profile/versions`, newest first. */
  listVersions(ns: string, kind: string, name: string, opts: { limit?: number; before?: number } = {}): Promise<VersionList> {
    return this.json<VersionList>(`${this.workloadPath(ns, kind, name)}/profile/versions`, opts);
  }

  /** `GET …/profile/diff?from=&to=` (both optional: latest vs its predecessor). */
  getDiff(ns: string, kind: string, name: string, opts: { from?: number; to?: number } = {}): Promise<ProfileDiff> {
    return this.json<ProfileDiff>(`${this.workloadPath(ns, kind, name)}/profile/diff`, opts);
  }
}

export const profileApi = new ProfileApi();
