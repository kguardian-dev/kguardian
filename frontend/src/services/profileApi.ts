import apiClient from './api';
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
 *  - `busy`: 503, the read budget shed the request; retry later;
 *  - `bad_request`: 400;
 *  - `error`: anything else (network, 500, auth).
 */
export type ProfileErrorKind = 'workload_not_found' | 'revision_not_found' | 'unsupported' | 'busy' | 'bad_request' | 'error';

export class ProfileApiError extends Error {
  readonly status: number;
  readonly kind: ProfileErrorKind;

  constructor(status: number, kind: ProfileErrorKind, message: string) {
    super(message);
    this.name = 'ProfileApiError';
    this.status = status;
    this.kind = kind;
  }
}

export function errorKind(err: unknown): ProfileErrorKind {
  return err instanceof ProfileApiError ? err.kind : 'error';
}

export function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

function classify(status: number, text: string): ProfileApiError {
  let code: string | undefined;
  let message: string | undefined;
  try {
    const body = JSON.parse(text) as { error?: unknown; message?: unknown };
    if (typeof body.error === 'string') code = body.error;
    if (typeof body.message === 'string') message = body.message;
  } catch {
    /* plain-text body */
  }
  const msg = message ?? (text.trim() || `request failed with ${status}`);
  if (status === 404 && (code === 'workload_not_found' || code === 'revision_not_found')) return new ProfileApiError(status, code, msg);
  if (status === 404) return new ProfileApiError(status, 'unsupported', 'This Broker does not serve workload profiles. Upgrade the Broker to a release with the profile API.');
  if (status === 503) return new ProfileApiError(status, 'busy', 'The Broker is shedding reads right now (read budget). Try again in a few seconds.');
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

  constructor(opts: { fetchImpl?: typeof fetch } = {}) {
    this.fetchImpl = opts.fetchImpl ?? ((...args) => fetch(...args));
  }

  private get base(): string {
    return (apiClient?.baseURL ?? '/api').replace(/\/$/, '');
  }

  private async json<T>(path: string, query: Record<string, string | number | undefined> = {}): Promise<T> {
    const sp = new URLSearchParams();
    for (const [k, v] of Object.entries(query)) if (v !== undefined && v !== '') sp.set(k, String(v));
    const q = sp.toString();
    let res: Response;
    try {
      res = await this.fetchImpl(`${this.base}${path}${q ? `?${q}` : ''}`, {
        headers: { Accept: 'application/json' },
        credentials: 'same-origin',
      });
    } catch (err) {
      throw new ProfileApiError(0, 'error', `Could not reach the Broker: ${errorMessage(err)}`);
    }
    const text = await res.text();
    if (!res.ok) throw classify(res.status, text);
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
