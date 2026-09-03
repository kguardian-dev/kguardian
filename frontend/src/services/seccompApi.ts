import apiClient from './api';
import type { ExportBody, ExportParams, WorkloadProfileDetail, WorkloadProfileSummary } from '../types/seccompWorkload';

/**
 * Typed, read-only client for the broker's per-workload seccomp endpoints.
 * The UI never writes cluster or broker state: it reads the observed profile,
 * the mirrored CR status, and renders/export the CR manifest the user commits.
 *
 * `fetch`-based rather than another method on the axios BrokerAPIClient so the
 * broker's structured error bodies survive (the axios wrapper's
 * swallow-and-return-empty convention would lose them) and so `/export` can
 * return YAML text. Routes through the same base path (`apiClient.baseURL`,
 * the `/api` proxy) — one broker origin.
 */

export class SeccompApiError extends Error {
  readonly status: number;
  /** Parsed JSON body when the broker sent one, else the raw text. */
  readonly body: unknown;

  constructor(status: number, message: string, body: unknown) {
    super(message);
    this.name = 'SeccompApiError';
    this.status = status;
    this.body = body;
  }
}

export interface SeccompApiOptions {
  fetchImpl?: typeof fetch;
}

function seg(s: string): string {
  return encodeURIComponent(s);
}

export class SeccompApi {
  private readonly fetchImpl: typeof fetch;

  constructor(opts: SeccompApiOptions = {}) {
    // Bind lazily so a test can install a global fetch mock after construction.
    this.fetchImpl = opts.fetchImpl ?? ((...args) => fetch(...args));
  }

  private get base(): string {
    return apiClient.baseURL.replace(/\/$/, '');
  }

  private async send(method: 'GET' | 'POST', path: string, accept: string, body?: unknown): Promise<{ status: number; ok: boolean; text: string }> {
    const headers: Record<string, string> = { Accept: accept };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const res = await this.fetchImpl(`${this.base}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'same-origin',
    });
    return { status: res.status, ok: res.ok, text: await res.text() };
  }

  private get(path: string, accept: string) {
    return this.send('GET', path, accept);
  }

  private fail(status: number, text: string, path: string, method = 'GET'): never {
    let parsed: unknown = text;
    try {
      parsed = JSON.parse(text);
    } catch {
      /* not JSON */
    }
    const msg =
      parsed && typeof parsed === 'object' && typeof (parsed as { error?: unknown }).error === 'string'
        ? (parsed as { error: string }).error
        : text || `${method} ${path} failed with ${status}`;
    throw new SeccompApiError(status, msg, parsed);
  }

  private async json<T>(path: string): Promise<T> {
    const r = await this.get(path, 'application/json');
    if (!r.ok) this.fail(r.status, r.text, path);
    return (r.text ? JSON.parse(r.text) : undefined) as T;
  }

  private workloadPath(ns: string, kind: string, name: string): string {
    return `/seccomp/profiles/${seg(ns)}/${seg(kind)}/${seg(name)}`;
  }

  /** `GET /seccomp/profiles` — every workload with an observed set. */
  async listProfiles(): Promise<WorkloadProfileSummary[]> {
    const rows = await this.json<WorkloadProfileSummary[] | null>('/seccomp/profiles');
    return Array.isArray(rows) ? rows : [];
  }

  /** `GET /seccomp/profiles/{ns}/{kind}/{name}` — summary + rendered observed profile. */
  getProfile(ns: string, kind: string, name: string): Promise<WorkloadProfileDetail> {
    return this.json<WorkloadProfileDetail>(this.workloadPath(ns, kind, name));
  }

  /**
   * `GET …/export` — the `SeccompProfile` CR manifest (YAML by default) rendered
   * from the observed set, with the broker's capture-level comment block (and
   * its partial-capture WARNING when incomplete). Returned as text, verbatim.
   */
  async exportProfile(ns: string, kind: string, name: string, params: ExportParams = {}): Promise<string> {
    const sp = new URLSearchParams();
    if (params.name) sp.set('name', params.name);
    if (params.defaultAction) sp.set('defaultAction', params.defaultAction);
    if (params.format) sp.set('format', params.format);
    const q = sp.toString();
    const path = `${this.workloadPath(ns, kind, name)}/export${q ? `?${q}` : ''}`;
    const r = await this.get(path, params.format === 'json' ? 'application/json' : 'application/yaml');
    if (!r.ok) this.fail(r.status, r.text, path);
    return r.text;
  }

  /**
   * `POST …/export` — same document, with the UI's staged edits applied
   * server-side (`(observed ∪ add) \\ remove`). Still a pure render: the broker
   * stores nothing. Older brokers answer 404/405; callers fall back to the GET
   * form and render the edits locally.
   */
  async exportEdited(ns: string, kind: string, name: string, body: ExportBody): Promise<string> {
    const path = `${this.workloadPath(ns, kind, name)}/export`;
    const r = await this.send('POST', path, body.format === 'json' ? 'application/json' : 'application/yaml', body);
    if (!r.ok) this.fail(r.status, r.text, path, 'POST');
    return r.text;
  }
}

export const seccompApi = new SeccompApi();
