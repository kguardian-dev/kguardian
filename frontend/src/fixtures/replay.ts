import { ProfileApi } from '../services/profileApi';
import { ALL_CAPTURES, type Capture } from './profile';

/**
 * A ProfileApi whose fetch replays captured Broker responses. A request is
 * answered by the capture whose `request` line matches it exactly
 * (`GET /path?query`, the /api prefix removed, compared URL-decoded);
 * `extra` captures are tried
 * first, so a test can add or override one. Anything else is a 404 with an
 * empty body — what a Broker with no such route sends.
 */
export function replayApi(extra: Capture[] = []) {
  const calls: string[] = [];
  const all = [...extra, ...ALL_CAPTURES];
  const fetchImpl = (async (input: RequestInfo | URL) => {
    const url = new URL(String(input), 'http://x');
    const line = `GET ${url.pathname.replace(/^\/api/, '')}${url.search}`;
    calls.push(line);
    // Compare decoded: the captures record the query as typed
    // (after=observability/DaemonSet/…), the client sends it encoded.
    const norm = (r: string) => decodeURIComponent(r.replace(/\+/g, ' '));
    const hit = all.find((c) => norm(c.request) === norm(line));
    if (!hit) return new Response('', { status: 404 });
    return new Response(JSON.stringify(hit.body), { status: hit.status });
  }) as typeof fetch;
  return { api: new ProfileApi({ fetchImpl }), calls };
}

/** A capture-shaped answer for a request the Broker was not captured on. */
export function answer<T>(request: string, body: T, status = 200): Capture<T> {
  return { request, status, body };
}
