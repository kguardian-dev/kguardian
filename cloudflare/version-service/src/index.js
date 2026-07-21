/**
 * kguardian version service — the server side of the broker's daily
 * anonymous check-in (see docs/telemetry.mdx; the client is
 * broker/src/version_check.rs).
 *
 * GET /v1/check?install=&broker=&chart=&k8s=&nodes=&arch=
 *   → { "latest": { "chart": "1.13.2", "broker": "1.11.1", ... } }
 *
 * Latest versions come from the GitHub Releases API, cached in KV for
 * CACHE_TTL_SECS so the worker never rate-limits against GitHub and
 * check-ins stay fast. Each request's metadata is written to Workers
 * Analytics Engine (dataset: TELEMETRY) — that dataset is the project's
 * usage telemetry. IP addresses are not persisted; country comes from
 * Cloudflare's edge metadata.
 *
 * Privacy contract (must match docs/telemetry.mdx):
 *   stored per check-in → install UUID, versions, k8s version, node
 *   count, arch, country. Nothing else.
 */

const REPO = "kguardian-dev/kguardian";
// Synthetic cache key for the Workers Cache API (per-colo). Any URL on a
// zone we control works; this path is never actually routable.
const CACHE_KEY = "https://version.kguardian.dev/__cache/latest-versions";
const CACHE_TTL_SECS = 300;

/** Tag prefixes → response keys. Matches release-please's component tags. */
const COMPONENTS = [
  "chart",
  "broker",
  "controller",
  "frontend",
  "advisor",
  "llm-bridge",
  "mcp-server",
  "evaluator",
];

async function fetchLatestFromGitHub(env) {
  // One page of most-recent releases covers every component: kguardian
  // cuts at most a handful of releases per component between cache
  // expiries, and we only need the newest tag per prefix.
  const resp = await fetch(
    `https://api.github.com/repos/${REPO}/releases?per_page=100`,
    {
      headers: {
        "User-Agent": "kguardian-version-service",
        Accept: "application/vnd.github+json",
        // Optional: raises the rate limit from 60/h to 5000/h. The KV
        // cache keeps us far below either, so absence is fine.
        ...(env.GITHUB_TOKEN
          ? { Authorization: `Bearer ${env.GITHUB_TOKEN}` }
          : {}),
      },
    },
  );
  if (!resp.ok) throw new Error(`GitHub API ${resp.status}`);
  const releases = await resp.json();

  const latest = {};
  for (const rel of releases) {
    if (rel.draft || rel.prerelease) continue;
    // Tags look like "chart/v1.13.2" or "broker/v1.11.1".
    const [component, version] = rel.tag_name.split("/");
    if (!version || !COMPONENTS.includes(component)) continue;
    // Releases arrive newest-first; keep only the first per component.
    if (!(component in latest)) latest[component] = version.replace(/^v/, "");
  }
  return latest;
}

async function latestVersions(env) {
  // Workers Cache API instead of KV: per-colo rather than global, which is
  // fine here — worst case each colo refreshes from GitHub once per TTL,
  // still far under any rate limit — and it needs no pre-created namespace,
  // so the Git-connected build deploys with zero manual resources.
  const cache = caches.default;
  const hit = await cache.match(CACHE_KEY);
  if (hit) return hit.json();
  const fresh = await fetchLatestFromGitHub(env);
  await cache.put(
    CACHE_KEY,
    Response.json(fresh, {
      headers: { "Cache-Control": `public, max-age=${CACHE_TTL_SECS}` },
    }),
  );
  return fresh;
}

function recordCheckin(env, request, url) {
  // Analytics Engine is fire-and-forget and additive-only; a schema of
  // blobs (strings) + doubles (numbers) + an index. The install UUID is
  // the index so per-install queries (active installs, version spread)
  // are cheap.
  if (!env.TELEMETRY) return; // dataset unbound in local dev
  const q = url.searchParams;
  env.TELEMETRY.writeDataPoint({
    indexes: [q.get("install") ?? "unknown"],
    blobs: [
      q.get("broker") ?? "unknown",
      q.get("chart") ?? "unknown",
      q.get("k8s") ?? "unknown",
      q.get("arch") ?? "unknown",
      request.cf?.country ?? "unknown",
    ],
    doubles: [Number(q.get("nodes")) || 0],
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/healthz") {
      return Response.json({ ok: true });
    }

    if (url.pathname !== "/v1/check" || request.method !== "GET") {
      return Response.json({ error: "not found" }, { status: 404 });
    }

    recordCheckin(env, request, url);

    let latest;
    try {
      latest = await latestVersions(env);
    } catch (e) {
      // GitHub briefly unreachable and cache cold: the check-in was
      // still recorded; give the client an empty payload rather than an
      // error it would just discard.
      console.error("latest-version lookup failed:", e.message);
      latest = {};
    }

    return Response.json(
      { latest },
      {
        headers: {
          // Downstream caches may keep it briefly; clients only call daily.
          "Cache-Control": `public, max-age=${CACHE_TTL_SECS}`,
        },
      },
    );
  },
};
