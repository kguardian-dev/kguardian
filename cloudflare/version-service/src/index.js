/**
 * kguardian version service — the server side of the broker's daily
 * anonymous check-in (see docs/telemetry.mdx; the client is
 * broker/src/version_check.rs).
 *
 * GET /v1/check?install=&broker=&chart=&k8s=&nodes=&arch=
 *   → { "latest": { "chart": "1.13.2", "broker": "1.11.1", ... } }
 *
 * Latest versions come from the GitHub Releases API, cached via the
 * Workers Cache API for CACHE_TTL_SECS so the worker never rate-limits
 * against GitHub and
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
// Long-TTL stale copy served when GitHub errors on a cold fresh-cache miss
// (shared egress IPs can hit GitHub's unauthenticated rate limit). A day-old
// version map beats an empty one; clients only check daily anyway.
const STALE_KEY = "https://version.kguardian.dev/__cache/latest-versions-stale";
const STALE_TTL_SECS = 24 * 60 * 60;

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
        // Optional: raises the rate limit from 60/h to 5000/h. The
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
  let fresh;
  try {
    fresh = await fetchLatestFromGitHub(env);
  } catch (e) {
    // GitHub unreachable/rate-limited on a cold fresh-cache miss: serve the
    // long-TTL stale copy rather than an empty map.
    const stale = await cache.match(STALE_KEY);
    if (stale) {
      console.warn("serving stale latest-versions:", e.message);
      return stale.json();
    }
    throw e;
  }
  await cache.put(
    CACHE_KEY,
    Response.json(fresh, {
      headers: { "Cache-Control": `public, max-age=${CACHE_TTL_SECS}` },
    }),
  );
  await cache.put(
    STALE_KEY,
    Response.json(fresh, {
      headers: { "Cache-Control": `public, max-age=${STALE_TTL_SECS}` },
    }),
  );
  return fresh;
}

// Field shapes a genuine broker check-in can produce (wire contract:
// docs/telemetry.mdx, client: broker/src/version_check.rs). The endpoint
// is public, so anything can hit it — param-less curl pokes, bots,
// fuzzers. Those still get a version response, but a check-in is only
// recorded when every field validates: AE is append-only with a 3-month
// retention, so a junk row can't be deleted once written.
const INSTALL_UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Semver with optional -prerelease/+build (dev charts: "1.14.1+a1f714b…").
const SEMVER = /^\d+\.\d+\.\d+(?:[+-][0-9A-Za-z.-]{1,48})?$/;
// kubelet/apiserver format, incl. distro suffixes ("v1.28.3+k3s1",
// "v1.28.9-eks-036c24b").
const K8S_VERSION = /^v\d+\.\d+\.\d+(?:[+-][0-9A-Za-z.-]{1,48})?$/;
// Rust std::env::consts::ARCH values (x86_64, aarch64, …).
const ARCH = /^[A-Za-z0-9_]{1,16}$/;
const MAX_NODES = 10_000;

function parseCheckin(q) {
  const install = q.get("install") ?? "";
  const broker = q.get("broker") ?? "";
  const chart = q.get("chart") ?? "";
  const k8s = q.get("k8s") ?? "";
  const arch = q.get("arch") ?? "";
  const nodes = Number(q.get("nodes"));
  if (!INSTALL_UUID.test(install)) return null;
  if (!SEMVER.test(broker)) return null;
  // chart/k8s come from env vars the chart injects; a broker running
  // outside the chart sends the literal "unknown" on purpose so
  // non-chart installs are still countable (version_check.rs). The
  // compile-time fields (broker, arch) never legitimately do.
  if (chart !== "unknown" && !SEMVER.test(chart)) return null;
  if (k8s !== "unknown" && !K8S_VERSION.test(k8s)) return null;
  if (!ARCH.test(arch)) return null;
  if (!Number.isInteger(nodes) || nodes < 0 || nodes > MAX_NODES) return null;
  return { install, broker, chart, k8s, arch, nodes };
}

function recordCheckin(env, request, url) {
  // Analytics Engine is fire-and-forget and additive-only; a schema of
  // blobs (strings) + doubles (numbers) + an index. The install UUID is
  // the index so per-install queries (active installs, version spread)
  // are cheap.
  if (!env.TELEMETRY) return; // dataset unbound in local dev
  const c = parseCheckin(url.searchParams);
  if (!c) return;
  env.TELEMETRY.writeDataPoint({
    indexes: [c.install],
    blobs: [c.broker, c.chart, c.k8s, c.arch, request.cf?.country ?? "unknown"],
    doubles: [c.nodes],
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/healthz") {
      return Response.json({ ok: true });
    }

    // Humans curious what this endpoint is land on the page that documents
    // exactly what it collects.
    if (url.pathname === "/") {
      return Response.redirect("https://docs.kguardian.dev/telemetry", 302);
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
