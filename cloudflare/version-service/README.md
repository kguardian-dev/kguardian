# kguardian version service

Cloudflare Worker behind `https://version.kguardian.dev` — the server side of
the broker's daily anonymous check-in ([docs/telemetry](../../docs/telemetry.mdx),
client: [`broker/src/version_check.rs`](../../broker/src/version_check.rs)).

`GET /v1/check` returns the latest released component versions (GitHub
Releases, cached 5 min via the Workers Cache API) and records the check-in's metadata in Workers
Analytics Engine. IPs are not persisted; geo is Cloudflare's country code.

## Deploy

Deployed via Cloudflare's Git-connected Workers Builds: the dashboard
project **kguardian** points at this repo with root directory
`cloudflare/version-service`, and every push to `main` touching this
directory deploys automatically. No pre-created resources are needed —
the GitHub-releases cache uses the Workers Cache API and the Analytics
Engine dataset is provisioned on first deploy.

The `version.kguardian.dev` custom domain is claimed on deploy (the
`kguardian.dev` zone must be on the deploying account).

Manual deploy (fallback): `npx wrangler deploy` from this directory.
Optional: `wrangler secret put GITHUB_TOKEN` raises the GitHub API rate
limit; the cache keeps traffic minimal without it.

## Query the telemetry

Workers Analytics Engine, SQL API — e.g. active installs over 30 days:

```sql
SELECT COUNT(DISTINCT index1) AS installs
FROM kguardian_telemetry
WHERE timestamp > NOW() - INTERVAL '30' DAY
```

Version spread: `blob2` is the chart version; `blob3` the k8s version;
`blob5` the country; `double1` the node count.

## Local test

```bash
wrangler dev
curl "http://localhost:8787/v1/check?install=test&broker=1.11.1&chart=1.13.2&k8s=v1.33.0&nodes=3&arch=x86_64"
```
