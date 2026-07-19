# kguardian version service

Cloudflare Worker behind `https://version.kguardian.dev` — the server side of
the broker's daily anonymous check-in ([docs/telemetry](../../docs/telemetry.mdx),
client: [`broker/src/version_check.rs`](../../broker/src/version_check.rs)).

`GET /v1/check` returns the latest released component versions (GitHub
Releases, cached 5 min in KV) and records the check-in's metadata in Workers
Analytics Engine. IPs are not persisted; geo is Cloudflare's country code.

## Deploy

```bash
cd cloudflare/version-service
wrangler kv namespace create VERSIONS   # paste the id into wrangler.toml
wrangler deploy
wrangler secret put GITHUB_TOKEN        # optional: higher GitHub rate limit
```

The `version.kguardian.dev` custom domain is claimed on deploy (the
`kguardian.dev` zone must be on the deploying account).

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
