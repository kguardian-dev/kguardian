# Broker

The Broker is kguardian's API server: a Rust (actix-web) service that stores the telemetry the Controller captures — pod traffic, pod/service specs, syscalls — in PostgreSQL and serves it back to the UI, CLI, evaluator, and MCP server. It runs as a single replica behind the chart's `kguardian-broker` Service.

## Build

```bash
DOCKER_BUILDKIT=1 docker build . -t ghcr.io/kguardian-dev/kguardian/broker:latest
```

## Endpoints

Ingest (POST):

- `/pod/traffic` and `/pod/traffic/batch` — traffic rows from the Controller
- `/pod/spec`, `/pod/syscalls`, `/svc/spec` — pod details, syscalls, service details
- `/pod/mark_dead` — mark a pod as no longer running

Query (GET):

- `/pod/traffic` (`?limit=`, default 5000, max 20000), `/pod/traffic/{name}`
- `/pod/info`, `/pod/name/{name}`, `/pod/ip/{ip}`, `/pod/list/{node}`
- `/pod/syscalls/{name}`
- `/svc/info`, `/svc/ip/{ip}`
- `/audit/verdicts`
- `/version`, `/health`, `/metrics` (Prometheus text format)

With auth on (any `BROKER_TOKEN_*` or `BROKER_AUTH_TOKEN` set), every endpoint except `/health` and `/metrics` requires a bearer token carrying the endpoint's scope (`401` without a valid token, `403` without the scope). Each route's scope is declared in `src/auth.rs` (`ROUTES`), and each route carries `wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"`, which checks the scope after routing, against the route the router actually matched. A unit test fails for any route that is missing either one. At runtime a route with no `ROUTES` entry answers `403` to everyone, and a path that matches no route answers `404` before any handler runs. See the [authentication docs](https://kguardian.dev/api-reference/introduction#authentication).

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `LISTEN_ADDR` | `0.0.0.0:9090` | HTTP bind address |
| `DATABASE_URL` | — (required) | PostgreSQL connection string |
| `DB_POOL_MAX_SIZE` | `32` | r2d2 pool size (floored to keep headroom over audit permits) |
| `DB_STATEMENT_TIMEOUT_MS` | `30000` | Per-statement timeout backstop; `0` disables |
| `DB_MIGRATION_MAX_RETRIES` | `10` | Startup migration retry budget (2s spacing) |
| `BROKER_TOKEN_READ` | unset | Token with the `read` scope (frontend proxy, llm-bridge, CLI) |
| `BROKER_TOKEN_INGEST` | unset | Token with `ingest` + `read` (controller) |
| `BROKER_TOKEN_SUPPLYCHAIN` | unset | Token with `supplychain` + `read` (supply-chain writes) |
| `BROKER_TOKEN_ADMIN` | unset | Token with every scope (operators) |
| `BROKER_AUTH_TOKEN` | unset | Shared token from before scopes existed: `read` + `ingest` |
| `EVALUATOR_URL` | unset | Enables audit-evaluator forwarding when set |
| `AUDIT_INFLIGHT_PERMITS` | `16` | Max concurrent evaluator calls |
| `AUDIT_QUEUE_CAPACITY` | `2048` | Bounded ingest→audit queue size |
| `AUDIT_EVAL_TIMEOUT_MS` | `500` | Per-call evaluator timeout (min 50) |
| `AUDIT_VERDICTS_RETENTION_DAYS` | `30` | Verdict retention; `0` disables pruning |
| `AUDIT_VERDICTS_RETENTION_INTERVAL_SECS` | `3600` | Pruner cadence |
| `AUDIT_VERDICTS_RETENTION_BATCH_SIZE` | `5000` | Rows deleted per pruning batch |
| `POD_TRAFFIC_RETENTION_DAYS` | `14` | Traffic retention for departed pods, and for running pods' rows superseded by a newer row with the same rule and in-cluster peer; `0` disables pruning |
| `POD_TRAFFIC_MAX_ROWS_PER_POD` | `0` | Opt-in per-pod cap; over it, the pod's oldest rows with no peer identity are deleted (never in-cluster peers). `0` = off |
| `POD_TRAFFIC_RETENTION_INTERVAL_SECS` | `3600` | Pruner cadence (min 60) |
| `POD_TRAFFIC_RETENTION_BATCH_SIZE` | `5000` | Rows examined per pruning batch, clamped to [100, 100000] |
| `TELEMETRY_ENABLED` | `true` | Daily anonymous version check-in; `false` disables |
| `TELEMETRY_ENDPOINT` | `https://version.kguardian.dev/v1/check` | Check-in endpoint override |
| `TELEMETRY_INTERVAL_SECS` | `86400` | Check-in cadence (min 3600) |
| `CHART_VERSION` / `KUBE_VERSION` | unset | Reported in the version check-in |
| `RUST_LOG` | `info` | Log level |

PR images (`pr-<N>` tags on GHCR) are multi-arch: each architecture builds
natively in CI and the broker image is smoke-executed on both amd64 and arm64
before the manifest is assembled.
