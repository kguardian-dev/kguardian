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

When `BROKER_AUTH_TOKEN` is set, all endpoints except `/health` and `/metrics` require a bearer token.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `LISTEN_ADDR` | `0.0.0.0:9090` | HTTP bind address |
| `DATABASE_URL` | — (required) | PostgreSQL connection string |
| `DB_POOL_MAX_SIZE` | `32` | r2d2 pool size (floored to keep headroom over audit permits) |
| `DB_STATEMENT_TIMEOUT_MS` | `30000` | Per-statement timeout backstop; `0` disables |
| `DB_MIGRATION_MAX_RETRIES` | `10` | Startup migration retry budget (2s spacing) |
| `BROKER_AUTH_TOKEN` | unset | Enables bearer-token auth when set |
| `EVALUATOR_URL` | unset | Enables audit-evaluator forwarding when set |
| `AUDIT_INFLIGHT_PERMITS` | `16` | Max concurrent evaluator calls |
| `AUDIT_QUEUE_CAPACITY` | `2048` | Bounded ingest→audit queue size |
| `AUDIT_EVAL_TIMEOUT_MS` | `500` | Per-call evaluator timeout (min 50) |
| `AUDIT_VERDICTS_RETENTION_DAYS` | `30` | Verdict retention; `0` disables pruning |
| `AUDIT_VERDICTS_RETENTION_INTERVAL_SECS` | `3600` | Pruner cadence |
| `AUDIT_VERDICTS_RETENTION_BATCH_SIZE` | `5000` | Rows deleted per pruning batch |
| `TELEMETRY_ENABLED` | `true` | Daily anonymous version check-in; `false` disables |
| `TELEMETRY_ENDPOINT` | `https://version.kguardian.dev/v1/check` | Check-in endpoint override |
| `TELEMETRY_INTERVAL_SECS` | `86400` | Check-in cadence (min 3600) |
| `CHART_VERSION` / `KUBE_VERSION` | unset | Reported in the version check-in |
| `RUST_LOG` | `info` | Log level |
