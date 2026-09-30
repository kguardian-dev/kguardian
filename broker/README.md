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
| `DATABASE_URL` | — (required) | PostgreSQL connection string. Direct or session-mode pooled, not PgBouncer transaction mode: the compute history index build holds a session-scoped advisory lock |
| `DB_POOL_MAX_SIZE` | `32` | r2d2 pool size (floored to keep headroom over audit permits) |
| `DB_POOL_MIN_IDLE` | `4` | Idle connections each replica keeps open; the pool grows to `DB_POOL_MAX_SIZE` on demand and idles back down after 10 minutes |
| `DB_STATEMENT_TIMEOUT_MS` | `30000` | Per-statement timeout backstop; `0` disables |
| `DB_MIGRATION_MAX_RETRIES` | `10` | Startup migration retry budget (2s spacing) |
| `BROKER_TOKEN_READ` | unset | Token with the `read` scope (frontend proxy, llm-bridge, CLI) |
| `BROKER_TOKEN_INGEST` | unset | Token with `ingest` + `read` (controller) |
| `BROKER_TOKEN_SUPPLYCHAIN` | unset | Token with `supplychain` + `read` (supply-chain writes) |
| `BROKER_TOKEN_CATALOG` | unset | Token with the `catalog` scope only (the Controller's node catalog claims and SBOM uploads). Without it the catalog writes answer `503` |
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
| `IMAGE_INVENTORY_RUNNING_WINDOW_SECS` | `900` | A digest counts as running while refreshed within this window, or while the pod that last reported it is live; clamped to [360, 604800] |
| `IMAGE_INVENTORY_RETENTION_DAYS` | `30` | Prune image inventory digests no running pod has refreshed for this long; `0` disables pruning |
| `IMAGE_INVENTORY_RETENTION_INTERVAL_SECS` | `3600` | Pruner cadence (min 60) |
| `IMAGE_INVENTORY_RETENTION_BATCH_SIZE` | `5000` | Rows deleted per pruning batch, clamped to [100, 100000] |
| `LEADER_ELECTION_ENABLED` | auto | `true`/`false`; unset or `auto` means on when running in a pod (`KUBERNETES_SERVICE_HOST` set and a service account token mounted). Off: this replica runs every background job |
| `LEADER_ELECTION_LEASE_NAME` | `kguardian-broker-leader` | The `coordination.k8s.io/v1` Lease replicas contend for (chart: `<fullname>-broker-leader`) |
| `LEADER_ELECTION_NAMESPACE` | `POD_NAMESPACE`, then the service account namespace | Namespace of the Lease |
| `LEADER_ELECTION_LEASE_DURATION_SECS` | `15` | How long a follower waits after the leader's last renewal before taking over |
| `LEADER_ELECTION_RENEW_DEADLINE_SECS` | `10` | How long the leader keeps running the jobs without a successful renewal; must be below the lease duration |
| `LEADER_ELECTION_RETRY_PERIOD_SECS` | `2` | Renew/acquire cadence; must be below renew deadline / 1.2 (a bad combination falls back to 15/10/2) |
| `POD_NAME` | hostname | Lease holder identity (downward API). Lease requests go straight to the in-cluster API server and ignore `HTTP(S)_PROXY` |
| `BROKER_MAINTENANCE_VACUUM_ENABLED` | `true` | Leader-only `VACUUM (ANALYZE)` of the small high-churn tables when autovacuum falls behind (see below); `false` disables |
| `BROKER_MAINTENANCE_VACUUM_INTERVAL_SECS` | `300` | How often the leader checks those tables' dead tuples (min 60). One schedule across replicas, like the retention loops (`leader_task_runs`) |
| `BROKER_MAINTENANCE_VACUUM_DEAD_TUPLES` | `10000` | Dead tuples (heap + TOAST) a table needs, and at least a fifth of its live rows, before it is vacuumed (min 1000) |
| `NODE_CATALOG_GRANTS` | `true` | `false` stops every node catalog grant (the kill switch); uploads under a live lease still complete |
| `NODE_CATALOG_MAX_EPOCH` | `1000` | Highest catalog epoch accepted on claims and uploads (`422` above) |
| `NODE_CATALOG_MAX_HOLD_SECS` | `7200` | A claim held longer is not renewed (`409`); at least the 15 minute lease |
| `NODE_CATALOG_RETENTION_DAYS` | `14` | Delete node catalog claims, node SBOMs and package flags this many days after the digest left the image inventory (`images.last_seen`); `0` keeps them |
| `RUST_LOG` | `info` | Log level |

### Running more than one replica

Every replica serves the whole API, but the background jobs that prune or
derive shared data (retention prunes, the compute downsample, the workload
profile snapshotter, the peer late-resolve and stale-pod sweep, the
supply-chain rollups, the image attestation prune, the maintenance VACUUM) run
only on the replica holding a Lease. The rest, which feed each replica's own
`/metrics` and `GET /version`, run everywhere. The full list is in `src/leader.rs`.

A leader that stops renewing stops those jobs after the renew deadline; a
follower takes over once the lease has gone unrenewed for the lease duration
(by its own clock, so node clock skew does not matter). A leader shutting down
gracefully clears the holder, and a follower takes over within one retry
period. A pass that loses leadership stops at its next batch boundary. A new
leader runs each job within a few seconds (plus up to 30 s of jitter) if its
last pass, on any replica, is an interval old (recorded in
`leader_task_runs`), and otherwise keeps that pass's schedule, so a hand-off
neither skips a pass nor repeats one.

If the Lease API is unreachable or failing, every replica stays a follower
and keeps retrying: the jobs pause rather than risk two leaders. If it refuses
the broker (401/403) for about 20 seconds at startup, which means no Role is
bound to its service account (e.g. hand-written manifests), the broker runs
every job itself, which is the behaviour before leader election existed, warns
every five minutes and retries every 30 seconds; once the API accepts it, it
elects normally. `/metrics` shows the state:

- `broker_leader`: 1 on the replica running the jobs
- `broker_leader_election_active{mode="elected|disabled|fallback_forbidden|fallback_misconfigured"}`: 1 only while contending for the Lease
- `broker_leader_transitions_total`: acquisitions and losses on this replica
- `broker_leader_election_errors_total`: failed Lease requests; rising on every replica means no replica can lead and the jobs are paused

### Maintenance VACUUM

A few tables are rewritten every few seconds but stay small:
`pod_compute_latest` (every live container, every 5 s), `node_compute_latest`,
`seccomp_crs`, `seccomp_denial_nodes`, `runtime_in_use_coverage` and
`workload_containers`. Autovacuum normally keeps them clean (the migrations
give the compute tables aggressive per-table settings), but the broker does
not depend on it: with autovacuum stopped on a shared cluster,
`pod_compute_latest` once grew to about 1 GB an hour.

Every `BROKER_MAINTENANCE_VACUUM_INTERVAL_SECS` the leader reads each table's
dead tuples (heap plus its TOAST table) from the statistics collector and runs
a plain `VACUUM (ANALYZE)` on the ones past the threshold, on a dedicated
connection (VACUUM cannot run in a transaction) with a 300 s statement timeout
and a 5 s lock timeout. It never runs `VACUUM FULL`, and it leaves the large
append-and-prune tables (`pod_compute_history`, `pod_traffic`, ...) to
autovacuum and the operator. While autovacuum keeps up, a pass is one catalog
query. VACUUM needs only table ownership, which the broker's database user has
for every table its migrations created (or `MAINTAIN` on PostgreSQL 17+); a
table it may not vacuum is warned about once and skipped. A failed pass backs
off, doubling up to an hour. `/metrics`:

- `broker_maintenance_vacuum_total{table,outcome}`: `vacuumed`, `skipped`
  (under the threshold), `busy` (another VACUUM or DDL held the lock),
  `denied` (not the owner), `failed`
- `broker_maintenance_vacuum_last_success_timestamp_seconds`: the last pass
  that checked every table without a failure (0 on followers). Steady
  `vacuumed` counts mean autovacuum is not doing its job on this database.

### Node catalog

Each node's Controller offers the image digests it runs, and the Broker grants
each digest to exactly one node that runs it (a live pod on that node, by
`pod_details` and the image inventory). The node catalogs the image and posts
the SBOM, stored as SBOM source `node` with trust `scanned`. The design is in
[`docs/design/node-catalog.md`](../docs/design/node-catalog.md); the code is
`src/node_catalog.rs`.

| Route | Scope | |
|---|---|---|
| `POST /catalog/claims` | `catalog` | `{node, platform, epoch, offer[]}`: at most one grant, `{grantsEnabled, grant: {digest, claimToken, leaseExpiresAt, leaseSeconds} \| null}` |
| `PUT /catalog/claims/{digest}` | `catalog` | `X-Kguardian-Claim` token; `{action: renew\|fail\|skip, node, reason}` |
| `POST /catalog/images/{digest}/sbom` | `catalog` | `X-Kguardian-Claim` token; an `ImageSBOM` v1 (paged, gzip, at most 8 MiB compressed) plus `epoch`, `completeness`, `partial_reasons`, `stats` and per component `files_truncated` / `interpreted_content`; up to 4096 file paths per component |
| `GET /catalog/coverage` | `read` | running images with a trusted SBOM (Trivy Operator or node), claims by state, completeness and reason |
| `GET /catalog/status?node=` | `read` | one node's platform, held claims, cataloged count and releases by reason |

The three writes answer `503` until `BROKER_TOKEN_CATALOG` is set. A claim
token that no longer holds its digest (released, re-granted, lease expired),
or an upload `epoch` below the one the claim was granted under, gets `409`
and writes nothing. A grant never moves the digest's epoch; only a stored
SBOM does, and a higher epoch replaces the stored SBOM whatever the scan
times. At most 16 uploads are read or queued at once (the node share of the
ingest queue is half of it, and of the SBOM page staging ceiling); beyond
that `503` with `Retry-After`, before the body is read. The node name in a
claim is self-asserted: one catalog token serves every node, so a stolen one
can claim any digest running on some node, and nothing else. It can also pin
a digest's epoch at the ceiling by uploading at `NODE_CATALOG_MAX_EPOCH`;
recover by deleting that digest's `node_catalog_claims` row, or by raising
`NODE_CATALOG_MAX_EPOCH` and bumping the Controller's epoch above it. A
lease lasts 15 minutes; `timeout`, `oom` and `error` back off 1 h, 6 h, then
24 h; `pid_gone` and `drift` release the digest to other nodes at once, at
most 3 times per node in 24 h before that node is skipped for 24 h; the
per-node reasons (`lsm_denied`, `sandboxed`, ...) skip the node for 24 h.
`GET /images` items gain `sbomSources` and `nodeCatalog {state, reason,
platform, completeness, catalogedAt}`, both left out when empty. `GET
/images/{digest}/sbom` returns at most 16 `filePaths` per component, with
`filePathsTotal` when there are more (a node SBOM keeps up to 4096 for the
in-use match). A node SBOM links only to the digest it was claimed for, and
feeds no in-use verdict yet.

`/metrics`:

- `kguardian_node_catalog_granted_total{reason}`: grants, by why the digest was claimable (`pending`, `backoff_elapsed`, `lease_expired`, `epoch`)
- `kguardian_node_catalog_cataloged_total{reason}`: completed claims by completeness (`full`, `partial`, `os_only`), or `no_packages_found` / `superseded`
- `kguardian_node_catalog_failed_total{reason}`: claims released by `timeout`, `oom`, `error`, `pid_gone`, `drift`, `exited_before_catalog`
- `kguardian_node_catalog_skipped_total{reason}`: nodes skipped for a digest, by per-node reason or `retry_cap`
- `kguardian_node_catalog_scan_duration_seconds`: histogram of the cataloger's reported scan time
- `kguardian_node_catalog_grants_enabled`: 0 while `NODE_CATALOG_GRANTS=false`
- `kguardian_node_catalog_token_missing`: 1 while `BROKER_TOKEN_CATALOG` is not set
- `kguardian_node_catalog_queue_depth`, `kguardian_node_catalog_coverage_ratio`: offered digests not yet cataloged, and the share of running digests with a trusted SBOM; computed by the leader's supply-chain pass, so only the leader reports them

PR images (`pr-<N>` tags on GHCR) are multi-arch: each architecture builds
natively in CI and the broker image is smoke-executed on both amd64 and arm64
before the manifest is assembled.
