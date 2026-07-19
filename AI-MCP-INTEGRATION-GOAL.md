# Goal: Make the AI + MCP Integration Thoroughly Correct, Stable, and Productized

**Status:** Active · **Owner:** core · **Created:** 2026-07-08 · **Theme:** stability/reliability over features

> Existing users are reporting instability. This goal treats the AI assistant + MCP data
> path as a **product that must work reliably before it grows features**. It is the single
> source of truth for what "done and trustworthy" means for this integration, and the
> checklist we gate changes against.

---

## 1. Vision & Definition of Done

A user opens the AI assistant, asks a question about their cluster, and **every time** gets a
correct, grounded, timely answer — or a clear, honest error. The whole chain
(`frontend → llm-bridge → mcp-server → broker/advisor → Postgres`) is bounded, observable,
resilient to load, and pleasant to develop against.

**Done means all of the following hold in production, continuously:**

| Dimension | Target |
|---|---|
| Correctness | Every MCP tool returns accurate, schema-valid data; no tool silently returns wrong/empty results. |
| Availability | AI data path (broker + mcp-server + llm-bridge) ≥ 99.5% successful tool calls over 7 days. |
| Latency | p95 end-to-end tool call < 2s; p99 < 5s; no unbounded/25s+ queries anywhere. |
| Bounded resources | No endpoint can return an unbounded result set; no table grows without retention. |
| Resilience | One slow/bad query or one pod restart never takes down the data path. |
| Observability | Every failure is attributable from logs/metrics without a repro; golden-signal dashboards exist. |
| UX | Streaming responses, honest errors, visible grounding/citations, sensible empty/loading states. |
| DX | One-command local bring-up; contract-tested tools; clear docs; fast, meaningful CI gates. |

**Non-goals (explicitly deferred):** new MCP tools, new assistant features, new data sources —
until the above holds. Renovate/security dependency updates are **in-scope** (they are stability).

---

## 2. Architecture (what must work end to end)

```
frontend/AIAssistant.tsx
   │  POST /api/chat/stream (SSE)
   ▼
llm-bridge (TS/Express, @anthropic-ai/sdk, claude-opus-4-8, prompt caching)
   │  MCP tool calls
   ▼
mcp-server (Go, 11 tools) ──HTTP──► broker (Rust/actix, Postgres)   [pod/traffic, pod/info, audit/verdicts, …]
                          └─HTTP──► advisor (Go, serve mode)        [generate networkpolicy / seccomp]
```

Failure anywhere in this chain surfaces to the user as "the AI is broken." The chain is only as
reliable as its least-bounded query.

---

## 3. Workstreams

Each workstream has a **best-practice bar** (what "good" looks like) and **acceptance criteria**
(how we prove it). Concrete known defects from the 2026-07 audit are listed under each.

### WS1 — Correctness of the data path
**Bar:** Tools return accurate, complete-enough, schema-valid results. Tool descriptions match
behavior. No silent empty/zero results from field-name drift.
**Acceptance:** contract test per tool asserting shape + a non-trivial value against seeded data;
drift-guard between mcp-server tool set and llm-bridge; golden-answer tests for 5 canonical questions.
- Known: past bugs where `traffic_type`/`decision`/`traffic_in_out_ip` field-name mismatches made
  counts always 0 (fixed) — add regression tests so they can't recur.

### WS2 — Stability & performance (the instability root cause)
**Bar:** No unbounded reads; every growing table has retention; hot paths are index-backed;
responses are size-capped end to end.
**Acceptance:** a CI guard fails the build if a broker read lacks a bound; DB size stays flat
under steady state; p95/p99 latency targets met under a load test.
- **[P0] `/pod/traffic` unbounded** — FIXED, PR #1034 (bound + `idx_pod_traffic_time_stamp`). Deploy + verify.
- **[P0] `/pod/traffic/{name}` (`get.rs:368`) unbounded** — hit by the frontend per-pod on every
  view load AND by the advisor. Fix via **dedup (DISTINCT ON the flow tuple)** so the advisor keeps
  complete flows, not a blind LIMIT. Correct tuple = `(pod_ip, pod_port, ip_protocol, traffic_type,
  traffic_in_out_ip, traffic_in_out_port, decision)` — matches the insertion dedup in `add.rs`.
  Advisor is safe (it re-dedups generated rules, ignores time_stamp/uuid/count). Frontend note: it
  currently counts raw rows ("N connections/drops"); dedup shifts that to "N distinct flows" — a
  semantics change to surface in the PR (arguably clearer; raw counts reflect re-observation rate,
  not connection volume).
- **[P0-bug] `idx_pod_traffic_dedup` is missing `ip_protocol`** (2026-06-01 migration) — it can
  collapse TCP vs UDP flows on the same ports. Fix the index to match the `add.rs` insertion tuple
  before/with the DISTINCT ON query.
- **[corrected] `/pod/syscalls/{name}` (`get.rs:408`) is NOT unbounded** — `pod_name` is the PK, so
  it returns 0-1 rows. No action needed (earlier audit over-counted it).
- **[P0] `pod_traffic` has no retention** — 2.2 GB / 6.7M rows and growing. Add pruning mirroring
  `audit_verdicts` retention.
- **[P0] `audit_verdicts` bloat** — 726 MB for ~5k rows: DELETEs not reclaimed. Fix autovacuum
  tuning / one-time reclaim.
- **[P1] `/pod/info`, `/svc/info`** whole-table reads — compacted but still unbounded; add sane caps.

### WS3 — Reliability & resilience
**Bar:** Timeouts, retries with backoff, bounded concurrency/backpressure, graceful degradation;
no single query or pod restart is fatal.
**Acceptance:** chaos test (kill broker pod / inject slow query) keeps the assistant answering or
degrading cleanly; broker survives a burst of concurrent heavy calls.
- Broker is a **single replica** = SPOF for the entire data path. Decide HA (replicas + readiness)
  or at minimum isolate heavy queries (statement_timeout, separate pool) so one can't wedge the pod.
- Enforce `statement_timeout` on all broker queries as a backstop.
- mcp-server↔broker: confirm sane client timeouts (90s today) + retries; llm-bridge tool-call timeouts.

### WS4 — Observability
**Bar:** Golden signals (rate/errors/duration/saturation) per hop; structured logs with a request
id threaded end to end; health/readiness that reflect real dependency state.
**Acceptance:** a dashboard shows per-tool success/latency; a synthetic failure is diagnosable from
telemetry alone; alerts fire on error-rate/latency/DB-size breaches.
- Broker has Prometheus metrics + ServiceMonitor already — extend to per-endpoint latency/size +
  `pod_traffic`/`audit_verdicts` table-size gauges.
- Thread a correlation id: frontend → llm-bridge SSE → mcp-server → broker.

### WS5 — Testing & CI gates
**Bar:** Fast, meaningful, non-flaky CI that would have caught every bug in this list.
**Acceptance:** CI runs broker/controller/advisor/mcp-server/llm-bridge unit + contract tests on
every PR; an "unbounded-query" lint/guard; a load-smoke job; zero known-flaky tests.
- Fix flaky `TestBrokerClient_OversizedBodyTruncated` (deadlocks under parallel load).
- Add the WS1 contract tests and the WS2 bound-guard.
- Ensure Rust tests actually gate PRs (historically they didn't).

### WS6 — Security & trust
**Bar:** Broker API authenticated; secrets handled well; the LLM path is hardened against prompt
injection and can't be coerced into unsafe tool use; tools are least-privilege/read-only where possible.
**Acceptance:** broker rejects unauthenticated reads in-cluster; a prompt-injection test suite;
documented tool authz model.
- Broker currently unauthenticated in-cluster (NetworkPolicy is defence-in-depth only on Cilium).
  App-level auth or `CiliumNetworkPolicy fromEntities:[host,remote-node]` is the real fix.
- 59 Dependabot alerts (17 high) on default branch — triage and burn down.

### WS7 — User experience (the assistant)
**Bar:** Streaming with visible thinking; honest, specific error messages (never a blank/hang);
grounding is visible (which tools/data backed the answer); good loading/empty/rate-limit states;
conversation feels fast and trustworthy.
**Acceptance:** UX review against a checklist; error-injection shows graceful UI; latency budget met.
- Map every failure mode of the chain to a specific UI state (broker down, tool error, timeout,
  no data, model overloaded).

### WS8 — Developer experience & productization
**Bar:** One-command local stack (Tilt); tools self-describe; adding/changing a tool is a documented,
contract-tested path; runbooks for the common failure modes; clean, current docs.
**Acceptance:** a new contributor brings the full AI path up locally from the README in < 15 min and
can add a tool with a test template; runbooks exist for each WS3 failure mode.

---

### WS0 — Foundational: the mcp-server must actually be deployed
**Bar:** The assistant's tool path exists and is reachable in every environment where the assistant
is exposed. No component silently depends on a service that isn't deployed.
**Acceptance:** `MCP_SERVER_URL` resolves; tool discovery returns the full tool set; a live
`get_cluster_traffic` call succeeds end to end.
- **[P0] mcp-server is `enabled: false` in cluster-00** — no Service, no pod, yet `llm-bridge` is
  hard-wired to `kguardian-mcp-server:8081` with **no static tool fallback** (it throws on discovery
  failure). So the assistant's entire MCP tool path is off in prod; this is a large part of "MCP isn't
  working." It has never been enabled declaratively (only ad-hoc/manual pods, since pruned). Enable +
  stabilize it (Task #9). The #1034 broker fix is a prerequisite that's now in place.

## 4. Sequencing

- **P0 — Stop the bleeding (WS2 + the live deploy):** land #1034; dedup-bound the two sibling
  endpoints; `pod_traffic` retention; `audit_verdicts` bloat. Add `statement_timeout` backstop (WS3).
- **P1 — Make it stay fixed:** CI bound-guard + contract tests + flaky fix (WS5); observability for
  the golden signals + table-size alerts (WS4); broker SPOF decision (WS3).
- **P2 — Trust & polish:** UX failure-state mapping (WS7); broker auth + dep alert burndown (WS6);
  DX runbooks + local-stack doc (WS8).

## 5. Definition of "gated"
Every PR touching this chain must: be bounded (no unbounded read), carry a test that would catch its
own regression, keep CI green with no new flakes, and update the relevant runbook/doc. New features
wait until §1 targets hold.

## 6. Progress log
- 2026-07-08 — Charter created. `/pod/traffic` fix in PR #1034 (CI green).
- 2026-07-08 — **#1034 deployed + verified live** on cluster-00 (broker pr-1034). `/pod/traffic`:
  25s hang / `unexpected EOF` → **200, 1.66 MB, 49 ms**, index-scan plan. Task #1 done.
- 2026-07-08 — **Foundational finding:** mcp-server is `enabled: false` in cluster-00 (no Service/pod),
  while llm-bridge requires it — the assistant's tool path is off in prod. Added WS0 + Task #9.
- 2026-07-08 — Task #2 analysis: `/pod/syscalls/{name}` already bounded (PK); `idx_pod_traffic_dedup`
  missing `ip_protocol` (bug to fix with the DISTINCT ON change).
- 2026-07-08 — **mcp-server ENABLED + verified end-to-end** (Task #9 done). gitops `1d9ae8e5d`. MCP
  `initialize` OK, `tools/list` = 12 tools, `tools/call get_cluster_traffic` succeeds (was the broken
  tool). The assistant's MCP path is functional in prod again.
  - Observation feeding WS2/WS7: with `LIMIT 5000` the cluster-traffic summary covers only the pods in
    the most-recent 5000 events (currently 4 chatty pods) — too narrow on a busy cluster. The dedup
    approach (Task #2, distinct flows) or a time-windowed limit is the better long-term shape. Still a
    strict improvement (the tool returned an error before).
  - `advisor.enabled=false`, so `generate_network_policy` / `generate_seccomp_profile` are discoverable
    but have no backend — enable the advisor to complete tool coverage (add to Task #9 follow-ups).
- 2026-07-08 — **Task #5 done (PR #1036):** `statement_timeout` backstop on every broker DB connection
  (default 30s, `DB_STATEMENT_TIMEOUT_MS`/`broker.statementTimeoutMs`, migrations exempt). The universal
  WS3 safety net — any future unbounded/slow query is killed at the deadline instead of wedging the
  single-replica broker. fmt/clippy/test + helm all green locally; CI running.
  - Task #2 re-scoped by code review: the `ip_protocol` "index bug" is actually a `get_row` (6-col DB
    dedup) vs `traffic_content_key` (7-col in-batch) INGEST inconsistency — separate, riskier, deferred.
    Per-pod growth is churn-driven (new IP per restart), which retention (Task #3) attacks at the root.
