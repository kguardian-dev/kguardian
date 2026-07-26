# Goal: Simplify the Architecture Without Losing a Single Feature

**Status:** Active · **Owner:** core · **Created:** 2026-07-26 · **Theme:** fewer moving parts, same product
**Sibling charter:** [AI-MCP-INTEGRATION-GOAL.md](AI-MCP-INTEGRATION-GOAL.md) (stability of the AI chain) — its
gates stay in force; this charter must never trade stability for size.

> kguardian's data plane (controller → broker → Postgres) earns its complexity — eBPF capture is
> the product. The layers around it don't: the AI path is 3 services, 2 languages, and 3 copies of
> shared knowledge to deliver what is architecturally one stateless process; policy generation is
> implemented three times; 8 release units across 4 toolchains carry the rest. This charter shrinks
> the system for the person who has to **install it, upgrade it, and trust it** — a cluster operator
> who is not us.

---

## 1. Vision & Definition of Done

An operator installs kguardian with one Helm command, enables the AI assistant with **one value and
one secret**, and upgrades for a year without reading a migration guide. Every feature that exists
today still exists and behaves identically — proven by tests, not by hope.

**Done means all of the following hold:**

| Dimension | Target (today → done) |
|---|---|
| Workloads with AI enabled | 8 → **6** (core 5 unchanged; assistant replaces llm-bridge + mcp-server; advisor Deployment retired) |
| Values to enable the AI path | 3 coordinated toggles + per-provider secrets → **`ai.enabled=true` + 1 secret** |
| Release units | 8 → **6**; a component bump reaches the chart default in one automated pass |
| Tool definitions | 3 places / 2 languages → **1 registry** |
| Policy/seccomp generators | 3 implementations → **1 shared package** (+ CLI in provable parity) |
| Feature parity | **100%** — every tool, endpoint, generator output, and CLI behavior preserved; proven by the parity gates in §3 |
| Regressions | **Zero** — no user-visible behavior change ships without a test that would have caught its absence |
| CPU architectures | **linux/amd64 + linux/arm64, always** — every image and binary, at every pipeline stage including PR validation. Simplification means fewer components, never fewer supported platforms |
| Install/maintain UX | Quickstart unchanged (one `helm install`); values.yaml shrinks; no new mandatory inputs; deprecated keys warn, never break |

**Non-goals (explicitly deferred):** new features, new tools, new providers; merging the evaluator
into the broker (loose coupling, but it needs a K8s client the broker deliberately lacks — revisit
only after this charter closes); rewriting anything for its own sake.

---

## 2. Architecture (target)

```
                       TODAY                                        DONE
frontend ─SSE─► llm-bridge ─MCP─► mcp-server ─► broker      frontend ─SSE─► assistant ─► broker
                                      └───────► advisor                        └─ tools in-process
                                                (serve)                        └─ generators (shared TS pkg,
frontend ── own TS generators (duplicate)                                         same pkg as frontend)
advisor CLI ── own Go generators (duplicate)                advisor CLI ── Go generators + golden parity
```

- **assistant** = llm-bridge absorbing the 12 tools in-process (~500 LOC TS of HTTP proxy + compaction).
  The MCP hop, the Go service, the double truncation layer, and the "tool path deployed separately and
  silently off" failure class (WS0 in the sibling charter) all cease to exist. If external MCP clients
  ever become a product feature, the same registry is served over StreamableHTTP from the same process.
- **One generator**: the TS policy/seccomp generators become a shared package used by the frontend
  editor and the assistant's `generate_*` tools. The advisor keeps its Go generators for the kubectl
  plugin only — pinned to the TS implementation by golden fixtures (§3), with the `cilium/cilium`
  dependency replaced by plain typed structs for the YAML shape.
- Data plane untouched: controller, broker, database, evaluator keep their exact shape and contracts.

---

## 3. The parity & regression gates (how "no regressions" is proven)

Every workstream lands behind these gates. A PR that cannot show its gate is not mergeable.

- **G1 — Tool contract snapshot.** Before any merge work: capture the current 12 tools' names,
  schemas, and a recorded response per tool against seeded data. The assistant must reproduce this
  snapshot byte-for-byte (modulo documented compaction). The snapshot lives in-repo; CI diffs it.
- **G2 — Generator golden fixtures.** A language-neutral fixture set (broker JSON in → policy/seccomp
  YAML out) covering: standard + Cilium policy, no-traffic default-deny, multi-peer resolution,
  x86_64/aarch64 seccomp. Frontend TS, assistant TS, and advisor Go CLI must all pass the same
  fixtures in CI. Divergence is a build failure, permanently.
- **G3 — SSE contract test.** The `text|thinking|tool_use|tool_result|done|error` stream contract is
  pinned by a recorded-session test; the frontend parser and assistant emitter test against the same
  recording.
- **G4 — Chart upgrade test.** `helm upgrade` from the last pre-simplification chart with old values
  (`llmBridge.*`, `mcpServer.*`, `advisor.enabled`) must render successfully with deprecation warnings
  and produce a working assistant — mapped, not broken. CI runs this against a kind cluster.
- **G5 — Live canary.** Each phase deploys to cluster-00 and must hold the sibling charter's targets
  (tool-call success ≥ 99.5%, p95 < 2s) for 7 days before the superseded component is deleted.
  Old and new run side by side during the window; rollback is a values flip.

---

## 4. Workstreams

### WS-A — Dead weight (zero risk, do first)
**Bar:** No code, route, or config that nothing calls.
Remove: `POST /pod/traffic` (single-row; controller only batches), llm-bridge stale `BROKER_URL` env +
`BrokerClient` misnomer, unused `/api/chat` route, dead `conversationId` threading. Deduplicate the
`AIAssistant.tsx` modal/panel copy-paste (722 → ~400 LOC). Collapse OpenAI+Copilot provider loops into
one OpenAI-compatible client; mark Gemini experimental or remove (it pins a preview model id today).
**Acceptance:** grep-clean; frontend behavior pixel-identical; provider matrix documented honestly.

### WS-B — The assistant merge (mcp-server → llm-bridge)
**Bar:** One stateless service between frontend and broker; tool registry defined once.
**Acceptance:** G1 + G3 green; assistant image replaces two; `kguardian-mcp-server` and its release
pipeline deleted after the G5 window; the system prompt's tool guide is generated from the registry,
not hand-maintained; broker auth token wiring preserved.

### WS-C — One generator (shared TS package + advisor CLI parity)
**Bar:** "Generate a policy" has exactly one behavior, everywhere it's offered.
**Acceptance:** G2 green across all three consumers; advisor serve mode, Deployment templates,
`advisor-image-release.yaml`, and `ADVISOR_URL` wiring deleted; `cilium/cilium` gone from advisor
go.mod; kubectl-plugin UX byte-identical (G2 fixtures double as its regression suite).

### WS-D — Operator UX (the chart is the product surface)
**Bar:** Enabling AI is one decision. Upgrading is boring. values.yaml explains itself.
**Acceptance:** `ai.enabled` + `ai.provider` + one secret ref covers the whole path (old keys mapped
via G4); values.yaml materially shorter with shared boilerplate templated once; NOTES.txt states
exactly what's running and what was skipped; docs quickstart unchanged; an UPGRADING.md entry per
phase, written before the phase merges.

### WS-E — CI & release weight
**Bar:** CI cost proportional to what changed; releases stay fully automated end to end; **both
architectures (linux/amd64 + linux/arm64) are built and validated at every stage — PR and release.**
Dropping an architecture is never an acceptable cost reduction: an arm64-only build break must
surface on the PR, not at release time.
**Acceptance:** PR image builds keep full amd64+arm64 coverage but move the arm64 legs from QEMU
emulation (a PR broker build measured 45 min) to native `ubuntu-24.04-arm` runners with a manifest
merge, targeting minutes not hours; release units drop to 6 with renovate + release-please automation
verified end to end on the first post-merge bump; advisor's draft-release flow shrinks to the binary
matrix only (all four OS/arch binary targets retained).

---

## 5. Sequencing

- **P0 — WS-A + WS-E's native-arm-runner migration + `ai.enabled` umbrella (maps to existing toggles).** Ships value
  immediately, touches no contracts, builds the G1/G2 snapshots while the old system is still the
  reference implementation.
- **P1 — WS-B behind G1/G3/G5.** The biggest failure-surface reduction; directly serves the sibling
  charter's WS0/WS3.
- **P2 — WS-C behind G2/G5, then WS-D's values consolidation + G4.**
- Each phase closes with the sibling charter's targets re-verified on cluster-00 and a progress-log
  entry here.

## 6. Definition of "gated"

Every PR under this charter must: name its workstream, pass the relevant G-gates in CI, delete at
least as much as it adds (or justify why not), keep the quickstart true, and ship the UPGRADING/docs
change in the same PR. Anything that changes user-visible behavior is a bug in this charter, not a
judgment call.

**Release freeze (owner decision 2026-07-26):** no NEW public releases (chart or component) are cut
mid-restructure. Restructure PRs merge to `main` with non-release commit types (`refactor`/`chore`/
`test`) so release-please does not auto-cut; any release PR it does open is HELD unmerged. Canaries
deploy to cluster-00 from pre-release `pr-<N>` artifacts, never from a freshly cut public release.
When the whole restructure has landed and the G5 canary has held, cut ONE coherent release
representing the finished 6-workload architecture, with a single summary changelog. Rationale: an
intermediate public release can strand a half-migrated state (e.g. an enabled-but-unused mcp-server
pod, or a removed advisor before in-process generation ships) on a customer's cluster. Everything
released so far (through chart 1.16.0 / llm-bridge 1.5.0) is a working superset — nothing broken
shipped — but the freeze stops the untidiness from here on.

## 7. Progress log

- 2026-07-26 — **Assistant fully advisor-independent.** In-process NETWORK
  POLICY + Cilium generation (#1190): faithful TS port of the advisor Go
  generators (standard/cilium/types), all 5 paths (CIDR, service/pod
  endpoint-resolved, default-deny) proven byte-semantically identical to the
  advisor via the G2 netpol goldens; peer resolution mirrors the advisor's
  BrokerData seam via broker /svc/ip + /pod/ip. With in-process seccomp
  (#1188), the assistant makes NO advisor calls — ADVISOR_URL removed from the
  llm-bridge deployment. Canary re-pinned to pr-1190 (the complete advisor-free
  assistant) so one 7-day window gates removing BOTH mcp-server AND the advisor
  Deployment. Frontend keeps its own G2-locked generators for the ai.enabled
  =false case (no-workspace design). Freeze holding.
  - **Validated in-cluster (cluster-00):** pr-1190 rolled out healthy; generating
    a real NetworkPolicy for a live pod resolved a peer to a podSelector (real
    labels from the broker /pod/ip) — the broker-backed resolver works against
    the real broker, the one path the flat test fixture could not exercise.

- 2026-07-26 — **WS-C progress + G4 gate.** G4 values-compatibility gate (#1187):
  fast render check proving legacy per-component AI flags and the ai.enabled
  umbrella render the identical stack (guards upgrade safety). In-process
  SECCOMP generation (#1188): the assistant builds seccomp profiles itself from
  /pod/syscalls, G2-locked to the frontend + advisor-CLI generators — first tool
  decoupled from the advisor service. Design note: no npm-workspace (per-package
  Docker contexts make it deploy-risky); one-behavior enforced via G2 fixtures.
  Freeze holding (0 release PRs cut); canary healthy through day 1. Next: the
  in-process NETWORK POLICY port (must reproduce the advisor's exact YAML for G1
  + CLI parity — the riskiest remaining change), then advisor serve/Deployment/
  image removal after the 7-day canary.

- 2026-07-26 — **Release freeze adopted** (owner decision, see §6) + **WS-C cilium
  removal.** Owner flagged that mid-restructure public releases risk shipping a
  half-migrated state; froze new public releases until the restructure completes
  (restructure PRs land as refactor/chore/test; canary from pre-release
  artifacts; one coherent release at the end). Verified nothing broken shipped —
  everything through chart 1.16.0 is a working superset. WS-C: dropped
  github.com/cilium/cilium from the advisor (hand-rolled CNP types, every path
  golden-guarded); go.sum 1622->185 lines (-89% transitive surface); dead
  pkg/k8s cilium path deleted. dependabot alerts 71->35 as dep surface shrank.

- 2026-07-26 — **G5 canary OPEN on cluster-00.** Chart 1.16.0 + llm-bridge
  v1.5.0 (in-process tools) deployed and validated: both pods healthy,
  hasProvider:true, BROKER_URL resolves to kguardian-broker.kguardian.svc and
  the broker answers Healthy! from inside the pod. The assistant reaches the
  data plane with no mcp-server hop. mcp-server left deployed for rollback
  (revert the llm-bridge image pin). 7-day window to hold the sibling charter's
  tool-call success / latency targets before mcp-server retirement (task #12);
  checked daily. WS-C (shared generator, advisor CLI-only) proceeds in parallel.

- 2026-07-26 — **P1 core done: provider consolidation + WS-B assistant merge.**
  Provider consolidation (#1179): OpenAI+Copilot collapsed to one
  OpenAI-compatible client, dead /api/chat route removed, Gemini pinned off its
  -exp preview model. **WS-B (#1180, releasing as llm-bridge 1.5.0):** the
  assistant now runs all 12 tools IN-PROCESS (src/tools: registry + filter.go
  port + direct broker/advisor HTTP) instead of proxying through the Go
  mcp-server — one fewer deployment, one fewer hop, and the WS0 deployed-but-off
  failure class gone. Parity proven: src/tools/parity.test.ts replays the shared
  G1 fixtures and reproduces every mcp-server output. @modelcontextprotocol/sdk
  removed; McpClient public API unchanged so provider loops + G3 untouched.
  mcp-server stays deployed for canary rollback (retired after G5 holds).

- 2026-07-26 — **P1 gates built.** G1 tool-contract snapshot (#1176): 12-tool
  MCP wire contract pinned as goldens via an in-memory client session; also
  root-caused and fixed the long-standing OversizedBody suite deadlock and
  added the first CI test gate for mcp-server. G3 SSE stream contract (#1177):
  full session (thinking/tool/text/done) + error recording pinned on both the
  llm-bridge emitter and the frontend parser; first CI test gates for both.
  G2 generator parity (#1178): shared fixtures both advisor Go and frontend TS
  assert; surfaced and fixed two real frontend seccomp bugs (hardcoded x86 arch
  on aarch64 pods; missing allow rule) — advisor is the reference. Network-policy
  reference goldens pinned; frontend netpol wiring folds into WS-C.

- 2026-07-26 — Charter created from the full architecture review (four-quadrant exploration: AI chain,
  data plane, advisor, deployment/CI). Baseline: 7 runtime components, 8 release units, 4 toolchains,
  1,316-line values.yaml, tool definitions ×3, generators ×3.
- 2026-07-26 — **Architecture-support invariant added** (owner decision): amd64 + arm64 are guaranteed
  at every pipeline stage including PR validation. An initial amd64-only PR-build trim was closed
  unmerged; WS-E re-aimed at native arm64 runners instead of coverage reduction.
- 2026-07-26 — **P0 complete.** WS-A: dead broker route (#1166), llm-bridge stale naming + dead
  conversationId (#1167), AIAssistant chrome single-sourced 722→615 (#1169) — all merged. WS-D:
  ai.enabled umbrella shipped in chart 1.15.0, deployed + verified on cluster-00. WS-E: PR builds
  now native per-arch (#1174) — broker arm64 leg 45 min (QEMU) → 3m25s (native), smoke test now
  executes BOTH arches, pr-N manifests verified multi-arch. Deferred from WS-A into the provider
  consolidation: /api/chat route removal, provider-loop collapse.
