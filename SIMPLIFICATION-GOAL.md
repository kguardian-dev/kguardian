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
**Bar:** CI cost proportional to what changed; releases stay fully automated end to end.
**Acceptance:** PR image builds are amd64-only (multi-arch on release tags only — a PR broker build
measured 45 min under QEMU); release units drop to 6 with renovate + release-please automation
verified end to end on the first post-merge bump; advisor's draft-release flow shrinks to the binary
matrix only.

---

## 5. Sequencing

- **P0 — WS-A + WS-E's PR-build trim + `ai.enabled` umbrella (maps to existing toggles).** Ships value
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

## 7. Progress log

- 2026-07-26 — Charter created from the full architecture review (four-quadrant exploration: AI chain,
  data plane, advisor, deployment/CI). Baseline: 7 runtime components, 8 release units, 4 toolchains,
  1,316-line values.yaml, tool definitions ×3, generators ×3.
