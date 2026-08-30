# Upgrading the kguardian Helm chart

## External MCP endpoint (opt-in, default off)

**Existing installs are unaffected.** `ai.mcp.enabled` defaults to `false`,
and while it is false the `/mcp` route is not registered at all — the path
404s exactly as it did before this release. No new Deployment, Service, port,
or probe is added in either state, and no existing values key changes meaning.
If you do nothing, nothing changes.

When enabled, the llm-bridge serves kguardian's 12 tools over Model Context
Protocol (StreamableHTTP) at `/mcp` on its **existing** port 8080, so an
external MCP client can query cluster telemetry and generate policies.

```bash
kubectl -n <ns> create secret generic kguardian-mcp-token \
  --from-literal=token="$(openssl rand -hex 32)"
```
```yaml
ai:
  enabled: true
  mcp:
    enabled: true
    auth:
      existingSecret: kguardian-mcp-token
```
Then reach it over a port-forward:
```bash
kubectl -n <ns> port-forward svc/kguardian-llm-bridge 8080:8080
```
and point your MCP client at `http://localhost:8080/mcp`, sending
`Authorization: Bearer <token>`.

### The chart refuses to serve this endpoint open by accident

Setting `ai.mcp.enabled: true` **without** `ai.mcp.auth.existingSecret` makes
the chart fail to render, naming both remedies. This is deliberate. The
endpoint returns pod traffic, syscalls, and audit verdicts with no LLM in the
path and no per-tool authorization, and it is fronted by a ClusterIP Service —
which is not a security boundary. Every pod in the cluster can route to it
unless a NetworkPolicy says otherwise, and this chart ships no llm-bridge
NetworkPolicy. A forgotten token would hand your telemetry to any compromised
workload in the cluster.

If llm-bridge is already fronted by a default-deny NetworkPolicy or a mesh
with mTLS, the token is genuinely redundant. Say so explicitly:

```yaml
ai:
  mcp:
    auth:
      allowUnauthenticated: true
```
That opt-out exists so the decision lands in your values file and your code
review, which a silently-missing token never would.

Note that `MCP_AUTH_TOKEN` is injected **without** `optional: true`, unlike
the provider API keys. If the named Secret is missing the pod fails to start
rather than coming up unauthenticated — a typo in the Secret name must not
quietly open the endpoint.

## OpenAI-compatible gateways: `ai.baseUrl` and `ai.model` (opt-in, default off)

**Existing installs are unaffected.** Both keys default to `""`, and while
they are empty the chart emits no new environment variables at all — the
rendered llm-bridge is byte-identical to the previous release. Vendor
endpoints and default models are unchanged. If you do nothing, nothing
changes.

They let you point the provider named by `ai.provider` at an
OpenAI-compatible gateway (LiteLLM, vLLM, an enterprise proxy) instead of the
vendor's API:

```yaml
ai:
  enabled: true
  provider: openai
  secret: litellm-key                                   # still required — see below
  baseUrl: http://litellm.litellm.svc.cluster.local:4000/v1
  model: my-team/llama-3.3-70b
```

**You must still set `ai.secret`.** Provider availability is gated on the API
key alone, so a gateway configured without one leaves the assistant reporting
"no provider configured" no matter how correct the base URL is. Set it to your
gateway's virtual key, or to any non-empty dummy value if the gateway is
unauthenticated. This is the most common first-run mistake.

**The `/v1` segment is yours to get right.** kguardian appends the provider's
request path to your base URL verbatim and never inserts, removes, or rewrites
a `/v1`. LiteLLM answers on both `/chat/completions` and
`/v1/chat/completions`, so both forms appear to work there; vLLM and most
other gateways serve only the `/v1` form. A wrong base surfaces as a 404 or
405 whose error message names the offending environment variable — it never
silently falls back to the vendor API.

The keys map per provider, and the Gemini row is asymmetric on purpose — the
key is named for the vendor, the endpoint and model for the provider
`ai.provider` selects:

| `ai.provider` | API key env | `ai.baseUrl` env | `ai.model` env |
|---|---|---|---|
| `openai` | `OPENAI_API_KEY` | `OPENAI_BASE_URL` | `OPENAI_MODEL` |
| `anthropic` | `ANTHROPIC_API_KEY` | `ANTHROPIC_BASE_URL` | `ANTHROPIC_MODEL` |
| `gemini` | `GOOGLE_API_KEY` | `GEMINI_BASE_URL` | `GEMINI_MODEL` |
| `copilot` | `GITHUB_TOKEN` | `COPILOT_BASE_URL` | `COPILOT_MODEL` |

Both keys sit on the one-liner `ai.*` path only. Running two gateways at once
is still served by `llmBridge.env`, which is emitted last and therefore also
works as a per-value override.


## AI assistant is now a single workload (mcp-server / advisor-serve retired)

The assistant used to be three in-cluster workloads — `llm-bridge`, a
separate `mcp-server`, and an `advisor` HTTP service. As of this release the
`llm-bridge` runs all of the assistant tools **and** the NetworkPolicy /
seccomp generation **in-process**, so the `mcp-server` and advisor-serve
Deployments no longer exist.

**What happens on `helm upgrade`:** if you had the assistant enabled, Helm
removes the `kguardian-mcp-server` and `kguardian-advisor` Deployments (plus
their Services / ServiceAccounts). This is expected and safe — the assistant
loses no capability; the work simply moved into `llm-bridge`. No data is
touched. The advisor **CLI / kubectl-plugin** is unaffected: it ships as its
own released binary and never ran in the cluster.

The retired `mcpServer.*` and `advisor.*` values keys are now inert. They are
still accepted so an old values file keeps rendering, but they no longer
create anything — remove them from your values at your convenience.

## AI assistant: one-line enablement (`ai.*`)

The AI assistant is enabled with a single value and a single secret. No
existing values need to change — the `llmBridge.enabled` flag and the
per-provider secret blocks (`llmBridge.secrets.*`) still work exactly as
before, so upgrades are a no-op unless you opt into the new keys.

The one-line path:
```bash
kubectl -n <ns> create secret generic my-llm-key \
  --from-literal=api-key="sk-..."
```
```yaml
ai:
  enabled: true          # renders the llm-bridge assistant (tools + generation in-process)
  provider: anthropic    # openai | anthropic | gemini | copilot
  secret: my-llm-key     # holds the key under `api-key`
```
`ai.enabled=true` is the umbrella for the assistant;
`ai.provider` + `ai.secret` wire the chosen provider's API key. To run
several providers at once, keep using the per-provider
`llmBridge.secrets.*` blocks (they are additive to `ai.provider`).

## Optional broker API authentication (opt-in)

The broker API can now require a shared **bearer token**
(`broker.auth.enabled`, **default `false`** — no change for existing
installs). When enabled, the controller and llm-bridge must present the
token or their requests get `401`; `/health` and `/metrics` stay open.
This closes the unauthenticated forged-row / unauthorized-read exposure
on the server-to-server paths — the durable complement to the
NetworkPolicy below.

To enable, create the Secret yourself (kept out of the chart so it's
stable across upgrades) and point the chart at it:
```bash
kubectl -n <ns> create secret generic kguardian-broker-auth \
  --from-literal=token="$(openssl rand -hex 32)"
```
```yaml
broker:
  auth:
    enabled: true
    existingSecret: kguardian-broker-auth   # required when enabled
```
**Known gap:** the frontend calls the broker directly from the browser
and can't hold a static token, so auth does not cover the frontend path —
keep the frontend on a trusted network or front the broker with an
authenticating proxy for browser traffic. Tracked for a follow-up.

## Optional broker ingress NetworkPolicy (opt-in)

The chart can render an ingress `NetworkPolicy` for the broker
(`broker.networkPolicy.enabled`, **default `false`**). The broker HTTP API
is unauthenticated, so when enabled the policy restricts which in-cluster
sources may reach it.

**It is opt-in for a hard reason:** the controller is a hostNetwork eBPF
DaemonSet, so it posts to the broker from the **node IP**, and a
`podSelector` can never match it (NetworkPolicy-enforcing CNIs see node
identity, not the pod label). Enabling the policy **without** listing your
node network in `allowedNodeCIDRs` will **block the controller** and stall
its rollout. There is no safe cluster-agnostic default, hence opt-in.

To enable safely:
```yaml
broker:
  networkPolicy:
    enabled: true
    # REQUIRED: the node network(s) the controller DaemonSet runs on.
    allowedNodeCIDRs:
      - "10.0.0.0/16"     # e.g. your node subnet, or per-node /32s
    # Only if you scrape /metrics (it shares the broker HTTP port):
    allowMetricsFrom:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: monitoring
        podSelector:
          matchLabels:
            app.kubernetes.io/name: prometheus
```

When enabled, llm-bridge / frontend / the helm-test pod are admitted via
podSelector; the controller via `allowedNodeCIDRs`; everything else is
denied. Ingress-only — the broker's own DB / DNS / evaluator egress is
never restricted. Inert on clusters whose CNI doesn't enforce
NetworkPolicy.

> **Caveat (validated live on Cilium):** the `allowedNodeCIDRs` ipBlock
> that the hostNetwork controller requires is coarse — on Cilium it was
> observed to also admit unrelated in-cluster pods, so treat this policy
> as **defence-in-depth, not airtight isolation**. The pod clients are
> precisely scoped; the controller allowance is not. For strict broker
> isolation, use a CNI-native policy (e.g. a CiliumNetworkPolicy with
> `fromEntities: [host, remote-node]`) or add authentication to the
> broker API (the durable fix, tracked separately).

## CRD: `policyTypes` is now a constrained set

The `AuditNetworkPolicy` and `AuditClusterNetworkPolicy` CRDs now declare
`policyTypes` as `x-kubernetes-list-type: set` with `maxItems: 2`. This
stops accidental duplicate entries (e.g. `[Ingress, Ingress]`) at
admission, which the evaluator would otherwise double-count.

Impact: if you have an **existing** CR whose `policyTypes` already
contains duplicates, the API server may reject *updates* to it after the
CRD is applied (set semantics forbid duplicates). This is rare, but to be
safe, scan and clean before upgrading:

```bash
# List any audit policies with duplicate policyTypes entries.
kubectl get auditnetworkpolicies,auditclusternetworkpolicies -A -o json \
  | jq -r '.items[] | select((.spec.policyTypes | length) != (.spec.policyTypes | unique | length))
           | "\(.kind) \(.metadata.namespace)/\(.metadata.name)"'
# Re-apply each listed policy with de-duplicated policyTypes.
```

## `broker.audit.retention.days: 0` now correctly disables retention

Earlier chart versions used a Helm `with` block to emit
`AUDIT_VERDICTS_RETENTION_DAYS`. Helm's `with` treats `0` as falsy and
skipped the block — so operators who set `days: 0` (the documented
"disable retention" value per values.yaml) did NOT propagate the env
var to the broker, and retention kept running at the in-broker
default of 30 days. The chart now uses an explicit `hasKey` check, so
`0` honours the disable intent.

If you'd been relying on `days: 0` as a working disable and noticed
audit_verdicts WAS retained at 30 days, your cluster's `audit_verdicts`
table likely has older rows than you expect. After upgrading:

```sh
# Inspect the row count + oldest entry.
kubectl -n <ns> exec deploy/kguardian-db -- \
  psql -U rust -c "select count(*), min(observed_at) from audit_verdicts;"

# If you want to clear the historical accumulation that retention=0
# was supposed to prevent, do it explicitly after the chart upgrade:
kubectl -n <ns> exec deploy/kguardian-db -- \
  psql -U rust -c "delete from audit_verdicts where observed_at < now() - interval '30 days';"
```

## Cross-major Postgres upgrades: `database.persistence.safeBoot`

The chart includes an init container (`assert-safe-boot`) that refuses
to start the database when the PVC contains a Postgres datadir for a
**different** major than the running image AND the current major's
datadir is empty. Without it the postgres image would silently `initdb`
over the empty location and leave the prior data sitting unused on the
volume — exactly how the chart's pre-1.10.0 mount-path bug surfaced as
"silent" data loss when the path was corrected.

If you're intentionally rolling forward across a major (after running
`pg_upgrade` offline, or otherwise migrating the data on disk yourself):

```yaml
database:
  persistence:
    safeBoot: false
```

Set it back to `true` once the upgrade lands so the next major catches
the same class of footgun.

## Before any chart upgrade: back up the database

The chart's bundled PostgreSQL Deployment + ReadWriteOnce PVC pattern is
fragile across template changes. Mount-path corrections (#845), image
tag bumps, or strategy changes can leave the new pod attached to the
PVC at a path PostgreSQL doesn't recognise — at which point `initdb`
runs over an empty subtree and the broker silently sees a fresh schema.
The data isn't recoverable after the fact.

### Automatic: `database.persistence.preUpgradeBackup`

The chart runs `pg_dumpall` as a Helm `pre-upgrade,pre-rollback` hook
when `database.persistence.preUpgradeBackup` is `true` (the default).
The dump streams to the Job's stdout — retrieve it with:

```sh
kubectl -n <ns> logs job/kguardian-db-pre-upgrade-backup > kguardian-db-$(date +%Y%m%d-%H%M).sql
```

The hook is best-effort: if the backup fails (DB unreachable,
`pg_dumpall` errors), it logs a warning but does NOT block the
upgrade. To skip entirely (for ephemeral test deployments) set
`database.persistence.preUpgradeBackup: false`.

### Manual fallback

Take a logical dump yourself if you want to capture state at a
specific moment that isn't tied to a chart upgrade:

```sh
kubectl -n <ns> exec deploy/kguardian-db -- \
  pg_dumpall -U "$POSTGRES_USER" --clean --if-exists \
  > kguardian-db-$(date +%Y%m%d-%H%M).sql
```

If an upgrade lands on an empty database, the broker's `/health`
endpoint reports `503 Database schema not up to date` and the kubelet
restarts the pod. Startup re-runs migrations against the new instance,
which is enough to bring the system back online — but historical rows
in `pod_traffic`, `pod_details`, and `audit_verdicts` are gone. The
dump above is what lets you restore them.

To restore:

```sh
kubectl -n <ns> cp kguardian-db-YYYYMMDD-HHMM.sql kguardian-db-<pod>:/tmp/restore.sql
kubectl -n <ns> exec deploy/kguardian-db -- \
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f /tmp/restore.sql
```

The kguardian data model is observability state, not source of truth —
losing it is recoverable (the controller repopulates pod/svc snapshots
from live cluster state on its next sync). The dump matters most for
`audit_verdicts`, which is a time series with no other source.

## chart 1.10.0: PostgreSQL 15 → 18

The `database.image.tag` default moved from `15-alpine` to `18-alpine`.
PostgreSQL major-version data directories are not forward-compatible, so
existing installations with `database.persistence.enabled=true` will not
start under PostgreSQL 18 against a PG15 PVC. The database pod will fail
its readiness probe with:

```
database files are incompatible with server
The data directory was initialized by PostgreSQL version 15, which is
not compatible with this version 18.x.
```

Pick one of the two paths below before running `helm upgrade`.

### Option 1 — drop the data and repopulate (recommended)

The kguardian database stores only ephemeral observability state:
captured pod traffic, syscall samples, and pod/service spec snapshots.
The controller and broker repopulate it from the live cluster state
once they reconnect, so dropping the PVC is non-destructive in practice.

```sh
# 1. Scale broker + controller down so nothing is writing.
kubectl -n <ns> scale deploy/kguardian-broker --replicas=0
kubectl -n <ns> rollout pause daemonset/kguardian-controller

# 2. Delete the database deployment + PVC.
kubectl -n <ns> delete deploy/kguardian-db
kubectl -n <ns> delete pvc <existing-claim-name>

# 3. Apply the new chart (creates a fresh PG18 data dir).
helm upgrade --install kguardian kguardian/kguardian \
  --namespace <ns> \
  --set database.persistence.existingClaim=<new-claim-name>

# 4. Resume the controller; broker will be re-created by the chart.
kubectl -n <ns> rollout resume daemonset/kguardian-controller
```

### Option 2 — pg_upgrade in place (preserves data)

Use this if you have downstream tooling that depends on continuity of
the database contents.

```sh
# 1. Take a logical backup as a safety net.
kubectl -n <ns> exec deploy/kguardian-db -- pg_dumpall -U rust > backup.sql

# 2. Stop the broker (drops live writers).
kubectl -n <ns> scale deploy/kguardian-broker --replicas=0

# 3. Run pg_upgrade against the existing PVC. Easiest is to mount it in
#    a one-shot Job that runs both PG15 and PG18 binaries, e.g.
#    tianon/postgres-upgrade:15-to-18, with both /var/lib/postgres/15 and
#    /var/lib/postgres/18 PVCs mounted. After it completes, repoint the
#    chart at the new (PG18) PVC via database.persistence.existingClaim.

# 4. Apply the new chart.
helm upgrade --install kguardian kguardian/kguardian \
  --namespace <ns> \
  --set database.persistence.existingClaim=<pg18-claim-name>
```

If neither path is acceptable, pin the previous tag and stay on PG15:

```yaml
database:
  image:
    tag: "15-alpine"
```

PG15 is still receiving security fixes through 2027-11-11.
