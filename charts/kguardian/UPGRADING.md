# Upgrading the kguardian Helm chart

## Peer identity is now fixed when a flow is ingested

`pod_traffic` rows used to store only the peer's IP. The Network Map, the
Policy Builder, the CLI and the assistant all turned that IP into a pod at
read time, against `pod_details` as it stood at that moment. Pod IPs are
recycled constantly (a single address on one cluster had 50+ dead former
owners from hourly Jobs), and `pod_details` keeps no ownership history, so
weeks-old flows were drawn and allow-listed against whichever pod holds
the IP **today**. The same defect leaked Job-only labels (`job-name`,
`controller-uid`) into generated policies.

The broker now resolves the peer when the row is ingested and stores it on
the row (`peer_kind`, `peer_namespace`, `peer_name`, `peer_uid`,
`peer_workload_kind`, `peer_workload_name`, `peer_resolved_at`). Every
consumer reads those fields first. Where a by-IP lookup still runs, it
obeys a start-time guard: a flow is never attributed to a pod that
started after the flow. See
[How peers are attributed](https://kguardian.dev/concepts/peer-attribution).

**After upgrading the broker:**

1. **Existing rows are not backfilled.** The migration adds the columns
   and leaves them `NULL` on every pre-upgrade row — a backfill against
   today's tables would reproduce the bug permanently. Legacy rows are
   resolved by IP with the start-time guard (`GET /pod/ip/{ip}?at=`).
   The guard removes the impossible answers; it cannot recover history
   that was never recorded, so an old row can still render as an
   unattributed IP where a pod was previously (wrongly) shown.
   `pod_details.started_at` is likewise `NULL` on pre-upgrade pod rows
   until the controller re-posts the pod — every live pod is re-posted
   when the controller restarts, so the DaemonSet rollout fills it in;
   pods that were already dead at upgrade time never receive one (the
   controller only re-posts live pods, and stored manifests carry no
   `status`) and are excluded from by-IP attribution, so a historical
   row whose peer was such a pod renders as unattributed rather than
   being guessed from the IP's current holder. Live pods gain a start
   time within 60 s and every flow recorded after the upgrade carries
   its peer identity, so the gap is confined to pre-upgrade history and
   closes with retention. Among live pods, `NULL` means a ghost row or a
   Pending pod. A dead candidate is also rejected when it was already
   dead at flow time (its record `time_stamp` — last seen alive or marked
   dead — is before the flow); a pod marked dead late is over-permissive
   only for the bounded interval in between. The controller no longer
   posts Succeeded/Failed/deleting pods as alive and its reconciler marks
   them dead, so a completed Job cannot be attributed later flows on its
   recycled IP. The broker also
   marks alive rows dead when they have not been re-posted for
   `broker.peerResolution.staleAliveSeconds` (default 900, env
   `PEER_STALE_ALIVE_SECS`, `0` disables), since the controller re-posts
   live pods every 60 s; a ghost row can no longer claim an IP.
2. **Regenerate policies after a fresh observation window.** Rows written
   from now on carry a definite peer. Let a representative window of
   traffic accumulate (hours for most workloads; a full cycle for
   anything driven by CronJobs), then regenerate rather than reusing
   policies built from the pre-upgrade backlog. Expect some peers that
   used to render as a `podSelector` to become an `ipBlock` with a
   `# unattributed peer <ip> at <time>` comment — that is a stale
   identity being refused, not a regression.
3. **Late-resolve window.** A flow that arrives before its peer pod's
   spec is stored with a `NULL` peer and re-resolved by a broker task
   within `broker.peerResolution.lateResolveWindowSeconds` (default 600,
   env `PEER_LATE_RESOLVE_WINDOW_SECS`; `0` disables the task). Raise it
   only if the controller lags pod creation by more than ten minutes on
   your cluster. An IP that matches nothing — external traffic included —
   stays `NULL` rather than being stamped `external`, so the guarded
   fallback still applies to it later.
4. **Upgrade the broker first, then the frontend, CLI and llm-bridge.**
   An old consumer ignores the new fields and keeps resolving by IP
   without the guard. A new consumer against an old broker sees neither
   `peer_*` nor `started_at` on any record, so it cannot apply the guard
   either; the misattribution persists until the broker is upgraded.

## Node-IP traffic is now recorded; host-network peers render as `ipBlock` / entities

Controllers up to 1.11.0 with `controller.ignoreDaemonSet: true` (the default)
put every DaemonSet pod IP into the eBPF ignore list. Host-network
DaemonSets (node-exporter, the kguardian controller itself, most CNIs) have
the node's IP as their pod IP, so every node IP was ignored and **no**
pod-to-node flow was ever recorded: kubelet `:10250`, node-exporter
`:9100`, etcd `:2381`, the API server on `:6443` on control-plane nodes.
Policies generated for anything that scrapes or probes nodes were missing
those rules and broke on apply.

The controller now skips host-network DaemonSet pods (they are still not
registered with the probe) without ignoring their IP, and excluded
namespaces are checked before the ignore list is touched. `ignoreDaemonSet`
keeps its default and its meaning: DaemonSet pods' own traffic is not
recorded.

**After upgrading the controller:**

1. Node-IP flows start appearing in the broker and the UI. Expect the
   `pod_traffic` table to grow for monitoring, logging and service-mesh
   workloads.
2. Regenerate policies for any workload that talks to nodes (Prometheus,
   metrics agents, anything hitting kubelet or the API server via a node
   IP) after a fresh observation window. The new rules render as
   `ipBlock: {cidr: <node IP>/32}` on Kubernetes NetworkPolicies and
   `toEntities: [host, remote-node]` on CiliumNetworkPolicies, because a
   `podSelector` cannot match host-network traffic. Scope differs: the
   `ipBlock` names one node IP (the pod's own node is always allowed by the
   NetworkPolicy spec; enforcement for remote node IPs is CNI-specific),
   while the Cilium entities rule admits the port on every node, since
   Cilium does not apply CIDR rules to node IPs. See
   [Host-network peers and targets](https://kguardian.dev/guides/generating-network-policies#host-network-peers-and-targets).
3. Upgrade the broker alongside the controller. The controller reports
   `host_network` in the pod payload; an old broker has no column for it,
   so every generator falls back to the previous (ineffective)
   `podSelector` rendering for host-network peers. A new broker with an old
   controller derives the value from the stored pod manifest, so rendering
   is correct, but the node-IP flows themselves are still not captured
   until the controller is upgraded.

## Seccomp: capture tiers, and distribution is now driven by a `SeccompProfile` CRD

This release changes what the controller traces by default and how a seccomp
profile reaches a node. The previous chart's profile pipeline (broker-side
publish state, override endpoints, hash-named files) was never exposed in the
UI and is gone; read points 3–5 if you had `seccomp.distribute: true`.

### 1. Default capture is now `full`

The controller used to trace a fixed set of 56 security-relevant syscalls.
It now traces **every** syscall by default (`syscalls.captureLevel: full`).
The probe de-duplicates per pod network namespace inside BPF — each syscall
crosses into userspace once per pod — so the CPU cost is close to what it
was. Expect the broker's `pod_syscalls` table to grow (roughly 100–200 rows
per pod instead of a few dozen).

`full` is the only tier that yields a complete, enforceable profile. If you
never intend to ship profiles and want the old footprint back:

```yaml
syscalls:
  captureLevel: low      # exactly the previous 56 syscalls, by name
```

The other tiers are `high` (everything except hot-path noise), `medium`
(`low` plus network / file-permission / process-lifecycle families) and
`custom` (`syscalls.customList`, comma-joined into `SYSCALL_CUSTOM_LIST`).
The value is case-insensitive; an invalid level fails `helm template`. A
workload can raise its own tier above the cluster default with the
pod-template annotation `kguardian.dev/syscall-capture: <level>`; it can
never lower it. `kguardian.dev/seccomp-record: "true"` still works as an
alias for `full`.

### 2. arm64 nodes now trace the right syscalls

Syscall numbers were hard-coded for x86_64, so the filtered set selected
the **wrong** syscalls on arm64 nodes. Names are now resolved per
architecture at controller startup via libseccomp. No action needed — but
profiles generated from arm64 observations before this release should be
treated as suspect and regenerated.

### 3. Profiles reach nodes only through a `SeccompProfile` CR (behaviour change)

Previously, with `seccomp.distribute: true`, every workload with an observed
syscall set was written to every node automatically as
`kguardian/<ns>/<kind>-<name>-<hash>.json`. The controller no longer polls the
broker for profiles at all. It watches `SeccompProfile` objects
(`kguardian.dev/v1alpha1`, namespaced) and writes one file per CR:
`kguardian/<namespace>/<cr-name>.json`. Deleting the CR deletes the file.

**After upgrading, nothing new is written until you apply a CR.** Files the
old distributor wrote are left in place (the new controller never touches
paths it does not own), so a workload referencing an old hash-named file
keeps starting — but that file will never be updated again. To move over:

1. Export the CR for the workload (UI → Export, or
   `GET /seccomp/profiles/<ns>/<kind>/<name>/export`), review, commit, apply.
2. Wait for `kubectl -n <ns> get seccompprofile <name>` to show `READY n/n`.
3. Point the workload at `kguardian/<ns>/<cr-name>.json` and roll it.
4. Prune the old `kguardian/<ns>/*-<hash>.json` files by hand if you like;
   nothing depends on them any more.

The exported CR defaults to `defaultAction: SCMP_ACT_LOG`. Enforcing is a
one-line edit to the CR in git, not an API call.

Upgrade the broker and controller images together. An older controller
(chart ≤ 1.20) polling the new broker sees a summary without
`localhostProfile` and with `hash` now meaning the observed set, so it
distributes nothing and logs a parse warning every poll interval until it is
upgraded; a new controller against an old broker gets `404` on
`PUT /seccomp/crs` and has its `files` list ignored by node-status, so CR
status stays `Pending`. Both are harmless and clear once the images match.

### 4. The CRD is installed as a template: `seccomp.installCRDs` (default `true`)

Helm applies `crds/` on first install and never upgrades them. The
`SeccompProfile` CRD is instead rendered as a release resource (annotated
`helm.sh/resource-policy: keep`), so schema changes ship with `helm upgrade`.
Consequences:

- `helm uninstall` leaves the CRD — and every `SeccompProfile` — in place.
  Delete it by hand once no workload references a profile.
- If you manage CRDs separately, set `seccomp.installCRDs: false` and apply
  `charts/kguardian/files/kguardian.dev_seccompprofiles.yaml` yourself
  before enabling `distribute`.
- The two `AuditNetworkPolicy` CRDs still ship in `crds/` and install the old
  way: they predate this pattern and their schema has not needed an upgrade;
  `SeccompProfile` uses the template path because its schema is expected to
  evolve and Helm cannot upgrade anything under `crds/`.

With `seccomp.distribute: true` the controller ClusterRole gains
`get/list/watch` on `seccompprofiles`, `patch` on `seccompprofiles/status`,
and `list` on `nodes`. Nothing is added when distribution is off.

### 5. Removed: `seccomp.overrides.*` and the broker lifecycle endpoints

`seccomp.overrides.enabled` and `SECCOMP_OVERRIDES_ENABLED` are gone, along
with `PUT/DELETE /seccomp/profiles/.../override` and the short-lived
`publish` / `unpublish` / `enforce` / `audit` routes. Editing a profile is now
editing the CR. The broker migration drops the `workload_seccomp_overrides`,
`seccomp_override_audit` and `workload_seccomp_state` tables; none of them
had a UI, so there is nothing to migrate. A stale `seccomp.overrides` key in
your values file is ignored.

## Cilium policies: cross-namespace peers now carry the namespace label

Earlier generators emitted a peer in another namespace as bare
`k8s:<label>` entries in `fromEndpoints`/`toEndpoints`. Cilium scopes
those to the policy's own namespace, so the rule matched nothing and the
traffic was silently denied. Generated selectors for cross-namespace peers
now include `k8s:io.kubernetes.pod.namespace: <peer namespace>`.
Regenerate any CiliumNetworkPolicy that has cross-namespace peers (the
kube-dns egress rule is the usual one); Kubernetes NetworkPolicy output is
unaffected.

## SSO (opt-in): gate the UI behind OIDC via oauth2-proxy (`frontend.sso.*`)

The kguardian UI and broker API are unauthenticated by default. In a **Gateway
API** environment with an identity-aware proxy (**oauth2-proxy** in front of an
OIDC provider such as Dex/Keycloak/Authentik), the chart can gate the frontend
route behind SSO. It renders two Envoy Gateway objects (nothing when
`frontend.sso.enabled=false`, the default):

1. a **`SecurityPolicy`** that ext-auths the frontend HTTPRoute against
   oauth2-proxy — anonymous requests get `401` and are sent to sign in; and
2. an **`/oauth2/*` HTTPRoute** to oauth2-proxy so the OIDC callback and
   `/oauth2/userinfo` are served **same-origin**. The frontend auto-detects the
   session from `/oauth2/userinfo` at runtime (no rebuild, no env flag) and the
   account menu shows the signed-in user; without the proxy it stays in local
   mode.

```yaml
frontend:
  sso:
    enabled: true
    httpRouteName: kguardian          # the HTTPRoute you expose the UI on
    hostnames: ["kguardian.example.com"]
    parentRefs:
      - name: envoy-external
        namespace: network-system
        sectionName: https
    oauth2Proxy:
      name: oauth2-proxy
      namespace: network-system
      port: 80
```

**Required companion (not chart-rendered):** the oauth2-proxy `Service` is in
another namespace, so a **`ReferenceGrant`** in *that* namespace must allow
`SecurityPolicy` and `HTTPRoute` from the release namespace to reference it.
Add the release namespace to the proxy's existing grant. If the proxy uses a
domain-wide cookie (`cookie_domains=.example.com`), an existing SSO session on
any sibling app admits users here with no new OIDC client.
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
path and no per-tool authorization.

Be precise about what enabling it changes. A workload already inside the
cluster can read that same data from the Broker today, since
`broker.auth.enabled` defaults to `false`, so `/mcp` does not newly expose it
in-cluster. What `/mcp` adds is a path for that data to leave: it is built to
be consumed from a workstation over `kubectl port-forward`, by a client whose
config may be shared or committed. The token guards that path, and the strict
default is free to adopt now only because this endpoint is new and has no
existing users.

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
