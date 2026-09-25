# kguardian Helm Chart

This chart bootstraps the [kguardian]() controlplane onto a [Kubernetes](http://kubernetes.io) cluster using the [Helm](https://helm.sh) package manager.

![Version: 1.26.0](https://img.shields.io/badge/Version-1.26.0-informational?style=flat-square)

## Overview

This Helm chart deploys:

- A kguardian control plane configured to your specifications
- Additional features and components (optional)

## Prerequisites

- Linux Kernel 6.2+
- Kubernetes 1.19+
- kubectl v1.19+
- Helm 3.0+

## Install the Chart

To install the chart with the release name `kguardian`:

### Install from OCI Registry (Recommended)

```bash
helm install kguardian oci://ghcr.io/kguardian-dev/charts/kguardian \
  --namespace kguardian \
  --create-namespace
```

You can also specify a version:

```bash
helm install kguardian oci://ghcr.io/kguardian-dev/charts/kguardian \
  --version 1.1.1 \
  --namespace kguardian \
  --create-namespace
```

**Note:** *If you have the [Pod Securty Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/) enabled for your cluster you will need to add the following annotation to the namespace that the chart is deployed*

Example:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  labels:
    pod-security.kubernetes.io/enforce: privileged
    pod-security.kubernetes.io/warn: privileged
  name: kguardian
```

## Directory Structure

The following shows the directory structure of the Helm chart.

```bash
charts/kguardian/
├── .helmignore   # Contains patterns to ignore when packaging Helm charts.
├── Chart.yaml    # Information about your chart
├── values.yaml   # The default values for your templates
├── charts/       # Charts that this chart depends on
└── templates/    # The template files
    └── tests/    # The test files
```

## Configuration

The following table lists the configurable parameters of the kguardian chart and their default values.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| ai.baseUrl | string | `""` | Base URL of an OpenAI-compatible gateway (LiteLLM, vLLM, an enterprise proxy) to call instead of the vendor's own API. Applies to whichever provider `ai.provider` names. Empty = the vendor default.  kguardian appends the provider's request path to this value VERBATIM and never inserts, removes, or rewrites a `/v1` segment. That matters because LiteLLM answers on both `/chat/completions` and `/v1/chat/completions` while vLLM serves only the `/v1` form — so include `/v1` if your gateway needs it. A wrong base fails as a 404/405 whose error names this value, not as a silent fallback to the vendor API.   baseUrl: http://litellm.litellm.svc.cluster.local:4000/v1  YOU STILL NEED `ai.secret`. Provider availability is gated on the API key alone, so setting `baseUrl` without `ai.secret` still reports "no provider configured" and the assistant stays dark, however correct the URL is. Set `ai.secret` to your gateway's virtual key, or to any non-empty dummy value if the gateway is unauthenticated. This is the most common first-run mistake. |
| ai.enabled | bool | `false` | Enable the AI assistant with one toggle. The assistant is a single workload (llm-bridge) that runs the tools and policy/seccomp generation in-process — no separate mcp-server or advisor-serve components. |
| ai.mcp.auth.allowUnauthenticated | bool | `false` | Serve /mcp with NO authentication. Every caller that can reach the Service gets unrestricted read access to your cluster's telemetry.  This exists as an explicit, reviewable opt-out rather than the chart silently allowing it, and rather than the chart forbidding it outright: if you front llm-bridge with a default-deny NetworkPolicy or a mesh with mTLS, the bearer token is genuinely redundant and refusing to render would be the chart overruling you about your own cluster. Setting it to true makes that judgement visible in your values file and in code review, which a missing token never is.  Note the failure is loud: `helm template` errors, so with a GitOps controller the whole release stops reconciling, not just llm-bridge. That is deliberate for a config you have just written, but it is why the error names both remedies. |
| ai.mcp.auth.existingSecret | string | `""` | Name of an existing Secret holding the shared bearer token. REQUIRED when `ai.mcp.enabled=true` unless you explicitly set `allowUnauthenticated` below — the chart refuses to render an unauthenticated MCP endpoint by accident. Create it once:   kubectl create secret generic kguardian-mcp-token \     --from-literal=token="$(openssl rand -hex 32)" Clients then send `Authorization: Bearer <token>`. |
| ai.mcp.auth.secretKey | string | `"token"` | Key within that Secret. |
| ai.mcp.enabled | bool | `false` | Serve the MCP endpoint at /mcp. When false the path is not routed at all and 404s, so a disabled endpoint is indistinguishable from a build that never had one.  OFF by default. Enabled, it serves cluster telemetry — pod traffic, syscalls, audit verdicts — with no LLM in the path and no per-tool authorization.  To be accurate about what this does and does not change: a workload already inside the cluster can read that same data from the Broker today, since `broker.auth.enabled` is false by default and the Broker's API is a ClusterIP Service too. Turning /mcp on does not newly expose anything to a compromised pod. What it adds is a path for that data to leave the cluster — /mcp exists to be consumed from a workstation over `kubectl port-forward`, by a client whose config may be shared or committed. That is the exposure the token is for.  It is off by default, and authenticated by default, because this is a new endpoint with no existing users: the strict default costs nobody a migration today and could not be introduced later without breaking people. |
| ai.mcp.rateLimitPerMin | string | `""` | Per-IP request ceiling for /mcp, in requests per minute. Empty = the bridge's default of 300. Sized far above the chat route's 20/min because one MCP client session is many round-trips — an agent walking pods -> traffic -> verdicts -> policy burns 30-60 calls in seconds. The counter is per-replica (in-memory store), so with the default replicaCount of 2 the cluster-wide ceiling is roughly double this. It is a runaway-client guard, not a quota. A non-numeric or non-positive value is ignored by the bridge in favour of the default. |
| ai.model | string | `""` | Default model id the assistant asks the provider for. Empty = the built-in default for `ai.provider` (gpt-4o / claude-opus-4-8 / gemini-2.0-flash). Set this when pointing `ai.baseUrl` at a gateway whose model ids are its own — "gpt-4o" means nothing to a gateway routing to a local Llama, and the request fails model-not-found.   model: my-team/llama-3.3-70b |
| ai.provider | string | `""` | LLM provider for the assistant: one of "openai", "anthropic", "gemini", "copilot". With `ai.secret` this is the one-line way to wire a provider — the chart injects the right env var (OPENAI_API_KEY / ANTHROPIC_API_KEY / GOOGLE_API_KEY / GITHUB_TOKEN) from your secret. Leave empty to configure providers individually via llmBridge.secrets.* instead. |
| ai.secret | string | `""` | Name of an existing Secret holding the provider API key under the key `api-key` (override with llmBridge.secrets.keyName). Required when `ai.provider` is set. Create it once:   kubectl create secret generic my-llm-key --from-literal=api-key=sk-... |
| broker.affinity | object | `{}` | Affinity rules for broker pod assignment |
| broker.audit.evalTimeoutMs | int | `500` | Per-call timeout (in milliseconds) on the broker's POST to the evaluator's /evaluate endpoint. 500ms is plenty for an in-cluster evaluator (matcher is in-memory, sub-ms) but operators running the evaluator across cells / regions / VPNs may need more. Clamped to a minimum 50ms broker-side. |
| broker.audit.inflightPermits | int | `16` | Maximum concurrent in-flight /evaluate calls to the audit evaluator. Bound prevents an ingest spike from creating unbounded concurrent reqwest futures + connection-pool waiters. The broker's /metrics exposes broker_audit_inflight_available so operators can spot saturation. The metrics doc suggests bumping this value when the gauge sits at 0 (under sustained load you'll see "evaluator round-trips queueing"). In-broker default is 16 if unset; minimum is 1. |
| broker.audit.retention.batchSize | int | `5000` | Rows deleted per batched DELETE. The retention loop issues one DELETE per batch — bounded lock hold and bounded WAL chunk — and loops until the window is empty or a per-pass cap is hit. Clamped in the broker to [100, 100000]; values outside that range either round-trip the DB for trivial work (too small) or behave like an unbatched DELETE (too large). |
| broker.audit.retention.days | int | `30` | Retain audit_verdicts rows for this many days. Older rows are pruned by a tokio task in the broker that wakes every `intervalSeconds`. Set to 0 to disable retention entirely (table grows unbounded). |
| broker.audit.retention.intervalSeconds | int | `3600` | How often the cleanup pass runs, in seconds. Minimum 60. |
| broker.auth | object | `{"enabled":false,"existingSecret":"","secretKey":"token"}` | Optional bearer-token auth on the broker HTTP API. The broker API is otherwise unauthenticated; enabling this requires every controller / llm-bridge request to carry a shared secret, closing the forged-row / unauthorized-read exposure for those server-to-server paths. Opt-in (default false) for backward compatibility.  NOTE: the frontend talks to the broker directly from the browser and cannot safely hold a static token, so enabling auth does not cover the frontend path — keep the frontend on a trusted network or front the broker with an authenticating proxy for browser traffic.  /health and /metrics stay open (kubelet probes + Prometheus can't send the token). Provide the token yourself in a Secret (not generated by the chart, so it's stable across upgrades):   kubectl -n <ns> create secret generic kguardian-broker-auth \     --from-literal=token="$(openssl rand -hex 32)" |
| broker.auth.existingSecret | string | `""` | Name of an existing Secret holding the shared token. REQUIRED when enabled=true. |
| broker.auth.secretKey | string | `"token"` | Key within that Secret. |
| broker.autoscaling.enabled | bool | `false` | Enable horizontal pod autoscaling for broker |
| broker.autoscaling.maxReplicas | int | `100` | Maximum number of broker replicas |
| broker.autoscaling.minReplicas | int | `1` | Minimum number of broker replicas |
| broker.autoscaling.targetCPUUtilizationPercentage | int | `80` | Target CPU utilization percentage for autoscaling |
| broker.container.port | int | `9090` | Broker container port |
| broker.dbMigrationMaxRetries | int | `10` | Number of attempts the broker makes to run embedded migrations on startup, at 2s spacing. The chart's wait-for-db init container handles "DB not started" via TCP probe — this loop absorbs the gap between TCP-ready and postgres-accepting-queries (10-30s on slow / small nodes during initdb). 10 attempts ≈ 20s budget. Bump when broker crash-loops with "DB migration attempt N/10 failed" before postgres finishes warming up. Min 1. |
| broker.dbPoolMaxSize | int | `32` | r2d2 connection-pool max_size. r2d2's own default is 10, which is the bottleneck under heavy ingest: each audit evaluator round-trip and each regular request handler needs a pool connection. This MUST stay comfortably above audit.inflightPermits (default 16): if the pool only equals the permit count, a burst of audit evaluations can hold every connection and starve /health + ingest inserts — /health then 503s, liveness kills the broker, and it crash-loops (clients ECONNREFUSED → retry storm). The broker enforces a floor of inflightPermits + 8 at startup (logging a warn if it has to raise this), but the chart default ships safe: 32 with the default 16 permits leaves 16 connections of headroom. Tune up when broker logs show "could not get db conn for audit verdict insert" warns or when /metrics shows pool-acquire stalls. |
| broker.fullnameOverride | string | `""` | Override the full name of the broker resources |
| broker.helmTest.enabled | bool | `true` | Render a `helm.sh/hook: test` Pod that probes the broker's /health endpoint after install/upgrade. /health verifies schema state (kguardian-dev/kguardian#876), so a passing test confirms the broker can reach the database AND its migrations have run. Run with `helm test <release>`. |
| broker.image.pullPolicy | string | `"IfNotPresent"` | Broker image pull policy |
| broker.image.repository | string | `"ghcr.io/kguardian-dev/kguardian/broker"` | Broker container image repository |
| broker.image.sha | string | `""` | Overrides the image tag using SHA digest |
| broker.image.tag | string | `"1.18.2"` | Broker version tag (auto-updated by release-please) |
| broker.imagePullSecrets | list | `[]` | List of image pull secrets for private registries |
| broker.initContainer.image.pullPolicy | string | `"IfNotPresent"` | Broker init container image pull policy. See the controller's init container for why this is not `Always`. |
| broker.initContainer.image.repository | string | `"busybox"` | Broker init container image repository |
| broker.initContainer.image.sha | string | `""` | Overrides the init container image tag using SHA digest |
| broker.initContainer.image.tag | string | `"1.38.0"` | Broker init container image tag, pinned rather than `latest`. |
| broker.initContainer.securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true,"runAsNonRoot":true,"runAsUser":65534}` | Broker init container security context |
| broker.metrics.prometheusRule.enabled | bool | `false` | Create a PrometheusRule for prometheus-operator with alerts over the three `kguardian_seccomp_denial*` metrics above (fed by `seccomp.denials` — see that value for what feeds them). Off by default, like `serviceMonitor` above, for the same reason: it assumes a prometheus-operator Prometheus already exists and is configured to select PrometheusRule objects it did not create.  This toggle, `serviceMonitor.enabled`, and (if `broker.networkPolicy.enabled` is on) `broker.networkPolicy.allowMetricsFrom` are three independent switches. All three matter: a Prometheus that cannot reach the broker's /metrics — because nothing scrapes it, or because a default-deny NetworkPolicy blocks it — scrapes nothing, so enabling only this one renders alert rules that never fire because the series they name are simply absent, which alerts on absence (`absent()`) rather than the condition would surface, but plain threshold rules like these never will. |
| broker.metrics.prometheusRule.labels | object | `{}` | Extra labels on the PrometheusRule object (so prometheus-operator selects it — usually the same `release: kube-prometheus-stack` value set on `serviceMonitor.labels`; most installs require the matching label on both object kinds). |
| broker.metrics.serviceMonitor.enabled | bool | `false` | Create a ServiceMonitor for prometheus-operator. The broker exposes a Prometheus text-format /metrics endpoint with five gauges/counter:   broker_db_schema_ready, broker_db_reachable,   broker_audit_enabled, broker_audit_inflight_available,   broker_db_pool_idle, broker_db_pool_max,   broker_uptime_seconds Suggested alerts:   - broker_db_schema_ready == 0 for 5m   → silent failure mode   - broker_db_reachable == 0 for 1m      → DB connection issue   - broker_audit_inflight_available == 0 for 10m → bump     broker.audit.inflightPermits (default 16)   - broker_db_pool_idle == 0 for 10m     → bump     broker.dbPoolMaxSize (default 32) |
| broker.metrics.serviceMonitor.interval | string | `"30s"` | Scrape interval. |
| broker.metrics.serviceMonitor.labels | object | `{}` | Extra labels to add to the ServiceMonitor (so prometheus-operator picks it up — usually `release: kube-prometheus-stack`).  /metrics also carries `kguardian_seccomp_denials_total`, `kguardian_seccomp_denial_workloads` and `kguardian_seccomp_denial_rows_total` once `seccomp.denials.enabled` is capturing data — see `prometheusRule` below for alerts over them.  `kguardian_seccomp_denials_total` labels the denied workload's namespace `workload_namespace`, not `namespace`, so it survives the `namespace` target label prometheus-operator attaches to every ServiceMonitor job. Query and group on `workload_namespace`; there is deliberately no `honorLabels` setting here, because it would only cover operators scraping through this ServiceMonitor and a Prometheus with `overrideHonorLabels` pins it back to false anyway. |
| broker.metrics.serviceMonitor.path | string | `"/metrics"` | Endpoint path on the broker's HTTP service. |
| broker.metrics.serviceMonitor.port | string | `"http"` | Service port name to scrape. |
| broker.metrics.serviceMonitor.scrapeTimeout | string | `"10s"` | Scrape timeout. |
| broker.nameOverride | string | `""` | Override the name of the broker resources |
| broker.networkPolicy | object | `{"allowMetricsFrom":[],"allowedNodeCIDRs":[],"enabled":false}` | Ingress NetworkPolicy for the broker. The broker HTTP API is unauthenticated, so this restricts which in-cluster sources may reach it (llm-bridge, frontend, the helm-test pod via podSelector; the controller via allowedNodeCIDRs). Ingress-only — the broker's own egress (DB, DNS, evaluator) is never restricted. Requires a NetworkPolicy-enforcing CNI (Cilium, Calico, ...).  OPT-IN (default false) on purpose: the controller is a hostNetwork eBPF DaemonSet, so it posts to the broker from the NODE IP and a podSelector can NEVER match it. Enabling the policy without listing your node network in allowedNodeCIDRs will BLOCK the controller and stall its rollout. Enable only after setting allowedNodeCIDRs.  CAVEAT (validated on Cilium): the allowedNodeCIDRs ipBlock needed for the hostNetwork controller is a coarse allow — on some CNIs (Cilium) it also admits OTHER in-cluster pods, so this policy is defence-in- depth, NOT airtight isolation. The pod clients (llm-bridge/frontend) are precisely scoped via podSelector; the controller allowance is not. For strict broker isolation prefer a CNI-native policy (e.g. a CiliumNetworkPolicy using fromEntities: [host, remote-node]) or, the real fix, authentication on the broker API. |
| broker.networkPolicy.allowMetricsFrom | list | `[]` | Extra ingress peers allowed to reach the broker HTTP port. The /metrics endpoint shares that port, so when broker.metrics.serviceMonitor.enabled is true, add your Prometheus here. Each entry is a standard NetworkPolicyPeer. |
| broker.networkPolicy.allowedNodeCIDRs | list | `[]` | Node network CIDR(s) the controller DaemonSet runs on. Required when enabled=true, since the hostNetwork controller reaches the broker from its node IP. e.g. ["10.0.0.0/16"] or per-node /32s. On a dual-stack cluster list BOTH families — the controller reaches the broker over whichever the node resolves first, so a v4-only list silently blocks it on a v6-primary node. e.g. ["10.0.0.0/16", "fd00::/64"]. |
| broker.nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node labels for the kguardian broker pod assignment |
| broker.peerResolution.lateResolveWindowSeconds | int | `600` | Late-resolve window, in seconds. The broker stamps each traffic row's peer identity (pod / host-network pod / Service) when the row is ingested. A flow can arrive before the peer pod's spec does, in which case the row is stored with a NULL peer; a broker task wakes every 60 s (PEER_LATE_RESOLVE_INTERVAL_SECS, not exposed here) and re-resolves NULL rows whose time_stamp is younger than this window, at most 5000 per pass. Rows older than the window stay NULL for good (pre-upgrade history, an external IP, or a peer the cluster never learned about) and consumers fall back to a start-time-guarded by-IP lookup for them. Raise it on clusters where the controller lags pod creation by more than ten minutes. 0 disables the task; new rows then keep whatever resolved at ingest. Rendered as PEER_LATE_RESOLVE_WINDOW_SECS. |
| broker.peerResolution.staleAliveSeconds | int | `900` | Stale-alive sweep, in seconds. The controller re-posts every live pod every 60 s, so a pod_details row still marked alive that has not been re-posted for this long is a ghost (its node's controller lost it, or the row predates the upgrade). The broker marks such rows dead so they cannot win the alive-first ordering for an IP they no longer hold. 0 disables the sweep. Rendered as PEER_STALE_ALIVE_SECS. |
| broker.podAnnotations | object | `{}` | Annotations to add to broker pods |
| broker.podDisruptionBudget.enabled | bool | `false` | Create a PodDisruptionBudget for the broker. Defaults to false; enable when running >1 replica so voluntary evictions can't take all of them out. |
| broker.podDisruptionBudget.maxUnavailable | string | `""` |  |
| broker.podDisruptionBudget.minAvailable | int | `1` | Either minAvailable or maxUnavailable can be set (not both). Accepts integer or percentage string ("50%"). |
| broker.podSecurityContext | object | `{"fsGroup":1000,"fsGroupChangePolicy":"OnRootMismatch","runAsGroup":1000,"runAsUser":1000,"seccompProfile":{"type":"RuntimeDefault"},"supplementalGroups":[1000]}` | Broker pod security context. Runs as non-root user 1000 |
| broker.priorityClassName | string | `""` | Priority class to be used for the kguardian broker pods |
| broker.readAcquireWaitMs | int | `5000` | How long a read queues for budget before being shed with 503 (ms). 0 fails fast with no queueing. 5s rides out a burst (a hard-cap read holds its budget ~1-3s) while failing inside a typical client timeout. |
| broker.readMemoryBudgetMb | int | `256` | Total in-flight memory (MiB) the broker will commit to whole-result-set reads (/pod/traffic, /pod/info, /svc/info, /audit/verdicts, ...). This is what bounds concurrent heavy reads; dbPoolMaxSize does NOT — it was chosen for DB contention and never referenced memory, which let 32 concurrent 50 MiB reads be admitted into a 1Gi container and OOMKill it. One /pod/traffic?limit=20000 peaks at ~50 MiB (measured byte-exact: 1982 B/row of Rust heap + ~600 B/row of libpq PGresult). 256 MiB buys 5 concurrent hard-cap reads, or 20 concurrent default 5000-row reads. Reads that don't fit are REFUSED with 503 + Retry-After, never truncated — a short read would produce a policy with missing rules. Raise this and resources.limits.memory together: the broker clamps the budget to 30% of the limit and warns if you don't. Watch broker_read_shed_total and broker_read_budget_kib_available. |
| broker.replicaCount | int | `1` | Number of broker replicas to deploy |
| broker.resources | object | `{"limits":{"memory":"1Gi"},"requests":{"cpu":"100m","memory":"256Mi"}}` | Broker pod resource requests and limits |
| broker.seccomp.denials.metricsIntervalSeconds | int | `15` | Seconds between refreshes of the cached `kguardian_seccomp_denial*` aggregate that `/metrics` reads (the broker deliberately never queries Postgres on the scrape path — see `broker.metrics.prometheusRule`). Deliberately its own timer, NOT `retention.intervalSeconds` above: `KguardianSeccompEnforcingProfileDenials` fires on a 5-minute `increase()` window, and reusing the retention loop's cadence (default 3600s) would leave that alert — the one covering an enforcing profile actively blocking or killing a workload right now — up to an hour stale. Resist merging these two timers even though they look redundant; that is exactly the simplification that would quietly break the critical alert's latency. Broker default is 15s if unset, with a 5s floor. Lower for faster alerting at the cost of more frequent aggregation passes; there is little reason to raise it above the default. |
| broker.seccomp.denials.retention | object | `{"batchSize":5000,"days":30,"intervalSeconds":3600}` | Retention for the `seccomp_denials` table — the kernel-verdict rows the broker ingests from `POST /seccomp/denials` (fed by the controller's `audit_seccomp` kprobe; see `seccomp.denials` above). Mirrors `broker.audit.retention` in shape and mechanism: a tokio task wakes every `intervalSeconds` and deletes rows whose `last_seen` is older than `days`, `batchSize` rows per DELETE. |
| broker.seccomp.denials.retention.batchSize | int | `5000` | Rows deleted per batched DELETE. Same [100, 100000] clamp as `broker.audit.retention.batchSize`, for the same reason: bounded lock hold and bounded WAL chunk per statement. |
| broker.seccomp.denials.retention.days | int | `30` | Retain seccomp_denials rows for this many days. Also bounds the window `kguardian_seccomp_denial_workloads` counts over and what `GET /seccomp/denials?since=` can return. Set to 0 to disable retention entirely (table grows unbounded). |
| broker.seccomp.denials.retention.intervalSeconds | int | `3600` | How often the cleanup pass runs, in seconds. Minimum 60. |
| broker.seccomp.profilesCacheTtlSeconds | int | `10` | Seconds the Broker serves the same rendered `GET /seccomp/profiles` body before rebuilding it from the database. It is the Broker's heaviest read (~3 MB and ~2.5s per call at ~2,000 workloads): every open UI tab polls it every 15s, and the Controller's seccomp distributor polled it every 30s per node until #1632 moved that to the per-workload route, which on a 44-node cluster meant ~90 rebuilds a minute and grew the Broker from 380 MiB to its 4 GiB limit until it OOM-looped. Within the TTL every caller gets the same bytes and concurrent misses wait for one rebuild. The cost is staleness: a SeccompProfile CR's deployment state or drift can lag this list by up to this many seconds (the per-workload `GET /seccomp/profiles/{ns}/{kind}/{name}` route is never cached). Broker default is 10 if unset. Set 0 to rebuild on every request. |
| broker.securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"privileged":false,"readOnlyRootFilesystem":true,"runAsNonRoot":true,"runAsUser":1000}` | Broker container security context. Hardened with read-only root filesystem |
| broker.service.name | string | `"kguardian-broker"` | Broker service name |
| broker.service.port | int | `9090` | Broker service port |
| broker.service.type | string | `"ClusterIP"` | Broker service type |
| broker.serviceAccount.annotations | object | `{}` | Annotations to add to the service account |
| broker.serviceAccount.automountServiceAccountToken | bool | `false` | Automount API credentials for a service account |
| broker.serviceAccount.create | bool | `true` | Specifies whether a service account should be created |
| broker.serviceAccount.name | string | `""` | The name of the service account to use. If not set and create is true, a name is generated using the fullname template |
| broker.startupProbe | object | `{}` | Startup probe. Empty by default — opt in when slow startup is expected (e.g. cold image pull on small nodes). Replaces the default startup probe. |
| broker.statementTimeoutMs | int | `30000` | Per-statement timeout (ms) applied to every broker DB connection as a backstop: the broker runs as a single replica, so one slow or accidentally unbounded query would otherwise tie up a connection/worker indefinitely and can cascade into liveness-probe failures. Postgres kills any statement that exceeds this. 0 disables it. Startup migrations (long CREATE INDEX builds) are exempt. Healthy request queries are sub-second, so 30s is a safe ceiling that only ever fires on pathological queries. Tune down for tighter SLOs. |
| broker.tolerations | list | `[]` | Tolerations for the kguardian broker pod assignment |
| broker.topologySpreadConstraints | list | `[]` | Topology spread constraints applied to broker pods. Useful when running multiple replicas across zones/nodes. See https://kubernetes.io/docs/concepts/scheduling-eviction/topology-spread-constraints/ |
| broker.traffic.retention | object | `{"batchSize":5000,"days":14,"intervalSeconds":3600}` | Retention for the `pod_traffic` table, the observed flows every generated NetworkPolicy is built from. A tokio task in the broker wakes every `intervalSeconds` and deletes rows older than `days` whose pod no longer exists: dead, gone from the pod table, or an earlier pod that held the same name. Rows of running pods are never pruned, however old. Each flow is recorded once, when first seen, and a running pod does not report it again, so deleting those rows would drop rules from the next policy generated for that pod. |
| broker.traffic.retention.batchSize | int | `5000` | Rows examined per batched DELETE (at most this many are deleted per statement). Same [100, 100000] clamp as `broker.audit.retention.batchSize`, for the same reason. |
| broker.traffic.retention.days | int | `14` | Keep traffic of departed pods for this many days. The default of 14 keeps two runs of a weekly CronJob; raise it for jobs that run less often than every `days` / 2 days, or their flows can be gone by the time you generate a policy. Set to 0 to disable retention entirely (table grows unbounded). |
| broker.traffic.retention.intervalSeconds | int | `3600` | How often the cleanup pass runs, in seconds. Minimum 60. |
| compute | object | `{"contention":{"enabled":false,"minRunqLatencyUs":100},"enabled":true,"history":{"minuteResolutionHours":24,"retentionDays":7},"sampleInterval":5,"thresholds":{"blameShare":0.4,"memStallSome":10,"minRunqEvents":50,"refaultPerMin":1000,"runqP99Ms":20,"stallSome":20,"throttledRatio":0.25,"throttledRatioMax":0.1}}` | Live compute gauges and noisy-neighbour detection. Three layers, each gating the next: **usage** (CPU / memory per container against its limit, request or the node), **stall** (cgroup v2 PSI, CFS throttle counters, memory reclaim events) and **blame** (an eBPF scheduler probe that records, in kernel, who was on the CPU while a tracked pod waited). The first two are a file walk over `/sys/fs/cgroup` with no BPF; only the third loads a probe. Findings (`noisy-neighbor`, `cpu-throttled`, `cpu-contended`, `memory-pressure`, `memory-limit-thrash`) are computed in the broker so the UI, the CLI and the assistant agree. Needs cgroup v2 and PSI on the node; a node without them reports itself unsupported and renders without gauges. A pod opts out with the annotation `kguardian.dev/compute: "off"`. See docs/concepts/compute-contention. |
| compute.contention.enabled | bool | `false` | Load the `sched_contention` eBPF probe (`sched_wakeup`, `sched_wakeup_new`, `sched_switch`, `sched_process_exit`) so the broker can name the pod, system unit or kernel thread a stalled pod waited behind. Requires `compute.enabled`. Off by default until its per-node overhead is measured against the roadmap's controller-overhead line (design doc, Phase 4); without it kguardian still raises the self-inflicted findings (`cpu-throttled`, `memory-limit-thrash`) but never a `noisy-neighbor`. The probe requires kernel BTF (`/sys/kernel/btf/vmlinux`); without it the probe does not load, the node reports `contention_loaded=false` and the gauge and stall layers keep working. |
| compute.contention.minRunqLatencyUs | int | `100` | In-kernel filter: a run-queue wait shorter than this many microseconds is dropped before any map write. Lower values record more noise at higher probe cost; raise it on nodes with very high context-switch rates. |
| compute.enabled | bool | `true` | Master switch. Mounts `/sys/fs/cgroup` read-only into the controller and starts the sampler, which reads ~10 small files per container every `sampleInterval`. On by default: the gauge and stall layers cost about one file walk per interval and the feature is most useful when every pod already has history the first time someone looks. `false` removes the mount, the sampler and every `COMPUTE_*` setting below. |
| compute.history.minuteResolutionHours | int | `24` | Hours of history kept at one-minute resolution before the broker's retention pass folds it into 5-minute rows. Rendered into `COMPUTE_HISTORY_MINUTE_HOURS`. |
| compute.history.retentionDays | int | `7` | Days of per-pod compute and contention history the broker keeps. Minute rows are downsampled to 5-minute rows after `minuteResolutionHours`, so 7 days at 3 000 containers stays under ~10 M rows. `0` disables history inserts and pruning and, because every compute finding is computed from history, disables all findings too; only the live gauges (`pod_compute_latest`) remain. Rendered into `COMPUTE_HISTORY_RETENTION_DAYS`. |
| compute.sampleInterval | int | `5` | Seconds between cgroup samples. Drives the live gauges and the `pod_compute_latest` upsert; the controller folds one minute of samples into one history row regardless of this value. |
| compute.thresholds | object | `{"blameShare":0.4,"memStallSome":10,"minRunqEvents":50,"refaultPerMin":1000,"runqP99Ms":20,"stallSome":20,"throttledRatio":0.25,"throttledRatioMax":0.1}` | Finding thresholds, evaluated by the broker over the last five minutes of history. Rendered into `COMPUTE_THRESHOLD_*` on the broker. |
| compute.thresholds.blameShare | float | `0.4` | Share of a victim's total wait time a single cgroup must account for before it is named as the culprit. The culprit must also be using CPU above its own request (or have none) — a pod inside its request is entitled to that CPU. |
| compute.thresholds.memStallSome | int | `10` | `memory-pressure` fires when a container's `memory.pressure some avg10` is at or above this percentage while the node itself is under memory pressure. Memory blame is a heuristic and is labelled as one. |
| compute.thresholds.minRunqEvents | int | `50` | Run-queue events per minute a history row must carry before its p99 counts as a CPU stall. Filters p99-only findings on near-idle sidecars (a dozen wakeups a minute); the overflow bucket (multi-second waits) is never filtered. |
| compute.thresholds.refaultPerMin | int | `1000` | Workingset refaults per minute that count as thrashing for `memory-pressure`: the second way (besides `memStallSome`) a container qualifies as a memory victim while the node is under pressure. |
| compute.thresholds.runqP99Ms | int | `20` | Run-queue latency p99, in milliseconds, at or above which a victim counts as stalled. Only meaningful with `contention.enabled`. |
| compute.thresholds.stallSome | int | `20` | A victim counts as stalled when its cgroup `cpu.pressure some avg10` is at or above this percentage for two consecutive minutes (or its run-queue p99 crosses `runqP99Ms`). |
| compute.thresholds.throttledRatio | float | `0.25` | `cpu-throttled` fires when a container's CFS throttled time divided by its quota time over the window is at or above this ratio. Remediation is the container's own `limits.cpu`; no neighbour is named. |
| compute.thresholds.throttledRatioMax | float | `0.1` | Hard gate: a container throttled above this ratio is never reported as a `noisy-neighbor` victim, whatever the scheduler probe says, because its own quota explains the wait. |
| controller.affinity | object | `{}` | Affinity rules for controller pod assignment |
| controller.autoscaling.enabled | bool | `false` | Enable horizontal pod autoscaling for controller |
| controller.autoscaling.maxReplicas | int | `100` | Maximum number of controller replicas |
| controller.autoscaling.minReplicas | int | `1` | Minimum number of controller replicas |
| controller.autoscaling.targetCPUUtilizationPercentage | int | `80` | Target CPU utilization percentage for autoscaling |
| controller.containerdBundlePath | string | `"/run/containerd/io.containerd.runtime.v2.task"` | Path to the containerd runtime bundle directory on the host node. For k3s clusters, set to: /run/k3s/containerd/io.containerd.runtime.v2.task |
| controller.containerdSockPath | string | `"/run/containerd/containerd.sock"` | Path to the containerd socket on the host node. For k3s clusters, set to: /run/k3s/containerd/containerd.sock |
| controller.excludedNamespaces | list | `["kguardian","kube-system"]` | Namespaces excluded from network-flow and syscall capture (the inputs to NetworkPolicy and seccomp generation). Compute gauges and noisy-neighbour attribution still cover these namespaces when `compute.enabled` is on: a pod here still shows CPU/memory and can be a victim or a culprit. Opt a single pod out of compute with the `kguardian.dev/compute: "off"` annotation instead. |
| controller.fullnameOverride | string | `""` | Override the full name of the controller resources |
| controller.ignoreDaemonSet | bool | `true` | Skip DaemonSet pods: their network namespaces are not registered with the eBPF probe, so their own flows are never recorded (log shippers, CNI agents, node-exporter are noise for policy generation). Host-network DaemonSet pods share the node's IP; those pods are still skipped, but their IP is never added to the probe's ignore list, so traffic from any pod TO a node IP (kubelet :10250, node-exporter :9100, etcd :2381, apiserver :6443) is recorded and shows up in generated policies. Controllers up to 1.11.0 ignored the node IP as well, which silently dropped every pod-to-node flow. |
| controller.image.pullPolicy | string | `"IfNotPresent"` | Controller image pull policy |
| controller.image.repository | string | `"ghcr.io/kguardian-dev/kguardian/controller"` | Controller container image repository |
| controller.image.sha | string | `""` | Overrides the image tag using SHA digest |
| controller.image.tag | string | `"1.15.1"` | Controller version tag (auto-updated by release-please) |
| controller.imagePullSecrets | list | `[]` | List of image pull secrets for private registries |
| controller.initContainer.image.pullPolicy | string | `"IfNotPresent"` | Init container image pull policy. `IfNotPresent`, not `Always`: this init container runs on every node, and `Always` forces a registry manifest request on every pod start even when the image is already cached locally. Those requests count against Docker Hub's anonymous pull limit, which is per source IP, so a NATed cluster shares one bucket across the whole fleet. A throttled pull leaves the init container in ImagePullBackOff and the agent never starts on that node, so its pods are never observed and the generated policy silently omits their rules. |
| controller.initContainer.image.repository | string | `"busybox"` | Init container image repository |
| controller.initContainer.image.tag | string | `"1.38.0"` | Init container image tag. Pinned rather than `latest`: every other image in this chart is pinned, an unpinned tag means whatever it resolves to at pull time runs on every node, and `latest` is what forces `pullPolicy: Always` to re-check. |
| controller.initContainer.securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true,"runAsNonRoot":true,"runAsUser":65534}` | Init container security context |
| controller.nameOverride | string | `""` | Override the name of the controller resources |
| controller.nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node labels for the kguardian controller pod assignment |
| controller.podAnnotations | object | `{}` | Annotations to add to controller pods |
| controller.podSecurityContext | object | `{"seccompProfile":{"type":"RuntimeDefault"}}` | Controller pod security context. Runs with seccomp RuntimeDefault profile |
| controller.priorityClassName | string | `""` | Priority class to be used for the kguardian controller pods |
| controller.resources | object | `{"limits":{"memory":"512Mi"},"requests":{"cpu":"100m","memory":"256Mi"}}` | Controller pod resource requests and limits. eBPF requires more memory. |
| controller.securityContext | object | `{"allowPrivilegeEscalation":true,"capabilities":{"add":["CAP_BPF"]},"privileged":true,"readOnlyRootFilesystem":true}` | Controller container security context. Requires privileged mode for eBPF |
| controller.service.port | int | `80` | Controller service port |
| controller.service.type | string | `"ClusterIP"` | Controller service type |
| controller.serviceAccount.annotations | object | `{}` | Annotations to add to the service account |
| controller.serviceAccount.automountServiceAccountToken | bool | `true` | Automount API credentials for a service account (controller needs K8s API access) |
| controller.serviceAccount.create | bool | `true` | Specifies whether a service account should be created |
| controller.serviceAccount.name | string | `""` | The name of the service account to use. If not set and create is true, a name is generated using the fullname template |
| controller.tolerations | list | `[{"effect":"NoSchedule","key":"node-role.kubernetes.io/control-plane","operator":"Exists"}]` | Tolerations for the kguardian controller pod assignment |
| controller.updateStrategy | object | `{}` | Rolling update strategy for the Controller DaemonSet. Kubernetes defaults to maxUnavailable 1 with maxSurge 0, which updates one node at a time. A node the kubelet refuses the pod on (DiskPressure, for example) never becomes Ready, so it holds that single slot indefinitely and no further node is updated. On a large cluster one unhealthy node can stall the rollout completely. A percentage lets the rest proceed:   updateStrategy:     rollingUpdate:       maxUnavailable: 20% |
| database.affinity | object | `{}` | Affinity rules for database pod assignment |
| database.autoscaling.enabled | bool | `false` | Enable horizontal pod autoscaling for database |
| database.autoscaling.maxReplicas | int | `100` | Maximum number of database replicas |
| database.autoscaling.minReplicas | int | `1` | Minimum number of database replicas |
| database.autoscaling.targetCPUUtilizationPercentage | int | `80` | Target CPU utilization percentage for autoscaling |
| database.container.port | int | `5432` | PostgreSQL container port |
| database.databaseName | string | `"kube"` | Database name used by the broker. Must exist on external Postgres. |
| database.enabled | bool | `true` | Deploy the bundled in-cluster PostgreSQL. Set false to use an external PostgreSQL — populate `database.external.host` and provide credentials via `database.existingSecret`. |
| database.existingSecret | string | `""` | Existing Secret containing the DB password under the key configured by `database.passwordSecretKey`. When empty AND `database.enabled=true`, the chart provisions a Secret named "kguardian-db-credentials" with a random password (regenerated only on first install). |
| database.external.host | string | `""` | Hostname or FQDN of the external PostgreSQL instance, e.g. "postgres.databases.svc.cluster.local" or "db.example.com". Required when `database.enabled=false`. |
| database.external.port | int | `5432` | Port of the external PostgreSQL instance. |
| database.external.sslMode | string | `"prefer"` | libpq sslmode for the external connection (disable | allow | prefer | require | verify-ca | verify-full). Cloud-managed Postgres typically requires "require" or stricter. |
| database.fullnameOverride | string | `""` | Override the full name of the database resources |
| database.image.pullPolicy | string | `"IfNotPresent"` | PostgreSQL image pull policy |
| database.image.repository | string | `"postgres"` | PostgreSQL container image repository |
| database.image.sha | string | `""` | Overrides the image tag using SHA digest |
| database.image.tag | string | `"18-alpine"` | PostgreSQL image tag (pinned; bump deliberately). @breaking 18-alpine: PostgreSQL major-version data dirs are not forward-compatible. Existing PG15 PersistentVolumeClaims must be migrated with pg_upgrade or dropped before upgrading. See charts/kguardian/UPGRADING.md. |
| database.imagePullSecrets | list | `[]` | List of image pull secrets for private registries |
| database.name | string | `"kguardian-db"` | Object name for the in-cluster Database deployment / PVC / SA. Only used when `database.enabled=true`. |
| database.nameOverride | string | `""` | Override the name of the database resources |
| database.nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node labels for the kguardian database pod assignment |
| database.passwordSecretKey | string | `"password"` | Secret data key holding the DB password. |
| database.persistence.enabled | bool | `true` | Enable persistent storage for database. Defaults to true; set to false only for ephemeral testing. |
| database.persistence.existingClaim | string | `""` | Use an existing PersistentVolumeClaim instead of creating a new one. When unset, the chart provisions a PVC named "{{ database.name }}-data". |
| database.persistence.preUpgradeBackup | bool | `false` | Run a pg_dumpall as a Helm pre-upgrade/pre-rollback hook before each chart upgrade. The dump is printed to the Job's stdout — retrieve with `kubectl logs job/<database.name>-pre-upgrade-backup` or pipe to your existing log-aggregation backup pipeline.  Best-effort: a failed backup is logged but does NOT block the upgrade.  OFF BY DEFAULT because of where the dump goes. stdout means the cluster's log pipeline, and the payload is the whole database: every observed flow with addresses and ports, plus pod metadata and per-workload syscall sets — effectively a map of internal cluster traffic. A log sink is usually readable by a wider group than the database, is frequently a third-party SaaS, and has its own retention that outlives the Job. This template already strips role password hashes (`--no-role-passwords`) on exactly that reasoning; the same argument applies to the payload, which is why enabling it should be a deliberate choice rather than a default.  It is also large: `pod_traffic` keeps every flow of every running pod (only departed pods' traffic is pruned, see `broker.traffic.retention`), and the whole dump is emitted as a single burst on every upgrade.  Set to true if your log pipeline is an acceptable destination for that data, or prefer a backup that writes somewhere with access control comparable to the database itself. |
| database.persistence.safeBoot | bool | `true` | Refuse to start the database when the PVC contains an unrelated PostgreSQL data directory (e.g. PG15 layout from before chart 1.10.0) AND the current major's directory is empty. The default postgres image would silently `initdb` over the empty location and the operator would only notice once the schema came up empty.  Set to false to bypass the check — for example, when intentionally promoting from one major to another after running `pg_upgrade` offline. See charts/kguardian/UPGRADING.md. |
| database.persistence.size | string | `"10Gi"` | Size of the auto-provisioned PVC (only used when existingClaim is unset) |
| database.persistence.storageClassName | string | `""` | StorageClass for the auto-provisioned PVC (only used when existingClaim is unset). Empty string uses the cluster's default StorageClass. |
| database.podAnnotations | object | `{}` | Annotations to add to database pods |
| database.podSecurityContext | object | `{"fsGroup":999,"fsGroupChangePolicy":"OnRootMismatch","runAsGroup":999,"runAsUser":999,"seccompProfile":{"type":"RuntimeDefault"},"supplementalGroups":[999]}` | Database pod security context. Runs as postgres user (999) |
| database.priorityClassName | string | `""` | Priority class to be used for the kguardian database pods |
| database.resources | object | `{"limits":{"memory":"512Mi"},"requests":{"cpu":"100m","memory":"256Mi"}}` | Database pod resource requests and limits |
| database.securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"privileged":false,"readOnlyRootFilesystem":false,"runAsNonRoot":true,"runAsUser":999}` | Database container security context. Non-root with dropped capabilities |
| database.service.name | string | `"kguardian-db"` | Database service name |
| database.service.port | int | `5432` | Database service port |
| database.service.type | string | `"ClusterIP"` | Database service type |
| database.serviceAccount.annotations | object | `{}` | Annotations to add to the service account |
| database.serviceAccount.automountServiceAccountToken | bool | `false` | Automount API credentials for a service account |
| database.serviceAccount.create | bool | `true` | Specifies whether a service account should be created |
| database.serviceAccount.name | string | `""` | The name of the service account to use. If not set and create is true, a name is generated using the fullname template |
| database.tolerations | list | `[]` | Tolerations for the kguardian database pod assignment |
| database.user | string | `"rust"` | PostgreSQL role used by the broker. Must exist on external Postgres. |
| evaluator | object | `{"affinity":{},"autoscaling":{"enabled":false,"maxReplicas":5,"minReplicas":1,"targetCPUUtilizationPercentage":80},"container":{"port":8082},"enabled":true,"env":[],"image":{"pullPolicy":"IfNotPresent","repository":"ghcr.io/kguardian-dev/kguardian/evaluator","sha":"","tag":"v0.4.2"},"imagePullSecrets":[],"logLevel":"info","metrics":{"serviceMonitor":{"enabled":false,"interval":"30s","labels":{},"path":"/metrics","port":"http","scrapeTimeout":"10s"}},"nodeSelector":{"kubernetes.io/os":"linux"},"podAnnotations":{},"podDisruptionBudget":{"enabled":false,"maxUnavailable":"","minAvailable":1},"podSecurityContext":{"fsGroup":1000,"fsGroupChangePolicy":"OnRootMismatch","runAsGroup":1000,"runAsUser":1000,"seccompProfile":{"type":"RuntimeDefault"},"supplementalGroups":[1000]},"priorityClassName":"","replicaCount":1,"resources":{"limits":{"memory":"256Mi"},"requests":{"cpu":"50m","memory":"64Mi"}},"securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"privileged":false,"readOnlyRootFilesystem":true,"runAsNonRoot":true,"runAsUser":1000},"service":{"name":"kguardian-evaluator","port":8082,"type":"ClusterIP"},"serviceAccount":{"annotations":{},"automountServiceAccountToken":true,"create":true,"name":""},"startupProbe":{},"tolerations":[],"topologySpreadConstraints":[]}` | ----------------------------------------------------------------------- |
| evaluator.affinity | object | `{}` | Affinity rules for evaluator pod assignment |
| evaluator.autoscaling.enabled | bool | `false` | Enable horizontal pod autoscaling for evaluator |
| evaluator.autoscaling.maxReplicas | int | `5` | Maximum number of evaluator replicas |
| evaluator.autoscaling.minReplicas | int | `1` | Minimum number of evaluator replicas |
| evaluator.autoscaling.targetCPUUtilizationPercentage | int | `80` | Target CPU utilization percentage for autoscaling |
| evaluator.container.port | int | `8082` | Evaluator HTTP port |
| evaluator.enabled | bool | `true` | Deploy the audit-mode policy evaluator. When false, the evaluator workload, RBAC, Service, and PDB/ServiceMonitor are skipped. The CRD itself ships in charts/kguardian/crds/ and is always installed by Helm regardless of this toggle.  The evaluator is now published at ghcr.io/kguardian-dev/kguardian/evaluator and on by default. Set to false to skip the workload while still installing the AuditNetworkPolicy CRD (e.g. for shared-cluster setups where the evaluator runs elsewhere). |
| evaluator.env | list | `[]` | Additional environment variables for the evaluator |
| evaluator.image.pullPolicy | string | `"IfNotPresent"` | Evaluator image pull policy |
| evaluator.image.repository | string | `"ghcr.io/kguardian-dev/kguardian/evaluator"` | Evaluator container image repository |
| evaluator.image.sha | string | `""` | Overrides the image tag using SHA digest |
| evaluator.image.tag | string | `"v0.4.2"` | Evaluator version tag (auto-updated by release-please) |
| evaluator.imagePullSecrets | list | `[]` | List of image pull secrets for private registries |
| evaluator.logLevel | string | `"info"` | Log level for the evaluator process (panic|fatal|error|warn|info|debug|trace) |
| evaluator.metrics.serviceMonitor.enabled | bool | `false` | Create a ServiceMonitor for prometheus-operator. The evaluator does not currently expose /metrics natively — forward-compatible toggle for when it does. |
| evaluator.nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node labels for evaluator pod assignment |
| evaluator.podAnnotations | object | `{}` | Annotations to add to evaluator pods |
| evaluator.podDisruptionBudget.enabled | bool | `false` | Create a PodDisruptionBudget for the evaluator. Defaults to false; enable when running >1 replica. |
| evaluator.podSecurityContext | object | `{"fsGroup":1000,"fsGroupChangePolicy":"OnRootMismatch","runAsGroup":1000,"runAsUser":1000,"seccompProfile":{"type":"RuntimeDefault"},"supplementalGroups":[1000]}` | Evaluator pod security context. Runs as non-root user (1000) |
| evaluator.priorityClassName | string | `""` | Priority class to be used for the kguardian evaluator pods |
| evaluator.replicaCount | int | `1` | Number of evaluator replicas |
| evaluator.resources | object | `{"limits":{"memory":"256Mi"},"requests":{"cpu":"50m","memory":"64Mi"}}` | Evaluator pod resource requests and limits |
| evaluator.securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"privileged":false,"readOnlyRootFilesystem":true,"runAsNonRoot":true,"runAsUser":1000}` | Evaluator container security context. Hardened with read-only root filesystem |
| evaluator.service.name | string | `"kguardian-evaluator"` | Evaluator service name |
| evaluator.service.port | int | `8082` | Evaluator service port |
| evaluator.service.type | string | `"ClusterIP"` | Evaluator service type |
| evaluator.serviceAccount.annotations | object | `{}` | Annotations to add to the service account |
| evaluator.serviceAccount.automountServiceAccountToken | bool | `true` | Automount API credentials (the evaluator must reach the API server to watch CRDs, pods, and namespaces) |
| evaluator.serviceAccount.create | bool | `true` | Specifies whether a service account should be created |
| evaluator.serviceAccount.name | string | `""` | The name of the service account to use |
| evaluator.startupProbe | object | `{}` | Startup probe. Empty by default — opt in when slow startup is expected. |
| evaluator.tolerations | list | `[]` | Tolerations for evaluator pod assignment |
| evaluator.topologySpreadConstraints | list | `[]` | Topology spread constraints applied to evaluator pods. |
| frontend.affinity | object | `{}` | Affinity rules for frontend pod assignment |
| frontend.autoscaling.enabled | bool | `false` | Enable horizontal pod autoscaling for frontend |
| frontend.autoscaling.maxReplicas | int | `100` | Maximum number of frontend replicas |
| frontend.autoscaling.minReplicas | int | `1` | Minimum number of frontend replicas |
| frontend.autoscaling.targetCPUUtilizationPercentage | int | `80` | Target CPU utilization percentage for autoscaling |
| frontend.container.port | int | `5173` | Frontend container port (serve) |
| frontend.fullnameOverride | string | `""` | Override the full name of the frontend resources |
| frontend.image.pullPolicy | string | `"IfNotPresent"` | Frontend image pull policy |
| frontend.image.repository | string | `"ghcr.io/kguardian-dev/kguardian/frontend"` | Frontend container image repository |
| frontend.image.sha | string | `""` | Overrides the image tag using SHA digest |
| frontend.image.tag | string | `"1.19.0"` | Frontend version tag (auto-updated by release-please) |
| frontend.imagePullSecrets | list | `[]` | List of image pull secrets for private registries |
| frontend.ingress.annotations | object | `{}` | Ingress annotations |
| frontend.ingress.apiPath | bool | `true` | Also route /api on the same host to the Broker. The Broker serves bare paths (/pod/info, /pod/traffic), so this only works behind an ingress controller that strips the prefix, such as nginx with rewrite-target. Controllers that pass the path through unchanged (AWS ALB, for example) make every /api request a 404. The UI image proxies /api to the Broker itself, so setting this to false serves the whole application from the UI Service and works on any controller. |
| frontend.ingress.className | string | `""` | Ingress class name |
| frontend.ingress.enabled | bool | `false` | Enable ingress for frontend |
| frontend.ingress.hosts | list | `[{"host":"kguardian.example.com","paths":[{"path":"/","pathType":"Prefix"}]}]` | Ingress hosts configuration |
| frontend.ingress.tls | list | `[]` | Ingress TLS configuration |
| frontend.metrics.serviceMonitor.enabled | bool | `false` | Create a ServiceMonitor for prometheus-operator. The frontend does not currently expose /metrics — forward-compatible toggle. |
| frontend.metrics.serviceMonitor.interval | string | `"30s"` |  |
| frontend.metrics.serviceMonitor.labels | object | `{}` |  |
| frontend.metrics.serviceMonitor.path | string | `"/metrics"` |  |
| frontend.metrics.serviceMonitor.port | string | `"http"` |  |
| frontend.metrics.serviceMonitor.scrapeTimeout | string | `"10s"` |  |
| frontend.nameOverride | string | `""` | Override the name of the frontend resources |
| frontend.nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node labels for the kguardian frontend pod assignment |
| frontend.podAnnotations | object | `{}` | Annotations to add to frontend pods |
| frontend.podDisruptionBudget.enabled | bool | `false` | Create a PodDisruptionBudget for the frontend. Defaults to false; enable when running >1 replica. |
| frontend.podDisruptionBudget.maxUnavailable | string | `""` |  |
| frontend.podDisruptionBudget.minAvailable | int | `1` |  |
| frontend.podSecurityContext | object | `{"fsGroup":1337,"fsGroupChangePolicy":"OnRootMismatch","runAsGroup":1337,"runAsUser":1337,"seccompProfile":{"type":"RuntimeDefault"},"supplementalGroups":[1337]}` | Frontend pod security context. Runs as non-root user (1337) |
| frontend.priorityClassName | string | `""` | Priority class to be used for the kguardian frontend pods |
| frontend.replicaCount | int | `1` | Number of frontend replicas to deploy |
| frontend.resources | object | `{"limits":{"memory":"256Mi"},"requests":{"cpu":"50m","memory":"128Mi"}}` | Frontend pod resource requests and limits |
| frontend.securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"privileged":false,"readOnlyRootFilesystem":false,"runAsNonRoot":true,"runAsUser":1337}` | Frontend container security context. Hardened with read-only root filesystem |
| frontend.service.name | string | `"kguardian-frontend"` | Frontend service name |
| frontend.service.port | int | `5173` | Frontend service port |
| frontend.service.type | string | `"ClusterIP"` | Frontend service type |
| frontend.serviceAccount.annotations | object | `{}` | Annotations to add to the service account |
| frontend.serviceAccount.automountServiceAccountToken | bool | `false` | Automount API credentials for a service account |
| frontend.serviceAccount.create | bool | `true` | Specifies whether a service account should be created |
| frontend.serviceAccount.name | string | `""` | The name of the service account to use. If not set and create is true, a name is generated using the fullname template |
| frontend.sso.enabled | bool | `false` | Gate the frontend behind SSO (renders a SecurityPolicy + /oauth2 route) |
| frontend.sso.headersToBackend | list | `["x-auth-request-user","x-auth-request-email"]` | Identity headers the proxy injects back into the app after auth |
| frontend.sso.headersToExtAuth | list | `["cookie","authorization"]` | Request headers the gateway forwards to the proxy for the auth check |
| frontend.sso.hostnames | list | `[]` | Hostnames for the /oauth2 auth-flow route — must match the app host |
| frontend.sso.httpRouteName | string | `""` | Name of the HTTPRoute to protect (you or your gitops render the route) |
| frontend.sso.oauth2Proxy | object | `{"authPath":"/oauth2/auth","name":"oauth2-proxy","namespace":"network-system","port":80}` | The identity-aware proxy providing ext-auth + the /oauth2 endpoints |
| frontend.sso.oauth2Proxy.authPath | string | `"/oauth2/auth"` | ext-auth check path on the proxy |
| frontend.sso.parentRefs | list | `[]` | Gateway parentRefs the /oauth2 route attaches to |
| frontend.startupProbe | object | `{}` | Startup probe. Empty by default — opt in when slow startup is expected. |
| frontend.tolerations | list | `[]` | Tolerations for the kguardian frontend pod assignment |
| frontend.topologySpreadConstraints | list | `[]` | Topology spread constraints applied to frontend pods. |
| global.annotations | object | `{}` | Annotations to apply to all resources |
| global.labels | object | `{}` | Labels to apply to all resources |
| global.priorityClassName | string | `""` | Priority class to be used for the kguardian pods |
| llmBridge.affinity | object | `{}` | Affinity rules for llm-bridge pod assignment |
| llmBridge.autoscaling.enabled | bool | `false` | Enable horizontal pod autoscaling for llm-bridge |
| llmBridge.autoscaling.maxReplicas | int | `10` | Maximum number of llm-bridge replicas |
| llmBridge.autoscaling.minReplicas | int | `2` | Minimum number of llm-bridge replicas |
| llmBridge.autoscaling.targetCPUUtilizationPercentage | int | `80` | Target CPU utilization percentage for autoscaling |
| llmBridge.container.port | int | `8080` | LLM Bridge container port |
| llmBridge.enabled | bool | `false` | Enable LLM Bridge service for AI assistant (or use ai.enabled to turn on the whole path) |
| llmBridge.env | list | `[]` | Additional environment variables for llm-bridge |
| llmBridge.fullnameOverride | string | `""` | Override the full name of the llm-bridge resources |
| llmBridge.image.pullPolicy | string | `"IfNotPresent"` | LLM Bridge image pull policy |
| llmBridge.image.repository | string | `"ghcr.io/kguardian-dev/kguardian/llm-bridge"` | LLM Bridge container image repository |
| llmBridge.image.sha | string | `""` | Overrides the image tag using SHA digest |
| llmBridge.image.tag | string | `"1.11.2"` | LLM Bridge version tag (auto-updated by release-please) |
| llmBridge.imagePullSecrets | list | `[]` | List of image pull secrets for private registries |
| llmBridge.metrics.serviceMonitor.enabled | bool | `false` | Create a ServiceMonitor for prometheus-operator. llm-bridge does not currently expose /metrics — forward-compatible toggle. |
| llmBridge.metrics.serviceMonitor.interval | string | `"30s"` |  |
| llmBridge.metrics.serviceMonitor.labels | object | `{}` |  |
| llmBridge.metrics.serviceMonitor.path | string | `"/metrics"` |  |
| llmBridge.metrics.serviceMonitor.port | string | `"http"` |  |
| llmBridge.metrics.serviceMonitor.scrapeTimeout | string | `"10s"` |  |
| llmBridge.nameOverride | string | `""` | Override the name of the llm-bridge resources |
| llmBridge.nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node labels for the kguardian llm-bridge pod assignment |
| llmBridge.podAnnotations | object | `{}` | Annotations to add to llm-bridge pods |
| llmBridge.podDisruptionBudget.enabled | bool | `false` | Create a PodDisruptionBudget for the llm-bridge. Defaults to false; enable when running >1 replica. |
| llmBridge.podDisruptionBudget.maxUnavailable | string | `""` |  |
| llmBridge.podDisruptionBudget.minAvailable | int | `1` |  |
| llmBridge.podSecurityContext | object | `{"fsGroup":1000,"fsGroupChangePolicy":"OnRootMismatch","runAsGroup":1000,"runAsUser":1000,"seccompProfile":{"type":"RuntimeDefault"},"supplementalGroups":[1000]}` | LLM Bridge pod security context. Runs as non-root user (node:1000) |
| llmBridge.priorityClassName | string | `""` | Priority class to be used for the kguardian llm-bridge pods |
| llmBridge.replicaCount | int | `2` | Number of llm-bridge replicas to deploy |
| llmBridge.resources | object | `{"limits":{"memory":"512Mi"},"requests":{"cpu":"100m","memory":"256Mi"}}` | LLM Bridge pod resource requests and limits |
| llmBridge.secrets.anthropic.enabled | bool | `false` | Enable Anthropic Claude provider |
| llmBridge.secrets.anthropic.name | string | `"kguardian-anthropic"` | Secret name for Anthropic |
| llmBridge.secrets.copilot.enabled | bool | `false` | Enable GitHub Copilot provider |
| llmBridge.secrets.copilot.name | string | `"kguardian-copilot"` | Secret name for GitHub Copilot |
| llmBridge.secrets.gemini.enabled | bool | `false` | Enable Google Gemini provider |
| llmBridge.secrets.gemini.name | string | `"kguardian-gemini"` | Secret name for Gemini |
| llmBridge.secrets.keyName | string | `"api-key"` | Normalized secret key name used for all providers |
| llmBridge.secrets.openai.enabled | bool | `false` | Enable OpenAI provider |
| llmBridge.secrets.openai.name | string | `"kguardian-openai"` | Secret name for OpenAI |
| llmBridge.securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"privileged":false,"readOnlyRootFilesystem":true,"runAsNonRoot":true,"runAsUser":1000}` | LLM Bridge container security context. Hardened with read-only root filesystem |
| llmBridge.service.name | string | `"kguardian-llm-bridge"` | LLM Bridge service name |
| llmBridge.service.port | int | `8080` | LLM Bridge service port |
| llmBridge.service.type | string | `"ClusterIP"` | LLM Bridge service type |
| llmBridge.serviceAccount.annotations | object | `{}` | Annotations to add to the service account |
| llmBridge.serviceAccount.automountServiceAccountToken | bool | `false` | Automount API credentials for a service account |
| llmBridge.serviceAccount.create | bool | `true` | Specifies whether a service account should be created |
| llmBridge.serviceAccount.name | string | `""` | The name of the service account to use. If not set and create is true, a name is generated using the fullname template |
| llmBridge.startupProbe | object | `{}` | Startup probe. Empty by default — opt in when slow startup is expected. |
| llmBridge.tolerations | list | `[]` | Tolerations for the kguardian llm-bridge pod assignment |
| llmBridge.topologySpreadConstraints | list | `[]` | Topology spread constraints applied to llm-bridge pods. |
| namespace.annotations | object | `{}` | Annotations to add to the namespace |
| namespace.labels | object | `{}` | Labels to add to the namespace |
| namespace.name | string | `""` | Namespace name. If empty, uses the release namespace |
| seccomp | object | `{"denials":{"enabled":true,"intervalSeconds":10},"distribute":false,"distributeIntervalSeconds":"","installCRDs":true,"kubeletRoot":"/var/lib/kubelet"}` | Seccomp profile distribution, driven by the user-owned `SeccompProfile` CRD (`kguardian.dev/v1alpha1`). kguardian observes syscalls and renders a CR manifest you can commit; nothing reaches a node until you apply that CR. When `distribute` is on, the controller on every node watches `SeccompProfile` objects cluster-wide and writes each one to `<kubeletRoot>/seccomp/kguardian/<namespace>/<name>.json`, so a workload references it with `securityContext.seccompProfile.type: Localhost` + `localhostProfile: kguardian/<namespace>/<name>.json`. Deleting the CR deletes the file. kguardian never edits workloads and never writes a profile that is not backed by a CR. See docs/guides/distributing-seccomp-profiles. |
| seccomp.denials | object | `{"enabled":true,"intervalSeconds":10}` | Capture the kernel's own seccomp verdicts and turn them into a kguardian signal. A `SeccompProfile` with `defaultAction: SCMP_ACT_LOG` (kguardian's own default export — see above) makes the kernel write every would-be denial to the node's audit log (`type=SECCOMP` in `dmesg` / auditd); until this feature, kguardian never read that back, so the audit output of the very profile it generated was invisible to it. This attaches a kprobe on the kernel's `audit_seccomp()` — called whenever seccomp has decided an action is loggable — so the controller sees the verdict directly, attributes it to a pod/workload, and the broker stores it, exports `kguardian_seccomp_denial*` Prometheus metrics (see `broker.metrics.prometheusRule`), and mirrors it onto the `SeccompProfile`'s `status.denials` and `DenialsObserved` condition.  This answers a different question than the `Drift` condition. `Drift` is inferred from eBPF syscall observation and fires as soon as the workload makes a syscall your CR does not allow — even if no pod has ever referenced the profile. A denial only exists once a kernel filter built from that profile has actually been loaded and evaluated a syscall. Use `Drift` to catch a profile falling behind the workload; use denials to know the kernel is really acting on what you shipped. See docs/guides/distributing-seccomp-profiles. |
| seccomp.denials.enabled | bool | `true` | Load the `audit_seccomp` kprobe. Requires `CONFIG_AUDITSYSCALL=y` on the node kernel; where the symbol is absent the controller skips the probe and logs a warning rather than failing to start — the same degrade-gracefully pattern used for the syscall probe's IPv6 kprobe pair (see `controller/src/bpf.rs`, `kernel_can_fentry` / `symbol_location`). On by default: an audit-mode profile (`SCMP_ACT_LOG`) is inert without this — the kernel logs the verdict to the node's kernel ring buffer and nothing in kguardian ever reads it back.  Setting this also mounts the host's cgroup v2 root (`/sys/fs/cgroup`) read-only into the controller, the same mount `compute.enabled` asks for. A `hostNetwork: true` pod has no network namespace of its own, so its denials can only be attributed by the cgroup the calling task was in, and resolving a container's cgroup id needs that tree. Without it those verdicts are counted and dropped, and a workload whose denials nothing can attribute reports none at all. |
| seccomp.denials.intervalSeconds | int | `10` | Seconds between drains of the in-kernel denial counter map. Denials are counted in an LRU hash keyed on (netns, cgroup, generation, syscall, action) rather than streamed one ringbuffer event per denial — a compromised or malfunctioning process making the same blocked syscall in a tight loop must not be able to flood the controller — and the controller drains and clears that map on this interval, posting the counts to the broker. Matches the syscall probe's own drain cadence (`controller/src/syscall.rs`).  The Controller also declares this value to the Broker on every report, empty heartbeats included, and the Broker derives that node's staleness window from it: the node counts as still watching for `max(300, intervalSeconds * 3)` seconds after its last report, and a workload's `denials` block (and the `DenialsObserved` condition) falls back to "Unknown" only once no capturing node is inside its own window. Below ~100 the 300 s floor governs, which is the point: a node that misses a drain or two is late, not gone.  The supported range is 1-600 and the chart refuses anything larger. That staleness window is not only a timeout — it is how long kguardian will keep telling you a workload is clean on the strength of one old report — so the Broker caps it at 1800 s. Without the cap, a large interval meant that when the last capturing node went away (spot reclaim, autoscaler, a `CONFIG_AUDITSYSCALL=n` rebuild) every workload kept reading `total: 0` for hours with nothing watching. A node draining slower than 600 s is heard from less often than the Broker will vouch for it, so its workloads would sit at "Unknown" between reports: the honest answer, but not a useful setting.  Lower it for faster metric/status visibility at the cost of more frequent Broker POSTs; raise it on very large clusters to reduce Broker load — 600 is 60x fewer POSTs than the default. |
| seccomp.distribute | bool | `false` | Reconcile `SeccompProfile` CRs onto nodes. Adds a hostPath mount of the kubelet seccomp directory to the controller pod and grants the controller get/list/watch on `seccompprofiles`, patch on `seccompprofiles/status`, and list on `nodes`. Off by default — referencing a profile is a workload-availability decision for the app team. Without it the CRD still installs and the UI still exports manifests; they just never land on a node. |
| seccomp.distributeIntervalSeconds | string | `""` | Seconds between full resyncs of the `SeccompProfile` watch (the watch itself reacts to changes immediately). A resync lists nodes once and reads one Broker profile per distinct `workloadRef`; with no `SeccompProfile` objects it reads nothing. Empty uses the controller default (30). |
| seccomp.installCRDs | bool | `true` | Install the `SeccompProfile` CRD as a chart template (with `helm.sh/resource-policy: keep`) rather than from `crds/`. Helm applies `crds/` on install only and never upgrades them; a templated CRD is upgraded with the release, so schema changes ship with the chart. The trade-off: the CRD is part of the release, so a `helm uninstall` leaves it behind on purpose (the `keep` policy) — delete it by hand if you also want every `SeccompProfile` object gone. Set to `false` if you manage CRDs separately; then apply `charts/kguardian/files/kguardian.dev_seccompprofiles.yaml` yourself before enabling `distribute`. |
| seccomp.kubeletRoot | string | `"/var/lib/kubelet"` | Kubelet root directory on the host. Profiles are written under `<kubeletRoot>/seccomp/kguardian/`. Not `/var/lib/kubelet` everywhere: k3s uses `/var/lib/rancher/k3s/agent/kubelet`, some kubeadm installs and OpenShift differ. |
| syscalls | object | `{"captureLevel":"full","customList":[]}` | Syscall capture tier for the controller's eBPF probe. Sets `SYSCALL_CAPTURE_LEVEL` / `SYSCALL_CUSTOM_LIST` on the controller DaemonSet. |
| syscalls.captureLevel | string | `"full"` | Cluster-wide capture level: `full` (default, every syscall — the only tier an enforcing seccomp profile can be exported from), `high`, `medium`, `low` or `custom`. Full capture is de-duplicated in BPF so it costs about the same CPU as `low`; pick a lower tier only if you never intend to enforce seccomp profiles and want a smaller syscall table in the broker. Below `full`, the broker still exports audit-only (`SCMP_ACT_LOG`) profiles and stamps every manifest with `kguardian.dev/capture-level` and `kguardian.dev/capture-complete`, but refuses to render a denying `defaultAction` unless the request passes `acknowledgePartial=true`. The block above lists what each tier traces. |
| syscalls.customList | list | `[]` | Syscall names for `captureLevel: custom` (ignored on any other level), rendered comma-joined into `SYSCALL_CUSTOM_LIST`, e.g. `[execve, openat, connect]`. A name unknown on the node's architecture is logged and skipped, never fatal. |
| telemetry.enabled | bool | `true` | Enable the daily anonymous version check-in. The broker asks the kguardian version service for the latest released versions (surfacing an update notice in the UI and at GET /version); the request doubles as the project's only usage signal. Exactly six fields are sent — a random install UUID, broker version, chart version, Kubernetes version, live node count, and CPU architecture. No cluster names, no IPs stored, no user data. Documented verbatim at https://docs.kguardian.dev/telemetry. Set to false to disable entirely: no task is spawned and no request is ever made. Air-gapped/egress-restricted clusters can also just leave it on — failures are silent and harmless. |
| telemetry.endpoint | string | `"https://version.kguardian.dev/v1/check"` | Version service the broker calls once a day. Override to self-host or point at a mock; unreachable endpoints are ignored silently. |

## Upgrading

For breaking-change migrations between chart versions (e.g. PostgreSQL major-version
bumps), see [UPGRADING.md](./UPGRADING.md).

## Uninstalling the Chart

To uninstall/delete the my-release deployment:

```bash
helm uninstall my-release
```
