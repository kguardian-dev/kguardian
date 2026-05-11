# kguardian Helm Chart

This chart bootstraps the [kguardian]() controlplane onto a [Kubernetes](http://kubernetes.io) cluster using the [Helm](https://helm.sh) package manager.

![Version: 1.11.1](https://img.shields.io/badge/Version-1.11.1-informational?style=flat-square)

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
| broker.affinity | object | `{}` | Affinity rules for broker pod assignment |
| broker.audit.evalTimeoutMs | int | `500` | Per-call timeout (in milliseconds) on the broker's POST to the evaluator's /evaluate endpoint. 500ms is plenty for an in-cluster evaluator (matcher is in-memory, sub-ms) but operators running the evaluator across cells / regions / VPNs may need more. Clamped to a minimum 50ms broker-side. |
| broker.audit.inflightPermits | int | `16` | Maximum concurrent in-flight /evaluate calls to the audit evaluator. Bound prevents an ingest spike from creating unbounded concurrent reqwest futures + connection-pool waiters. The broker's /metrics exposes broker_audit_inflight_available so operators can spot saturation. The metrics doc suggests bumping this value when the gauge sits at 0 (under sustained load you'll see "evaluator round-trips queueing"). In-broker default is 16 if unset; minimum is 1. |
| broker.audit.retention.batchSize | int | `5000` | Rows deleted per batched DELETE. The retention loop issues one DELETE per batch — bounded lock hold and bounded WAL chunk — and loops until the window is empty or a per-pass cap is hit. Clamped in the broker to [100, 100000]; values outside that range either round-trip the DB for trivial work (too small) or behave like an unbatched DELETE (too large). |
| broker.audit.retention.days | int | `30` | Retain audit_verdicts rows for this many days. Older rows are pruned by a tokio task in the broker that wakes every `intervalSeconds`. Set to 0 to disable retention entirely (table grows unbounded). |
| broker.audit.retention.intervalSeconds | int | `3600` | How often the cleanup pass runs, in seconds. Minimum 60. |
| broker.autoscaling.enabled | bool | `false` | Enable horizontal pod autoscaling for broker |
| broker.autoscaling.maxReplicas | int | `100` | Maximum number of broker replicas |
| broker.autoscaling.minReplicas | int | `1` | Minimum number of broker replicas |
| broker.autoscaling.targetCPUUtilizationPercentage | int | `80` | Target CPU utilization percentage for autoscaling |
| broker.container.port | int | `9090` | Broker container port |
| broker.dbMigrationMaxRetries | int | `10` | Number of attempts the broker makes to run embedded migrations on startup, at 2s spacing. The chart's wait-for-db init container handles "DB not started" via TCP probe — this loop absorbs the gap between TCP-ready and postgres-accepting-queries (10-30s on slow / small nodes during initdb). 10 attempts ≈ 20s budget. Bump when broker crash-loops with "DB migration attempt N/10 failed" before postgres finishes warming up. Min 1. |
| broker.dbPoolMaxSize | int | `16` | r2d2 connection-pool max_size. r2d2's own default is 10, which is the bottleneck under heavy ingest: each audit evaluator round-trip and each regular request handler needs a pool connection. 16 here matches audit.inflightPermits for parity. Tune up when broker logs show "could not get db conn for audit verdict insert" warns or when /metrics shows pool-acquire stalls. |
| broker.fullnameOverride | string | `""` | Override the full name of the broker resources |
| broker.helmTest.enabled | bool | `true` | Render a `helm.sh/hook: test` Pod that probes the broker's /health endpoint after install/upgrade. /health verifies schema state (kguardian-dev/kguardian#876), so a passing test confirms the broker can reach the database AND its migrations have run. Run with `helm test <release>`. |
| broker.image.pullPolicy | string | `"IfNotPresent"` | Broker image pull policy |
| broker.image.repository | string | `"ghcr.io/kguardian-dev/kguardian/broker"` | Broker container image repository |
| broker.image.sha | string | `""` | Overrides the image tag using SHA digest |
| broker.image.tag | string | `"1.9.0"` | Broker version tag (auto-updated by release-please) |
| broker.imagePullSecrets | list | `[]` | List of image pull secrets for private registries |
| broker.initContainer.image.pullPolicy | string | `"Always"` | Broker init container image pull policy |
| broker.initContainer.image.repository | string | `"busybox"` | Broker init container image repository |
| broker.initContainer.image.sha | string | `""` | Overrides the init container image tag using SHA digest |
| broker.initContainer.image.tag | string | `"latest"` | Broker init container image tag |
| broker.initContainer.securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true,"runAsNonRoot":true,"runAsUser":65534}` | Broker init container security context |
| broker.metrics.serviceMonitor.enabled | bool | `false` | Create a ServiceMonitor for prometheus-operator. The broker exposes a Prometheus text-format /metrics endpoint with five gauges/counter:   broker_db_schema_ready, broker_db_reachable,   broker_audit_enabled, broker_audit_inflight_available,   broker_db_pool_idle, broker_db_pool_max,   broker_uptime_seconds Suggested alerts:   - broker_db_schema_ready == 0 for 5m   → silent failure mode   - broker_db_reachable == 0 for 1m      → DB connection issue   - broker_audit_inflight_available == 0 for 10m → bump     broker.audit.inflightPermits (default 16)   - broker_db_pool_idle == 0 for 10m     → bump     broker.dbPoolMaxSize (default 16) |
| broker.metrics.serviceMonitor.interval | string | `"30s"` | Scrape interval. |
| broker.metrics.serviceMonitor.labels | object | `{}` | Extra labels to add to the ServiceMonitor (so prometheus-operator picks it up — usually `release: kube-prometheus-stack`). |
| broker.metrics.serviceMonitor.path | string | `"/metrics"` | Endpoint path on the broker's HTTP service. |
| broker.metrics.serviceMonitor.port | string | `"http"` | Service port name to scrape. |
| broker.metrics.serviceMonitor.scrapeTimeout | string | `"10s"` | Scrape timeout. |
| broker.nameOverride | string | `""` | Override the name of the broker resources |
| broker.nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node labels for the kguardian broker pod assignment |
| broker.podAnnotations | object | `{}` | Annotations to add to broker pods |
| broker.podDisruptionBudget.enabled | bool | `false` | Create a PodDisruptionBudget for the broker. Defaults to false; enable when running >1 replica so voluntary evictions can't take all of them out. |
| broker.podDisruptionBudget.maxUnavailable | string | `""` |  |
| broker.podDisruptionBudget.minAvailable | int | `1` | Either minAvailable or maxUnavailable can be set (not both). Accepts integer or percentage string ("50%"). |
| broker.podSecurityContext | object | `{"fsGroup":1000,"fsGroupChangePolicy":"OnRootMismatch","runAsGroup":1000,"runAsUser":1000,"seccompProfile":{"type":"RuntimeDefault"},"supplementalGroups":[1000]}` | Broker pod security context. Runs as non-root user 1000 |
| broker.priorityClassName | string | `""` | Priority class to be used for the kguardian broker pods |
| broker.replicaCount | int | `1` | Number of broker replicas to deploy |
| broker.resources | object | `{"limits":{"memory":"1Gi"},"requests":{"cpu":"100m","memory":"256Mi"}}` | Broker pod resource requests and limits |
| broker.securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"privileged":false,"readOnlyRootFilesystem":true,"runAsNonRoot":true,"runAsUser":1000}` | Broker container security context. Hardened with read-only root filesystem |
| broker.service.name | string | `"kguardian-broker"` | Broker service name |
| broker.service.port | int | `9090` | Broker service port |
| broker.service.type | string | `"ClusterIP"` | Broker service type |
| broker.serviceAccount.annotations | object | `{}` | Annotations to add to the service account |
| broker.serviceAccount.automountServiceAccountToken | bool | `false` | Automount API credentials for a service account |
| broker.serviceAccount.create | bool | `true` | Specifies whether a service account should be created |
| broker.serviceAccount.name | string | `""` | The name of the service account to use. If not set and create is true, a name is generated using the fullname template |
| broker.startupProbe | object | `{}` | Startup probe. Empty by default — opt in when slow startup is expected (e.g. cold image pull on small nodes). Replaces the default startup probe. |
| broker.tolerations | list | `[]` | Tolerations for the kguardian broker pod assignment |
| broker.topologySpreadConstraints | list | `[]` | Topology spread constraints applied to broker pods. Useful when running multiple replicas across zones/nodes. See https://kubernetes.io/docs/concepts/scheduling-eviction/topology-spread-constraints/ |
| controller.affinity | object | `{}` | Affinity rules for controller pod assignment |
| controller.autoscaling.enabled | bool | `false` | Enable horizontal pod autoscaling for controller |
| controller.autoscaling.maxReplicas | int | `100` | Maximum number of controller replicas |
| controller.autoscaling.minReplicas | int | `1` | Minimum number of controller replicas |
| controller.autoscaling.targetCPUUtilizationPercentage | int | `80` | Target CPU utilization percentage for autoscaling |
| controller.containerdBundlePath | string | `"/run/containerd/io.containerd.runtime.v2.task"` | Path to the containerd runtime bundle directory on the host node. For k3s clusters, set to: /run/k3s/containerd/io.containerd.runtime.v2.task |
| controller.containerdSockPath | string | `"/run/containerd/containerd.sock"` | Path to the containerd socket on the host node. For k3s clusters, set to: /run/k3s/containerd/containerd.sock |
| controller.excludedNamespaces | list | `["kguardian","kube-system"]` | Namespaces to be excluded from monitoring (comma-separated list) |
| controller.fullnameOverride | string | `""` | Override the full name of the controller resources |
| controller.ignoreDaemonSet | bool | `true` | Ignore traffic from daemonset pods to reduce noise |
| controller.image.pullPolicy | string | `"IfNotPresent"` | Controller image pull policy |
| controller.image.repository | string | `"ghcr.io/kguardian-dev/kguardian/controller"` | Controller container image repository |
| controller.image.sha | string | `""` | Overrides the image tag using SHA digest |
| controller.image.tag | string | `"1.8.1"` | Controller version tag (auto-updated by release-please) |
| controller.imagePullSecrets | list | `[]` | List of image pull secrets for private registries |
| controller.initContainer.image.pullPolicy | string | `"Always"` | Init container image pull policy |
| controller.initContainer.image.repository | string | `"busybox"` | Init container image repository |
| controller.initContainer.image.tag | string | `"latest"` | Init container image tag |
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
| database.persistence.preUpgradeBackup | bool | `true` | Run a pg_dumpall as a Helm pre-upgrade/pre-rollback hook before each chart upgrade. The dump is printed to the Job's stdout — retrieve with `kubectl logs job/<database.name>-pre-upgrade-backup` or pipe to your existing log-aggregation backup pipeline.  Best-effort: a failed backup is logged but does NOT block the upgrade. Set to false to skip entirely (e.g. for ephemeral test deployments). |
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
| evaluator | object | `{"affinity":{},"autoscaling":{"enabled":false,"maxReplicas":5,"minReplicas":1,"targetCPUUtilizationPercentage":80},"container":{"port":8082},"enabled":true,"env":[],"image":{"pullPolicy":"IfNotPresent","repository":"ghcr.io/kguardian-dev/kguardian/evaluator","sha":"","tag":"v0.2.0"},"imagePullSecrets":[],"logLevel":"info","metrics":{"serviceMonitor":{"enabled":false,"interval":"30s","labels":{},"path":"/metrics","port":"http","scrapeTimeout":"10s"}},"nodeSelector":{"kubernetes.io/os":"linux"},"podAnnotations":{},"podDisruptionBudget":{"enabled":false,"maxUnavailable":"","minAvailable":1},"podSecurityContext":{"fsGroup":1000,"fsGroupChangePolicy":"OnRootMismatch","runAsGroup":1000,"runAsUser":1000,"seccompProfile":{"type":"RuntimeDefault"},"supplementalGroups":[1000]},"priorityClassName":"","replicaCount":1,"resources":{"limits":{"memory":"256Mi"},"requests":{"cpu":"50m","memory":"64Mi"}},"securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"privileged":false,"readOnlyRootFilesystem":true,"runAsNonRoot":true,"runAsUser":1000},"service":{"name":"kguardian-evaluator","port":8082,"type":"ClusterIP"},"serviceAccount":{"annotations":{},"automountServiceAccountToken":true,"create":true,"name":""},"startupProbe":{},"tolerations":[],"topologySpreadConstraints":[]}` | ----------------------------------------------------------------------- |
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
| evaluator.image.tag | string | `"v0.2.0"` | Evaluator version tag (auto-updated by release-please) |
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
| frontend.image.tag | string | `"1.9.0"` | Frontend version tag (auto-updated by release-please) |
| frontend.imagePullSecrets | list | `[]` | List of image pull secrets for private registries |
| frontend.ingress.annotations | object | `{}` | Ingress annotations |
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
| llmBridge.enabled | bool | `false` | Enable LLM Bridge service for AI assistant |
| llmBridge.env | list | `[]` | Additional environment variables for llm-bridge |
| llmBridge.fullnameOverride | string | `""` | Override the full name of the llm-bridge resources |
| llmBridge.image.pullPolicy | string | `"IfNotPresent"` | LLM Bridge image pull policy |
| llmBridge.image.repository | string | `"ghcr.io/kguardian-dev/kguardian/llm-bridge"` | LLM Bridge container image repository |
| llmBridge.image.sha | string | `""` | Overrides the image tag using SHA digest |
| llmBridge.image.tag | string | `"1.2.3"` | LLM Bridge version tag (auto-updated by release-please) |
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
| mcpServer.affinity | object | `{}` | Affinity rules for mcp-server pod assignment |
| mcpServer.autoscaling.enabled | bool | `false` | Enable horizontal pod autoscaling for mcp-server |
| mcpServer.autoscaling.maxReplicas | int | `5` | Maximum number of mcp-server replicas |
| mcpServer.autoscaling.minReplicas | int | `1` | Minimum number of mcp-server replicas |
| mcpServer.autoscaling.targetCPUUtilizationPercentage | int | `80` | Target CPU utilization percentage for autoscaling |
| mcpServer.container.port | int | `8081` | MCP Server container HTTP port for StreamableHTTP transport |
| mcpServer.enabled | bool | `false` | Enable MCP Server for external integrations |
| mcpServer.env | list | `[]` | Additional environment variables for mcp-server |
| mcpServer.fullnameOverride | string | `""` | Override the full name of the mcp-server resources |
| mcpServer.image.pullPolicy | string | `"IfNotPresent"` | MCP Server image pull policy |
| mcpServer.image.repository | string | `"ghcr.io/kguardian-dev/kguardian/mcp-server"` | MCP Server container image repository |
| mcpServer.image.sha | string | `""` | Overrides the image tag using SHA digest |
| mcpServer.image.tag | string | `"1.3.4"` | MCP Server version tag (auto-updated by release-please) |
| mcpServer.imagePullSecrets | list | `[]` | List of image pull secrets for private registries |
| mcpServer.metrics.serviceMonitor.enabled | bool | `false` | Create a ServiceMonitor for prometheus-operator. mcp-server has a /metrics endpoint configured via kmcp.yaml; toggle this on once the exposed port matches `service.port`. |
| mcpServer.metrics.serviceMonitor.interval | string | `"30s"` |  |
| mcpServer.metrics.serviceMonitor.labels | object | `{}` |  |
| mcpServer.metrics.serviceMonitor.path | string | `"/metrics"` |  |
| mcpServer.metrics.serviceMonitor.port | string | `"http"` |  |
| mcpServer.metrics.serviceMonitor.scrapeTimeout | string | `"10s"` |  |
| mcpServer.nameOverride | string | `""` | Override the name of the mcp-server resources |
| mcpServer.nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node labels for the kguardian mcp-server pod assignment |
| mcpServer.podAnnotations | object | `{}` | Annotations to add to mcp-server pods |
| mcpServer.podDisruptionBudget.enabled | bool | `false` | Create a PodDisruptionBudget for the mcp-server. Defaults to false; enable when running >1 replica. |
| mcpServer.podDisruptionBudget.maxUnavailable | string | `""` |  |
| mcpServer.podDisruptionBudget.minAvailable | int | `1` |  |
| mcpServer.podSecurityContext | object | `{"fsGroup":1000,"fsGroupChangePolicy":"OnRootMismatch","runAsGroup":1000,"runAsUser":1000,"seccompProfile":{"type":"RuntimeDefault"},"supplementalGroups":[1000]}` | MCP Server pod security context. Runs as non-root user (mcp:1000) |
| mcpServer.priorityClassName | string | `""` | Priority class to be used for the kguardian mcp-server pods |
| mcpServer.replicaCount | int | `1` | Number of mcp-server replicas to deploy (ignored if useKmcp is true and autoscaling is enabled) |
| mcpServer.resources | object | `{"limits":{"memory":"256Mi"},"requests":{"cpu":"50m","memory":"128Mi"}}` | MCP Server pod resource requests and limits |
| mcpServer.securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"privileged":false,"readOnlyRootFilesystem":true,"runAsNonRoot":true,"runAsUser":1000}` | MCP Server container security context. Hardened with read-only root filesystem |
| mcpServer.service.name | string | `"kguardian-mcp-server"` | MCP Server service name |
| mcpServer.service.port | int | `8081` | MCP Server service port |
| mcpServer.service.type | string | `"ClusterIP"` | MCP Server service type |
| mcpServer.serviceAccount.annotations | object | `{}` | Annotations to add to the service account |
| mcpServer.serviceAccount.automountServiceAccountToken | bool | `false` | Automount API credentials for a service account |
| mcpServer.serviceAccount.create | bool | `true` | Specifies whether a service account should be created |
| mcpServer.serviceAccount.name | string | `""` | The name of the service account to use. If not set and create is true, a name is generated using the fullname template |
| mcpServer.startupProbe | object | `{}` | Startup probe. Empty by default — opt in when slow startup is expected. |
| mcpServer.tolerations | list | `[]` | Tolerations for the kguardian mcp-server pod assignment |
| mcpServer.topologySpreadConstraints | list | `[]` | Topology spread constraints applied to mcp-server pods. |
| namespace.annotations | object | `{}` | Annotations to add to the namespace |
| namespace.labels | object | `{}` | Labels to add to the namespace |
| namespace.name | string | `""` | Namespace name. If empty, uses the release namespace |

## Upgrading

For breaking-change migrations between chart versions (e.g. PostgreSQL major-version
bumps), see [UPGRADING.md](./UPGRADING.md).

## Uninstalling the Chart

To uninstall/delete the my-release deployment:

```bash
helm uninstall my-release
```
