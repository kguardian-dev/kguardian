# Workload Security Profile — broker API contract

Part of #1533. Implemented in `broker/src/workload_profile.rs` (read model, posture, versions, diff) and
`broker/src/pod_security.rs` (Pod Security Standards analyser). Consumers: the frontend profile page,
llm-bridge tools and the advisor `profile` commands.
Status: **v1, stable**. Changes are appended to the CHANGELOG at the bottom, dated. Nothing above the
CHANGELOG is edited silently.

## 0. Conventions (apply to every response below)

- **Every documented field is always present.** Fields are never omitted.
  - `null` = **unknown / not available** (kguardian cannot tell, the source is not configured, or no
    data has arrived yet). Never render `null` as 0, "none", "ok" or "false".
  - `[]` = **known to be empty** (we looked and there is nothing).
  - `false` = known false.
- Timestamps are RFC 3339 UTC with `Z` (`"2026-09-26T10:04:00Z"`).
- JSON keys are camelCase.
- Workload key = `(namespace, kind, name)`, exactly the key `workload_syscalls`, `workload_containers` and
  the SeccompProfile `workloadRef` use (controller owner resolution: ReplicaSet->Deployment,
  Job->CronJob; a pod with no owner is `kind = "Pod"`, `name = <pod name>`). `kind` is case-sensitive
  (`Deployment`, `StatefulSet`, `DaemonSet`, `CronJob`, `Job`, `ReplicaSet`, `Pod`, ...).
  `clusterId` is always `"primary"` until multi-cluster ingest lands.
- Status enum everywhere: `"ok" | "warn" | "risk" | "unknown"`.
- Severity enum: `"critical" | "high" | "medium" | "low" | "info"`. Tier (UX priority) is derived:
  critical -> `"P0"`, high -> `"P1"`, medium -> `"P2"`, low/info -> `null`.
- All routes are `GET`, READ scope (`BROKER_TOKEN_READ` or any token carrying read). Errors below.
- Report and generate only: nothing here applies anything to the cluster.

### Error codes (all endpoints)

| HTTP | When | Body |
|---|---|---|
| 400 | Malformed path/query (empty segment, segment > 253 chars, bad `limit`/`after`/`from`/`to`/`status`) | `{"error":"bad_request","message":"..."}` |
| 401 / 403 | Missing/invalid token / token lacks read scope (auth middleware, only when broker auth is on) | plain text (existing middleware) |
| 404 | Workload unknown to the broker (no inventory, no syscall aggregate, no live pod and no stored profile), or a requested revision does not exist | `{"error":"workload_not_found" \| "revision_not_found","message":"..."}` |
| 503 | Read budget shed (existing `read_budget` behaviour), carries `Retry-After` | plain text (existing) |
| 500 | Database error | plain text |

There is **no 501 / feature-off state**: the profile read model is always on (it only joins data the
broker already has). Sources that are not configured (vulnerability scanning, signatures) appear as
`null` with a `notConfigured` reason inside the payload, never as an HTTP error.

## 1. `GET /workloads` — paginated list with posture summary

Query: `namespace` (exact, optional), `kind` (exact, optional), `status` (`ok|warn|risk|unknown`,
filters on `posture.status`, optional), `limit` (default 100, max 500; out of range is clamped),
`after` (the previous page's `nextAfter`, opaque string).

Order: `(namespace, kind, name)` ascending. `nextAfter` is `null` on the last page.

Source: the `workload_profile_latest` read model, refreshed by a background snapshotter (every
`PROFILE_SNAPSHOT_INTERVAL_SECS`, default 300 s, `PROFILE_SNAPSHOT_BATCH` workloads per tick, default 200,
least recently computed first). A workload appears after its first snapshot (first tick runs ~60 s after
broker start); `computedAt` says how fresh each row is. The detail endpoint (section 2) is always computed
live.

```json
{
  "items": [
    {
      "clusterId": "primary",
      "namespace": "payments",
      "kind": "Deployment",
      "name": "checkout",
      "revision": 3,
      "contentHash": "fnv1a64:6f1c2a9e0b7d4c31",
      "computedAt": "2026-09-26T10:05:00Z",
      "lastChangedAt": "2026-09-25T18:40:12Z",
      "posture": {
        "status": "warn",
        "score": 71,
        "coverage": 0.47,
        "grade": null,
        "unknownDimensions": ["network", "images"]
      },
      "dimensions": {
        "network":     { "status": "unknown", "score": null },
        "syscalls":    { "status": "warn",    "score": 60 },
        "podSecurity": { "status": "ok",      "score": 80, "level": "restricted", "levelConfidence": "upper_bound" },
        "images":      { "status": "ok",      "score": null, "runningDigests": 1, "mixedDigests": false },
        "compute":     { "status": "ok",      "score": null }
      },
      "findingCounts": { "critical": 0, "high": 0, "medium": 1, "low": 2, "info": 0 }
    }
  ],
  "nextAfter": "payments/Deployment/checkout"
}
```

Semantics:
- `revision`/`contentHash`: the latest stored version (section 3). `revision` starts at 1.
- `posture.score`: 0-100 or `null` when no dimension is scored. `posture.coverage`: 0.0-1.0 = the
  fraction of scoring weight whose dimension is known (section 2.2). `grade`: `"A".."F"` only when
  `coverage >= 0.8`, else `null`.
- `dimensions.*.score` may be `null` while `status` is known: e.g. `images` has an inventory (status known)
  but no vulnerability source, so it is not scored. `compute` is never scored in v1 (informational).
- `podSecurity.level`: `"privileged" | "baseline" | "restricted" | null` (null = no container
  securityContext has been reported for this workload). See 2.3 for `levelConfidence`.

## 2. `GET /workloads/{namespace}/{kind}/{name}/profile` — full profile, computed live

404 `workload_not_found` when none of: inventory rows, syscall aggregate, live pods in `pod_details`,
stored profile exist for the key.

```json
{
  "workload": {
    "clusterId": "primary",
    "namespace": "payments",
    "kind": "Deployment",
    "name": "checkout",
    "transient": false,
    "pods": { "live": 2, "names": ["checkout-7d9f8b6c5-2xkqp", "checkout-7d9f8b6c5-9hmtz"], "truncated": false }
  },
  "generatedAt": "2026-09-26T10:07:31Z",
  "contentHash": "fnv1a64:6f1c2a9e0b7d4c31",
  "version": { "revision": 3, "contentHash": "fnv1a64:6f1c2a9e0b7d4c31", "createdAt": "2026-09-25T18:40:12Z" },
  "snapshotPending": false,

  "posture": {
    "status": "warn",
    "score": 71,
    "coverage": 0.47,
    "grade": null,
    "weights": { "network": 20, "syscalls": 15, "podSecurity": 20, "images": 30 },
    "unknownDimensions": ["network", "images"],
    "deductions": [
      { "dimension": "syscalls", "findingId": "syscalls.no_enforcing_profile", "points": 40 },
      { "dimension": "podSecurity", "findingId": "podSecurity.readOnlyRootFilesystem/app", "points": 5 }
    ]
  },

  "attention": [
    { "id": "syscalls.no_enforcing_profile", "dimension": "syscalls", "severity": "medium", "tier": "P2",
      "title": "No SeccompProfile CR enforces the observed syscall set",
      "detail": "Pods run with RuntimeDefault only. Export the observed profile (61 syscalls) and apply it in audit mode first.",
      "container": null }
  ],

  "findings": [ "... every finding, same shape as attention[]; attention = top 5 by severity" ],

  "controls": [
    { "control": "networkPolicy",   "state": "unknown",  "detail": "No audit policy covers this workload; applied NetworkPolicies are not visible to the broker", "inSync": null },
    { "control": "seccompProfile",  "state": "none",     "detail": "No SeccompProfile CR references this workload", "inSync": null },
    { "control": "imageAdmission",  "state": null,       "detail": "Signature/admission checks are not configured", "inSync": null }
  ],

  "readiness": [
    { "id": "trafficObserved24h",   "ok": true,  "message": "Traffic observed for 6d 4h" },
    { "id": "syscallCaptureComplete","ok": true, "message": "Every pod captured at level full (startup included)" },
    { "id": "noWouldDeny24h",       "ok": null,  "message": "No audit policy covers this workload" },
    { "id": "imageSigned",          "ok": null,  "message": "Signature verification is not configured" },
    { "id": "podSecurityRestricted","ok": true,  "message": "Evaluated checks pass restricted; 9 checks could not be evaluated" }
  ],

  "exposure": { "ingressPeers": 3, "ingressExternal": 0, "egressPeers": 4, "egressExternal": 1 },

  "dimensions": {
    "network":     { "...": "2.4" },
    "syscalls":    { "...": "2.5" },
    "podSecurity": { "...": "2.3" },
    "images":      { "...": "2.6" },
    "compute":     { "...": "2.7" }
  }
}
```

- `contentHash` is the hash of the live profile's policy-relevant snapshot (section 3). `version` is the
  latest **stored** version (`null` if the snapshotter has not stored one yet). `snapshotPending: true`
  means live differs from the latest stored version; the snapshotter will store it on its next visit.
- `controls[].state`: networkPolicy `"audit" | "unknown"`; seccompProfile `"enforcing" | "audit" | "none"`;
  imageAdmission always `null` in v1. `inSync`: `true|false|null`.
- `readiness[].ok`: `true | false | null` (null = cannot tell).
- `exposure` counts come from observed flows (distinct peers); all `null` when the network dimension has
  no flows.

### 2.1 Common dimension envelope

Every entry in `dimensions` has at least:

```json
{
  "status": "ok|warn|risk|unknown",
  "score": 80,
  "scored": true,
  "coverage": { "level": "full|partial|none", "fraction": 0.5, "observedSince": "2026-09-20T06:00:00Z", "note": "..." },
  "reasons": [ { "code": "machine_code", "message": "human sentence" } ]
}
```

- `score`: 0-100 = `100 - sum(points of this dimension's findings)`, floored at 0, **or `null`** when the
  dimension is not scored (`scored: false`). A dimension with `status: "unknown"` is never scored.
- `coverage.fraction`: dimension-specific (checks evaluated / checks defined for podSecurity; pods with
  full capture / pods for syscalls; `null` when not meaningful). `observedSince`: earliest evidence
  timestamp, `null` if unknown.
- `reasons`: why the status is what it is, incl. why something is unknown. Codes are stable.

### 2.2 Posture rollup

- Weights (v1, constants): network 20, syscalls 15, podSecurity 20, images 30. compute has weight 0.
- `score` = weighted mean of **scored** dimensions only (rounded). `coverage` = sum of weights of scored
  dimensions / 85. Unknown or unscored dimensions are **excluded**, never counted as 0 or 100, and are
  listed in `unknownDimensions`.
- `grade`: A >= 90, B >= 80, C >= 70, D >= 60, else F — only when `coverage >= 0.8`, else `null`.
- `status`: worst of the known dimension statuses (`risk` > `warn` > `ok`); `unknown` only if every
  dimension is unknown.
- Scored dimension status from score: >= 80 ok, 50-79 warn, < 50 risk. Unscored dimension status from its
  findings: any high/critical -> risk, any medium -> warn, else ok; no data -> unknown.
- Every point deducted appears in `deductions[]` with the finding id.

### 2.3 `podSecurity` (P0-4) — Pod Security Standards

Rules follow the upstream PSS check list exactly: kubernetes.io/docs/concepts/security/pod-security-standards
(kubernetes/website `main` @ `2c1aa11c`, 2026-08-02, docs for Kubernetes v1.37).

Check ids (stable) and whether v1 can evaluate them from the image inventory:

| id | level | evaluated? | rule (upstream) |
|---|---|---|---|
| `hostProcess` | baseline | no (field not ingested) | windowsOptions.hostProcess undefined/false |
| `hostNamespaces` | baseline | yes | hostNetwork, hostPID, hostIPC undefined/false |
| `privileged` | baseline | yes | securityContext.privileged undefined/false |
| `capabilitiesBaseline` | baseline | yes | capabilities.add only AUDIT_WRITE, CHOWN, DAC_OVERRIDE, FOWNER, FSETID, KILL, MKNOD, NET_BIND_SERVICE, SETFCAP, SETGID, SETPCAP, SETUID, SYS_CHROOT |
| `hostPathVolumes` | baseline | **no** (volumes not ingested) | volumes[*].hostPath undefined |
| `hostPorts` | baseline | no | ports[*].hostPort undefined/0 |
| `hostProbesLifecycle` | baseline | no | probe/lifecycle httpGet/tcpSocket host undefined/"" (v1.34+) |
| `appArmor` | baseline | no | appArmorProfile.type undefined/RuntimeDefault/Localhost |
| `seLinux` | baseline | no | seLinuxOptions type in allowed set; user/role undefined |
| `procMount` | baseline | no | procMount undefined/Default |
| `seccompBaseline` | baseline | yes | seccompProfile.type not `Unconfined` (pod and container) |
| `sysctls` | baseline | no | sysctls in the safe set |
| `volumeTypes` | restricted | no | only configMap, csi, downwardAPI, emptyDir, ephemeral, persistentVolumeClaim, projected, secret |
| `privilegeEscalation` | restricted | yes | allowPrivilegeEscalation == false (explicitly) |
| `runAsNonRoot` | restricted | yes | container or pod runAsNonRoot == true |
| `runAsUser` | restricted | yes | runAsUser (container, else pod) non-zero or undefined |
| `seccompRestricted` | restricted | yes | effective (container, else pod) seccompProfile.type is RuntimeDefault or Localhost |
| `capabilitiesRestricted` | restricted | yes | capabilities.drop includes ALL; add only NET_BIND_SERVICE |

hostPath is **not** available (volumes are not ingested) and is reported as unevaluated, never as pass.
Linux is assumed (kguardian's controller runs on Linux/containerd). The user-namespace relaxation of
runAsNonRoot/runAsUser (alpha feature gate) is not applied.

Level computation (`level`, `levelConfidence`):
- Any evaluated **baseline** check fails -> `"privileged"`, confidence `"confirmed"`.
- Else any evaluated **restricted** check fails -> `"baseline"`, confidence `"upper_bound"` (unevaluated
  baseline checks could still fail).
- Else -> `"restricted"`, confidence `"upper_bound"`.
- `"confirmed"` is only possible for `privileged` in v1 because 9 checks are unevaluable. The UI should
  show `upper_bound` as "at most baseline" / "restricted (unverified: hostPath, ...)".
- Workload level = lowest level across containers (all kinds: init, regular, ephemeral — PSS covers all).

```json
{
  "status": "ok",
  "score": 80,
  "scored": true,
  "coverage": { "level": "partial", "fraction": 0.5, "observedSince": "2026-09-19T08:12:00Z",
                "note": "9 of 18 PSS checks evaluated; volumes, ports, probes, AppArmor, SELinux, procMount, sysctls and hostProcess are not ingested" },
  "reasons": [ { "code": "pss_upper_bound", "message": "Evaluated checks pass restricted; unevaluated checks may lower the level" } ],
  "pssVersion": "kubernetes/website@2c1aa11c (Kubernetes v1.37 docs)",
  "level": "restricted",
  "levelConfidence": "upper_bound",
  "unevaluatedChecks": ["hostProcess","hostPathVolumes","hostPorts","hostProbesLifecycle","appArmor","seLinux","procMount","sysctls","volumeTypes"],
  "pod": {
    "serviceAccountName": "checkout",
    "automountServiceAccountToken": null,
    "hostNetwork": false,
    "hostPID": null,
    "hostIPC": null,
    "hostUsers": null,
    "securityContext": { "runAsNonRoot": true, "runAsUser": null, "runAsGroup": null, "fsGroup": 2000, "seccompProfileType": "RuntimeDefault" }
  },
  "containers": [
    {
      "name": "app",
      "kind": "regular",
      "source": "running",
      "digest": "sha256:9f2c0d1e...",
      "securityContext": {
        "privileged": null, "allowPrivilegeEscalation": false, "runAsNonRoot": null, "runAsUser": 10001,
        "runAsGroup": null, "readOnlyRootFilesystem": null, "capabilitiesAdd": null,
        "capabilitiesDrop": ["ALL"], "seccompProfileType": null
      },
      "level": "restricted",
      "failing": []
    },
    {
      "name": "migrate",
      "kind": "init",
      "source": "last_known",
      "digest": "sha256:41ab77c0...",
      "securityContext": { "privileged": null, "allowPrivilegeEscalation": null, "runAsNonRoot": null, "runAsUser": null,
        "runAsGroup": null, "readOnlyRootFilesystem": null, "capabilitiesAdd": null, "capabilitiesDrop": null, "seccompProfileType": null },
      "level": "baseline",
      "failing": [
        { "check": "privilegeEscalation", "level": "restricted",
          "field": "spec.initContainers[migrate].securityContext.allowPrivilegeEscalation", "value": null,
          "message": "allowPrivilegeEscalation must be set to false" },
        { "check": "capabilitiesRestricted", "level": "restricted",
          "field": "spec.initContainers[migrate].securityContext.capabilities.drop", "value": null,
          "message": "capabilities.drop must include ALL" }
      ]
    }
  ],
  "recommendation": {
    "recommendation": true,
    "targetLevel": "restricted",
    "format": "strategic-merge-patch",
    "yaml": "# kguardian recommendation, not applied. Review before use.\n# Target: Pod Security Standards restricted (kubernetes.io/docs/concepts/security/pod-security-standards)\nspec:\n  template:\n    spec:\n      initContainers:\n      - name: migrate\n        securityContext:\n          allowPrivilegeEscalation: false\n          capabilities:\n            drop: [\"ALL\"]\n",
    "caveats": [
      "Checks kguardian cannot see (hostPath and other volume types, hostPort, AppArmor, SELinux, procMount, sysctls) may still fail restricted.",
      "runAsNonRoot: true fails at container start if the image's USER is root; set runAsUser to a UID the image supports."
    ]
  }
}
```

- `containers[].source`: `"running"` = newest running digest row; `"last_known"` = no running row, newest
  row kept by the inventory. `digest` is the digest that row was reported with.
- `securityContext` values are exactly what the controller reported: `null` = not set in the spec.
- `pod` = pod-level fields from the newest container row. `automountServiceAccountToken: null` means not set
  on the pod; the ServiceAccount's own setting is **not** visible, so the token is assumed mounted
  (finding `podSecurity.automountToken`).
- `failing[].value`: the reported value (`null` = unset).
- `recommendation`: `null` when every evaluated check already passes restricted. Otherwise a minimal
  strategic-merge patch containing only the fields that fail evaluated restricted/baseline checks, under
  the kind's template path (`spec.template.spec` for Deployment/StatefulSet/DaemonSet/ReplicaSet/Job,
  `spec.jobTemplate.spec.template.spec` for CronJob, `spec` for a bare Pod). Ephemeral containers are
  never patched (listed in caveats). It is always marked `recommendation: true`.

podSecurity findings (id = `podSecurity.<code>` or `podSecurity.<code>/<container>`, points in brackets):
`privileged` high [40], `hostNetwork` / `hostPID` / `hostIPC` high [30 each], `capabilitiesAdded`
high when outside the baseline set [30] else low [5] (NET_BIND_SERVICE alone: no finding),
`allowPrivilegeEscalation` medium [10], `runAsRoot` high when runAsUser == 0 [30], `mayRunAsRoot` medium
when neither runAsNonRoot true nor a non-zero runAsUser (image USER decides) [10], `seccompUnconfined` high
[30], `seccompUnset` medium [10], `capabilitiesNotDropped` medium [10], `readOnlyRootFilesystem` low [5],
`automountToken` low [5]. A finding repeated across containers deducts once per container, capped at the
dimension floor 0.

### 2.4 `network`

```json
{
  "status": "unknown",
  "score": null,
  "scored": false,
  "coverage": { "level": "partial", "fraction": null, "observedSince": "2026-09-20T06:02:11Z",
                "note": "Flows from 2 live pods; 214 flow rows summarised" },
  "reasons": [ { "code": "policy_state_unknown", "message": "No audit policy covers this workload; applied NetworkPolicies are not visible to the broker" } ],
  "summary": {
    "ingress": { "peers": 3, "external": 0, "ports": ["TCP/8080"] },
    "egress":  { "peers": 4, "external": 1, "ports": ["TCP/443", "TCP/5432", "UDP/53"] }
  },
  "peers": [
    { "direction": "ingress", "protocol": "TCP", "port": 8080,
      "peer": { "kind": "pod", "namespace": "ingress-nginx", "workloadKind": "Deployment", "workloadName": "ingress-nginx-controller", "name": "ingress-nginx-controller-5c8d7f9b4-q2w8r", "ip": "10.42.1.17" },
      "flows": 12, "firstSeen": "2026-09-20T06:02:11Z", "lastSeen": "2026-09-26T09:58:40Z" },
    { "direction": "egress", "protocol": "TCP", "port": 443,
      "peer": { "kind": "external", "namespace": null, "workloadKind": null, "workloadName": null, "name": null, "ip": "203.0.113.10" },
      "flows": 3, "firstSeen": "2026-09-21T11:00:00Z", "lastSeen": "2026-09-26T08:00:00Z" }
  ],
  "truncated": false,
  "policy": {
    "audit": null,
    "enforced": null
  }
}
```

- `peer.kind`: `"pod" | "service" | "node" | "external" | "unresolved"`. `external` = the IP is not
  in-cluster; `unresolved` = in-cluster identity not resolved (legacy rows / spec never arrived). Identity
  fields are `null` when not applicable.
- `peers[]` is at most 200 rows, ordered by (direction, protocol, port, peer); `truncated: true` if more
  exist (or if the flow scan hit its 50 000-row cap). `port` is the pod's own port for ingress and the
  peer's port for egress; `null` if unparseable.
- `policy.audit`: `null` when no AuditNetworkPolicy verdicts mention the workload's pods in the last 24 h.
  Otherwise `{ "policies": [{"namespace","name"}], "allow": n, "wouldDeny": n, "lastVerdictAt": ts, "windowHours": 24 }`.
- `policy.enforced`: always `null` in v1 (the broker does not mirror applied NetworkPolicy/CNP objects).
- Scored only when `policy.audit` is non-null: `wouldDeny > 0` -> finding `network.wouldDeny` high [30].
  With no audit policy the dimension is `unknown` (flows are still summarised).
- No flows at all -> `status: "unknown"`, `peers: []`, `summary` counts 0, reason `no_flows`.

### 2.5 `syscalls`

```json
{
  "status": "warn",
  "score": 60,
  "scored": true,
  "coverage": { "level": "full", "fraction": 1.0, "observedSince": null, "note": "capture level full on 2 pods" },
  "reasons": [ { "code": "no_cr", "message": "No SeccompProfile CR references this workload" } ],
  "observed": { "syscallCount": 61, "hash": "a1b2c3d4e5f60718", "architectures": ["x86_64"], "updatedAt": "2026-09-26T09:40:00Z" },
  "capture": { "level": "full", "complete": true, "incompletePods": 0 },
  "cr": null,
  "denials": { "total": 0, "syscalls": [], "lastSeen": null }
}
```

- `observed`: `null` when the workload has no syscall aggregate (then `status: "unknown"`, `score: null`).
- `capture.level`: `full|high|medium|low|custom|unknown` (lowest across contributing pods).
  `complete: false` -> reason `capture_incomplete`, status at least `warn`, `coverage.level: "partial"`.
- `cr`: `null` = no SeccompProfile CR references the workload. Otherwise
  `{ "name", "defaultAction", "mode": "enforce"|"audit", "syscallCount", "inSync": bool, "missing": [..], "extra": [..], "distribution": {"ready","total","state"} }`.
  `mode` is `audit` when defaultAction is `SCMP_ACT_LOG` (or ALLOW), else `enforce`. `missing` = observed but
  not allowed by the CR (would be blocked when enforced).
- `denials`: `null` = the broker cannot tell "nothing denied" from "nothing capturing" (same rule as
  `GET /seccomp/profiles`). Otherwise totals over the denial retention window.
- Findings: `syscalls.no_enforcing_profile` medium [40] (no CR, or CR in audit mode: [20] instead),
  `syscalls.drift` medium [20] (CR not in sync), `syscalls.denials` high [30] (denials.total > 0).

### 2.6 `images`

```json
{
  "status": "ok",
  "score": null,
  "scored": false,
  "coverage": { "level": "full", "fraction": null, "observedSince": "2026-09-19T08:12:00Z", "note": "running window 900 s" },
  "reasons": [ { "code": "vulnerabilities_not_configured", "message": "No vulnerability source is configured; images are inventoried but not scored" } ],
  "runningWindowSeconds": 900,
  "containers": [
    {
      "name": "app",
      "kind": "regular",
      "mixedDigests": false,
      "running": [
        { "digest": "sha256:9f2c0d1e...", "imageRef": "ghcr.io/example/checkout:4.0.9", "state": "running", "stateReason": null,
          "ranAsInit": false, "lastPodName": "checkout-7d9f8b6c5-2xkqp", "firstSeen": "2026-09-19T08:12:00Z", "lastSeen": "2026-09-26T10:05:00Z" }
      ],
      "previous": [
        { "digest": "sha256:0c3d...", "imageRef": "ghcr.io/example/checkout:4.0.8", "state": "terminated", "stateReason": "Completed",
          "ranAsInit": false, "lastPodName": null, "firstSeen": "2026-09-10T07:00:00Z", "lastSeen": "2026-09-19T08:20:00Z" }
      ]
    }
  ],
  "truncated": false,
  "vulnerabilities": null,
  "supplyChain": null
}
```

- Mirrors `GET /workloads/{ns}/{kind}/{name}/containers` without the securityContext blobs. `state`:
  `running|waiting|terminated|null` (null = older controller); `waiting` + `stateReason` covers
  `CrashLoopBackOff`, `ImagePullBackOff`, `ContainerCreating`. `ranAsInit`: completed init container.
- `vulnerabilities`: always `null` in this PR = **not configured**, reason `vulnerabilities_not_configured`.
  When the scanner lands it becomes an object; the null contract does not change meaning.
- `supplyChain`: `null` = not configured (signatures/provenance, later wave).
- No inventory rows -> `status: "unknown"`, `containers: []`, reason `no_inventory`.
- Findings (unscored, status only): `images.mixedDigests/<c>` low, `images.crashLoop/<c>` medium,
  `images.pullBackOff/<c>` medium, `images.configDigestOnly/<c>` info (digest not registry-resolvable).

### 2.7 `compute` (informational, never scored)

```json
{
  "status": "warn",
  "score": null,
  "scored": false,
  "coverage": { "level": "full", "fraction": null, "observedSince": "2026-09-26T10:04:00Z", "note": "2 containers reporting" },
  "reasons": [ { "code": "missing_limits", "message": "1 container has no memory limit" } ],
  "containers": [
    { "pod": "checkout-7d9f8b6c5-2xkqp", "container": "app", "cpuRequestMillis": 100, "cpuLimitMillis": null,
      "memRequestBytes": 134217728, "memLimitBytes": null, "cpuUsageMillis": 12.5, "memWorkingSetBytes": 98566144,
      "oomKills": 0, "throttledRatio": 0.0, "updatedAt": "2026-09-26T10:04:00Z" }
  ],
  "truncated": false
}
```

- From `pod_compute_latest` for the workload's live pods (max 50 rows). No rows -> `unknown`, reason
  `no_compute_data` (compute collection off or no live pods).
- Findings: `compute.missingMemoryLimit/<c>` low, `compute.oomKilled/<c>` medium.

## 3. Versions

A version is an **immutable, content-hashed snapshot of the policy-relevant parts** of the profile:

- `podSecurity`: pod fields, each container's securityContext and kind, PSS level.
- `images`: container -> sorted running digests.
- `syscalls`: sorted observed syscall names, capture level, CR `{name, defaultAction, hash}` or null.
- `network`: sorted set of rules `{direction, protocol, port, peer}` where `peer` is
  `pod:<ns>/<workloadKind>/<workloadName>` (or `pod:<ns>/<name>` without a workload), `service:<ns>/<name>`,
  `node`, `external:<ip>`, `unresolved:<ip>`; plus `audited: bool`.
- NOT included: timestamps, counts, compute, scores (they change without the policy changing).

`contentHash` = FNV-1a 64 over the canonical JSON of the snapshot, prefixed `fnv1a64:`;
`dimensionHashes` = the same per dimension. A new version is written by the snapshotter only when
`contentHash` differs from the latest stored one. `revision` increases by 1 per workload.
Retention: the newest `PROFILE_VERSIONS_MAX_PER_WORKLOAD` (default 50) per workload are kept; beyond that
the oldest go. The global retention loop also deletes versions older than
`PROFILE_VERSIONS_RETENTION_DAYS` (default 90; 0 disables) **except the newest version of each workload**,
and `workload_profile_latest` rows not recomputed within that window (workload gone).

### 3.1 `GET /workloads/{namespace}/{kind}/{name}/profile/versions`

Query: `limit` (default 50, max 200), `before` (revision; returns revisions < before). Newest first.
404 `workload_not_found` when the workload has no stored versions and is unknown. A known workload with
no stored versions yet returns `items: []`.

```json
{
  "namespace": "payments", "kind": "Deployment", "name": "checkout",
  "items": [
    { "revision": 3, "contentHash": "fnv1a64:6f1c2a9e0b7d4c31", "createdAt": "2026-09-25T18:40:12Z",
      "dimensionHashes": { "network": "fnv1a64:...", "syscalls": "fnv1a64:...", "podSecurity": "fnv1a64:...", "images": "fnv1a64:..." },
      "changedDimensions": ["images"],
      "posture": { "status": "warn", "score": 71, "coverage": 0.47, "grade": null } }
  ],
  "nextBefore": 3
}
```

`changedDimensions`: dimensions whose hash differs from the previous revision (`[]`... never for rev > 1;
all four for revision 1). `nextBefore` is `null` on the last page.

### 3.2 `GET /workloads/{namespace}/{kind}/{name}/profile/versions/{revision}`

The stored snapshot: `{ "namespace","kind","name","revision","contentHash","createdAt","dimensionHashes","posture","snapshot": { "podSecurity": {...}, "images": {...}, "syscalls": {...}, "network": {...} } }`.
404 `revision_not_found`.

### 3.3 `GET /workloads/{namespace}/{kind}/{name}/profile/diff?from=&to=`

`to`: revision, default = latest. `from`: revision, default = `to - 1` (if revision 1 is `to` and `from`
is omitted, `from` is `null` and everything shows as added). `from` must be < `to` (400 otherwise).

```json
{
  "namespace": "payments", "kind": "Deployment", "name": "checkout",
  "from": { "revision": 2, "contentHash": "fnv1a64:...", "createdAt": "2026-09-22T09:00:00Z" },
  "to":   { "revision": 3, "contentHash": "fnv1a64:...", "createdAt": "2026-09-25T18:40:12Z" },
  "changed": true,
  "dimensions": {
    "podSecurity": {
      "changed": true,
      "level": { "from": "baseline", "to": "restricted" },
      "pod": [ { "field": "securityContext.seccompProfileType", "from": null, "to": "RuntimeDefault" } ],
      "containersAdded": [], "containersRemoved": [],
      "containers": [ { "name": "app", "fields": [ { "field": "allowPrivilegeEscalation", "from": null, "to": false } ] } ]
    },
    "images": {
      "changed": true,
      "containersAdded": [], "containersRemoved": [],
      "containers": [ { "name": "app", "added": ["sha256:9f2c..."], "removed": ["sha256:0c3d..."] } ]
    },
    "syscalls": {
      "changed": false, "added": [], "removed": [],
      "captureLevel": null,
      "cr": null
    },
    "network": {
      "changed": false, "added": [], "removed": [], "audited": null
    }
  }
}
```

- A scalar change is `{ "from": x, "to": y }`; an unchanged scalar is `null` (e.g. `level: null`,
  `captureLevel: null`, `cr: null`, `audited: null` = unchanged).
- `syscalls.cr` when changed: `{ "from": {name, defaultAction, hash} | null, "to": ... }`.
- `network.added/removed[]`: rule objects `{ "direction", "protocol", "port", "peer" }` (peer string as in
  section 3).
- 404 `revision_not_found` if either revision is missing; 404 `workload_not_found` if no versions exist.

## 4. Storage (for reviewers; not an API)

- `workload_profile_versions(id bigserial PK, cluster_id, pod_namespace, workload_kind, workload_name,
  revision int, content_hash, dimension_hashes jsonb, snapshot jsonb, posture jsonb, created_at)`,
  unique `(cluster_id, pod_namespace, workload_kind, workload_name, revision)`.
- `workload_profile_latest(cluster_id, pod_namespace, workload_kind, workload_name PK, revision,
  content_hash, summary jsonb, computed_at, last_changed_at)` — backs `GET /workloads`.
- Migration `2026-09-27-100000_workload_profiles`.

## CHANGELOG

- 2026-09-26: v1 published.
- 2026-09-26 (v1.1, implementation landed; all changes additive or clarifying, no field renamed or removed):
  - `dimensions.podSecurity.pod.failing[]` added: pod-level failing checks (hostNetwork/hostPID/hostIPC,
    pod runAsNonRoot=false, pod runAsUser=0, pod seccomp Unconfined), same shape as `containers[].failing[]`.
    The workload `level` accounts for them.
  - `posture.unknownDimensions` lists every weighted dimension that is **not scored**, whether its status is
    `unknown` or known but unscored (e.g. `images` with inventory but no vulnerability source).
  - `dimensions.syscalls.coverage.fraction` is `null` in v1 (not pods-with-full-capture / pods). Use
    `capture.complete` / `capture.incompletePods`.
  - `dimensions.syscalls.observed.architectures` are the tokens `GET /seccomp/profiles` returns
    (`SCMP_ARCH_X86_64`), not `x86_64`.
  - `capture.level` can be `"unknown"` (no contributing pod reported a tier); then `complete: false`.
  - The `images.configDigestOnly/<c>` finding is not emitted in v1 (digest kind is not joined).
  - `compute.containers[].oomKills` = OOM kills in the latest sample interval (a delta, not lifetime).
  - List item: `dimensions.images.runningDigests` / `mixedDigests` are `null` when there is no inventory;
    any `dimensions.*.score` may be `null`.
  - `snapshotPending` is `true` whenever `version` is `null`.
  - Versions list: `changedDimensions` is `null` for the oldest retained revision when its predecessor was
    trimmed (unknown, not guessed). All four for revision 1.
  - Diff: `from` is `null` when diffing revision 1 with no `from`; `audited`/`captureLevel` show
    `{from: null, to: ...}` in that case.
  - Repo copy: `docs/design/workload-security-profile-api.md` (same content).
