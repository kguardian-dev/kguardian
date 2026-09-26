# Workload Security Profile — broker API contract

Part of #1533. Implemented in `broker/src/workload_profile.rs` (read model, posture, versions, diff) and
`broker/src/pod_security.rs` (Pod Security Standards analyser), PR #1669. Consumers: the frontend profile
page (#1672), llm-bridge tools and the advisor `profile` commands (#1668).

Status: **v1.7, stable**. Every change is appended to the CHANGELOG at the bottom, dated.

**Examples:** every example below is generated from raw responses of a v1.4 broker build against a
seeded test database (neutral names only). Values are verbatim. The only edits are: lists longer than the stated
limit are cut and end with a `"(N more in the capture)"` string, and a key listed in `_omitted` was left out
(it is shown in its own section). The section 4 captures are from v1.4; the v1.5 changes to the `sbom` and
`vex` artifacts are described in text next to them.

## 0. Conventions (apply to every response below)

- **Every documented field is always present.** Fields are never omitted.
  - `null` = **unknown / not available** (kguardian cannot tell, the source is not configured, or no
    data has arrived yet). Never render `null` as 0, "none", "ok" or "false".
  - `[]` = **known to be empty** (we looked and there is nothing).
  - `false` = known false.
- **No numeric scores.** Posture is a tier (`status`) plus `coverage` and the `reasons` that produced it.
- Timestamps are RFC 3339 UTC with `Z`.
- JSON keys are camelCase.
- Workload key = `(namespace, kind, name)`, exactly the key `workload_syscalls`, `workload_containers` and
  the SeccompProfile `workloadRef` use (controller owner resolution: ReplicaSet->Deployment,
  Job->CronJob; a pod with no owner is `kind = "Pod"`, `name = <pod name>`). `kind` is case-sensitive.
  `clusterId` is always `"primary"` until multi-cluster ingest lands.
- Status enum everywhere: `"ok" | "warn" | "risk" | "unknown"`.
- Severity enum: `"critical" | "high" | "medium" | "low" | "info"`. Tier (UX priority) is derived:
  critical -> `"P0"`, high -> `"P1"`, medium -> `"P2"`, low/info -> `null`.
- All routes are `GET`, READ scope. Report and generate only: nothing here applies anything.

### Error codes (all endpoints)

| HTTP | When | Body |
|---|---|---|
| 400 | Malformed path/query (empty segment, segment > 253 chars, bad `after`/`from`/`to`/`status`, `from >= to`) | `{"error":"bad_request","message":"..."}` |
| 401 / 403 | Missing/invalid token / token lacks read scope (auth middleware, only when broker auth is on) | plain text |
| 404 | Workload unknown to the broker, or a requested revision does not exist | `{"error":"workload_not_found" \| "revision_not_found","message":"..."}` |
| 503 | Read budget shed, carries `Retry-After` | plain text |
| 500 | Database error | plain text |

A 404 **with** a JSON `error` code comes only from these profile routes. An older broker without the
routes answers the framework's default 404 with an empty, non-JSON body. There is **no 501 /
feature-off state**. Sources that are not configured appear as `null` with a reason, never as an HTTP
error.

## 1. `GET /workloads` — paginated list with posture summary

Query (all optional): `namespace` (exact), `kind` (exact), `status` (`ok|warn|risk|unknown`, filters on
`posture.status`), `search` (case-insensitive substring of the workload name, max 253 chars), `limit`
(default 100, max 500, clamped), `after` (the previous page's `nextAfter`, opaque).

Order: `(namespace, kind, name)` ascending. `nextAfter` is `null` on the last page.

Source: the `workload_profile_latest` read model, refreshed by a background snapshotter (every
`PROFILE_SNAPSHOT_INTERVAL_SECS`, default 300 s, floor 60; `PROFILE_SNAPSHOT_BATCH` workloads per tick,
default 200, least recently computed first). A workload appears after its first snapshot (the first tick
runs ~60 s after broker start); `computedAt` says how fresh each row is. The detail endpoint (section 2)
is always computed live. Captures: `list-page1-limit2`, `list-page2-after`, `list-namespace-payments`,
`list-search-ledger`, `list-status-risk`.

From `GET /workloads?limit=2` -> 200 (capture `list-page1-limit2.json`, `body`):

```json
{
  "items": [
    {
      "clusterId": "primary",
      "computedAt": "2026-09-26T03:05:49.483524Z",
      "contentHash": "fnv1a64:5ba183ed9b98a6fa",
      "dimensions": {
        "compute": {
          "status": "unknown"
        },
        "images": {
          "mixedDigests": false,
          "runningDigests": 1,
          "status": "unknown"
        },
        "network": {
          "status": "ok"
        },
        "podSecurity": {
          "level": "restricted",
          "levelConfidence": "upper_bound",
          "status": "unknown"
        },
        "syscalls": {
          "status": "ok"
        }
      },
      "drift": {
        "byType": {},
        "count": 0
      },
      "findingCounts": {
        "critical": 0,
        "high": 0,
        "info": 0,
        "low": 0,
        "medium": 0
      },
      "kind": "Deployment",
      "lastChangedAt": "2026-09-26T03:05:49.483524Z",
      "name": "source-controller",
      "namespace": "flux-system",
      "posture": {
        "coverage": 0.5,
        "status": "unknown",
        "unknownDimensions": [
          "podSecurity",
          "images"
        ]
      },
      "revision": 3
    },
    {
      "clusterId": "primary",
      "computedAt": "2026-09-26T03:05:49.470604Z",
      "contentHash": "fnv1a64:edc8ee3dbec5d0e4",
      "dimensions": {
        "compute": {
          "status": "unknown"
        },
        "images": {
          "mixedDigests": null,
          "runningDigests": null,
          "status": "unknown"
        },
        "network": {
          "status": "unknown"
        },
        "podSecurity": {
          "level": null,
          "levelConfidence": null,
          "status": "unknown"
        },
        "syscalls": {
          "status": "unknown"
        }
      },
      "drift": {
        "byType": {},
        "count": 0
      },
      "findingCounts": {
        "critical": 0,
        "high": 0,
        "info": 0,
        "low": 0,
        "medium": 0
      },
      "kind": "Deployment",
      "lastChangedAt": "2026-09-26T03:04:42.210577Z",
      "name": "ingress-nginx-controller",
      "namespace": "ingress-nginx",
      "posture": {
        "coverage": 0.0,
        "status": "unknown",
        "unknownDimensions": [
          "network",
          "syscalls",
          "podSecurity",
          "images"
        ]
      },
      "revision": 1
    }
  ],
  "nextAfter": "ingress-nginx/Deployment/ingress-nginx-controller"
}
```

- `revision` / `contentHash`: the latest stored version (section 3).
- `drift`: `{ "count": n, "byType": { "<type>": n } }` from the latest snapshot (section 2.8); `byType`
  is `{}` when there is no drift.
- `posture`: see 2.2. `dimensions.images.runningDigests` / `mixedDigests` are `null` when there is no
  inventory. `podSecurity.level` / `levelConfidence` are `null` when no current container is known.

## 2. `GET /workloads/{namespace}/{kind}/{name}/profile` — full profile, computed live

404 `workload_not_found` when the broker has none of: inventory rows, a syscall aggregate, pods in
`pod_details`, a stored profile. Captures: `profile-unknown-partial-flux-system-source-controller` (every
known dimension ok, but not all known: `unknown`), `profile-warn-payments-refunds-init-fails-restricted`,
`profile-warn-payments-ledger-mixed-crashloop-stale`,
`profile-risk-observability-node-exporter-hostpid-wouldDeny`,
`profile-unknown-observability-otel-collector-fresh` (nothing known). No workload can be posture `ok` in
v1.3 until vulnerability data exists (section 2.2).


From `GET /workloads/payments/Deployment/refunds/profile` -> 200 (capture `profile-warn-payments-refunds-init-fails-restricted.json`, `body`):

```json
{
  "workload": {
    "clusterId": "primary",
    "namespace": "payments",
    "kind": "Deployment",
    "name": "refunds",
    "transient": false,
    "pods": {
      "live": 1,
      "names": [
        "refunds-6c8d9e7f5-r7t2v"
      ],
      "truncated": false
    }
  },
  "generatedAt": "2026-09-26T03:06:02.401338275Z",
  "contentHash": "fnv1a64:3948ec39cd68f413",
  "version": {
    "revision": 3,
    "contentHash": "fnv1a64:3948ec39cd68f413",
    "createdAt": "2026-09-26T03:05:49.476840Z"
  },
  "snapshotPending": false,
  "posture": {
    "status": "warn",
    "coverage": 0.25,
    "unknownDimensions": [
      "network",
      "syscalls",
      "images"
    ],
    "reasons": [
      {
        "dimension": "network",
        "status": "unknown",
        "message": "No flows observed for this workload's pods"
      },
      {
        "dimension": "syscalls",
        "status": "unknown",
        "message": "No syscalls have been captured for this workload"
      },
      {
        "dimension": "podSecurity",
        "status": "warn",
        "message": "At most baseline: migrate (init) fail(s) a restricted check; unevaluated checks may lower it further"
      },
      "(1 more in the capture)"
    ]
  },
  "attention": [
    {
      "id": "podSecurity.allowPrivilegeEscalation/migrate",
      "dimension": "podSecurity",
      "severity": "medium",
      "tier": "P2",
      "title": "Container migrate allows privilege escalation",
      "detail": "allowPrivilegeEscalation is not set to false, so setuid binaries can gain privileges.",
      "container": "migrate"
    },
    {
      "id": "podSecurity.capabilitiesNotDropped/migrate",
      "dimension": "podSecurity",
      "severity": "medium",
      "tier": "P2",
      "title": "Container migrate does not drop ALL capabilities",
      "detail": "The runtime's default capability set stays granted.",
      "container": "migrate"
    }
  ],
  "findings": [
    {
      "id": "podSecurity.allowPrivilegeEscalation/migrate",
      "dimension": "podSecurity",
      "severity": "medium",
      "tier": "P2",
      "title": "Container migrate allows privilege escalation",
      "detail": "allowPrivilegeEscalation is not set to false, so setuid binaries can gain privileges.",
      "container": "migrate"
    },
    {
      "id": "podSecurity.capabilitiesNotDropped/migrate",
      "dimension": "podSecurity",
      "severity": "medium",
      "tier": "P2",
      "title": "Container migrate does not drop ALL capabilities",
      "detail": "The runtime's default capability set stays granted.",
      "container": "migrate"
    },
    {
      "id": "podSecurity.readOnlyRootFilesystem/app",
      "dimension": "podSecurity",
      "severity": "low",
      "tier": null,
      "title": "Container app root filesystem is writable",
      "detail": "readOnlyRootFilesystem is not true (hardening; not required by PSS restricted).",
      "container": "app"
    },
    "(1 more in the capture)"
  ],
  "controls": [
    {
      "control": "networkPolicy",
      "state": "unknown",
      "detail": "No audit policy covers this workload; applied NetworkPolicies are not visible to the broker",
      "inSync": null
    },
    {
      "control": "seccompProfile",
      "state": "none",
      "detail": "No SeccompProfile CR references this workload",
      "inSync": null
    },
    {
      "control": "imageAdmission",
      "state": null,
      "detail": "Signature/admission checks are not configured",
      "inSync": null
    }
  ],
  "readiness": [
    {
      "id": "trafficObserved24h",
      "ok": false,
      "message": "No flows observed"
    },
    {
      "id": "syscallCaptureComplete",
      "ok": null,
      "message": "No syscall capture for this workload"
    },
    {
      "id": "noWouldDeny24h",
      "ok": null,
      "message": "No audit policy covers this workload"
    },
    "(2 more in the capture)"
  ],
  "exposure": {
    "ingressPeers": null,
    "ingressExternal": null,
    "egressPeers": null,
    "egressExternal": null
  },
  "drift": {
    "baselines": {
      "export": null,
      "securityContext": {
        "source": "previousVersion",
        "revision": 2,
        "since": "2026-09-26T03:04:42.217070Z"
      }
    },
    "evaluated": [
      "tagMoved"
    ],
    "items": []
  },
  "_omitted": [
    "dimensions"
  ]
}
```

- `contentHash`: hash of the live profile's policy-relevant snapshot (section 3). `version`: the latest
  **stored** version (`null` until the snapshotter stores one). `snapshotPending: true` = live differs
  from the stored version (always `true` when `version` is `null`).
- `controls[].state`: networkPolicy `"audit" | "unknown"`; seccompProfile `"enforcing" | "audit" | "none"`;
  imageAdmission always `null`. `inSync`: `true | false | null`.
- `readiness[].ok`: `true | false | null` (null = cannot tell).
  - `podSecurityRestricted` is `false` when the level is `baseline` or `privileged`. It is **`null`** when
    the level is `restricted`, because that is only an upper bound in v1 (checks kguardian cannot see,
    such as hostPath, may still fail). It is never `true` in v1.
- `exposure`: distinct peers from observed flows; all `null` when there are no flows.
- `drift`: section 2.8. Drift findings (dimension `"drift"`) are also in `findings` / `attention`.
- `capabilities`: section 2.9. Observed capability use and the evidence behind the `capabilities` part of
  the podSecurity recommendation. Not part of the stored snapshot (counts move constantly); the
  recommendation reaches versions through `dimensions.podSecurity.recommendation`.

### 2.1 Common dimension envelope

```json
{
  "status": "ok|warn|risk|unknown",
  "coverage": { "level": "full|partial|none", "fraction": 0.5, "observedSince": "2026-09-20T06:00:00Z", "note": "…" },
  "reasons": [ { "code": "machine_code", "message": "human sentence" } ]
}
```

- `status`: a tier from fixed rules (2.2), never from a number.
- `coverage.fraction`: evaluated / defined PSS checks for podSecurity; `null` elsewhere.
- `reasons`: why the status is what it is, including why something is unknown. Codes are stable.

### 2.2 Posture rollup and status rules

- Core dimensions: network, syscalls, podSecurity, images. `compute` is informational and excluded.
- `posture.status`:
  - `ok` **only when every core dimension is known and ok**;
  - with any unknown core dimension: the worst known status if that is `warn` or `risk`, otherwise
    `unknown` ("partial data");
  - `unknown` when every core dimension is unknown.
  An unknown dimension never counts as ok or as risk.
- `posture.coverage` = known core dimensions / 4, 2 decimals. `posture.unknownDimensions` = core
  dimensions whose status is `unknown`; always present, `[]` only when all four are known.
- `posture.reasons[]`: one `{dimension, status, message}` per core dimension that is not `ok`, in the order
  network, syscalls, podSecurity, images. podSecurity and every `unknown` dimension use their first
  reason (podSecurity's names the containers that set the level); the others use their most severe
  finding of severity medium or worse, else their first reason.
- Dimension status from findings: any critical/high finding -> `risk`; else any medium -> `warn`; else
  `ok`; no data -> `unknown`. Then:
  - **podSecurity**: level `privileged` -> `risk`; level `baseline` -> at least `warn`; level `restricted`
    (only ever an upper bound in v1) -> **never `ok`**: `unknown` unless a finding makes it warn/risk.
  - **syscalls**: `capture.complete: false` -> at least `warn`.
  - **network**: `unknown` unless an audit policy covers the workload's pods in the last 24 h.
  - **images**: `unknown` while there is no vulnerability data for the running digests (always, until
    the P1-3 vulnerability source lands); then derived from findings. Inventory facts (digests, mixed
    rollouts, crash loops, pull failures) stay in the dimension's details, its reason and its findings.

### 2.3 `podSecurity` — Pod Security Standards

Rules follow the upstream PSS check list exactly: kubernetes.io/docs/concepts/security/pod-security-standards
(kubernetes/website `main` @ `2c1aa11c`, 2026-08-02, docs for Kubernetes v1.37).

| id | level | evaluated? | rule (upstream) |
|---|---|---|---|
| `hostProcess` | baseline | no (field not ingested) | windowsOptions.hostProcess undefined/false |
| `hostNamespaces` | baseline | yes, **if** the pod-level block was reported | hostNetwork, hostPID, hostIPC undefined/false |
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
| `runAsNonRoot` | restricted | yes (see below) | container or pod runAsNonRoot == true |
| `runAsUser` | restricted | yes | runAsUser non-zero or undefined (container and pod) |
| `seccompRestricted` | restricted | yes (see below) | effective (container, else pod) seccompProfile.type is RuntimeDefault or Localhost |
| `capabilitiesRestricted` | restricted | yes | capabilities.drop includes ALL; add only NET_BIND_SERVICE |

- hostPath is **not** available and is reported as unevaluated, never as a pass. Linux is assumed. The
  user-namespace relaxation of runAsNonRoot/runAsUser (alpha feature gate) is not applied.
- **Missing pod-level block** (`pod.known: false`: empty or malformed in the inventory, e.g. an older
  controller): `hostNamespaces` is added to `unevaluatedChecks`, no pod-level check or finding is
  produced, and a container that leaves `runAsNonRoot` / `seccompProfile` to the pod is not failed on
  them (`runAsNonRoot` / `seccompRestricted` are then added to `unevaluatedChecks` too). Reason
  `pod_fields_unknown`.
- **Which containers count:** every **current** container of every kind (regular, init, ephemeral). A row is
  current when a pod of the workload still reports it (refreshed within the inventory's running window, or
  its last reporting pod is still live). Each container is evaluated from its newest running row
  (`source: "running"`), else its newest current row (`source: "last_known"`, e.g. a completed init
  container). A container with no current row (renamed or removed from the spec) is **stale**: it is
  listed in `staleContainers` and does not affect the level, findings, patch or snapshot.
- **Level** = the minimum over the pod-level checks and every current container:
  - any evaluated baseline check fails -> `"privileged"`, `levelConfidence: "confirmed"`;
  - else any evaluated restricted check fails -> `"baseline"`, `"upper_bound"`;
  - else `"restricted"`, `"upper_bound"` (never confirmed in v1).


From `GET /workloads/observability/DaemonSet/node-exporter/profile` -> 200 (capture `profile-risk-observability-node-exporter-hostpid-wouldDeny.json`, `body.dimensions.podSecurity`):

```json
{
  "status": "risk",
  "coverage": {
    "level": "partial",
    "fraction": 0.5,
    "observedSince": "2026-09-20T02:17:01.219542Z",
    "note": "9 of 18 PSS checks evaluated; volumes, ports, probes, AppArmor, SELinux, procMount, sysctls and hostProcess are not ingested"
  },
  "reasons": [
    {
      "code": "pss_fails_baseline",
      "message": "Privileged under PSS: pod spec fail(s) a baseline check"
    }
  ],
  "pssVersion": "kubernetes/website@2c1aa11c (Kubernetes v1.37 docs)",
  "level": "privileged",
  "levelConfidence": "confirmed",
  "unevaluatedChecks": [
    "hostProcess",
    "hostPathVolumes",
    "hostPorts",
    "hostProbesLifecycle",
    "appArmor",
    "seLinux",
    "procMount",
    "sysctls",
    "volumeTypes"
  ],
  "pod": {
    "known": true,
    "serviceAccountName": "node-exporter",
    "automountServiceAccountToken": false,
    "hostNetwork": true,
    "hostPID": true,
    "hostIPC": null,
    "hostUsers": null,
    "securityContext": {
      "runAsNonRoot": null,
      "runAsUser": null,
      "runAsGroup": null,
      "fsGroup": null,
      "seccompProfileType": null
    },
    "failing": [
      {
        "check": "hostNamespaces",
        "level": "baseline",
        "field": "spec.hostNetwork",
        "value": true,
        "message": "hostNetwork must be unset or false"
      },
      {
        "check": "hostNamespaces",
        "level": "baseline",
        "field": "spec.hostPID",
        "value": true,
        "message": "hostPID must be unset or false"
      }
    ]
  },
  "containers": [
    {
      "name": "node-exporter",
      "kind": "regular",
      "source": "running",
      "digest": "sha256:7d4eaaf37d4eaaf37d4eaaf37d4eaaf37d4eaaf37d4eaaf37d4eaaf37d4eaaf3",
      "securityContext": {
        "privileged": null,
        "allowPrivilegeEscalation": null,
        "runAsNonRoot": true,
        "runAsUser": 65534,
        "runAsGroup": null,
        "readOnlyRootFilesystem": true,
        "capabilitiesAdd": null,
        "capabilitiesDrop": null,
        "seccompProfileType": null
      },
      "level": "baseline",
      "failing": [
        {
          "check": "privilegeEscalation",
          "level": "restricted",
          "field": "spec.containers[node-exporter].securityContext.allowPrivilegeEscalation",
          "value": null,
          "message": "allowPrivilegeEscalation must be set to false"
        },
        {
          "check": "seccompRestricted",
          "level": "restricted",
          "field": "spec.containers[node-exporter].securityContext.seccompProfile.type",
          "value": null,
          "message": "seccompProfile.type must be RuntimeDefault or Localhost (on the container, or on the pod)"
        },
        {
          "check": "capabilitiesRestricted",
          "level": "restricted",
          "field": "spec.containers[node-exporter].securityContext.capabilities.drop",
          "value": null,
          "message": "capabilities.drop must include ALL"
        }
      ]
    }
  ],
  "recommendation": {
    "recommendation": true,
    "targetLevel": "restricted",
    "format": "strategic-merge-patch",
    "yaml": "# kguardian recommendation, not applied. Review before use.\n# Target: Pod Security Standards restricted (kubernetes.io/docs/concepts/security/pod-security-standards)\nspec:\n  template:\n    spec:\n      hostNetwork: false\n      hostPID: false\n      securityContext:\n        seccompProfile:\n          type: RuntimeDefault\n      containers:\n      - name: node-exporter\n        securityContext:\n          allowPrivilegeEscalation: false\n          capabilities:\n            drop: [\"ALL\"]\n",
    "caveats": [
      "Checks kguardian cannot see (hostPath and other volume types, hostPort, probe hosts, AppArmor, SELinux, procMount, sysctls) may still fail restricted.",
      "This looks like a node agent (DaemonSet or hostNetwork). CNI plugins, CSI drivers and node agents usually need privileges restricted forbids; a namespace-level PSS exemption is often the right answer instead of this patch.",
      "Turning off hostNetwork/hostPID/hostIPC breaks components that need the node's namespaces (CNI, node exporters, service meshes' node proxies); hostNetwork: false also changes the pod's IP and port bindings.",
      "drop: [\"ALL\"] also removes CHOWN, SETUID, SETGID, DAC_OVERRIDE and NET_BIND_SERVICE. Images that start as root and drop privileges, change file ownership at startup, or bind ports below 1024 may fail; add back NET_BIND_SERVICE only if the app needs it."
    ]
  },
  "staleContainers": []
}
```

- `pod.known`: see above. When `false` every other `pod` field is `null` and `pod.failing` is `[]`.
- `staleContainers[]`: `{name, kind, digest, lastSeen}` (see "Which containers count").
- `securityContext` values are exactly what the controller reported: `null` = not set in the spec.
- `automountServiceAccountToken: null` = not set on the pod; the ServiceAccount's own setting is not
  visible, so the token is assumed mounted (finding `podSecurity.automountToken`).
- `recommendation`: a minimal strategic-merge patch with only the fields that fail evaluated checks, under
  the kind's template path (`spec.template.spec`; `spec.jobTemplate.spec.template.spec` for CronJob;
  `spec` for a bare Pod). Always `recommendation: true`. It is **`null`** when nothing evaluated fails,
  **and** when nothing failing is patchable (for example only an ephemeral container fails; reason
  `ephemeral_unpatchable`). It never contains an empty template, stale or ephemeral containers, or
  `readOnlyRootFilesystem`. `caveats[]` always include the unevaluated-checks warning, plus, when they
  apply: the runAsNonRoot/USER warning; a node-agent warning (DaemonSet or hostNetwork workload);
  `privileged: false`; hostNetwork/hostPID/hostIPC `false`; and `drop: ["ALL"]` (CHOWN, SETUID, SETGID,
  DAC_OVERRIDE, NET_BIND_SERVICE); plus the names of failing ephemeral containers.
- Reason codes: `pss_fails_baseline`, `pss_fails_restricted`, `pss_unverified`, `pod_fields_unknown`,
  `ephemeral_unpatchable`, `stale_containers_excluded`, `no_inventory`, `only_stale_containers`.
- Findings (id `podSecurity.<code>` or `podSecurity.<code>/<container>`): `privileged` high,
  `hostNetwork` / `hostPID` / `hostIPC` high, `capabilitiesAdded` high outside the baseline set else low
  (NET_BIND_SERVICE alone: none), `allowPrivilegeEscalation` medium, `runAsRoot` high (runAsUser 0),
  `mayRunAsRoot` medium, `seccompUnconfined` high, `seccompUnset` medium, `capabilitiesNotDropped`
  medium, `readOnlyRootFilesystem` low, `automountToken` low. No pod-level finding when `pod.known` is
  false.

### 2.4 `network`


From `GET /workloads/observability/DaemonSet/node-exporter/profile` -> 200 (capture `profile-risk-observability-node-exporter-hostpid-wouldDeny.json`, `body.dimensions.network`):

```json
{
  "status": "warn",
  "coverage": {
    "level": "full",
    "fraction": null,
    "observedSince": "2026-09-23T02:17:01.229165Z",
    "note": "Flows from the workload's pod(s) (1 live)"
  },
  "reasons": [],
  "summary": {
    "egress": {
      "peers": 1,
      "external": 1,
      "ports": [
        "TCP/443"
      ]
    },
    "ingress": {
      "peers": 1,
      "external": 0,
      "ports": [
        "TCP/9100"
      ]
    }
  },
  "peers": [
    {
      "direction": "ingress",
      "protocol": "TCP",
      "port": 9100,
      "peer": {
        "kind": "pod",
        "namespace": "observability",
        "workloadKind": "StatefulSet",
        "workloadName": "prometheus",
        "name": "prometheus-0",
        "ip": "10.42.2.5"
      },
      "flows": 1,
      "firstSeen": "2026-09-23T02:17:01.229165Z",
      "lastSeen": "2026-09-23T02:17:01.229165Z"
    },
    {
      "direction": "egress",
      "protocol": "TCP",
      "port": 443,
      "peer": {
        "kind": "external",
        "namespace": null,
        "workloadKind": null,
        "workloadName": null,
        "name": null,
        "ip": "198.51.100.7"
      },
      "flows": 1,
      "firstSeen": "2026-09-26T00:17:01.229165Z",
      "lastSeen": "2026-09-26T00:17:01.229165Z"
    }
  ],
  "truncated": false,
  "policy": {
    "audit": {
      "policies": [
        {
          "namespace": "observability",
          "name": "node-exporter"
        }
      ],
      "allow": 1,
      "wouldDeny": 1,
      "lastVerdictAt": "2026-09-26T01:17:01.231848Z",
      "windowHours": 24
    },
    "enforced": null
  }
}
```

- `peer.kind`: `"pod" | "service" | "node" | "external" | "unresolved"` (`external` = a public IP;
  `unresolved` = a private IP with no resolved identity).
- `peers[]`: at most 200 groups from the newest 50 000 flow rows; `truncated: true` if either bound hit.
  `port` = the pod's own port for ingress, the peer's port for egress; `null` if unparseable.
- `policy.audit`: `null` when no AuditNetworkPolicy verdict mentions the workload's pods in the last 24 h.
  `policy.enforced`: always `null` (applied NetworkPolicies are not mirrored).
- Status: `unknown` with no audit policy (reason `policy_state_unknown`) or no flows (`no_flows`);
  otherwise `warn` when `wouldDeny > 0` (finding `network.wouldDeny`, medium), else `ok`.

### 2.5 `syscalls`


From `GET /workloads/flux-system/Deployment/source-controller/profile` -> 200 (capture `profile-unknown-partial-flux-system-source-controller.json`, `body.dimensions.syscalls`):

```json
{
  "status": "ok",
  "coverage": {
    "level": "full",
    "fraction": null,
    "observedSince": null,
    "note": "capture level full"
  },
  "reasons": [
    {
      "code": "denials_unknown",
      "message": "Denial capture is not reporting for this workload's nodes, so an absence of denials cannot be confirmed"
    }
  ],
  "observed": {
    "syscallCount": 5,
    "hash": "5c1f0e2d3a4b5c6d",
    "architectures": [
      "SCMP_ARCH_X86_64"
    ],
    "updatedAt": "2026-09-26T02:17:01.224138Z"
  },
  "capture": {
    "level": "full",
    "complete": true,
    "incompletePods": 0
  },
  "cr": {
    "name": "source-controller",
    "defaultAction": "SCMP_ACT_ERRNO",
    "mode": "enforce",
    "syscallCount": 5,
    "inSync": true,
    "missing": [],
    "extra": [],
    "distribution": {
      "ready": 0,
      "total": 1,
      "state": "Pending"
    }
  },
  "denials": null
}
```

- `observed`: `null` when there is no syscall aggregate (status `unknown`, reason `no_observations`).
- `capture.level`: `full|high|medium|low|custom|unknown`; `complete: false` -> reason `capture_incomplete`,
  status at least `warn`.
- `cr`: `null` = no SeccompProfile CR references the workload. `mode`: `audit` for `SCMP_ACT_LOG` /
  `SCMP_ACT_ALLOW`, else `enforce`. `missing` = observed but not allowed (blocked when enforced).
- `denials`: `null` = cannot tell "nothing denied" from "nothing capturing" (reason `denials_unknown`).
- Findings: `syscalls.no_enforcing_profile` medium (no CR, or a CR in audit mode), `syscalls.drift`
  medium, `syscalls.denials` high.

### 2.6 `images`


From `GET /workloads/payments/Deployment/ledger/profile` -> 200 (capture `profile-warn-payments-ledger-mixed-crashloop-stale.json`, `body.dimensions.images`):

```json
{
  "status": "unknown",
  "coverage": {
    "level": "partial",
    "fraction": null,
    "observedSince": "2026-09-06T02:17:01.217147Z",
    "note": "inventory only (running window 900 s); no vulnerability data"
  },
  "reasons": [
    {
      "code": "vulnerabilities_not_configured",
      "message": "2 running digest(s) across 1 container(s); vulnerability data not configured"
    }
  ],
  "runningWindowSeconds": 900,
  "containers": [
    {
      "name": "ledger",
      "kind": "regular",
      "mixedDigests": true,
      "stale": false,
      "running": [
        {
          "digest": "sha256:4a1b77c04a1b77c04a1b77c04a1b77c04a1b77c04a1b77c04a1b77c04a1b77c0",
          "imageRef": "ghcr.io/example/ledger:2.3.0",
          "state": "running",
          "stateReason": null,
          "ranAsInit": false,
          "lastPodName": "ledger-5b7c9d8f6-q8wzn",
          "firstSeen": "2026-09-20T02:17:01.219542Z",
          "lastSeen": "2026-09-26T03:05:37.122592Z"
        },
        {
          "digest": "sha256:5b2c88d15b2c88d15b2c88d15b2c88d15b2c88d15b2c88d15b2c88d15b2c88d1",
          "imageRef": "ghcr.io/example/ledger:2.3.1",
          "state": "waiting",
          "stateReason": "CrashLoopBackOff",
          "ranAsInit": false,
          "lastPodName": "ledger-5b7c9d8f6-q8wzn",
          "firstSeen": "2026-09-20T02:17:01.219542Z",
          "lastSeen": "2026-09-26T03:05:37.122592Z"
        }
      ],
      "previous": []
    },
    {
      "name": "legacy-proxy",
      "kind": "regular",
      "mixedDigests": false,
      "stale": true,
      "running": [],
      "previous": [
        {
          "digest": "sha256:6c3d99e26c3d99e26c3d99e26c3d99e26c3d99e26c3d99e26c3d99e26c3d99e2",
          "imageRef": "docker.io/envoyproxy/envoy:v1.29.0",
          "state": "running",
          "stateReason": null,
          "ranAsInit": false,
          "lastPodName": "ledger-5b7c9d8f6-old01",
          "firstSeen": "2026-09-06T02:17:01.217147Z",
          "lastSeen": "2026-09-24T02:17:01.217147Z"
        }
      ]
    }
  ],
  "truncated": false,
  "vulnerabilities": null,
  "supplyChain": null
}
```

- `status`: `unknown` in v1.3 whenever there is an inventory, because there is no vulnerability data
  (reason `vulnerabilities_not_configured`, message "N running digest(s) across M container(s);
  vulnerability data not configured"; `coverage.level: "partial"`). No inventory -> `unknown`, reason
  `no_inventory`.
- `stale: true`: not in the current spec (see 2.3); listed, never a finding.
- `vulnerabilities` / `supplyChain`: always `null` = **not configured**.
- Findings: `images.mixedDigests/<c>` low, `images.crashLoop/<c>` medium, `images.pullBackOff/<c>` medium.

### 2.7 `compute` (informational, not in the rollup)

`{ status, coverage, reasons, containers: [ { pod, container, cpuRequestMillis, cpuLimitMillis,
memRequestBytes, memLimitBytes, cpuUsageMillis, memWorkingSetBytes, oomKills, throttledRatio, updatedAt } ],
truncated }` from `pod_compute_latest` for the live pods (max 50). `oomKills` = in the latest sample
interval. No rows -> `unknown`, reason `no_compute_data`. Findings: `compute.missingMemoryLimit/<c>` low,
`compute.oomKilled/<c>` medium.

### 2.8 `drift` (P2-5; not a core dimension, never sets posture)

Four checks, each a finding with `dimension: "drift"` and an entry in `drift.items`:

| `type` | when | severity |
|---|---|---|
| `tagMoved` | a current container's image **tag** (a reference without `@digest`) has resolved to more than one digest in the inventory (re-pushed tag, or nodes resolved it differently) | medium |
| `imageChangedSinceExport` | a current container runs a digest the last export's snapshot did not have, or the container is new since that export. Needs an export record (a `POST .../export`, section 4) | medium |
| `securityContextRegression` | a PSS check that passed in the baseline fails now, for a container that existed in the baseline or at pod level. Baseline = the last export when there is one, else the newest stored version whose podSecurity content differs from the live one | high if a baseline check newly fails, else medium |
| `unshippedExecutable` (v1.7) | a current container, on a digest it runs now, executed or loaded a file its image did not ship as it ran: from the container's writable layer, from a memfd, or deleted while running (the runtime inventory's `unshipped` origins). Needs the runtime inventory; see `notEvaluated` | high for `writableLayer` or `memfd`, medium for `deleted` only |

From `GET /workloads/payments/Deployment/checkout/profile` -> 200 (capture `profile-drift-payments-checkout-after-export.json`, `body.drift`):

```json
{
  "baselines": {
    "export": {
      "revision": 4,
      "contentHash": "fnv1a64:3369d0d1f33d02b4",
      "mode": "audit",
      "artifacts": [
        "networkpolicy",
        "seccompprofile",
        "securitycontext"
      ],
      "exportedAt": "2026-09-26T03:03:52.663640Z"
    },
    "securityContext": {
      "source": "export",
      "revision": 4,
      "since": "2026-09-26T03:03:52.663640Z"
    }
  },
  "evaluated": [
    "tagMoved",
    "imageChangedSinceExport",
    "securityContextRegression"
  ],
  "items": [
    {
      "type": "tagMoved",
      "findingId": "drift.tagMoved/app",
      "severity": "medium",
      "container": "app",
      "detail": {
        "digests": [
          "sha256:ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34",
          "sha256:cd56ef78cd56ef78cd56ef78cd56ef78cd56ef78cd56ef78cd56ef78cd56ef78"
        ],
        "imageRef": "ghcr.io/example/checkout:4.1.0",
        "since": "2026-09-26T03:04:03.273543Z"
      }
    },
    {
      "type": "imageChangedSinceExport",
      "findingId": "drift.imageChangedSinceExport/app",
      "severity": "medium",
      "container": "app",
      "detail": {
        "containerInExport": true,
        "exportedDigests": [
          "sha256:ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34"
        ],
        "newDigests": [
          "sha256:cd56ef78cd56ef78cd56ef78cd56ef78cd56ef78cd56ef78cd56ef78cd56ef78"
        ]
      }
    },
    {
      "type": "securityContextRegression",
      "findingId": "drift.securityContextRegression/app",
      "severity": "high",
      "container": "app",
      "detail": {
        "levelFrom": "baseline",
        "levelTo": "privileged",
        "newlyFailing": [
          "privileged"
        ]
      }
    }
  ]
}
```

- `baselines.export`: the last export `{revision, contentHash, mode, artifacts, exportedAt}`, `null` when the
  workload was never exported. `baselines.securityContext`: `{source: "export"|"previousVersion", revision,
  since}`, `null` when there is no baseline.
- `evaluated`: the checks that could run for the whole workload. A check that is not listed was **not
  evaluated** (no inventory, no export, no baseline, no runtime coverage); its absence from `items` means
  nothing. `unshippedExecutable` is listed only when every current running container's capture covered it
  over the coverage window (`kg_runtime_coverage`) and the unshipped read was not cut.
- `notEvaluated` (v1.7): `[{type, container, reason}]`, per container, the checks that could not run and
  why; `container` is `null` for the whole workload. For `unshippedExecutable` the reason is
  `no_inventory` (the controller reports no runtime inventory for the workload: mode off, excluded or
  opted out), `no_runtime_data` (no coverage heartbeat for the container's running digest),
  `truncated` (more unshipped rows than the read returns), or the coverage function's own reason
  (`capture_gap`, lost events, incomplete backfill, ...). A file seen running from an unshipped origin is
  an item whatever the coverage; coverage only decides whether "none seen" may be said.
- `items[]`: `{type, findingId, severity, container, detail}`. `detail` by type:
  - `tagMoved`: `{imageRef, digests[], since}`;
  - `imageChangedSinceExport`: `{containerInExport, exportedDigests[], newDigests[]}`;
  - `securityContextRegression`: `{newlyFailing[] (check ids), levelFrom, levelTo}`; `container` is `null`
    for a pod-level regression;
  - `unshippedExecutable`: `{origins[], files[] (newest first, at most 20: {path, kind, origin, digest,
    pathComplete, firstSeen, lastSeen}), filesTotal, truncated}`. Rows of a digest the container no
    longer runs are not current drift and are not listed. `pathComplete: false` means the kernel path walk
    was cut and `path` is a suffix.
- A new container is not a securityContext regression. An improvement is never reported.
- Metrics: `/metrics` exposes the gauge `kguardian_workload_drift{workload_namespace, workload_kind,
  workload, type}` = drift items of that type in the workload's latest snapshot, refreshed every 60 s from
  the read model (at most 5 000 series). A workload leaves the gauge when its read-model row is pruned.

### 2.9 `capabilities` (P2-7; not a dimension, never sets posture)

Which Linux capabilities each container actually used, from the controller's capability probe
(`controller.runtimeInventory.capabilities`, off by default), and whether that is enough evidence to
recommend `drop: [ALL]` plus only those.

From a live broker build (`live_evidence_drives_the_profile_and_its_patch`, `body.capabilities`):

```json
{
  "containers": [
    {
      "container": "app",
      "denied": [
        {
          "capability": "SYS_ADMIN",
          "count": 4,
          "firstSeen": "2026-09-26T10:00:00",
          "lastSeen": "2026-09-26T11:00:00"
        }
      ],
      "digests": [
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      ],
      "evidence": "sufficient",
      "observedSince": "2026-09-18T13:28:45.825117",
      "probed": [
        {
          "capability": "SYS_ADMIN",
          "count": 25,
          "firstSeen": "2026-09-26T10:00:00",
          "lastSeen": "2026-09-26T11:00:00"
        }
      ],
      "reason": null,
      "recommendation": {
        "add": [
          "NET_BIND_SERVICE",
          "SYS_TIME"
        ],
        "drop": [
          "ALL"
        ],
        "probedKept": [],
        "probedOmitted": [
          {
            "capability": "SYS_ADMIN",
            "reason": "probed only (memory reserve / seccomp without no_new_privs); allowPrivilegeEscalation=false removes the need"
          }
        ]
      },
      "unusedAdded": [
        "NET_ADMIN"
      ],
      "used": [
        {
          "capability": "NET_BIND_SERVICE",
          "count": 5,
          "firstSeen": "2026-09-26T10:00:00",
          "lastSeen": "2026-09-26T11:00:00"
        },
        {
          "capability": "SYS_TIME",
          "count": 1,
          "firstSeen": "2026-09-26T10:00:00",
          "lastSeen": "2026-09-26T11:00:00"
        }
      ]
    }
  ],
  "windowHours": 168
}
```

- `windowHours`: the evidence window (`CAPABILITY_EVIDENCE_WINDOW_HOURS`, default 168, clamped to
  24-2160). Long on purpose: a capability used weekly must have had a chance to show up.
- One entry per current container. `digests`: its current digests, all of which the evidence must cover.
- `used`: ordinary checks that succeeded (the container needed the capability), summed over every digest
  the container ran, current or previous. `denied`: ordinary checks the container made without holding the
  capability (granting it would change behaviour). `probed`: `CAP_OPT_NOAUDIT` checks that succeeded, the
  kernel asking whether the process is privileged (every root process's memory admin-reserve check asks
  for `SYS_ADMIN`; others gate real behaviour: a seccomp filter without `no_new_privs`, ptrace access to
  other processes). Each has `count`, `firstSeen`, `lastSeen`.
- Not counted: container runtime setup (a task that has not exec'd since it was forked by a process
  outside every pod cgroup, i.e. runc init; decided by provenance, so a process renaming itself `runc:[`
  is still counted), and checks against a user namespace the container created.
- `evidence`: `sufficient` only when `kg_capability_coverage` says every current digest was watched for
  the whole window: the runtime coverage (`kg_runtime_coverage`: probes, no lost events, no heartbeat gaps,
  no untracked live pods) **and**, for every instance in the window, the capability probe on the
  `cap_capable` hook, captured from the container's start with no gap since (capabilities have no `/proc`
  backfill, so a container already running when the probe attached is never evidence until it restarts).
  Otherwise `insufficient`, with `reason`: a `kg_runtime_coverage` reason, `capabilities_not_tracked`,
  `capabilities_partial_hook`, `capabilities_not_seen_since_start`, `no_current_digest`, or
  `rows_truncated`.
- `recommendation`: only with sufficient evidence: `drop: ["ALL"]`, `add`: every used and every probed
  capability, with one exception below (a used capability is never recommended for dropping),
  `probedKept`: the part of `add` there only because of probes, to be removed only after a person
  confirms, and `probedOmitted`: probed-only capabilities left out, each `{capability, reason}`. `null`
  otherwise.
- The exception: a **probed-only `SYS_ADMIN`** is left out (listed in `probedOmitted` with reason "probed
  only (memory reserve / seccomp without no_new_privs); allowPrivilegeEscalation=false removes the need")
  unless the container is currently privileged. It comes almost entirely from the memory admin-reserve
  check every root process makes; the one real gate among its non-audited callers is installing a seccomp
  filter without `no_new_privs`, and the recommendation keeps or sets `allowPrivilegeEscalation: false`,
  which sets `no_new_privs`. A caveat says so. For a privileged container it stays in `add`. Every other
  probed capability (e.g. `SYS_PTRACE`) stays in `add`.
- `unusedAdded`: capabilities the current `securityContext.capabilities.add` grants that were never used or
  probed (only with sufficient evidence).
- Retention keeps capability rows for at least the window plus a day, so a capability used inside the
  window is never pruned while the window counts as evidence.
- The podSecurity recommendation (section 2.3, and the export's `securitycontext` artifact) uses this: with
  sufficient evidence a container's patch is `drop: ["ALL"]` + `add: <used>` (`add: null` when none was
  used), and it is emitted even when every PSS check passes if the current set is wider than the used
  one. A used capability other than `NET_BIND_SERVICE` keeps the container below restricted; a caveat
  says so, and another names capabilities kept only because of probes. Without evidence the patch keeps
  the restricted default and a caveat says it is not observed evidence.
- Not seen: capabilities checked by kernel paths that do not go through `cap_capable`/`security_capable`,
  and capabilities a container would need only in a situation that did not occur in the window.

## 3. Versions

A version is an **immutable, content-hashed snapshot of the policy-relevant parts** of the profile:

- `podSecurity`: `level`, the pod block (without `failing`), each **current** container's kind and
  securityContext.
- `images`: each current container -> sorted running digests.
- `syscalls`: sorted observed syscall names, capture level, CR `{name, defaultAction, hash}` or null.
- `network`: `{ "rules": [ {direction, protocol, port, peer} ] }`: the **distinct rule set over all retained
  flows** of the workload's pods (deduplicated in SQL, at most 2 000 rules), not the newest-N peer table.
  `peer` is `pod:<ns>/<workloadKind>/<workloadName>` (or `pod:<ns>/<name>` without a workload),
  `service:<ns>/<name>`, `node`, `external:<ip>`, `unresolved:<ip>`.
- NOT included: timestamps, counts, flow truncation, the 24 h audit state, compute, posture, stale
  containers. None of them change the hash.

`contentHash` = FNV-1a 64 over the canonical JSON, prefixed `fnv1a64:`; `dimensionHashes` = the same per
dimension. A new version is written only when `contentHash` differs from the latest stored one.
`revision` increases by 1 per workload. Retention: the newest `PROFILE_VERSIONS_MAX_PER_WORKLOAD`
(default 50) per workload; `PROFILE_VERSIONS_RETENTION_DAYS` (default 90; 0 disables) prunes older
versions except each live workload's newest, and read-model rows not recomputed in that window.
Concurrent writers: if another writer stored a different profile at the same revision first, nothing is
written and the latest pointer is left alone; the latest pointer never moves to a lower revision.

### 3.1 `GET /workloads/{namespace}/{kind}/{name}/profile/versions`

Query: `limit` (default 50, max 200), `before` (revision; returns revisions < before). Newest first. 404
`workload_not_found` when the workload has no versions and is unknown; a known workload with none yet
returns `items: []`. Captures: `versions-payments-checkout`, `versions-payments-checkout-page`.

From `GET /workloads/payments/Deployment/checkout/profile/versions` -> 200 (capture `versions-payments-checkout.json`, `body`):

```json
{
  "items": [
    {
      "changedDimensions": [
        "podSecurity",
        "images"
      ],
      "contentHash": "fnv1a64:44c9939f6034479f",
      "createdAt": "2026-09-26T03:05:49.507372Z",
      "dimensionHashes": {
        "images": "fnv1a64:36a8abee01f3a6ca",
        "network": "fnv1a64:076a93e6e419f917",
        "podSecurity": "fnv1a64:a06c1a54bf60dcff",
        "syscalls": "fnv1a64:c9b16fe56ade7d93"
      },
      "posture": {
        "coverage": 0.5,
        "status": "risk"
      },
      "revision": 6
    },
    {
      "changedDimensions": [
        "podSecurity",
        "images"
      ],
      "contentHash": "fnv1a64:17b3716f1d04b24d",
      "createdAt": "2026-09-26T03:04:42.249342Z",
      "dimensionHashes": {
        "images": "fnv1a64:b9f6d7ae2a24fa93",
        "network": "fnv1a64:076a93e6e419f917",
        "podSecurity": "fnv1a64:486973277f0aab10",
        "syscalls": "fnv1a64:c9b16fe56ade7d93"
      },
      "posture": {
        "coverage": 0.5,
        "status": "risk"
      },
      "revision": 5
    },
    {
      "changedDimensions": null,
      "contentHash": "fnv1a64:4c1d1714495b7cb8",
      "createdAt": "2026-09-26T02:21:21.027754Z",
      "dimensionHashes": {
        "images": "fnv1a64:de99962acfed6b4a",
        "network": "fnv1a64:076a93e6e419f917",
        "podSecurity": "fnv1a64:14765c2d405c573e",
        "syscalls": "fnv1a64:c9b16fe56ade7d93"
      },
      "posture": {
        "coverage": 0.25,
        "status": "warn"
      },
      "revision": 4
    }
  ],
  "kind": "Deployment",
  "name": "checkout",
  "namespace": "payments",
  "nextBefore": null
}
```

- `changedDimensions`: dimensions whose hash differs from the previous revision; all four for revision 1;
  `null` when the previous revision was trimmed (unknown, not guessed).
- `posture`: `{status, coverage}` at that revision (rows stored before v1.2 may also carry
  `score` / `grade`; ignore them).

### 3.2 `GET /workloads/{namespace}/{kind}/{name}/profile/versions/{revision}`

`{ namespace, kind, name, revision, contentHash, createdAt, dimensionHashes, posture, snapshot }` with the
snapshot shape of section 3. 404 `revision_not_found`. Capture: `version-payments-checkout-rev4`.

### 3.3 `GET /workloads/{namespace}/{kind}/{name}/profile/diff?from=&to=`

`to`: revision, default latest. `from`: revision, default = the previous one. `from >= to` -> 400. An
explicit missing `from`/`to` -> 404 `revision_not_found`; no versions -> 404 `workload_not_found`.
**Trimmed predecessor:** with `from` omitted, when `to - 1` was trimmed the diff uses the newest retained
revision below `to`, or `from: null` (everything shows as added) when none is left, and sets
`fromTrimmed: true`. Captures: `diff-payments-checkout-default`, `diff-payments-checkout-4-to-6`,
`diff-payments-checkout-trimmed-predecessor`, `error-404-revision-not-found`, `error-400-bad-order`.

From `GET /workloads/payments/Deployment/checkout/profile/diff?from=4&to=6` -> 200 (capture `diff-payments-checkout-4-to-6.json`, `body`):

```json
{
  "changed": true,
  "dimensions": {
    "images": {
      "changed": true,
      "containers": [
        {
          "added": [
            "sha256:cd56ef78cd56ef78cd56ef78cd56ef78cd56ef78cd56ef78cd56ef78cd56ef78"
          ],
          "name": "app",
          "removed": [
            "sha256:ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34"
          ]
        }
      ],
      "containersAdded": [],
      "containersRemoved": []
    },
    "network": {
      "added": [],
      "changed": false,
      "removed": []
    },
    "podSecurity": {
      "changed": true,
      "containers": [
        {
          "fields": [
            {
              "field": "securityContext.privileged",
              "from": null,
              "to": true
            }
          ],
          "name": "app"
        },
        {
          "fields": [
            {
              "field": "securityContext.allowPrivilegeEscalation",
              "from": false,
              "to": null
            },
            {
              "field": "securityContext.capabilitiesDrop",
              "from": [
                "ALL"
              ],
              "to": null
            }
          ],
          "name": "migrate"
        }
      ],
      "containersAdded": [],
      "containersRemoved": [],
      "level": {
        "from": "restricted",
        "to": "privileged"
      },
      "pod": []
    },
    "syscalls": {
      "added": [],
      "captureLevel": null,
      "changed": false,
      "cr": null,
      "removed": []
    }
  },
  "from": {
    "contentHash": "fnv1a64:4c1d1714495b7cb8",
    "createdAt": "2026-09-26T02:21:21.027754Z",
    "revision": 4
  },
  "fromTrimmed": false,
  "kind": "Deployment",
  "name": "checkout",
  "namespace": "payments",
  "to": {
    "contentHash": "fnv1a64:44c9939f6034479f",
    "createdAt": "2026-09-26T03:05:49.507372Z",
    "revision": 6
  }
}
```

- A changed scalar is `{ "from": x, "to": y }`; an unchanged scalar is `null`.
- `syscalls.cr` when changed: `{ "from": {name, defaultAction, hash} | null, "to": … }`.

## 4. `GET|POST /workloads/{namespace}/{kind}/{name}/export` — export bundle (P2-4)

Query (all optional):

| param | values | default |
|---|---|---|
| `artifacts` | comma list of `networkpolicy`, `ciliumnetworkpolicy`, `seccompprofile`, `securitycontext`, `sbom`, `vex`, `admission` | all |
| `mode` | `audit` \| `enforce` | `audit` |
| `format` | `yaml` (multi-document YAML) \| `zip-manifest` (JSON manifest of files) | `yaml` |
| `acknowledgePartial` | `true` to take enforce-mode artifacts built from partial evidence | `false` |
`GET` (READ scope) is side-effect free: it generates the bundle and writes nothing. `POST` on the same
path with the same query (**admin** scope) returns the same bundle and also records it as the workload's
drift baseline (see Recording below). Recording says "this is what the operator accepted", so a read token
must not be able to do it. `GET ...?record=<truthy>` is a 400 pointing at POST; `record` is ignored on POST.

Report and generate only: **kguardian never applies anything**, and every document says so.
The response carries `X-Kguardian-Export-Mode` and `X-Kguardian-Export-Recorded` (`true` only for a POST
that stored a record).

Artifacts and where they come from (existing generators only):

| artifact | audit mode | enforce mode | generator |
|---|---|---|---|
| `networkpolicy` | `AuditNetworkPolicy` (`kguardian.dev/v1alpha1`, same spec; the evaluator reports would-deny without dropping) | `NetworkPolicy` | the advisor reference generator, ported to the broker and held to the shared goldens (`test/fixtures/generators/networkpolicy`) |
| `ciliumnetworkpolicy` | **withheld** (a CNP has no per-policy audit mode) | `CiliumNetworkPolicy` | same |
| `seccompprofile` | `SeccompProfile` with `SCMP_ACT_LOG` | `SCMP_ACT_ERRNO` | the `/seccomp/profiles/{..}/export` path |
| `securitycontext` | strategic-merge **patch** + `pod-security.kubernetes.io/audit=restricted` label suggestion | same patch + `.../enforce=restricted` | the profile's `podSecurity.recommendation` |
| `sbom` | the stored SBOM of each container image as CycloneDX 1.5 JSON (`sbom-<container>-<digest12>.cdx.json`), one document per digest, with `image` saying which source and trust it came from; unavailable per image, with the reason, when no source has an SBOM or it does not fit the bundle cap | same | `supplychain_read::cyclonedx_for`, the `/images/{digest}/sbom/cyclonedx` document (#1671) |
| `vex` | OpenVEX 0.2.0 draft (`vex.openvex.json`): `not_affected` only for packages unseen in every container over a covered capture window, each statement marked as a draft for human review; commented out of the YAML apply stream; unavailable, with the reason, when no statement qualifies | same | `in_use_store::openvex_draft` (P1-5) |
| `admission` | not available (needs the image trust policy, P2-3) | same | stub |

- **SBOM per image (v1.5):** the images are each current container's running digests (or its newest
  digest when none runs; stale containers are left out), one document per digest, shared by every container
  running it. The SBOM is the one `GET /images/{digest}/sbom/cyclonedx` returns: Trivy Operator's
  (`sbomTrust: scanned`) first, a registry-attached one (`unverified` / `attached-unbound`: signature not
  checked) only when it is the only one. `image.source` and `image.sbomTrust` say which; `applyWith` says it
  in words. No SBOM for a digest is an unavailable document for that image ("contents are unknown"), never
  an empty SBOM. An SBOM whose source listed no components is still an available document, but its
  `applyWith` and YAML header say "0 components reported by <source> (<trust>)", so it is not read as a
  checked clean image. At most 10 000 components per bundle. When `sbom` is requested the export first reads the
  chosen SBOMs' sizes and charges the read budget for exactly that many components (three copies for
  `format=yaml`, two for `zip-manifest`), and never loads more than it charged for; an image that does not
  fit is unavailable with the per-image route to download it.
- **OpenVEX (v1.5):** see the `vex` row. Statements come only from packages unseen in every container over a
  covered capture window (vulnerabilities API, "In use"); without that coverage signal the artifact is
  unavailable, with the reason.
- **Network policies for a workload:** the generator is per pod. It gets the newest flow rows of every
  pod of the workload (at most 20 000) and, as its target, the newest live pod with the workload's
  selector labels (so it selects every replica, not one ReplicaSet's `pod-template-hash`). Its object name
  is `<workload>-kguardian`.
- **Enforce refusals** (as the standalone seccomp export): `seccompprofile` when the capture is not full;
  `networkpolicy` / `ciliumnetworkpolicy` when no flows were seen, the flow summary is truncated, or
  traffic has been observed for under 24 h. Any refusal answers **409** unless `acknowledgePartial=true`:

From `GET /workloads/payments/Deployment/checkout/export?mode=enforce` -> 409 (capture `export-409-enforce-refused.json`, `body`):

```json
{
  "error": "export_refused",
  "message": "enforce mode was refused for artifacts whose evidence is partial; export in audit mode, drop those artifacts, or pass acknowledgePartial=true",
  "refusals": [
    {
      "artifact": "seccompprofile",
      "reason": "refusing to export an enforcing profile (SCMP_ACT_ERRNO) from a partial capture: medium on 1 pod(s): checkout-7d9f8b6c5-2xkqp (medium).\nOnly the full tier observes every syscall, so this profile would block syscalls the workload makes. Raise the tier to full (the kguardian.dev/syscall-capture pod annotation, or SYSCALL_CAPTURE_LEVEL cluster-wide), let the profile re-accrue, then export again.\nOr export with defaultAction=SCMP_ACT_LOG for an audit-only profile now, or pass acknowledgePartial=true to take this one as it is."
    }
  ]
}
```

- **Provenance:** every Kubernetes document carries these annotations: `kguardian.dev/generated-by`,
  `generated-at`, `source-workload` (`ns/Kind/name`), `profile-revision` (or `unversioned`),
  `profile-hash`, `export-mode`, and `applied-by-kguardian: "false"`. Each document is preceded by a
  `# kguardian export: <artifact> (<mode> mode)` / `# kguardian never applies this document` header.
- **Recording (POST only):** a successful export with at least one included artifact is stored
  (`workload_profile_exports`: newest 20 per workload, aged out by `PROFILE_VERSIONS_RETENTION_DAYS`
  except each live workload's newest). It is the `imageChangedSinceExport` / securityContext baseline
  (section 2.8).
- **Errors:** 400 `bad_request` (unknown artifact, mode or format; `record` on GET), 401/403 without the
  required scope when auth is on, 404 `workload_not_found`, 409
  `export_refused` as above, 503 read budget.

### 4.1 `format=yaml`

A bundle header (workload, mode, profile revision, "kguardian never applies anything", one
`# not included: <artifact> (<reason>)` line per unavailable artifact), then one `---` document per
included Kubernetes object. The securityContext patch is **not** an object, so it is appended as comments
after the last document; the stream stays safe to pass to `kubectl apply -f`. From v1.5 the OpenVEX draft
and each available SBOM are appended as comments the same way, each SBOM under a header naming its image,
source and trust (`# ---- sbom (CycloneDX SBOM <fileName> for <digest> (<containers>), source <source>,
trust <trust>; not part of the apply stream) ----`). `format=zip-manifest` carries them as plain files.

From `GET /workloads/payments/Deployment/checkout/export` -> 200 (capture `export-yaml-audit-payments-checkout.json`, body verbatim):

```yaml
# kguardian export bundle for payments/Deployment/checkout
# mode: audit; profile revision 6 (fnv1a64:44c9939f6034479f); generated 2026-09-26T03:06:02.481263599+00:00 by kguardian-broker/1.18.2
# kguardian never applies anything. Review every document, commit it, and apply it yourself.
# not included: ciliumnetworkpolicy (withheld in audit mode: a CiliumNetworkPolicy has no per-policy audit mode and enforces as soon as it is applied. Use the networkpolicy artifact (an AuditNetworkPolicy, evaluated by kguardian without blocking) to audit, then export with mode=enforce.)
# not included: sbom (not available: a CycloneDX runtime SBOM needs the runtime package data from P1-3/P1-5, which does not exist yet)
# not included: vex (not available: an OpenVEX draft needs vulnerability data and runtime package evidence (P1-3/P1-5), which do not exist yet)
# not included: admission (not available: the image admission policy needs the image trust policy (P2-3), which has not landed)
---
# kguardian export: networkpolicy (audit mode)
# kguardian never applies this document. Review it, commit it, and apply it yourself.
# AuditNetworkPolicy: same spec as a NetworkPolicy; the kguardian evaluator reports would-deny flows without dropping anything. Promote with `kubectl kguardian audit promote`.
apiVersion: kguardian.dev/v1alpha1
kind: AuditNetworkPolicy
metadata:
  annotations:
    kguardian.dev/applied-by-kguardian: 'false'
    kguardian.dev/export-mode: audit
    kguardian.dev/generated-at: 2026-09-26T03:06:02.481263599+00:00
    kguardian.dev/generated-by: kguardian-broker/1.18.2
    kguardian.dev/profile-hash: fnv1a64:44c9939f6034479f
    kguardian.dev/profile-revision: '6'
    kguardian.dev/source-workload: payments/Deployment/checkout
  labels:
    app.kubernetes.io/component: standard-policy
    app.kubernetes.io/name: checkout
    app.kubernetes.io/part-of: kguardian
  name: checkout-kguardian
  namespace: payments
spec:
  egress:
  - ports:
    - port: 5432
      protocol: TCP
    to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: payments
      podSelector:
        matchLabels:
          app: ledger
          pod-template-hash: 7d9f8b6c5
  - ports:
    - port: 443
      protocol: TCP
    to:
    - ipBlock:
        cidr: 198.51.100.20/32
  - ports:
    - port: 443
      protocol: TCP
    to:
    - ipBlock:
        cidr: 203.0.113.10/32
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: ingress-nginx
      podSelector:
        matchLabels:
          app.kubernetes.io/name: ingress-nginx
    ports:
    - port: 8080
      protocol: TCP
  podSelector:
    matchLabels:
      app: checkout
  policyTypes:
  - Ingress
  - Egress
---
# kguardian export: seccompprofile (audit mode)
# kguardian never applies this document. Review it, commit it, and apply it yourself.
# kguardian SeccompProfile export
# workload: payments Deployment/checkout
# observed syscalls: 4 (x86_64)
# capture: medium — INCOMPLETE (1 of 1 contributing pod(s) below full)
# WARNING: partial capture (medium on 1 pod(s): checkout-7d9f8b6c5-2xkqp (medium)) — this profile will block
# WARNING: syscalls the workload makes. Raise the tier to "full" (kguardian.dev/syscall-capture
# WARNING: annotation or SYSCALL_CAPTURE_LEVEL) and re-export before enforcing.
apiVersion: kguardian.dev/v1alpha1
kind: SeccompProfile
metadata:
  name: deployment-checkout
  namespace: payments
  annotations:
    kguardian.dev/applied-by-kguardian: "false"
    kguardian.dev/capture-complete: "false"
    kguardian.dev/capture-level: medium
    kguardian.dev/capture-warning: "partial capture (medium on 1 pod(s): checkout-7d9f8b6c5-2xkqp (medium)) — this profile omits syscalls the workload makes; raise the tier to full and re-export before enforcing"
    kguardian.dev/export-mode: audit
    kguardian.dev/generated-at: "2026-09-26T03:06:02.481263599+00:00"
    kguardian.dev/generated-by: kguardian-broker/1.18.2
    kguardian.dev/profile-hash: "fnv1a64:44c9939f6034479f"
    kguardian.dev/profile-revision: "6"
    kguardian.dev/source-workload: payments/Deployment/checkout
spec:
  defaultAction: SCMP_ACT_LOG
  architectures:
    - SCMP_ARCH_X86_64
  syscalls:
    - names:
        - accept4
        - exit_group
        - read
        - write
      action: SCMP_ACT_ALLOW
  workloadRef:
    kind: Deployment
    name: checkout

# ---- securitycontext (strategic-merge patch; not part of the apply stream) ----
# kguardian export: securitycontext (audit mode)
# kguardian never applies this document. Review it, commit it, and apply it yourself.
# Strategic-merge PATCH for Deployment/checkout, not a standalone object. Apply with:
#   kubectl patch deployment checkout -n payments --type strategic --patch-file securitycontext.patch.yaml
# Then check the namespace against the target level without blocking first:
#   kubectl label namespace payments pod-security.kubernetes.io/audit=restricted
# CAVEAT: Checks kguardian cannot see (hostPath and other volume types, hostPort, probe hosts, AppArmor, SELinux, procMount, sysctls) may still fail restricted.
# CAVEAT: privileged: false removes host device and kernel access; workloads that manage the node (CNI, CSI, device plugins, eBPF agents) will break.
# CAVEAT: drop: ["ALL"] also removes CHOWN, SETUID, SETGID, DAC_OVERRIDE and NET_BIND_SERVICE. Images that start as root and drop privileges, change file ownership at startup, or bind ports below 1024 may fail; add back NET_BIND_SERVICE only if the app needs it.
# kguardian recommendation, not applied. Review before use.
# Target: Pod Security Standards restricted (kubernetes.io/docs/concepts/security/pod-security-standards)
#   spec:
#     template:
#       spec:
#         initContainers:
#         - name: migrate
#           securityContext:
#             allowPrivilegeEscalation: false
#             capabilities:
#               drop: ["ALL"]
#         containers:
#         - name: app
#           securityContext:
#             privileged: false
```

### 4.2 `format=zip-manifest`

A JSON manifest whose `documents[]` are the files a client zips:

From `GET /workloads/payments/Deployment/checkout/export?mode=enforce&format=zip-manifest&acknowledgePartial=true` -> 200 (capture `export-manifest-enforce-payments-checkout.json`, `body`):

```json
{
  "workload": {
    "clusterId": "primary",
    "kind": "Deployment",
    "name": "checkout",
    "namespace": "payments"
  },
  "mode": "enforce",
  "generatedAt": "2026-09-26T03:06:02.625396528+00:00",
  "profile": {
    "contentHash": "fnv1a64:44c9939f6034479f",
    "revision": 6
  },
  "recorded": false,
  "documents": [
    {
      "artifact": "networkpolicy",
      "fileName": "networkpolicy.yaml",
      "available": true,
      "refused": null,
      "reason": null,
      "apiVersion": "networking.k8s.io/v1",
      "kind": "NetworkPolicy",
      "mode": "enforce",
      "contentType": "application/yaml",
      "content": "# kguardian export: networkpolicy (enforce mode)\n# kguardian never applies this document. Review it, commit it, and apply it yourself.\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  annotations:\n    kguardian.dev/applied-by-kguardian: 'false'\n    kguardian.dev/export-mode: enforce\n    kguardian.dev/generated-at: 2026-09-26T03:06:02.625396528+00:00\n    kguardian.dev/generated-by: kguardian-broker/1.18.2\n    kguardian.dev/profile-hash: fnv1a64:44c9939f6034479f\n    kguardian.dev/profile-revision: '6'\n    kguardian.dev/source-workload: payments/Deployment/checkout\n  labels:\n    app.kubernetes.io/component: standard-policy\n    app.kubernetes.io/name: checkout\n    app.kubernetes.io/part-of: kguardian\n  name: checkout-kguardian\n  namespace: payments\nspec:\n  egress:\n  - ports:\n    - port: 5432\n      protocol: TCP\n    to:\n    - namespaceSelector:\n        matchLabels:\n          kubernetes.io/metadata.name: payments\n      podSelector:\n        matchLabels:\n          app: ledger\n          pod-template-hash: 7d9f8b6c5\n  - ports:\n    - port: 443\n      protocol: TCP\n    to:\n    - ipBlock:\n        cidr: 198.51.100.20/32\n  - ports:\n    - port: 443\n      protocol: TCP\n    to:\n    - ipBlock:\n        cidr: 203.0.113.10/32\n  ingress:\n  - from:\n    - namespaceSelector:\n        matchLabels:\n          kubernetes.io/metadata.name: ingress-nginx\n      podSelector:\n        matchLabels:\n          app.kubernetes.io/name: ingress-nginx\n    ports:\n    - port: 8080\n      protocol: TCP\n  podSelector:\n    matchLabels:\n      app: checkout\n  policyTypes:\n  - Ingress\n  - Egress\n",
      "applyWith": "kubectl apply -f networkpolicy.yaml"
    },
    {
      "artifact": "ciliumnetworkpolicy",
      "fileName": "ciliumnetworkpolicy.yaml",
      "available": true,
      "refused": null,
      "reason": null,
      "apiVersion": "cilium.io/v2",
      "kind": "CiliumNetworkPolicy",
      "mode": "enforce",
      "contentType": "application/yaml",
      "content": "# kguardian export: ciliumnetworkpolicy (enforce mode)\n# kguardian never applies this document. Review it, commit it, and apply it yourself.\napiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  annotations:\n    kguardian.dev/applied-by-kguardian: 'false'\n    kguardian.dev/export-mode: enforce\n    kguardian.dev/generated-at: 2026-09-26T03:06:02.625396528+00:00\n    kguardian.dev/generated-by: kguardian-broker/1.18.2\n    kguardian.dev/profile-hash: fnv1a64:44c9939f6034479f\n    kguardian.dev/profile-revision: '6'\n    kguardian.dev/source-workload: payments/Deployment/checkout\n  labels:\n    app.kubernetes.io/component: cilium-policy\n    app.kubernetes.io/name: checkout\n    app.kubernetes.io/part-of: kguardian\n  name: checkout-kguardian\n  namespace: payments\nspec:\n  description: Cilium network policy for pod checkout-7d9f8b6c5-2xkqp generated by kguardian\n  egress:\n  - toEndpoints:\n    - matchLabels:\n        k8s:app: ledger\n        k8s:pod-template-hash: 7d9f8b6c5\n    toPorts:\n    - ports:\n      - port: '5432'\n        protocol: TCP\n  - toCIDR:\n    - 198.51.100.20/32\n    toPorts:\n    - ports:\n      - port: '443'\n        protocol: TCP\n  - toCIDR:\n    - 203.0.113.10/32\n    toPorts:\n    - ports:\n      - port: '443'\n        protocol: TCP\n  endpointSelector:\n    matchLabels:\n      k8s:app: checkout\n  ingress:\n  - fromEndpoints:\n    - matchLabels:\n        k8s:app.kubernetes.io/name: ingress-nginx\n        k8s:io.kubernetes.pod.namespace: ingress-nginx\n    toPorts:\n    - ports:\n      - port: '8080'\n        protocol: TCP\nstatus: {}\n",
      "applyWith": "kubectl apply -f ciliumnetworkpolicy.yaml"
    },
    {
      "artifact": "seccompprofile",
      "fileName": "seccompprofile.yaml",
      "available": true,
      "refused": null,
      "reason": null,
      "apiVersion": "kguardian.dev/v1alpha1",
      "kind": "SeccompProfile",
      "mode": "enforce",
      "contentType": "application/yaml",
      "content": "# kguardian export: seccompprofile (enforce mode)\n# kguardian never applies this document. Review it, commit it, and apply it yourself.\n# kguardian SeccompProfile export\n# workload: payments Deployment/checkout\n# observed syscalls: 4 (x86_64)\n# capture: medium \u2014 INCOMPLETE (1 of 1 contributing pod(s) below full)\n# WARNING: partial capture (medium on 1 pod(s): checkout-7d9f8b6c5-2xkqp (medium)) \u2014 this profile will block\n# WARNING: syscalls the workload makes. Raise the tier to \"full\" (kguardian.dev/syscall-capture\n# WARNING: annotation or SYSCALL_CAPTURE_LEVEL) and re-export before enforcing.\napiVersion: kguardian.dev/v1alpha1\nkind: SeccompProfile\nmetadata:\n  name: deployment-checkout\n  namespace: payments\n  annotations:\n    kguardian.dev/applied-by-kguardian: \"false\"\n    kguardian.dev/capture-complete: \"false\"\n    kguardian.dev/capture-level: medium\n    kguardian.dev/capture-warning: \"partial capture (medium on 1 pod(s): checkout-7d9f8b6c5-2xkqp (medium)) \u2014 this profile omits syscalls the workload makes; raise the tier to full and re-export before enforcing\"\n    kguardian.dev/export-mode: enforce\n    kguardian.dev/generated-at: \"2026-09-26T03:06:02.625396528+00:00\"\n    kguardian.dev/generated-by: kguardian-broker/1.18.2\n    kguardian.dev/profile-hash: \"fnv1a64:44c9939f6034479f\"\n    kguardian.dev/profile-revision: \"6\"\n    kguardian.dev/source-workload: payments/Deployment/checkout\nspec:\n  defaultAction: SCMP_ACT_ERRNO\n  architectures:\n    - SCMP_ARCH_X86_64\n  syscalls:\n    - names:\n        - accept4\n        - exit_group\n        - read\n        - write\n      action: SCMP_ACT_ALLOW\n  workloadRef:\n    kind: Deployment\n    name: checkout\n",
      "applyWith": "kubectl apply -f seccompprofile.yaml"
    },
    "(4 more in the capture)"
  ]
}
```

- `documents[]`: `{artifact, fileName, available, refused, reason, apiVersion, kind, mode, contentType,
  content, applyWith, image}`, in bundle order: one per requested artifact, except `sbom`, which has one per
  container image (v1.5). `available: false` means `content` is `null` and `reason` says why. `refused` is
  only set on a 409. `fileName` is `securitycontext.patch.yaml` for the patch, `vex.openvex.json`,
  `sbom-<container>-<digest12>.cdx.json`, otherwise `<artifact>.yaml`. `contentType` is
  `application/yaml`, `application/json` (vex) or `application/vnd.cyclonedx+json` (sbom).
- `image` (v1.5; `null` except on `sbom` documents): `{containers, digest, imageRef, source, sbomTrust,
  scannedAt, components}`. `source` / `sbomTrust` / `scannedAt` / `components` are `null` when no source
  has an SBOM for the digest.

## 5. Storage (for reviewers; not an API)

- `workload_profile_versions(id bigserial PK, cluster_id, pod_namespace, workload_kind, workload_name,
  revision int, content_hash, dimension_hashes jsonb, snapshot jsonb, posture jsonb, created_at)`,
  unique `(cluster_id, pod_namespace, workload_kind, workload_name, revision)`.
- `workload_profile_latest(cluster_id, pod_namespace, workload_kind, workload_name PK, revision,
  content_hash, posture_status, summary jsonb, computed_at, last_changed_at)`, backing `GET /workloads`.
- `workload_profile_exports(id, cluster_id, pod_namespace, workload_kind, workload_name, revision, content_hash,
  mode, artifacts text[], baseline jsonb, exported_at)` (section 4).
- Migrations `2026-09-27-100000_workload_profiles`, `2026-09-27-300000_workload_profile_exports`.

## CHANGELOG

- 2026-09-26: v1 published.
- 2026-09-26 (v1.1, implementation landed; additive or clarifying):
  - `dimensions.podSecurity.pod.failing[]` added (pod-level failing checks).
  - `posture.unknownDimensions` also listed unscored dimensions (superseded by v1.2).
  - `syscalls.coverage.fraction` is `null`; `observed.architectures` are `SCMP_ARCH_*` tokens;
    `capture.level` may be `"unknown"`.
  - `images.configDigestOnly/<c>` finding not emitted; `compute.containers[].oomKills` is per interval.
  - List `images.runningDigests` / `mixedDigests` `null` without inventory; `snapshotPending` is `true`
    when `version` is `null`; versions `changedDimensions` `null` when the predecessor was trimmed; diff
    `from` is `null` for revision 1.
- 2026-09-26 (**v1.2**, from review of #1669 and #1672; **breaking** for score fields and some statuses):
  - **Numeric scores removed** everywhere: `posture.score`, `posture.grade`, `posture.weights`,
    `posture.deductions`, `dimensions.*.score`, `dimensions.*.scored`, the list's `posture.score` /
    `grade` / `dimensions.*.score`, and `score` / `grade` in version entries. There is no internal score.
  - **Added `posture.reasons[]`** `{dimension, status, message}` (one per core dimension that is not ok).
  - **Rollup** (2.2): `coverage` = known core dimensions / 4 (was the scored weight fraction);
    `unknownDimensions` = core dimensions with status `unknown` only; `compute` left out of the rollup.
  - **Status rules** (2.2): status comes from findings (critical/high -> risk, medium -> warn) plus
    floors. A privileged container, or hostNetwork alone, is now **risk** (was warn via score 50 / 70).
    `network.wouldDeny` is medium (warn).
  - **podSecurity never `ok` on an upper bound**: level `restricted` (always an upper bound in v1) gives
    status `unknown` unless a finding makes it warn/risk; reason `pss_unverified` replaces
    `pss_upper_bound`. Reason codes `pss_fails_baseline` / `pss_fails_restricted` name the containers (with
    kind) or `pod spec` that set the level.
  - **`readiness.podSecurityRestricted.ok` is `null`** (not `true`) when the level is restricted, since
    restricted is only an upper bound.
  - **Level** was already the minimum over all containers (init and ephemeral included). The v1/v1.1
    example in 2.3 was internally inconsistent (`level: restricted` next to a `baseline` init container);
    every example is now copied from real broker output and the raw captures are in
    `team/profile-captures/`.
  - **Stale containers** (renamed or removed from the spec) no longer count: new
    `dimensions.podSecurity.staleContainers[]` `{name, kind, digest, lastSeen}`, new
    `dimensions.images.containers[].stale`, reason `stale_containers_excluded`; they are excluded from the
    level, findings, patch and snapshot. `containers[].source` `last_known` now means "current, not
    running" (e.g. a completed init container).
  - **Missing pod-level block**: new `pod.known`; when `false`, `hostNamespaces` (and inherited
    `runAsNonRoot` / `seccompRestricted`) are unevaluated, not passed; reason `pod_fields_unknown`.
  - **Recommendation**: `null` when nothing failing is patchable (e.g. only an ephemeral container fails;
    reason `ephemeral_unpatchable`); never an empty template. New caveats for node agents / DaemonSets /
    hostNetwork, `privileged: false`, host namespaces `false`, and `drop: ["ALL"]`.
  - **Versions/network snapshot**: the network part is the distinct rule set over all retained flows
    (bounded by 2 000 distinct rules), with no truncation flag and no audit state; `network.audited` is
    removed from the snapshot and from the diff. The hash no longer changes with flow volume, dead pods or
    the 24 h audit window.
  - **Diff**: new `fromTrimmed`. A default diff whose predecessor was trimmed falls back to the newest
    retained revision below `to` (or `from: null`) instead of returning 404.
  - **List**: new `search` query parameter (case-insensitive substring of the workload name).
  - **Concurrency**: a writer that loses a race at a revision writes nothing; the latest pointer never
    moves backwards.
- 2026-09-26 (**v1.3**, coordinator decision "unknown is never safe"; status values only, no shape change):
  - **images status** is `unknown` while there is no vulnerability data for the running digests (was `ok`
    or a findings-derived `warn`). Reason `vulnerabilities_not_configured` now reads "N running digest(s)
    across M container(s); vulnerability data not configured"; `coverage.level` is `"partial"`. Inventory
    findings (`images.crashLoop`, `images.pullBackOff`, `images.mixedDigests`) are still emitted and still
    appear in `findings` / `attention`; they no longer set the images status.
  - **posture.status** can be `ok` only when all four core dimensions are known and ok. With any unknown
    core dimension it is the worst known status if that is `warn` / `risk`, otherwise `unknown`.
    `unknownDimensions` is always present. Consequence today: no workload is posture `ok` (images is always
    unknown), and a workload whose known dimensions are all ok reads `unknown`, not `ok`.
  - `posture.reasons[]` for an `unknown` dimension now uses that dimension's own reason (so images says
    "vulnerability data not configured" rather than naming an inventory finding).
  - The `GET /workloads?status=` filter follows the new values.
  - Examples in this document are regenerated from v1.3 captures (the v1.2 section 2.3 example listed
    node-exporter failing only `privilegeEscalation`; the real response also fails `seccompRestricted`
    and `capabilitiesRestricted`). Captures renamed: `profile-ok-flux-system-source-controller` ->
    `profile-unknown-partial-flux-system-source-controller`, `profile-warn-payments-checkout` ->
    `profile-warn-payments-checkout-after-fix`; new `profile-warn-payments-refunds-init-fails-restricted`.
- 2026-09-27 (**v1.4**, P2-4 export + P2-5 drift; additive only, no existing field or status changes):
  - New `GET /workloads/{ns}/{kind}/{name}/export` (section 4, READ, side-effect free): `artifacts`,
    `mode=audit|enforce`, `format=yaml|zip-manifest`, `acknowledgePartial`; 409 `export_refused` for
    enforce-mode artifacts built from partial evidence.
  - New `POST` on the same path (admin scope): the same bundle, also recorded as the drift baseline.
    Recording is not reachable with a read token.
  - New top-level `drift` in the profile (section 2.8) with `baselines`, `evaluated` and `items`; drift
    findings (dimension `"drift"`: `drift.tagMoved/<c>`, `drift.imageChangedSinceExport/<c>`,
    `drift.securityContextRegression/<c|pod>`) join `findings` / `attention`. Drift never sets posture.
  - List items gain `drift: {count, byType}`.
  - `/metrics` gains `kguardian_workload_drift{workload_namespace, workload_kind, workload, type}`.
- 2026-09-26 (**v1.5**, export bundle `sbom` and `vex` artifacts; additive fields, one semantic change):
  - `vex` is the OpenVEX 0.2.0 draft (`vex.openvex.json`, `application/json`), commented out of the YAML
    apply stream; unavailable with the reason when no statement qualifies.
  - `sbom` is the stored SBOM of each container image as CycloneDX (`application/vnd.cyclonedx+json`):
    **one document per digest**, so `artifact: "sbom"` can appear more than once in `documents[]` (the
    semantic change). Carried as comments in `format=yaml` (under a header naming image, source and trust),
    as files by `format=zip-manifest`.
    At most 10 000 components per bundle.
  - New `documents[].image` (`null` except on `sbom`): which image, source and SBOM trust.
- 2026-09-29 (**v1.6**, P2-7 capabilities; additive):
  - New top-level `capabilities` in the profile (section 2.9): observed capability use per container,
    evidence (`kg_capability_coverage`) and an evidence-based recommendation.
  - The podSecurity recommendation (and the export's `securitycontext` artifact) uses that evidence for
    `capabilities`: `drop: ["ALL"]` + `add` = the observed set; emitted also when PSS passes but the
    current set is wider than the observed one. New caveats name evidence-based and default containers.
  - New `GET /workloads/{ns}/{kind}/{name}/capabilities` (READ): the same `capabilities` block.
- 2026-09-26 (**v1.7**, P2-5 runtime drift; additive, on top of v1.6):
  - New drift type `unshippedExecutable` (section 2.8): files a current container ran that its image did
    not ship (writable layer, memfd, deleted), from the runtime inventory (#1683). Finding id
    `drift.unshippedExecutable/<container>`, dimension `drift`; like every drift finding it never sets
    posture.
  - New `drift.notEvaluated[]` `{type, container, reason}`: why a check could not run for a container.
    No runtime inventory or no capture coverage is "not evaluated", never "no drift".
  - `/metrics` `kguardian_workload_drift` gains the `type="unshippedExecutable"` series.
