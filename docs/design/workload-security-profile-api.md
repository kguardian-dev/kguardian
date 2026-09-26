# Workload Security Profile — broker API contract

Part of #1533. Implemented in `broker/src/workload_profile.rs` (read model, posture, versions, diff) and
`broker/src/pod_security.rs` (Pod Security Standards analyser), PR #1669. Consumers: the frontend profile
page (#1672), llm-bridge tools and the advisor `profile` commands (#1668).

Status: **v1.2, stable**. Every change is appended to the CHANGELOG at the bottom, dated.

**Examples:** the snippets below are trimmed from raw responses of a v1.2
broker build against a seeded database.

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

```json
{
  "items": [
    {
      "clusterId": "primary",
      "namespace": "flux-system",
      "kind": "Deployment",
      "name": "source-controller",
      "revision": 1,
      "contentHash": "fnv1a64:…",
      "computedAt": "2026-09-26T02:05:41.1Z",
      "lastChangedAt": "2026-09-26T02:04:41.1Z",
      "posture": { "status": "ok", "coverage": 0.75, "unknownDimensions": ["podSecurity"] },
      "dimensions": {
        "network":     { "status": "ok" },
        "syscalls":    { "status": "ok" },
        "podSecurity": { "status": "unknown", "level": "restricted", "levelConfidence": "upper_bound" },
        "images":      { "status": "ok", "runningDigests": 1, "mixedDigests": false },
        "compute":     { "status": "ok" }
      },
      "findingCounts": { "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0 }
    }
  ],
  "nextAfter": "observability/DaemonSet/node-exporter"
}
```

- `revision` / `contentHash`: the latest stored version (section 3).
- `posture`: see 2.2. `dimensions.images.runningDigests` / `mixedDigests` are `null` when there is no
  inventory. `podSecurity.level` / `levelConfidence` are `null` when no current container is known.

## 2. `GET /workloads/{namespace}/{kind}/{name}/profile` — full profile, computed live

404 `workload_not_found` when the broker has none of: inventory rows, a syscall aggregate, pods in
`pod_details`, a stored profile. Captures: `profile-ok-flux-system-source-controller`,
`profile-warn-payments-checkout`, `profile-warn-payments-ledger-mixed-crashloop-stale`,
`profile-risk-observability-node-exporter-hostpid-wouldDeny`,
`profile-unknown-observability-otel-collector-fresh`.

Top level (from `profile-warn-payments-ledger-mixed-crashloop-stale`, trimmed):

```json
{
  "workload": { "clusterId": "primary", "namespace": "payments", "kind": "Deployment", "name": "ledger",
                "transient": false, "pods": { "live": 1, "names": ["ledger-5b7c9d8f6-q8wzn"], "truncated": false } },
  "generatedAt": "2026-09-26T02:08:10Z",
  "contentHash": "fnv1a64:…",
  "version": { "revision": 1, "contentHash": "fnv1a64:…", "createdAt": "2026-09-26T02:04:41Z" },
  "snapshotPending": false,
  "posture": {
    "status": "warn",
    "coverage": 0.5,
    "unknownDimensions": ["network", "podSecurity"],
    "reasons": [
      { "dimension": "network", "status": "unknown", "message": "No audit policy covers this workload; applied NetworkPolicies are not visible to the broker" },
      { "dimension": "syscalls", "status": "warn", "message": "SeccompProfile ledger is in audit mode" },
      { "dimension": "podSecurity", "status": "unknown", "message": "Every evaluated check passes restricted, but 9 checks cannot be seen (e.g. hostPath), so restricted is not confirmed" },
      { "dimension": "images", "status": "warn", "message": "Container ledger is in CrashLoopBackOff" }
    ]
  },
  "attention": [ { "id": "images.crashLoop/ledger", "dimension": "images", "severity": "medium", "tier": "P2",
                   "title": "Container ledger is in CrashLoopBackOff", "detail": "The running digest keeps exiting.", "container": "ledger" } ],
  "findings": [ "… every finding, same shape; attention = the first 5 of severity medium or worse" ],
  "controls": [
    { "control": "networkPolicy",  "state": "unknown", "detail": "…", "inSync": null },
    { "control": "seccompProfile", "state": "audit",   "detail": "SeccompProfile ledger (SCMP_ACT_LOG), 4 syscalls, distribution …", "inSync": true },
    { "control": "imageAdmission", "state": null,      "detail": "Signature/admission checks are not configured", "inSync": null }
  ],
  "readiness": [
    { "id": "trafficObserved24h",     "ok": true, "message": "Traffic observed for 5d 0h" },
    { "id": "syscallCaptureComplete", "ok": true, "message": "Every contributing pod captured at level full (startup included)" },
    { "id": "noWouldDeny24h",         "ok": null, "message": "No audit policy covers this workload" },
    { "id": "imageSigned",            "ok": null, "message": "Signature verification is not configured" },
    { "id": "podSecurityRestricted",  "ok": null, "message": "Every evaluated check passes restricted; 9 checks cannot be seen, so restricted is not confirmed" }
  ],
  "exposure": { "ingressPeers": 1, "ingressExternal": 0, "egressPeers": 0, "egressExternal": 0 },
  "dimensions": { "network": {}, "syscalls": {}, "podSecurity": {}, "images": {}, "compute": {} }
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
- `posture.status` = worst **known** core status (`risk` > `warn` > `ok`); `unknown` only when every core
  dimension is unknown. An unknown dimension never counts as ok or as risk.
- `posture.coverage` = known core dimensions / 4, 2 decimals. `posture.unknownDimensions` = core
  dimensions whose status is `unknown`.
- `posture.reasons[]`: one `{dimension, status, message}` per core dimension that is not `ok`, in the order
  network, syscalls, podSecurity, images. podSecurity uses its level reason (naming the containers that
  set the level); the others use their most severe finding of severity medium or worse, else their first
  reason.
- Dimension status from findings: any critical/high finding -> `risk`; else any medium -> `warn`; else
  `ok`; no data -> `unknown`. Then:
  - **podSecurity**: level `privileged` -> `risk`; level `baseline` -> at least `warn`; level `restricted`
    (only ever an upper bound in v1) -> **never `ok`**: `unknown` unless a finding makes it warn/risk.
  - **syscalls**: `capture.complete: false` -> at least `warn`.
  - **network**: `unknown` unless an audit policy covers the workload's pods in the last 24 h.

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

Trimmed from `profile-risk-observability-node-exporter-hostpid-wouldDeny`:

```json
{
  "status": "risk",
  "coverage": { "level": "partial", "fraction": 0.5, "observedSince": "…", "note": "9 of 18 PSS checks evaluated; …" },
  "reasons": [ { "code": "pss_fails_baseline", "message": "Privileged under PSS: pod spec fail(s) a baseline check" } ],
  "pssVersion": "kubernetes/website@2c1aa11c (Kubernetes v1.37 docs)",
  "level": "privileged",
  "levelConfidence": "confirmed",
  "unevaluatedChecks": ["hostProcess","hostPathVolumes","hostPorts","hostProbesLifecycle","appArmor","seLinux","procMount","sysctls","volumeTypes"],
  "pod": {
    "known": true,
    "serviceAccountName": "node-exporter", "automountServiceAccountToken": false,
    "hostNetwork": true, "hostPID": true, "hostIPC": null, "hostUsers": null,
    "securityContext": { "runAsNonRoot": null, "runAsUser": null, "runAsGroup": null, "fsGroup": null, "seccompProfileType": null },
    "failing": [
      { "check": "hostNamespaces", "level": "baseline", "field": "spec.hostNetwork", "value": true, "message": "hostNetwork must be unset or false" },
      { "check": "hostNamespaces", "level": "baseline", "field": "spec.hostPID", "value": true, "message": "hostPID must be unset or false" }
    ]
  },
  "containers": [
    { "name": "node-exporter", "kind": "regular", "source": "running", "digest": "sha256:7d4e…",
      "securityContext": { "privileged": null, "allowPrivilegeEscalation": null, "runAsNonRoot": true, "runAsUser": 65534,
                           "runAsGroup": null, "readOnlyRootFilesystem": true, "capabilitiesAdd": null,
                           "capabilitiesDrop": null, "seccompProfileType": null },
      "level": "baseline",
      "failing": [ { "check": "privilegeEscalation", "level": "restricted", "field": "spec.containers[node-exporter].securityContext.allowPrivilegeEscalation", "value": null, "message": "allowPrivilegeEscalation must be set to false" } ] }
  ],
  "staleContainers": [],
  "recommendation": {
    "recommendation": true,
    "targetLevel": "restricted",
    "format": "strategic-merge-patch",
    "yaml": "# kguardian recommendation, not applied. Review before use.\n# Target: …\nspec:\n  template:\n    spec:\n      hostNetwork: false\n      hostPID: false\n      …",
    "caveats": [ "Checks kguardian cannot see …", "This looks like a node agent (DaemonSet or hostNetwork). …", "Turning off hostNetwork/hostPID/hostIPC breaks …", "drop: [\"ALL\"] also removes CHOWN, SETUID, …" ]
  }
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

Trimmed from `profile-risk-observability-node-exporter-hostpid-wouldDeny`:

```json
{
  "status": "warn",
  "coverage": { "level": "full", "fraction": null, "observedSince": "…", "note": "Flows from the workload's pod(s) (1 live)" },
  "reasons": [],
  "summary": {
    "egress":  { "peers": 1, "external": 1, "ports": ["TCP/443"] },
    "ingress": { "peers": 1, "external": 0, "ports": ["TCP/9100"] }
  },
  "peers": [
    { "direction": "ingress", "protocol": "TCP", "port": 9100,
      "peer": { "kind": "pod", "namespace": "observability", "workloadKind": "StatefulSet", "workloadName": "prometheus", "name": "prometheus-0", "ip": "10.42.2.5" },
      "flows": 1, "firstSeen": "…", "lastSeen": "…" },
    { "direction": "egress", "protocol": "TCP", "port": 443,
      "peer": { "kind": "external", "namespace": null, "workloadKind": null, "workloadName": null, "name": null, "ip": "198.51.100.7" },
      "flows": 1, "firstSeen": "…", "lastSeen": "…" }
  ],
  "truncated": false,
  "policy": {
    "audit": { "policies": [ { "namespace": "observability", "name": "node-exporter" } ], "allow": 1, "wouldDeny": 1, "lastVerdictAt": "…", "windowHours": 24 },
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

Trimmed from `profile-ok-flux-system-source-controller`:

```json
{
  "status": "ok",
  "coverage": { "level": "full", "fraction": null, "observedSince": null, "note": "capture level full" },
  "reasons": [],
  "observed": { "syscallCount": 5, "hash": "5c1f0e2d3a4b5c6d", "architectures": ["SCMP_ARCH_X86_64"], "updatedAt": "…" },
  "capture": { "level": "full", "complete": true, "incompletePods": 0 },
  "cr": { "name": "source-controller", "defaultAction": "SCMP_ACT_ERRNO", "mode": "enforce", "syscallCount": 5,
          "inSync": true, "missing": [], "extra": [], "distribution": { "ready": 0, "total": 1, "state": "Pending" } },
  "denials": { "total": 0, "syscalls": [], "lastSeen": null }
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

Trimmed from `profile-warn-payments-ledger-mixed-crashloop-stale`:

```json
{
  "status": "warn",
  "coverage": { "level": "full", "fraction": null, "observedSince": "…", "note": "running window 900 s" },
  "reasons": [ { "code": "vulnerabilities_not_configured", "message": "No vulnerability source is configured; images are inventoried but not assessed for vulnerabilities" } ],
  "runningWindowSeconds": 900,
  "containers": [
    { "name": "ledger", "kind": "regular", "mixedDigests": true, "stale": false,
      "running": [
        { "digest": "sha256:4a1b…", "imageRef": "ghcr.io/example/ledger:2.3.0", "state": "running", "stateReason": null, "ranAsInit": false, "lastPodName": "ledger-5b7c9d8f6-q8wzn", "firstSeen": "…", "lastSeen": "…" },
        { "digest": "sha256:5b2c…", "imageRef": "ghcr.io/example/ledger:2.3.1", "state": "waiting", "stateReason": "CrashLoopBackOff", "ranAsInit": false, "lastPodName": "ledger-5b7c9d8f6-q8wzn", "firstSeen": "…", "lastSeen": "…" }
      ],
      "previous": [] },
    { "name": "legacy-proxy", "kind": "regular", "mixedDigests": false, "stale": true, "running": [], "previous": [ { "digest": "sha256:6c3d…", "…": "…" } ] }
  ],
  "truncated": false,
  "vulnerabilities": null,
  "supplyChain": null
}
```

- `stale: true`: not in the current spec (see 2.3); listed, never a finding.
- `vulnerabilities` / `supplyChain`: always `null` = **not configured**.
- No inventory -> `unknown`, reason `no_inventory`.
- Findings: `images.mixedDigests/<c>` low, `images.crashLoop/<c>` medium, `images.pullBackOff/<c>` medium.

### 2.7 `compute` (informational, not in the rollup)

`{ status, coverage, reasons, containers: [ { pod, container, cpuRequestMillis, cpuLimitMillis,
memRequestBytes, memLimitBytes, cpuUsageMillis, memWorkingSetBytes, oomKills, throttledRatio, updatedAt } ],
truncated }` from `pod_compute_latest` for the live pods (max 50). `oomKills` = in the latest sample
interval. No rows -> `unknown`, reason `no_compute_data`. Findings: `compute.missingMemoryLimit/<c>` low,
`compute.oomKilled/<c>` medium.

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

```json
{
  "namespace": "payments", "kind": "Deployment", "name": "checkout",
  "items": [
    { "revision": 4, "contentHash": "fnv1a64:…", "createdAt": "…", "dimensionHashes": { "images": "…", "network": "…", "podSecurity": "…", "syscalls": "…" },
      "changedDimensions": ["podSecurity"], "posture": { "status": "warn", "coverage": 0.75 } },
    { "revision": 3, "…": "…", "changedDimensions": ["network"] },
    { "revision": 2, "…": "…", "changedDimensions": null }
  ],
  "nextBefore": null
}
```

- `changedDimensions`: dimensions whose hash differs from the previous revision; all four for revision 1;
  `null` when the previous revision was trimmed (unknown, not guessed).
- `posture`: `{status, coverage}` at that revision (rows stored before v1.2 may also carry
  `score` / `grade`; ignore them).

### 3.2 `GET /workloads/{namespace}/{kind}/{name}/profile/versions/{revision}`

`{ namespace, kind, name, revision, contentHash, createdAt, dimensionHashes, posture, snapshot }` with the
snapshot shape of section 3. 404 `revision_not_found`. Capture: `version-payments-checkout-rev2`.

### 3.3 `GET /workloads/{namespace}/{kind}/{name}/profile/diff?from=&to=`

`to`: revision, default latest. `from`: revision, default = the previous one. `from >= to` -> 400. An
explicit missing `from`/`to` -> 404 `revision_not_found`; no versions -> 404 `workload_not_found`.
**Trimmed predecessor:** with `from` omitted, when `to - 1` was trimmed the diff uses the newest retained
revision below `to`, or `from: null` (everything shows as added) when none is left, and sets
`fromTrimmed: true`. Captures: `diff-payments-checkout-default`, `diff-payments-checkout-2-to-4`,
`diff-payments-checkout-trimmed-predecessor`, `error-404-revision-not-found`, `error-400-bad-order`.

```json
{
  "namespace": "payments", "kind": "Deployment", "name": "checkout",
  "from": { "revision": 2, "contentHash": "fnv1a64:…", "createdAt": "…" },
  "to":   { "revision": 4, "contentHash": "fnv1a64:…", "createdAt": "…" },
  "changed": true,
  "fromTrimmed": false,
  "dimensions": {
    "podSecurity": { "changed": true, "level": { "from": "baseline", "to": "restricted" }, "pod": [],
                     "containersAdded": [], "containersRemoved": [],
                     "containers": [ { "name": "migrate", "fields": [
                       { "field": "securityContext.allowPrivilegeEscalation", "from": null, "to": false },
                       { "field": "securityContext.capabilitiesDrop", "from": null, "to": ["ALL"] } ] } ] },
    "images":   { "changed": false, "containersAdded": [], "containersRemoved": [], "containers": [] },
    "syscalls": { "changed": false, "added": [], "removed": [], "captureLevel": null, "cr": null },
    "network":  { "changed": true, "added": [ { "direction": "egress", "peer": "external:198.51.100.20", "port": 443, "protocol": "TCP" } ], "removed": [] }
  }
}
```

- A changed scalar is `{ "from": x, "to": y }`; an unchanged scalar is `null`.
- `syscalls.cr` when changed: `{ "from": {name, defaultAction, hash} | null, "to": … }`.

## 4. Storage (for reviewers; not an API)

- `workload_profile_versions(id bigserial PK, cluster_id, pod_namespace, workload_kind, workload_name,
  revision int, content_hash, dimension_hashes jsonb, snapshot jsonb, posture jsonb, created_at)`,
  unique `(cluster_id, pod_namespace, workload_kind, workload_name, revision)`.
- `workload_profile_latest(cluster_id, pod_namespace, workload_kind, workload_name PK, revision,
  content_hash, posture_status, summary jsonb, computed_at, last_changed_at)`, backing `GET /workloads`.
- Migration `2026-09-27-100000_workload_profiles`.

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
