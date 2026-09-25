# kguardian-supplychain

Supply-chain data for the workloads kguardian already profiles: which
vulnerabilities and packages are in the images they run. Part of
[#1533](https://github.com/kguardian-dev/kguardian/issues/1533).

It is off by default (`supplychain.enabled: false` in the Helm chart) and
only reports. It never blocks, admits, or changes a workload.

## What it does today

The `serve` mode reads [Trivy Operator](https://github.com/aquasecurity/trivy-operator)
`VulnerabilityReport` and `SbomReport` resources, normalises them into one
payload per image digest, and hands each payload to a broker client.

- **Read-only.** The ClusterRole grants `get`, `list` and `watch` on
  `aquasecurity.github.io` `vulnerabilityreports` and `sbomreports` and
  nothing else. It has no access to Secrets, so it never holds registry
  credentials.
- **Keyed by digest.** Trivy Operator writes one report per workload
  container. A Deployment with ten replicas, or ten Deployments on one image,
  produce one payload.
- **Quiet on resync.** A payload is sent only when its content changes. An
  older scan of a digest never overwrites a newer one.
- **No tag guessing.** A report that names its image only by tag gets its
  digest from the SbomReport for the *same workload container* (its
  `RepoDigest` property). If none exists the report is held back and counted
  in `kguardian_supplychain_unresolved_reports`. It is not sent under a mutable
  tag. A resolver that asks the broker's image inventory for the running
  digest is planned for when that endpoint exists.
- **Optional source.** If the Trivy Operator CRDs are not installed the
  source idles, `/readyz` still passes, and
  `kguardian_supplychain_source_available{source="trivy-operator"}` is 0.
  Discovery is re-checked every `TRIVY_RECHECK_PERIOD`. The component makes
  no outbound requests except to the Kubernetes API (and, once enabled, the
  broker).
- **Trivy's format, not Trivy's code.** The report types are a small local
  mirror of trivy-operator's `v1alpha1` API. Nothing from the Trivy module
  tree is linked in.

### Broker hand-off

Broker ingest is **off** until the broker's supply-chain routes land (#1533
P1-3). Until then the default `LoggingClient` logs one line per payload
(digest, ref, counts by severity) and sends nothing.

With `BROKER_INGEST_ENABLED=true` the `HTTPClient` POSTs each payload as JSON
to the broker with `Authorization: Bearer $BROKER_AUTH_TOKEN`. That token is
the broker's scoped key for the `supplychain` scope. The route paths
(`POST /images/{digest}/vulnerabilities`, `POST /images/{digest}/sbom`) are
provisional; P1-3 owns the final shape.

Sends go through a coalescing queue keyed by (kind, digest). Informer
handlers never block on the network, a burst of updates to one digest
sends only the latest, and a failed send retries with backoff (5 s doubling
to 5 min) unless a newer payload has replaced it.

## Commands

| Command | Purpose |
|---|---|
| `serve` | The central Deployment: sources, and later the Grype matcher and attestation verifier. |
| `node-sbom` | The optional per-node SBOM sidecar. **Not implemented**: it exits 1 with a message. |
| `version` | Print the build version. |

## Configuration (`serve`)

| Variable | Default | Meaning |
|---|---|---|
| `LISTEN_ADDR` | `:8083` | HTTP listen address for `/healthz`, `/readyz` and `/metrics`. |
| `LOG_LEVEL` | `info` | logrus level. |
| `TRIVY_OPERATOR_ENABLED` | `true` | Enable the Trivy Operator source. The chart sets this from `supplychain.sources.trivyOperator.enabled`. |
| `TRIVY_RESYNC_PERIOD` | `10m` | Informer resync. It also retries digest resolution for held-back reports. |
| `TRIVY_RECHECK_PERIOD` | `5m` | How often to re-check whether the CRDs have been installed. |
| `BROKER_INGEST_ENABLED` | `false` | Send payloads to the broker instead of logging them. |
| `BROKER_URL` | `http://kguardian-broker:9090` | Broker base URL. |
| `BROKER_AUTH_TOKEN` | *(unset)* | Scoped broker token, sent as a bearer token. |

## HTTP endpoints

| Path | |
|---|---|
| `GET /healthz` | 200 while the process serves. |
| `GET /readyz` | 200 once every enabled source has synced its caches or found its API absent. |
| `GET /metrics` | Prometheus text format. |

There is no data endpoint. Findings go to the broker, which owns storage,
auth and the read APIs.

## Metrics

| Metric | Labels | |
|---|---|---|
| `kguardian_supplychain_source_available` | `source` | 1 when the source's API is served. |
| `kguardian_supplychain_report_events_total` | `source`, `kind`, `event` | Informer events: `add`, `update`, `delete`, `decode_error`. |
| `kguardian_supplychain_tracked_digests` | `source`, `kind` | Distinct digests held. |
| `kguardian_supplychain_unresolved_reports` | `source`, `kind` | Reports held back for lack of a digest. |
| `kguardian_supplychain_emissions_total` | `kind`, `result` | Payloads handed to the broker client (`ok` / `error`). |
| `kguardian_supplychain_pending_emissions` | | Coalescing queue depth. |

Plus the standard Go runtime and process collectors.

## Payload schema (v1)

JSON, snake_case, `schema_version: 1`. Each payload **replaces** what the
broker holds for `(image.digest, source)`. Go definitions are in
[`pkg/types/types.go`](pkg/types/types.go).

### `ImageVulnerabilities`

```json
{
  "schema_version": 1,
  "image": {
    "digest": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "ref": "ghcr.io/example/api:2.4.1",
    "registry": "ghcr.io",
    "repository": "example/api",
    "tag": "2.4.1"
  },
  "source": "trivy-operator",
  "scanner": { "name": "Trivy", "vendor": "Aqua Security", "version": "0.58.1" },
  "scanned_at": "2026-09-20T08:00:00Z",
  "os": { "family": "alpine", "name": "3.20.3" },
  "observed_in": [
    { "namespace": "shop", "kind": "ReplicaSet", "name": "api-7c9d8f6b5", "container": "api" }
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2099-1002",
      "package": { "name": "express", "version": "4.18.2", "type": "node-pkg", "purl": "pkg:npm/express@4.18.2" },
      "fixed_version": "4.19.2",
      "severity": "MEDIUM",
      "score": 6.1,
      "cvss": { "nvd": { "v3_score": 6.1, "v3_vector": "CVSS:3.1/..." } },
      "title": "...",
      "primary_url": "https://avd.aquasec.com/nvd/cve-2099-1002",
      "target": "Node.js",
      "class": "lang-pkgs",
      "published_at": "2099-01-02T03:04:05Z",
      "last_modified_at": "2099-01-03T03:04:05Z",
      "file_paths": ["app/node_modules/express/package.json"]
    }
  ]
}
```

| Field | Notes |
|---|---|
| `image.digest` | `sha256:<64 hex>`. Always set: payloads are never keyed by tag. This is the digest the scanner reported, which can be a multi-arch index digest rather than the platform manifest. The broker should match it against both. |
| `scanned_at` | When the source produced the report (`report.updateTimestamp`). |
| `db_updated_at` | Build time of the vulnerability DB used. **Omitted for Trivy Operator**, which does not record it. The Grype matcher will set it. |
| `observed_in` | The report(s) this payload was built from at send time. Provenance only. The authoritative workload-to-image mapping is the broker's inventory. |
| `vulnerabilities[].severity` | One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE`, `UNKNOWN`. Anything else is mapped to `UNKNOWN`. |
| `vulnerabilities[].score` | The scanner's headline score. `cvss` holds the per-vendor detail (`v2_*`, `v3_*`, `v40_*`). |
| `vulnerabilities[].fixed_version` | Omitted when no fix is published. |
| `vulnerabilities[].file_paths` | In-image paths owned by the package: the report's `packagePath` plus any `aquasecurity:trivy:FilePath` the SBOM gives for the same PURL. This is the join key for runtime "loaded" data. Expect it to be empty for OS packages: Trivy's SbomReport (upstream sample included) gives dpkg/apk packages no file paths. |
| `primary_url`, `title` | Untrusted third-party text. Render it, never fetch or execute it. |

Verbatim duplicate findings in one report are collapsed. Vulnerabilities are
sorted by id, package, version and target, so equal content always
serialises the same way.

### `ImageSBOM`

```json
{
  "schema_version": 1,
  "image": { "digest": "sha256:53a1...", "ref": "k8s.gcr.io/kube-apiserver:v1.21.1", "...": "..." },
  "source": "trivy-operator",
  "scanner": { "name": "Trivy", "vendor": "Aqua Security", "version": "0.74.0" },
  "scanned_at": "2023-07-10T09:37:21Z",
  "format": "CycloneDX",
  "spec_version": "1.4",
  "observed_in": [ { "namespace": "kube-system", "kind": "Pod", "name": "kube-apiserver-kind-control-plane", "container": "kube-apiserver" } ],
  "components": [
    {
      "name": "base-files",
      "version": "10.3+deb10u9",
      "purl": "pkg:deb/debian/base-files@10.3+deb10u9?arch=amd64&distro=debian-10.9",
      "type": "debian",
      "src_name": "base-files",
      "src_version": "10.3+deb10u9",
      "licenses": ["GPL-3.0"],
      "layer_digest": "sha256:5dea5ec2..."
    },
    { "name": "debian", "version": "10.9", "type": "operating-system", "class": "os-pkgs" }
  ]
}
```

Components are the CycloneDX `components` with Trivy's `aquasecurity:trivy:*`
properties lifted into fields. The dependency graph is not carried in v1.

## Development

```sh
go vet ./...
golangci-lint run ./...
go test -race ./...
```

Test fixtures are in [`pkg/trivy/testdata`](pkg/trivy/testdata). Each one
says where it came from. The `*-docs*` files are the samples from
trivy-operator v0.34.0 `docs/docs/crds/`. The others are derived from the
v0.34.0 Go API types and use synthetic `CVE-2099-*` ids.
