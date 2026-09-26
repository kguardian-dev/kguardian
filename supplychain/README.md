# kguardian-supplychain

Supply-chain data for the workloads kguardian already profiles: which
vulnerabilities and packages are in the images they run, and who signed
them. Part of
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
- **Trivy's format, not Trivy's code.** The report types are a small local
  mirror of trivy-operator's `v1alpha1` API. Nothing from the Trivy module
  tree is linked in.

### Lifecycle and readiness

- At startup, discovery of `aquasecurity.github.io/v1alpha1` is retried with
  exponential backoff (1 s doubling to 2 min). `/readyz` fails until it
  answers.
- Discovery re-runs every `TRIVY_RECHECK_PERIOD`. When the set of served
  report resources changes (Trivy Operator installed, upgraded or removed),
  the informers are restarted for the new set. Restarting re-lists, but
  nothing already sent is sent again.
- While watching, `/readyz` passes once every informer has synced and none
  has failed `WatchErrorThreshold` (3) consecutive list/watch calls. A
  streak ends as soon as a list or watch makes progress.
  `kguardian_supplychain_source_healthy` mirrors this.
- **Missing RBAC leaves the pod NotReady.** If the ClusterRole is absent or
  wrong, the list is Forbidden, the cache never syncs, and `/readyz` returns
  503. Check the pod's logs for `forbidden`.

### Memory

The informer stores a **slim** copy of each report. A transform decodes it
and keeps only the fields the tracker reads: identity labels, artifact,
scanner, and per-vulnerability ids, packages, versions, severity and scores.
For SBOMs it keeps the component name, version, PURL, type, licences and the
Trivy properties listed in `pkg/trivy/slim.go`. Descriptions, links, the
dependency graph, hashes, suppliers and `managedFields` are dropped before
caching.

The tracker holds **one normalised payload per (kind, digest)** plus the set
of reports that point at it. The only per-report payloads are for tag-only
reports still waiting for a digest.

So, roughly: memory ≈ (number of reports × slim report size) + (distinct
digests × normalised payload size). The first term grows with workload
containers, the second with distinct images. No figures are given here
because none have been measured on a real cluster yet. Watch the pod's
working set against `kguardian_supplychain_tracked_digests` and raise
`supplychain.resources.limits.memory` on large clusters.

### Digest kind (registry lookup)

Trivy Operator reports the digest it resolved. That can be a multi-arch
**index**, while kubelet's `imageID` for a running container is often the
platform **manifest**. So that the broker can join either way, each payload
carries:

- `image.digest`: exactly what the source reported.
- `image.digest_kind`: `index`, `manifest` or `unknown`.
- `image.platform_manifests`: for an index, `"os/arch[/variant]"` → manifest
  digest. Attestation entries (`unknown/unknown`) are skipped.

These come from an anonymous registry lookup: go-containerregistry with
`authn.Anonymous`, and never pull secrets or any other credential. The
lookup runs on the dispatcher's worker pool (3 workers), never in an
informer handler. Each lookup has a 5 s timeout, so a slow registry ties up
one worker, not the queue.

- **Caching.** Definitive answers are cached per digest, since digests are
  immutable. Failures and refusals are cached for an hour. A private,
  unreachable or refused registry leaves `digest_kind` as reported
  (`unknown`) and `platform_manifests` empty.
- **Default.** Off, and independent of broker ingest: set
  `supplychain.registryLookup.enabled=true` (`REGISTRY_LOOKUP_ENABLED=true`)
  to turn it on. While it is off, every payload carries `digest_kind:
  "unknown"` and no `platform_manifests`, which consumers must read as
  unknown, never as single-arch.

**Address guard.** The registry name comes from a pod spec, so anyone who
can create a pod picks the destination. Every connection goes through a
guard: the registry, the token realm it advertises, and every redirect.

| Destination | Handling |
|---|---|
| Loopback, link-local (`169.254.0.0/16` incl. cloud metadata, `fe80::/10`), unspecified, multicast, `0.0.0.0/8`, `198.18.0.0/15` (benchmarking), `240.0.0.0/4` (reserved, incl. broadcast), `localhost` | Always refused. |
| NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`), 6to4 (`2002::/16`), IPv4-compatible (`::a.b.c.d`) | Classified by the IPv4 address they embed, so `64:ff9b::a9fe:a9fe` is refused as `169.254.169.254`. |
| RFC1918, CGNAT `100.64.0.0/10`, ULA `fc00::/7`, `*.local`, single-label names | Refused unless `supplychain.registryLookup.allowPrivateRegistries=true` (`REGISTRY_ALLOW_PRIVATE`), e.g. for a homelab LAN registry. |

- The host name is checked on every request.
- The **resolved IP** is checked again in the dialer, immediately before
  each connect, so DNS rebinding cannot get round the name check.
- Proxy environment variables are ignored for lookups: behind a proxy, the
  dial check would only see the proxy's address.
- go-containerregistry already rejects a token realm that is a private or
  link-local IP literal; that is reported as `blocked_realm`.
- Refused lookups are counted in
  `kguardian_supplychain_registry_lookups_skipped_total{reason}`, with
  reason `blocked_address`, `private_address`, `local_hostname` or
  `blocked_realm`.

**Join contract for the broker (P1-3).** To attach a payload to running
containers, the broker should try, in order:

1. the container's kubelet `imageID` digest equal to `image.digest`;
2. the `imageID` digest equal to a value in `image.platform_manifests`
   (index → platform manifest);
3. `(workload, container, repository:tag)` matching an `observed_in` entry
   plus `image.repository`/`image.tag`, as a last resort.

It should record which rule matched.

### Broker hand-off

Broker ingest is **off** until the broker's supply-chain routes land (#1533
P1-3). Until then the default `LoggingClient` logs one line per payload
(digest, digest kind, ref, counts by severity) and sends nothing.

With `BROKER_INGEST_ENABLED=true`, the `HTTPClient`:

- POSTs **gzip-compressed JSON** (`Content-Encoding: gzip`,
  `Content-Type: application/json`) with
  `Authorization: Bearer $BROKER_AUTH_TOKEN`, the broker's scoped key for
  the `supplychain` scope.
- Keeps every request within the broker's ingest limits: **1 MiB
  compressed** (`broker.MaxRequestBytes`), 8 MiB inflated, at most 10 000
  SBOM components and 20 000 findings. Over those limits the broker answers
  413, so the client checks them before sending.
  - Vulnerability sets are sent whole. They come from one Kubernetes object,
    which etcd already bounds. One that still compresses above the limit is
    rejected locally as `too_large` and never sent.
  - SBOMs are sent whole when they fit. Otherwise they are **paged**: see
    [SBOM paging](#sbom-paging).
- Uses provisional route paths `POST /images/{digest}/vulnerabilities` and
  `POST /images/{digest}/sbom`; P1-3 owns the final shape.

Sends go through a queue keyed by (kind, digest) and run on a pool of 3
workers, never more than one send per key at a time. Informer handlers
never block on the network, and a burst of updates to one digest sends only
the latest. Each key has its own retry state, so one bad payload never holds up
the others:

| Outcome | Handling |
|---|---|
| 2xx | Done. |
| 5xx, 408, 429, network error | Retried on that key only, with exponential backoff (5 s doubling to 5 min) and jitter (each wait lies between half and all of the nominal backoff). Other keys keep draining. |
| Any other 4xx (400, 401, 403, 404, 413, 422, ...), a payload too large even after paging, an encoding error | **Dropped**: logged at error level and counted in `kguardian_supplychain_emissions_dropped_total{kind,reason}`. Never retried. |

A payload replaced by a newer one for the same key is never retried over
it. The replacement starts with a clean backoff.

### Registry SBOM source

Publishers increasingly attach SBOMs to their images, and the supplychain
component reads them (`source: "registry"`). **Registry SBOMs are
unverified**: no signature is checked, so anyone who can push to a
repository can attach one. They only ever **add** to what Trivy found;
they never replace or shrink it (see [SBOM trust and the union](#sbom-trust-and-the-union)).

The source is **off by default** and does not follow broker ingest: set
`supplychain.sources.registry.enabled=true` (`REGISTRY_SBOM_ENABLED=true`)
to turn it on. It is egress to the registries of your running images.

1. Every `REGISTRY_SBOM_INTERVAL` (15 min), it lists running digests from
   the broker's image inventory (`GET /images`, read scope, paged). Only
   rows with `runningContainers > 0` are used.
2. It looks each digest up at most once a day, found or not, so steady
   state is one inventory listing per interval and no registry traffic.
   Lookups run on 2 workers.
3. Lookups are anonymous and go through the [address guard](#digest-kind-registry-lookup).
   `allowPrivateRegistries` applies here too.

For each digest it tries, in order, and keeps the first acceptable SBOM per
subject:

| Order | Mechanism (`attestation.mechanism`) | Where |
|---|---|---|
| 1 | `oci-referrer` | OCI referrers API (or the referrers tag fallback): sigstore bundles (cosign v3), in-toto statements, DSSE envelopes, bare SPDX/CycloneDX artifacts. |
| 2 | `cosign-attestation` | cosign's `sha256-<hex>.att` tag: DSSE-wrapped in-toto statements. |
| 3 | `cosign-sbom` | cosign's `sha256-<hex>.sbom` tag: `cosign attach sbom` documents. |
| 4 | `buildkit-attestation` | Inside an image index: BuildKit's `unknown/unknown` attestation manifests (`vnd.docker.reference.type: attestation-manifest`). |

**Acceptance checks.** None of these checks a signature. Each document
must still pass:

| Document | Rule | If it fails |
|---|---|---|
| in-toto statement (bare, DSSE, sigstore bundle) | A `subject` sha256 must equal the running digest or one of its platform manifests (BuildKit). | Rejected: `rejected_subject_mismatch`, or `rejected_subject_missing` when there is no sha256 subject. |
| Bare SPDX/CycloneDX (e.g. `cosign attach sbom`) | Nothing in it says what it describes. | Accepted as `sbom_trust: "attached-unbound"`: harmless, because it can only add. |
| Any | At least one component. | Rejected: `rejected_empty` (counted as absent). |

These outcomes are counted in `kguardian_supplychain_registry_sbom_lookups_total{result}`.
An SBOM with no distro packages (only language packages) is counted as
`found_source_only`. It is partial by nature, and the union below never
lets it stand in for Trivy's scan.

- **Documents read:** CycloneDX JSON and SPDX 2.x JSON, bare or inside an
  in-toto statement (predicate types `https://cyclonedx.org/bom*` and
  `https://spdx.dev/Document*`).
- **Skipped:** other predicates (e.g. SLSA provenance), XML, and SPDX
  tag-value.
- **Limits:** at most 16 artifacts per digest, 32 MiB per layer, 50 000
  components per document.
- **File paths:** these come from SPDX `CONTAINS` relationships and
  CycloneDX file dependencies or evidence, made image-root relative.

A BuildKit attestation describes one **platform manifest**, not the index.
The payload is keyed by that manifest digest (`digest_kind: "manifest"`)
and carries `image.index_digest` for the index it belongs to.

### SBOM trust and the union

**Rule: an unverified document may only add information, never remove
it.**

`sbom_trust` on every payload says how far its SBOM input can be trusted,
weakest first:

| `sbom_trust` | Meaning |
|---|---|
| `attached-unbound` | A bare document attached to the image. Nothing binds it to the image. |
| `unverified` | An in-toto statement whose subject is the image (or one of its platform manifests). The signature was not checked. |
| `scanned` | Produced by a scanner that read the running image in the cluster (Trivy Operator). |
| `verified` | Signature and signer identity checked. Nothing produces this yet (#1533 P2-1). |

**Grype input is the union.** For each image the matcher gets every SBOM
held for it: Trivy's SbomReport and any registry SBOM, merged.

- Packages de-duplicate on (type, name, version) within the image; type
  maps Trivy's distro names onto PURL types (`debian` → `deb`).
- **Trivy's entries are authoritative.** On a collision a registry entry
  may only add file paths and licences, and fill a PURL Trivy left empty.
  It never changes Trivy's PURL (distro, arch, upstream), source package
  or version. The matcher also treats `src_name` as authoritative over any
  `upstream` qualifier in a PURL.
- Exactly one operating-system component is kept: Trivy's when it has one,
  whatever a registry SBOM says. The matcher takes the distro from it
  before any PURL qualifier.
- **The 50 000-component cap** (the matcher's request limit) never evicts a
  Trivy component. Registry SBOMs fill only the capacity left over, split
  evenly between them, so a registry SBOM full of junk cannot crowd out
  Trivy's packages or another SBOM's. What does not fit counts in
  `kguardian_supplychain_grype_components_clamped_total`.
- So a registry SBOM can neither hide a finding (it can remove or change
  none of Trivy's packages) nor redirect one. It can only add packages, and
  those can only add findings. A property test merges 500 random hostile
  registry SBOMs with a fixed Trivy SBOM and checks that Trivy's findings
  always survive.

**Join key.** A platform-manifest registry SBOM (BuildKit) whose
`index_digest` has a Trivy SBOM is folded into that index's group and
matched there. It is not matched on its own while Trivy's exists. A
registry SBOM for an image Trivy has not scanned is matched alone, with its
own trust level.

### Source rules (contract for the broker)

| Data | Rule |
|---|---|
| SBOMs | Store each source's SBOM separately, keyed `(digest, source)`. Serve each source separately, and/or the union as above. **Never let a registry SBOM replace or hide Trivy's in the SBOM view**, and always show `sbom_trust` next to it. `verified` is the only value that may be presented as signed. |
| Vulnerabilities | Keep sets **side by side**, tagged by `source` (`trivy-operator`, `grype`). Each payload replaces only its own `(digest, source)` set; do not merge or dedupe across sources at ingest. `grype` payloads list their inputs in `sbom_sources` and carry the weakest input trust in `sbom_trust`. |
| Join | Kubelet imageID first, then index→`platform_manifests` / `index_digest`, then (workload, container, repository:tag). |

### Grype matcher

Grype matching runs in the **supplychain-matcher** sidecar
([`../supplychain-matcher`](../supplychain-matcher/README.md)), enabled with
`supplychain.grype.enabled=true`. The chart then sets `GRYPE_MATCHER_URL` to
the sidecar's loopback address. Embedding Grype here would take this binary
from 29.7 MB and 124 Go modules to about 71 MB and 817.

The coordinator (`pkg/match`):

- holds every source's SBOM per digest, up to 2000 digests, and matches
  the union described above;
- matches on one worker, with a time limit per match;
- re-matches when any input changes (it fingerprints the union);
- re-matches everything it holds when the sidecar reports a new database
  build, without fetching any SBOM again. It polls the sidecar's `/db`
  every minute;
- emits `ImageVulnerabilities` with `source: "grype"`, `sbom_sources`,
  `sbom_trust`, `db_updated_at`, and per-vulnerability `kev` / `epss` when
  the database has them.
### Signature discovery

Off unless `ATTESTATION_ENABLED=true` (chart:
`supplychain.signatureDiscovery.enabled`). Every `interval` the component
reads the running digests from the broker (`GET /images`), finds out who
signed each one and posts one result per digest to
`POST /images/{digest}/attestation`. It reports; it never blocks.

For each digest it reads the cosign `sha256-<hex>.sig` and `.att` tags and
the Sigstore bundles attached as OCI referrers (referrers API, or the
`sha256-<hex>` tag fallback on registries without it, such as GHCR). A
platform manifest with no signature of its own is also checked through the
multi-arch index its tags resolve to (`signed_via: index`). Everything is
verified with sigstore-go, offline against the trusted root: the
transparency-log proofs travel with the signature, so Rekor is never
called.

| Verdict | Meaning |
|---|---|
| `verified` | At least one signature verified. `signer_kind: keyless` gives the OIDC issuer and certificate SAN; `key` gives the configured key's name and fingerprint. |
| `key_signed` | Signed with a public key that is not configured, so the signature exists but was not checked. Configure the key to get `verified` or `invalid`. |
| `unsigned` | Every lookup answered and there is no signature. |
| `invalid` | Signatures exist and none verified: a bad signature, a signature for another digest, or a malformed one. |
| `unknown` | Something could not be checked (`reason`: `registry_auth` for a private image, `rate_limited`, `network`, `no_repo_digest`, `untrusted_root` for a signature logged in a Sigstore instance the trusted root does not hold, ...). Never read as unsigned. |

`verified` says a signature is valid, not that it is from someone you
trust: anyone who can push to the repository can attach a valid keyless
signature from their own identity. Always read it with the signer, and use
an ImageTrustPolicy (or your admission policy) to say which signers count.

Attestations (SLSA provenance, SPDX/CycloneDX SBOMs, anything else) are
listed with their predicate type, signer and, for provenance, the builder
and source repository. An unverified attestation is listed with its error
and no identity.

- **Anonymous only.** Pull secrets are never read (#1533 D3); every
  registry request goes through the same address guard as the digest
  lookup.
- **Trust root.** The public-good Sigstore instance, fetched through its
  TUF repository and refreshed daily; or a mounted `trusted_root.json`
  (`ATTESTATION_TRUSTED_ROOT_FILE`) for a private Sigstore or an air-gapped
  cluster, in which case nothing is fetched.
- **Keys.** PEM public keys in `ATTESTATION_KEYS_DIR` (chart:
  `signatureDiscovery.publicKeys`) verify key-signed images. A key
  signature needs no transparency-log entry, like
  `cosign verify --key --insecure-ignore-tlog`. A bundle names its key with
  a hint; if the hint names a configured key and the signature fails, the
  result is `invalid`. A legacy `.sig` has no hint, so an altered one reads
  as `key_signed`, never `verified`.
- **Printable only.** A signature or attestation whose signer-supplied
  fields (SAN, predicate type, provenance) hold a control character, a
  Unicode line separator or a bidi/format control (which can make an
  identity display as another) is reported malformed and unverified,
  without those fields. The broker refuses such characters anywhere, so one odd
  attestation cannot get a digest's whole result refused.
- **Real signatures first.** Before a payload is capped (32 signatures, 64
  attestations), verified entries go first, then key signatures, so junk
  attached to an image cannot push the real signature out.
- **Bounded.** Results are cached per digest (24h, 1h for `unknown`) and a
  result is posted only when it changes. Registry requests are rate-limited
  (`ATTESTATION_REGISTRY_RPS`), each digest has a 60s budget, and sizes are
  capped (64 KiB signature payload, 1 MiB bundle, 16 MiB attestation).
- **Keyed by digest.** The broker stores one result per digest. The same
  digest pulled from two repositories whose signatures differ shows the
  last one checked.

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
| `TRIVY_RECHECK_PERIOD` | `5m` | How often discovery re-runs to pick up installed or removed CRDs. |
| `REGISTRY_LOOKUP_ENABLED` | `false` | Anonymous registry lookup for `digest_kind` / `platform_manifests` (opt-in; egress to image registries). While off, `digest_kind` is `unknown`. |
| `REGISTRY_ALLOW_PRIVATE` | `false` | Let lookups reach RFC1918/CGNAT/ULA addresses, `.local` and single-label names. Loopback, link-local, unspecified and multicast are always refused. |
| `REGISTRY_SBOM_ENABLED` | `false` | Fetch registry-attached SBOMs for running digests (opt-in; egress to image registries). Needs `BROKER_URL` and a token with the read scope (the supplychain token has it). |
| `REGISTRY_SBOM_INTERVAL` | `15m` | How often to list running images. |
| `GRYPE_MATCHER_URL` | *(unset)* | Loopback URL of the matcher sidecar; set by the chart when `supplychain.grype.enabled`. Unset = no Grype matching. |
| `BROKER_INGEST_ENABLED` | `false` | Send payloads to the broker instead of logging them. |
| `BROKER_URL` | `http://kguardian-broker:9090` | Broker base URL. |
| `BROKER_AUTH_TOKEN` | *(unset)* | Scoped broker token, sent as a bearer token. |
| `ATTESTATION_ENABLED` | `false` | Signature discovery. Needs `BROKER_INGEST_ENABLED=true`. |
| `ATTESTATION_INTERVAL` | `10m` | Time between passes over the running digests (at least `1m`). |
| `ATTESTATION_WORKERS` | `2` | Digests verified concurrently (1-16). |
| `ATTESTATION_REGISTRY_RPS` | `5` | Registry requests per second, all registries together. |
| `ATTESTATION_TRUSTED_ROOT_FILE` | *(unset)* | `trusted_root.json` to use instead of the public-good instance over TUF. |
| `ATTESTATION_TUF_MIRROR` | *(unset)* | TUF repository URL (must serve the public-good root). |
| `ATTESTATION_SKIP_SCT` | `false` | Drop the SCT requirement (private Fulcio without a CT log). |
| `ATTESTATION_KEYS_DIR` | *(unset)* | Directory of PEM public keys (`*.pub`, `*.pem`); the file name is the key name. |

## HTTP endpoints

| Path | |
|---|---|
| `GET /healthz` | 200 while the process serves. |
| `GET /readyz` | 200 once discovery has answered and every running informer has synced and is not failing (see [Lifecycle and readiness](#lifecycle-and-readiness)). |
| `GET /metrics` | Prometheus text format. |

There is no data endpoint. Findings go to the broker, which owns storage,
auth and the read APIs.

## Metrics

| Metric | Labels | |
|---|---|---|
| `kguardian_supplychain_source_available` | `source` | 1 when the source's API is served. |
| `kguardian_supplychain_source_healthy` | `source` | 0 while an informer is on a list/watch failure streak. |
| `kguardian_supplychain_report_events_total` | `source`, `kind`, `event` | Informer events: `add`, `update`, `delete`, `decode_error`. |
| `kguardian_supplychain_tracked_digests` | `source`, `kind` | Distinct digests held (one payload each). |
| `kguardian_supplychain_unresolved_reports` | `source`, `kind` | Reports held back for lack of a digest. |
| `kguardian_supplychain_emissions_total` | `kind`, `result` | Send attempts: `ok`, `retry`, `dropped`. |
| `kguardian_supplychain_emissions_dropped_total` | `kind`, `reason` | Payloads dropped as non-retryable (`http_<code>`, `too_large`, `encoding`). |
| `kguardian_supplychain_pending_emissions` | | Queue depth, including keys waiting out a backoff. |
| `kguardian_supplychain_registry_lookups_total` | `result` | Uncached registry lookups: `index`, `manifest`, `unknown`, `skipped`. |
| `kguardian_supplychain_registry_lookups_skipped_total` | `reason` | Lookups refused by the address guard. |
| `kguardian_supplychain_registry_sbom_lookups_total` | `result` | Registry SBOM lookups per digest: `found`, `found_source_only`, `none`, `error`, `skipped_<reason>`, `rejected_empty`, `rejected_subject_mismatch`, `rejected_subject_missing`, `list_error`. |
| `kguardian_supplychain_grype_components_clamped_total` | | Matches whose SBOM union exceeded 50 000 components and was truncated. |
| `kguardian_supplychain_grype_db_built_timestamp_seconds` | | Build time of the loaded Grype DB; DB age is `time() - this`. |
| `kguardian_supplychain_grype_match_runs_total` | `result` | Match runs (`ok`, `error`). |
| `kguardian_supplychain_grype_matches_total` | | Vulnerabilities returned by match runs. |
| `kguardian_supplychain_grype_match_duration_seconds` | | Time to match one SBOM. |
| `kguardian_supplychain_grype_sboms_held` | | Digests whose SBOMs are held for re-matching. |
| `kguardian_supplychain_attestation_results_total` | `verdict`, `reason` | Signature discovery results posted. |
| `kguardian_supplychain_attestation_posts_total` | `result` | Result sends: `ok`, `retry`, `dropped`. |
| `kguardian_supplychain_attestation_passes_total` | `result` | Passes over the running digests: `ok`, `error`. |
| `kguardian_supplychain_attestation_targets` | | Running digests in the last pass. |
| `kguardian_supplychain_attestation_pass_seconds` | | Duration of the last pass. |

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
    "tag": "2.4.1",
    "digest_kind": "index",
    "platform_manifests": {
      "linux/amd64": "sha256:1f3a...",
      "linux/arm64": "sha256:9c0d..."
    }
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
| `image.digest` | `sha256:<64 hex>`. Always set: payloads are never keyed by tag. This is the digest the scanner reported. It can be a multi-arch index digest rather than the platform manifest. |
| `image.digest_kind` | `index`, `manifest` or `unknown`. See [Digest kind](#digest-kind-registry-lookup). |
| `image.platform_manifests` | For an index: `"os/arch[/variant]"` → platform manifest digest. Omitted otherwise. |
| `scanned_at` | When the source produced the report (`report.updateTimestamp`). |
| `source` | `trivy-operator` or `grype`. |
| `sbom_sources` | For `grype`: every SBOM source in the matched union (`registry`, `trivy-operator`). Omitted otherwise. |
| `sbom_trust` | Weakest trust among the SBOM inputs (`attached-unbound` < `unverified` < `scanned` < `verified`); `scanned` for `trivy-operator`. See [SBOM trust and the union](#sbom-trust-and-the-union). |
| `db_updated_at` | Build time of the vulnerability DB used. **Omitted for Trivy Operator**, which does not record it. Set for `grype`. |
| `vulnerabilities[].kev`, `kev_date_added` | In CISA's Known Exploited Vulnerabilities catalogue, and since when. Grype DB only. Absent means unknown, not "not exploited". |
| `vulnerabilities[].epss`, `epss_percentile` | FIRST.org EPSS probability and percentile (0-1). Grype DB only. |
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

For `source: "registry"` the SBOM also carries:

```json
"sbom_trust": "unverified",
"attestation": {
  "mechanism": "buildkit-attestation",
  "artifact_digest": "sha256:6243...",
  "media_type": "application/vnd.in-toto+json",
  "predicate_type": "https://spdx.dev/Document",
  "payload_sha256": "<hex, DSSE/bundle only>",
  "verified": false
}
```

with `scanner: {"name": "registry", "vendor": "<mechanism>"}` and, for a
BuildKit platform SBOM, `image.index_digest`. `attestation.payload_sha256` is the hex sha256
of the raw DSSE payload bytes (after base64 decoding, before JSON parsing).
It is set only when the SBOM came from a DSSE envelope or sigstore bundle,
and signature verification (P2-1) binds its verdict to it. Every `ImageSBOM` carries
`sbom_trust` (`scanned` for Trivy Operator). `format`
is `CycloneDX` or `SPDX`.

Components are the CycloneDX `components` with Trivy's `aquasecurity:trivy:*`
properties lifted into fields. The dependency graph is not carried in v1.

### SBOM paging

An `ImageSBOM` whose gzip body would exceed 1 MiB is split into pages.

- Pages start at 2000 components each, and any page still over the limit is
  halved until it fits.
- Every page repeats the header fields (`schema_version`, `image`, `source`,
  `scanner`, `scanned_at`, `format`, `spec_version`, `observed_in`) and adds:

  ```json
  "page": { "set_id": "5f0c...", "index": 0, "total": 3 }
  ```

- `set_id` is a hash of the SBOM's content. A retry of the same SBOM reuses
  it, so re-sent pages are idempotent.
- Pages are sent in index order. If any page fails, the whole set is retried
  later (or dropped, per the table under Broker hand-off).

The broker should:

- store pages by `(digest, source, set_id)`;
- replace the stored SBOM only once all `total` pages (`index` 0 to
  `total-1`) of one set have arrived;
- let a newer complete set supersede an older one, and discard incomplete
  sets after a timeout.

An SBOM that fits in one request carries no `page` field. A single component
too large to fit on its own is dropped as `too_large`.

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

Signature fixtures are in [`pkg/attest/testdata`](pkg/attest/testdata):
real signature artifacts recorded byte for byte from public registries
(`ATTEST_RECORD=1 go test -run TestRecord ./pkg/attest`), plus two images
signed by cosign v3.0.5 with the key in `testdata/cosign.pub` (the private
key was discarded; see `localRecordTargets`). Tests replay them into an
in-memory registry, so CI never touches the network. `ATTEST_LIVE=1` checks
real public images; `ATTEST_E2E_BROKER=<url> ATTEST_E2E_TOKEN=<token>` posts
the acceptance fixtures to a running broker.
