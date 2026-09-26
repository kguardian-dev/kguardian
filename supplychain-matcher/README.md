# kguardian-supplychain-matcher

Grype vulnerability matching for kguardian's supplychain component
([#1533](https://github.com/kguardian-dev/kguardian/issues/1533)). It runs as
a second container in the supplychain pod, only when
`supplychain.grype.enabled=true`.

It is a separate module and image on purpose. Embedding Grype (v0.119.0)
takes a static binary from about 30 MB to about 71 MB, and from 124 to 817
Go modules: the source providers alone pull in docker, containerd, AWS S3
and Google Cloud Storage clients. Keeping it here means the default
supplychain image does not carry that code. The container that does carry
it holds no Kubernetes or broker credentials.

## Boundaries

- Listens on a loopback address only. It refuses to start on anything else
  and rejects requests from non-loopback peers.
- No service-account token. The pod never auto-mounts one; the chart
  projects a token into the supplychain container alone.
- No broker token. Results go back to the supplychain container, which
  sends them to the broker.
- Owns the Grype database on its own volume (`/var/lib/grype`): an 8 GiB
  emptyDir by default, or a PVC.

## API (loopback)

| Endpoint | |
|---|---|
| `POST /match` | gzip JSON: `{"image":{"digest"},"components":[...]}`, a subset of supplychain's `ImageSBOM`. Returns `{"db":{...},"vulnerabilities":[...]}`, with vulnerabilities in supplychain's `Vulnerability` shape (`kev`, `kev_date_added`, `epss`, `epss_percentile` included). |
| `GET /db` | Database status: build time, schema, loaded, last refresh check and error. |
| `GET /healthz`, `GET /readyz` | Liveness, and whether a database is loaded. |

Kubelet HTTP probes cannot reach a loopback listener, so the chart uses
`kguardian-supplychain-matcher probe healthz` as an exec probe.

## Database

The download client is kguardian's own (`internal/dbdist`), not Grype's.
Grype's client hands URLs to go-getter, which also speaks git, hg, s3, gcs
and file, and honours `X-Terraform-Get`. Grype's installation curator is
still used for everything after the download.

- **Listing:** `GRYPE_DB_URL/v6/latest.json` (default
  `https://grype.anchore.io/databases`). An internal mirror with the same
  layout works for air-gapped clusters.
- **Transport:** plain HTTP(S) only. https is required unless the operator
  configured an `http://` URL.
- **Address guard:** every connection and every redirect hop refuses
  loopback, link-local (including cloud metadata `169.254.169.254` and
  `fe80::/10`), unspecified and multicast addresses. The check runs after
  DNS resolution. Private addresses are allowed, because mirrors are often
  internal.
- **Archive:** the path in the listing may not leave the listing's host or
  directory. The sha256 is checked before anything is unpacked. Unpacking
  accepts only regular files at the archive root (no symlinks,
  subdirectories or `..`), with size limits.
- **Integrity, not authenticity.** The sha256 comes from the same listing
  as the archive URL, so it proves the archive is the one the listing
  named, not who published it. Anchore publishes no signature. **TLS to
  the configured URL is the trust anchor.** The curator re-checks the
  unpacked database's checksum on every load.
- **Refresh:** every `GRYPE_DB_UPDATE_INTERVAL` (12h); Grype itself allows
  at most one check per 2h. The new database is unpacked beside the current
  one and swapped in, and a failed refresh keeps the loaded database.
- **Air-gapped:** `GRYPE_DB_AUTO_UPDATE=false` uses only a database already
  on the volume. `GRYPE_DB_MAX_AGE` (120h, `0` = off) refuses stale ones.

**Storage.** The unpacked DB is 3.1 GB, and a refresh needs about 6.4 GB
at peak.

- **emptyDir (default):** 8 GiB `sizeLimit`, with the matcher requesting
  7Gi and limited to 9Gi of ephemeral storage.
- **Persistent volume:** recommended on nodes with less than about 40 GB
  free (`supplychain.grype.persistence.enabled=true`). A restart then skips
  the re-download.

## Measured (2026-09-26, grype v0.119.0, DB v6.1.9 built 2026-09-25)

| | |
|---|---|
| Archive | 181 MB `.tar.zst` |
| Unpacked DB | 3.11 GB (`vulnerability.db`); a refresh needs about 6.4 GB at peak |
| First download, verify, unpack and load (this client) | 74–80 s, peak RSS 330 MB |
| Load an existing DB (includes its checksum) | 8 to 13 s |
| Match nginx:1.27, 151 components | 624 vulnerabilities, 2.4 s |
| Match python:3.12-slim, 96 components | 156 vulnerabilities, 1.3 to 1.7 s |
| Match alpine:3.20, 15 components | 0 vulnerabilities, 0.3 s |
| Server peak RSS over those matches | 78 MB |
| Static binary | 70.7 MB (about 23 MB gzip) |

These were measured on one workstation, not in a cluster. The chart
defaults (128Mi memory request, 512Mi limit, 8Gi volume, 7Gi/9Gi ephemeral
storage) follow from these numbers.

## Matching details

The matcher receives kguardian's normalised components, not the original
SBOM. It rewrites them as a minimal CycloneDX document for Grype's reader,
and two steps in that rewrite decide whether OS packages match:

- **Distro.** When there is no operating-system component, the distro is
  inferred from PURL qualifiers (`distro=…`, `os_name`/`os_version`).
- **Source package.** For deb/rpm, the source package is added as the PURL
  `upstream` qualifier from `src_name`.

Checked against the real database (`TestMatchRealDB`): libc6 on debian 12
matches 30 advisories with both steps, and 0 without either one. No CPEs
are sent, so Grype's CPE matching does not run.

## Development

```sh
go vet ./...
golangci-lint run ./...
go test -race ./...
GRYPE_TEST_DB_DIR=/path/to/grype/db go test -run TestMatchRealDB -v ./internal/engine/   # needs a ~3 GB DB
```
