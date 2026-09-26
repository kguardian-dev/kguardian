-- Supply-chain ingest (#1533 P1-3): vulnerability and SBOM payloads from
-- the supplychain component (Trivy Operator reports today).
--
-- Everything is keyed by the digest the SOURCE reported (`digest`), never
-- by pod: a digest scanned once is one set of rows however many replicas
-- run it. That digest can be a multi-arch index while the inventory holds
-- the kubelet's platform manifest, so the join to the inventory lives in
-- its own table (supplychain_image_links) and records which rule matched.
--
-- Growth is O(distinct scanned images x findings). retention.rs
-- ("Supply chain") deletes a payload once no inventory digest it links to
-- has run for SUPPLYCHAIN_RETENTION_DAYS, and expires staged SBOM pages.

-- One row per (digest, source, kind): the payload header. kind is
-- 'vulnerabilities' or 'sbom'; the two arrive separately and carry their
-- own scanned_at, so an older scan of one never replaces a newer one.
CREATE TABLE IF NOT EXISTS vuln_sources (
    digest             VARCHAR   NOT NULL,          -- image.digest as reported
    source             VARCHAR   NOT NULL,          -- e.g. trivy-operator
    kind               VARCHAR   NOT NULL,          -- vulnerabilities | sbom
    digest_kind        VARCHAR   NOT NULL,          -- index | manifest | unknown
    -- os/arch[/variant] -> manifest digest, for an index; and the values
    -- alone, for the join (GIN, = ANY).
    platform_manifests JSONB     NOT NULL DEFAULT '{}'::jsonb,
    manifest_digests   TEXT[]    NOT NULL DEFAULT '{}',
    -- A platform-manifest payload's index (BuildKit SBOMs); also in
    -- manifest_digests so the index/manifest join finds it.
    index_digest       VARCHAR   NULL,
    image_ref          VARCHAR   NULL,
    registry           VARCHAR   NULL,
    repository         VARCHAR   NULL,
    -- registry/repository normalised the way the inventory stores
    -- images.repository (docker.io/library/nginx), for the tag join.
    norm_repository    VARCHAR   NULL,
    tag                VARCHAR   NULL,
    scanner_name       VARCHAR   NULL,
    scanner_vendor     VARCHAR   NULL,
    scanner_version    VARCHAR   NULL,
    scanned_at         TIMESTAMP NOT NULL,
    db_updated_at      TIMESTAMP NULL,
    os_family          VARCHAR   NULL,
    os_name            VARCHAR   NULL,
    os_eosl            BOOLEAN   NOT NULL DEFAULT false,
    -- [{namespace, kind, name, container}], capped. Provenance, and the
    -- input to the last-resort (workload, container, repo:tag) join.
    observed_in        JSONB     NOT NULL DEFAULT '[]'::jsonb,
    -- md5 of the normalised findings (vulnerabilities) or the page set id
    -- (sbom): an identical re-send is a no-op.
    content_hash       VARCHAR   NOT NULL,
    sbom_format        VARCHAR   NULL,
    sbom_spec_version  VARCHAR   NULL,
    item_count         INTEGER   NOT NULL DEFAULT 0,
    -- Matcher findings (source grype): which SBOM source(s) were matched.
    sbom_sources       TEXT[]    NOT NULL DEFAULT '{}',
    -- attached-unbound | unverified | scanned | verified (weakest first).
    -- Unknown values, and a registry SBOM that states none, are stored as
    -- attached-unbound. Only verified may be shown as signed.
    sbom_trust         VARCHAR   NULL,
    -- Registry-attached SBOMs: where it was found and whether a signature
    -- was verified (stored as sent; false = not checked, never "signed").
    attestation        JSONB     NULL,
    received_at        TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    PRIMARY KEY (digest, source, kind)
);
CREATE INDEX IF NOT EXISTS idx_vuln_sources_manifests ON vuln_sources USING GIN (manifest_digests);
CREATE INDEX IF NOT EXISTS idx_vuln_sources_received ON vuln_sources (received_at);

-- One row per finding. Replaced as a set per (digest, source).
CREATE TABLE IF NOT EXISTS image_vulnerabilities (
    id                BIGSERIAL PRIMARY KEY,
    digest            VARCHAR   NOT NULL,
    source            VARCHAR   NOT NULL,
    vuln_id           VARCHAR   NOT NULL,          -- CVE-/GHSA-/... id
    pkg_name          VARCHAR   NOT NULL,
    pkg_type          VARCHAR   NULL,
    pkg_purl          VARCHAR   NULL,
    installed_version VARCHAR   NOT NULL,
    fixed_version     VARCHAR   NULL,              -- NULL = no fix published
    severity          VARCHAR   NOT NULL,          -- CRITICAL..UNKNOWN
    severity_rank     SMALLINT  NOT NULL,          -- 5 CRITICAL .. 0 UNKNOWN
    score             REAL      NULL,
    cvss              JSONB     NOT NULL DEFAULT '{}'::jsonb,
    title             VARCHAR   NULL,              -- untrusted text
    primary_url       VARCHAR   NULL,              -- untrusted, never fetched
    target            VARCHAR   NULL,
    class             VARCHAR   NULL,
    published_at      TIMESTAMP NULL,
    last_modified_at  TIMESTAMP NULL,
    file_paths        TEXT[]    NOT NULL DEFAULT '{}',
    -- Exploitation signals from the Grype DB. NULL = unknown (Trivy never
    -- sets them), never "not exploited".
    kev               BOOLEAN   NULL,
    kev_date_added    TIMESTAMP NULL,
    epss              REAL      NULL,
    epss_percentile   REAL      NULL,
    scanned_at        TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_image_vulns_key ON image_vulnerabilities (digest, source, severity_rank DESC, id);
CREATE INDEX IF NOT EXISTS idx_image_vulns_vuln_id ON image_vulnerabilities (vuln_id);

-- One row per SBOM component, replaced as a set per (digest, source) only
-- once every page of a set has arrived (image_sbom_pages).
CREATE TABLE IF NOT EXISTS image_sbom_components (
    id           BIGSERIAL PRIMARY KEY,
    digest       VARCHAR   NOT NULL,
    source       VARCHAR   NOT NULL,
    name         VARCHAR   NOT NULL,
    version      VARCHAR   NULL,
    purl         VARCHAR   NULL,
    type         VARCHAR   NULL,
    class        VARCHAR   NULL,
    src_name     VARCHAR   NULL,
    src_version  VARCHAR   NULL,
    licenses     TEXT[]    NOT NULL DEFAULT '{}',
    layer_digest VARCHAR   NULL,
    -- In-image paths the package owns, capped per component. The later
    -- path -> package mapping (P1-5) looks paths up here.
    file_paths   TEXT[]    NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_image_sbom_components_key ON image_sbom_components (digest, source, id);
CREATE INDEX IF NOT EXISTS idx_image_sbom_components_paths ON image_sbom_components USING GIN (file_paths);

-- Staged pages of a paged SBOM. A set is swapped into
-- image_sbom_components atomically when all `total` pages are here, then
-- its pages are deleted; an incomplete set expires after
-- SUPPLYCHAIN_SBOM_PAGE_TTL_SECS.
CREATE TABLE IF NOT EXISTS image_sbom_pages (
    digest      VARCHAR   NOT NULL,
    source      VARCHAR   NOT NULL,
    set_id      VARCHAR   NOT NULL,
    page_index  INTEGER   NOT NULL,
    total       INTEGER   NOT NULL,
    scanned_at  TIMESTAMP NOT NULL,
    components  JSONB     NOT NULL,
    received_at TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    PRIMARY KEY (digest, source, set_id, page_index)
);
CREATE INDEX IF NOT EXISTS idx_image_sbom_pages_received ON image_sbom_pages (received_at);

-- Which inventory digest(s) a payload applies to, and by which rule:
--   image_id          the kubelet imageID digest equals the payload digest
--   platform_manifest the imageID digest is one of the payload's
--                     platform manifests (payload is an index)
--   workload_tag      last resort: same (namespace, workload, container)
--                     as an observed_in entry and the same repository:tag
-- Recomputed at ingest and by the retention loop, so a digest the
-- inventory learns about after the scan is linked within one interval.
CREATE TABLE IF NOT EXISTS supplychain_image_links (
    digest       VARCHAR   NOT NULL,   -- payload digest
    source       VARCHAR   NOT NULL,
    image_digest VARCHAR   NOT NULL,   -- images.digest
    join_kind    VARCHAR   NOT NULL,
    join_rank    SMALLINT  NOT NULL,   -- 1 image_id, 2 platform_manifest, 3 workload_tag
    linked_at    TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    PRIMARY KEY (digest, source, image_digest)
);
CREATE INDEX IF NOT EXISTS idx_supplychain_links_image ON supplychain_image_links (image_digest);

-- GET /vulnerabilities reads this, not the findings: one row per CVE
-- cluster-wide (scope_namespace = '') and per (namespace, CVE), rebuilt by
-- the retention pass. vuln_cve_summary_state says when.
CREATE TABLE IF NOT EXISTS vuln_cve_summary (
    scope_namespace   VARCHAR   NOT NULL,
    vuln_id           VARCHAR   NOT NULL,
    severity_rank     SMALLINT  NOT NULL,
    max_score         REAL      NULL,
    fixable           BOOLEAN   NOT NULL,
    kev               BOOLEAN   NULL,
    max_epss          REAL      NULL,
    packages          TEXT[]    NOT NULL DEFAULT '{}',
    -- Sources reporting it (findings are deduplicated across sources on
    -- (id, package, installed version); this says who contributed).
    sources           TEXT[]    NOT NULL DEFAULT '{}',
    images            BIGINT    NOT NULL,
    workloads         BIGINT    NOT NULL,
    running_workloads BIGINT    NOT NULL,
    namespaces        BIGINT    NOT NULL,
    weakest_rank      SMALLINT  NOT NULL,
    PRIMARY KEY (scope_namespace, vuln_id)
);
CREATE INDEX IF NOT EXISTS idx_vuln_cve_summary_order
    ON vuln_cve_summary (scope_namespace, severity_rank DESC, vuln_id);

CREATE TABLE IF NOT EXISTS vuln_cve_summary_state (
    id           SMALLINT  PRIMARY KEY CHECK (id = 1),
    refreshed_at TIMESTAMP NOT NULL,
    cves         BIGINT    NOT NULL
);
