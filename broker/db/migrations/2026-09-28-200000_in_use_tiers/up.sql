-- Runtime "in use" and risk tiers for vulnerability findings (#1533 P1-5).
--
-- Derived tables only: the retention pass rebuilds them from the runtime
-- inventory (P1-2), the SBOM components and pod_traffic, so every read is
-- an indexed lookup. Nothing here is a source of truth; dropping the rows
-- loses nothing that the next pass does not recompute.

-- Packages seen executed or loaded, per workload container and inventory
-- digest. Sparse: only packages with evidence. A package's in-use state
-- for a container is: a row here -> executed / loaded; else the
-- container's coverage decides (installed_not_observed or unknown).
CREATE TABLE IF NOT EXISTS runtime_package_use (
    cluster_id     VARCHAR   NOT NULL,
    pod_namespace  VARCHAR   NOT NULL,
    workload_kind  VARCHAR   NOT NULL,
    workload_name  VARCHAR   NOT NULL,
    container_name VARCHAR   NOT NULL,
    image_digest   VARCHAR   NOT NULL,   -- inventory digest (kubelet imageID)
    pkg_name       VARCHAR   NOT NULL,
    pkg_version    VARCHAR   NOT NULL,   -- '' when the SBOM gives none
    state          VARCHAR   NOT NULL,   -- executed | loaded
    path_match     VARCHAR   NOT NULL,   -- exact | merged_usr_alias | soname
    sample_path    VARCHAR   NOT NULL,   -- one path that proved it
    first_seen     TIMESTAMP NOT NULL,
    last_seen      TIMESTAMP NOT NULL,
    PRIMARY KEY (cluster_id, pod_namespace, workload_kind, workload_name, container_name,
                 image_digest, pkg_name, pkg_version)
);
CREATE INDEX IF NOT EXISTS idx_runtime_package_use_image
    ON runtime_package_use (image_digest, pkg_name, pkg_version);

-- Executed / loaded paths no package in any SBOM of the image owns: a
-- binary added outside a package manager, or written after start. Capped
-- per image.
CREATE TABLE IF NOT EXISTS runtime_unowned_paths (
    image_digest VARCHAR   NOT NULL,
    path         VARCHAR   NOT NULL,
    kind         VARCHAR   NOT NULL,     -- exec | lib
    workloads    INTEGER   NOT NULL,
    first_seen   TIMESTAMP NOT NULL,
    last_seen    TIMESTAMP NOT NULL,
    PRIMARY KEY (image_digest, path, kind)
);

-- Capture coverage per workload container and inventory digest, as the
-- in-use rules read it: covered = watched continuously for at least the
-- minimum window, so "installed, not observed" may be claimed.
CREATE TABLE IF NOT EXISTS runtime_in_use_coverage (
    cluster_id     VARCHAR   NOT NULL,
    pod_namespace  VARCHAR   NOT NULL,
    workload_kind  VARCHAR   NOT NULL,
    workload_name  VARCHAR   NOT NULL,
    container_name VARCHAR   NOT NULL,
    image_digest   VARCHAR   NOT NULL,
    covered        BOOLEAN   NOT NULL,
    -- NULL when covered; else no_runtime_data | capture_gap | host_network
    reason         VARCHAR   NULL,
    observed_since TIMESTAMP NULL,       -- start of continuous coverage
    window_hours   INTEGER   NOT NULL,   -- minimum window required
    computed_at    TIMESTAMP NOT NULL,
    PRIMARY KEY (cluster_id, pod_namespace, workload_kind, workload_name, container_name,
                 image_digest)
);
CREATE INDEX IF NOT EXISTS idx_runtime_in_use_coverage_image
    ON runtime_in_use_coverage (image_digest);

-- Observed network exposure per workload (the exposure view's rule),
-- precomputed for workloads running an image with findings so tiers can
-- be computed in the CVE summary without scanning pod_traffic per read.
CREATE TABLE IF NOT EXISTS workload_network_exposure (
    cluster_id     VARCHAR   NOT NULL,
    pod_namespace  VARCHAR   NOT NULL,
    workload_kind  VARCHAR   NOT NULL,
    workload_name  VARCHAR   NOT NULL,
    window_hours   INTEGER   NOT NULL,
    pods           BIGINT    NOT NULL,
    ingress_flows  BIGINT    NOT NULL,
    exposed        BOOLEAN   NULL,       -- NULL = unknown
    exposed_via    TEXT[]    NOT NULL DEFAULT '{}',
    computed_at    TIMESTAMP NOT NULL,
    PRIMARY KEY (cluster_id, pod_namespace, workload_kind, workload_name)
);

-- The tier rule, team/04-ux.md section 3. Mirrors in_use::tier() in the
-- broker; a live test checks both agree on every input combination.
-- in_use: executed | loaded | unknown | installed_not_observed.
-- Returns 0 P0, 1 P1, 2 P2, 3 Background.
CREATE OR REPLACE FUNCTION kg_vuln_tier(
    in_use text, severity_rank smallint, kev boolean, epss real,
    exposed boolean, fixable boolean,
    epss_threshold double precision, unknown_exposure_as_exposed boolean
) RETURNS smallint LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE
        WHEN in_use = 'installed_not_observed' THEN 3
        WHEN (COALESCE(kev, false) OR COALESCE(epss >= epss_threshold, false))
             AND COALESCE(exposed, unknown_exposure_as_exposed) THEN 0
        WHEN COALESCE(kev, false) OR COALESCE(epss >= epss_threshold, false) THEN 1
        WHEN severity_rank = 4 AND NOT fixable
             AND NOT COALESCE(exposed, unknown_exposure_as_exposed) THEN 2
        WHEN severity_rank IN (4, 5) THEN 1
        ELSE 2
    END::smallint
$$;

-- Whether exec/mmap evidence can say anything about a package type.
-- Mirrors in_use::is_observable_type(); a live test checks they agree.
CREATE OR REPLACE FUNCTION kg_pkg_observable(pkg_type text, class text)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE
        WHEN lower(COALESCE(pkg_type, '')) IN
            ('gobinary', 'rustbinary', 'rust-binary', 'go-module', 'binary') THEN true
        WHEN lower(COALESCE(pkg_type, '')) IN
            ('npm', 'node-pkg', 'yarn', 'pnpm', 'pip', 'python-pkg', 'pipenv', 'poetry',
             'jar', 'pom', 'gradle', 'gemspec', 'bundler', 'composer', 'nuget',
             'dotnet-core', 'conda-pkg') THEN false
        ELSE class IS DISTINCT FROM 'lang-pkgs'
    END
$$;

-- Package lookups by name within one SBOM (has-file-list checks).
CREATE INDEX IF NOT EXISTS idx_image_sbom_components_name
    ON image_sbom_components (digest, source, name);

-- The in-use state of package p_pkg in one workload container running
-- inventory digest p_image. Mirrors in_use::in_use_of():
--   executed / loaded      evidence in runtime_package_use (wins always)
--   unknown:<reason>       coverage row missing or not covered (its
--                          reason), a language package, or no SBOM lists
--                          the package's files
--   installed_not_observed covered, observable, has a file list, unseen
CREATE OR REPLACE FUNCTION kg_pkg_in_use(
    p_cluster text, p_ns text, p_kind text, p_name text, p_container text,
    p_image text, p_pkg text, p_observable boolean
) RETURNS text LANGUAGE sql STABLE AS $$
    SELECT COALESCE(
        (SELECT CASE WHEN bool_or(u.state = 'executed') THEN 'executed' ELSE 'loaded' END
         FROM runtime_package_use u
         WHERE u.cluster_id = p_cluster AND u.pod_namespace = p_ns
           AND u.workload_kind = p_kind AND u.workload_name = p_name
           AND u.container_name = p_container AND u.image_digest = p_image
           AND u.pkg_name = p_pkg
         HAVING count(*) > 0),
        (SELECT CASE
            WHEN c.covered IS NOT TRUE
                THEN 'unknown:' || COALESCE(c.reason, 'no_runtime_data')
            WHEN NOT p_observable THEN 'unknown:language_package'
            WHEN NOT EXISTS (
                SELECT 1 FROM supplychain_image_links l
                JOIN image_sbom_components sc ON sc.digest = l.digest AND sc.source = l.source
                    AND sc.name = p_pkg
                WHERE l.image_digest = p_image AND cardinality(sc.file_paths) > 0)
                THEN 'unknown:no_package_files'
            ELSE 'installed_not_observed'
         END
         FROM (SELECT (SELECT covered FROM runtime_in_use_coverage cv
                       WHERE cv.cluster_id = p_cluster AND cv.pod_namespace = p_ns
                         AND cv.workload_kind = p_kind AND cv.workload_name = p_name
                         AND cv.container_name = p_container AND cv.image_digest = p_image)
                          AS covered,
                      (SELECT reason FROM runtime_in_use_coverage cv
                       WHERE cv.cluster_id = p_cluster AND cv.pod_namespace = p_ns
                         AND cv.workload_kind = p_kind AND cv.workload_name = p_name
                         AND cv.container_name = p_container AND cv.image_digest = p_image)
                          AS reason) c)
    )
$$;

-- Order of in-use states, strongest first; unknown ranks above
-- installed_not_observed (degrade upward).
CREATE OR REPLACE FUNCTION kg_in_use_rank(s text) RETURNS smallint
LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE
        WHEN s = 'executed' THEN 0
        WHEN s = 'loaded' THEN 1
        WHEN s = 'installed_not_observed' THEN 3
        ELSE 2
    END::smallint
$$;

-- CVE summary: in-use and tier columns, per scope as before.
-- tier is NULL ("not computed yet") on rows summarised before this
-- migration, until the next retention pass rebuilds them with the
-- configured thresholds. A default tier would rank a KEV critical as P2
-- until then, and a thresholded UPDATE here would hard-code thresholds
-- the deployment may have changed.
ALTER TABLE vuln_cve_summary ADD COLUMN IF NOT EXISTS tier SMALLINT NULL;
ALTER TABLE vuln_cve_summary ADD COLUMN IF NOT EXISTS in_use VARCHAR NOT NULL DEFAULT 'unknown';
ALTER TABLE vuln_cve_summary ADD COLUMN IF NOT EXISTS executed_workloads BIGINT NOT NULL DEFAULT 0;
ALTER TABLE vuln_cve_summary ADD COLUMN IF NOT EXISTS loaded_workloads BIGINT NOT NULL DEFAULT 0;
ALTER TABLE vuln_cve_summary ADD COLUMN IF NOT EXISTS unknown_workloads BIGINT NOT NULL DEFAULT 0;
ALTER TABLE vuln_cve_summary ADD COLUMN IF NOT EXISTS not_observed_workloads BIGINT NOT NULL DEFAULT 0;
ALTER TABLE vuln_cve_summary ADD COLUMN IF NOT EXISTS exposed_workloads BIGINT NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_vuln_cve_summary_tier
    ON vuln_cve_summary (scope_namespace, tier, severity_rank DESC, vuln_id);
