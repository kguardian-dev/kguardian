-- Node catalog in-use guard (docs/design/node-catalog.md section 5, PR 6).
-- Node SBOM file lists (source 'node') now take part in the in-use
-- verdict. Positive evidence (runtime_package_use) needs no guard; a
-- negative claim (installed_not_observed) from a node file list needs the
-- whole guard below, and anything short of it is 'unknown' with a reason.
-- Nothing changes for Trivy Operator or registry SBOMs.
--
-- One new (derived) table, two new functions and kg_pkg_in_use
-- redefined: nothing here locks or rewrites an existing table, so the
-- migration is safe at startup behind long reads. Every statement is
-- IF NOT EXISTS / OR REPLACE, so a re-run is a no-op. Timestamps are
-- naive UTC, like runtime_coverage.

-- kg_node_sbom_guard (below) per workload container whose image has a
-- node SBOM linked, refreshed in place by every in-use refresh
-- (in_use_store::refresh_coverage, in the same transaction and with the
-- same window as runtime_in_use_coverage: a row is written only when its
-- reason changes; on the maintenance VACUUM list), so kg_pkg_in_use evaluates it
-- once per container rather than once per package. reason NULL = passes.
-- A container with no row here fails closed (sbom_incomplete).
-- sbom_platform is the claim's platform the row was judged against. What
-- can change between two refreshes is re-checked when the row is read
-- (kg_pkg_in_use): the SBOM's completeness and content hash, and the
-- claim's platform against sbom_platform. A node whose platform changes
-- marks its containers' passing rows platform_mismatch in the offer's
-- transaction (node_catalog::claim).
CREATE TABLE IF NOT EXISTS runtime_node_sbom_guard (
    cluster_id     VARCHAR NOT NULL,
    pod_namespace  VARCHAR NOT NULL,
    workload_kind  VARCHAR NOT NULL,
    workload_name  VARCHAR NOT NULL,
    container_name VARCHAR NOT NULL,
    image_digest   VARCHAR NOT NULL,
    reason         VARCHAR NULL,
    sbom_platform  VARCHAR NULL,
    PRIMARY KEY (cluster_id, pod_namespace, workload_kind, workload_name, container_name,
                 image_digest)
);

-- Whether the node SBOM linked to p_image may support
-- installed_not_observed for the workload container: NULL when it may,
-- else the reason, first failing of:
--   sbom_incomplete        no node SBOM, no claim row describing the stored
--                          one (same content hash), or completeness is not
--                          'full';
--   libraries_not_tracked  an instance in the window ran without the
--                          library probe in mode 'full' (kg_runtime_coverage
--                          already refuses coverage then; checked again so
--                          the guard never rests on another function);
--   platform_mismatch      no instance in the window, or one ran on a node
--                          whose platform (node_catalog_platforms) is not
--                          the platform the SBOM was cataloged for. A node
--                          missing from node_catalog_platforms, or an SBOM
--                          without a platform, is a mismatch (fail closed).
-- "Ran an instance in the window" is kg_runtime_coverage's own rule: a
-- runtime_coverage heartbeat within the last p_window_hours.
CREATE OR REPLACE FUNCTION kg_node_sbom_guard(
    p_cluster text, p_ns text, p_kind text, p_name text, p_container text, p_image text,
    p_window_hours integer)
RETURNS text LANGUAGE sql STABLE AS $fn$
WITH s AS (
    SELECT (c.completeness = 'full'
            AND c.content_hash IS NOT DISTINCT FROM vs.content_hash) AS full_,
           c.platform
    FROM supplychain_image_links l
    JOIN vuln_sources vs ON vs.digest = l.digest AND vs.source = l.source AND vs.kind = 'sbom'
    LEFT JOIN node_catalog_claims c ON c.inventory_digest = l.digest
    WHERE l.image_digest = p_image AND l.source = 'node'
),
i AS (
    SELECT (rc.lib_probe AND rc.mode = 'full') AS libs, p.platform
    FROM runtime_coverage rc
    LEFT JOIN node_catalog_platforms p ON p.node = rc.node_name
    WHERE rc.cluster_id = p_cluster AND rc.pod_namespace = p_ns AND rc.workload_kind = p_kind
      AND rc.workload_name = p_name AND rc.container_name = p_container
      AND rc.image_digest = p_image
      AND rc.last_heartbeat >= timezone('UTC', now())
          - make_interval(hours => GREATEST(p_window_hours, 0))
)
SELECT CASE
    WHEN NOT EXISTS (SELECT 1 FROM s) OR EXISTS (SELECT 1 FROM s WHERE s.full_ IS NOT TRUE)
        THEN 'sbom_incomplete'
    WHEN EXISTS (SELECT 1 FROM i WHERE NOT i.libs) THEN 'libraries_not_tracked'
    WHEN NOT EXISTS (SELECT 1 FROM i)
      OR EXISTS (SELECT 1 FROM i, s WHERE i.platform IS NULL OR s.platform IS NULL
                                       OR i.platform <> s.platform)
        THEN 'platform_mismatch'
END
$fn$;

-- The per-package half of the guard for a package whose only file list is
-- a node SBOM's: its flags (node_sbom_package_flags, keyed name@version,
-- over every version of p_pkg the SBOM lists). interpreted_content (bit
-- 2: it owns interpreted or loadable non-executable content, which
-- exec/mmap capture cannot see), then sbom_incomplete (bit 1,
-- files_truncated: its file list is not whole, including files the
-- cataloger dropped as runtime drift). NULL when neither is set.
CREATE OR REPLACE FUNCTION kg_node_pkg_flags(p_image text, p_pkg text)
RETURNS text LANGUAGE sql STABLE AS $fn$
SELECT CASE WHEN bit_or(f.flags) & 2 <> 0 THEN 'interpreted_content'
            WHEN bit_or(f.flags) & 1 <> 0 THEN 'sbom_incomplete' END
FROM supplychain_image_links l
JOIN image_sbom_components sc ON sc.digest = l.digest AND sc.source = l.source
    AND sc.name = p_pkg
JOIN node_sbom_package_flags f ON f.digest = sc.digest
    AND f.pkg_key = sc.name || '@' || COALESCE(sc.version, '')
WHERE l.image_digest = p_image AND l.source = 'node'
$fn$;

-- kg_pkg_in_use (2026-10-03-100000) with node file lists let in:
--   * executed / loaded from runtime_package_use, as before (node file
--     lists now feed it too: in_use_store::refresh_image_use);
--   * not covered, or a language package: unknown, as before;
--   * a non-node SBOM lists the package's files: installed_not_observed,
--     exactly as before (Trivy Operator and registry SBOMs unchanged);
--   * no SBOM lists them: unknown:no_package_files, as before;
--   * only a node SBOM lists them: installed_not_observed only when all
--     pass, else unknown:<the first failing>: the stored node SBOM is,
--     now, complete and described by its claim (sbom_incomplete); the
--     container's runtime_node_sbom_guard row exists (sbom_incomplete) and
--     passed (its reason); the claim's platform is, now, the one the row
--     was judged against (platform_mismatch); the package's
--     kg_node_pkg_flags.
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
            WHEN EXISTS (
                SELECT 1 FROM supplychain_image_links l
                JOIN image_sbom_components sc ON sc.digest = l.digest AND sc.source = l.source
                    AND sc.name = p_pkg AND sc.source <> 'node'
                WHERE l.image_digest = p_image AND cardinality(sc.file_paths) > 0)
                THEN 'installed_not_observed'
            WHEN NOT EXISTS (
                SELECT 1 FROM supplychain_image_links l
                JOIN image_sbom_components sc ON sc.digest = l.digest AND sc.source = l.source
                    AND sc.name = p_pkg
                WHERE l.image_digest = p_image AND l.source = 'node'
                  AND cardinality(sc.file_paths) > 0)
                THEN 'unknown:no_package_files'
            ELSE COALESCE('unknown:' || (
                SELECT CASE
                    WHEN NOT EXISTS (
                        SELECT 1 FROM vuln_sources vs
                        JOIN node_catalog_claims cl ON cl.inventory_digest = vs.digest
                        WHERE vs.digest = p_image AND vs.source = 'node' AND vs.kind = 'sbom'
                          AND cl.completeness = 'full' AND cl.content_hash = vs.content_hash)
                        THEN 'sbom_incomplete'
                    WHEN ng.image_digest IS NULL THEN 'sbom_incomplete'
                    WHEN ng.reason IS NOT NULL THEN ng.reason
                    WHEN ng.sbom_platform IS NULL OR ng.sbom_platform IS DISTINCT FROM (
                        SELECT cl.platform FROM node_catalog_claims cl
                        WHERE cl.inventory_digest = p_image)
                        THEN 'platform_mismatch'
                    ELSE kg_node_pkg_flags(p_image, p_pkg)
                END
                FROM (SELECT 1) one
                LEFT JOIN runtime_node_sbom_guard ng
                  ON ng.cluster_id = p_cluster AND ng.pod_namespace = p_ns
                 AND ng.workload_kind = p_kind AND ng.workload_name = p_name
                 AND ng.container_name = p_container AND ng.image_digest = p_image),
                'installed_not_observed')
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
