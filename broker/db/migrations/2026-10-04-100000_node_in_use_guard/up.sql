-- Node catalog in-use guard (docs/design/node-catalog.md section 5, PR 6).
-- Node SBOM file lists (source 'node') now take part in the in-use
-- verdict. Positive evidence (runtime_package_use) needs no guard; a
-- negative claim (installed_not_observed) from a node file list needs the
-- whole guard below, and anything short of it is 'unknown' with a reason.
-- Nothing changes for Trivy Operator or registry SBOMs.
--
-- Two new functions and kg_pkg_in_use redefined: nothing here locks or
-- rewrites a table, so the migration is safe at startup behind long
-- reads. Every statement is CREATE OR REPLACE, so a re-run is a no-op.
-- Timestamps are naive UTC, like runtime_coverage.

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

-- The guard for one package whose only file list is a node SBOM's: the
-- SBOM's guard above, then the package's own flags (node_sbom_package_flags,
-- keyed name@version, over every version of p_pkg the SBOM lists):
-- interpreted_content (bit 2: it owns interpreted or loadable
-- non-executable content, which exec/mmap capture cannot see), then
-- sbom_incomplete (bit 1, files_truncated: its file list is not whole,
-- including files the cataloger dropped as runtime drift). NULL when the
-- package may be installed_not_observed.
CREATE OR REPLACE FUNCTION kg_node_pkg_guard(
    p_cluster text, p_ns text, p_kind text, p_name text, p_container text, p_image text,
    p_pkg text, p_window_hours integer)
RETURNS text LANGUAGE sql STABLE AS $fn$
SELECT COALESCE(
    kg_node_sbom_guard(p_cluster, p_ns, p_kind, p_name, p_container, p_image, p_window_hours),
    (SELECT CASE WHEN bit_or(f.flags) & 2 <> 0 THEN 'interpreted_content'
                 WHEN bit_or(f.flags) & 1 <> 0 THEN 'sbom_incomplete' END
     FROM supplychain_image_links l
     JOIN image_sbom_components sc ON sc.digest = l.digest AND sc.source = l.source
         AND sc.name = p_pkg
     JOIN node_sbom_package_flags f ON f.digest = sc.digest
         AND f.pkg_key = sc.name || '@' || COALESCE(sc.version, '')
     WHERE l.image_digest = p_image AND l.source = 'node'))
$fn$;

-- kg_pkg_in_use (2026-10-03-100000) with node file lists let in:
--   * executed / loaded from runtime_package_use, as before (node file
--     lists now feed it too: in_use_store::refresh_image_use);
--   * not covered, or a language package: unknown, as before;
--   * a non-node SBOM lists the package's files: installed_not_observed,
--     exactly as before (Trivy Operator and registry SBOMs unchanged);
--   * no SBOM lists them: unknown:no_package_files, as before;
--   * only a node SBOM lists them: installed_not_observed only when
--     kg_node_pkg_guard passes, else unknown:<its reason>.
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
            ELSE COALESCE('unknown:' || kg_node_pkg_guard(p_cluster, p_ns, p_kind, p_name,
                              p_container, p_image, p_pkg, c.window_hours),
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
                          AS reason,
                      (SELECT window_hours FROM runtime_in_use_coverage cv
                       WHERE cv.cluster_id = p_cluster AND cv.pod_namespace = p_ns
                         AND cv.workload_kind = p_kind AND cv.workload_name = p_name
                         AND cv.container_name = p_container AND cv.image_digest = p_image)
                          AS window_hours) c)
    )
$$;
