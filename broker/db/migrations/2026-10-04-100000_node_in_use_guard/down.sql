-- kg_pkg_in_use back to its 2026-10-03-100000 definition (a source 'node'
-- file list never makes a package installed_not_observed), then the guard
-- functions it no longer calls.
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
                    AND sc.name = p_pkg AND sc.source <> 'node'
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

DROP FUNCTION IF EXISTS kg_node_pkg_guard(text, text, text, text, text, text, text, integer);
DROP FUNCTION IF EXISTS kg_node_sbom_guard(text, text, text, text, text, text, integer);
