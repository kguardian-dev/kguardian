-- Test reference (not a migration): the in-use guard as first written, with
-- kg_node_sbom_guard evaluated live on every kg_pkg_in_use call rather than
-- once per container in runtime_node_sbom_guard. The live tests install it
-- beside the shipped kg_pkg_in_use (it calls the shipped kg_node_sbom_guard)
-- and assert both give the same text after every in-use refresh.
CREATE OR REPLACE FUNCTION kg_node_pkg_guard_per_call(
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

CREATE OR REPLACE FUNCTION kg_pkg_in_use_per_call(
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
            ELSE COALESCE('unknown:' || kg_node_pkg_guard_per_call(p_cluster, p_ns, p_kind, p_name,
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
