-- Capability use per workload container (#1533 P2-7).
--
-- The controller counts every capability check a container's tasks make
-- (security_capable, or cap_capable), per capability and verdict, and posts
-- the count since its previous post to POST /runtime/capabilities.
-- Container runtime setup (a host-forked task before its exec) and checks
-- against a user namespace the container created are not counted.
-- CAP_OPT_NOAUDIT checks are counted apart as "probed" (probed = true):
-- often the kernel asking whether a task would be privileged (every root
-- process's memory admin-reserve check asks for SYS_ADMIN), but some gate
-- real behaviour. One row per (workload, container, image digest,
-- capability, verdict, probed); counts add up across replicas and posts.
--
-- last_reported: when a controller last reported the row. A running
-- container's rows are re-reported hourly even with no new use, so a
-- capability used once at startup is kept for as long as the workload
-- runs; retention prunes by this column.
CREATE TABLE IF NOT EXISTS runtime_capabilities (
    cluster_id     VARCHAR   NOT NULL DEFAULT 'primary',
    pod_namespace  VARCHAR   NOT NULL,
    workload_kind  VARCHAR   NOT NULL,
    workload_name  VARCHAR   NOT NULL,
    container_name VARCHAR   NOT NULL,
    image_digest   VARCHAR   NOT NULL,
    -- Kubernetes spelling, no CAP_ prefix (NET_BIND_SERVICE); CAP_<n> for a
    -- number newer than the controller knows.
    capability     VARCHAR   NOT NULL,
    -- true: the check succeeded (the capability was used). false: the task
    -- asked and did not have it.
    granted        BOOLEAN   NOT NULL,
    -- A CAP_OPT_NOAUDIT check (see above).
    probed         BOOLEAN   NOT NULL DEFAULT false,
    count          BIGINT    NOT NULL DEFAULT 0,
    last_pod_name  VARCHAR   NULL,
    first_seen     TIMESTAMP NOT NULL,
    last_seen      TIMESTAMP NOT NULL,
    last_reported  TIMESTAMP NOT NULL,
    PRIMARY KEY (cluster_id, pod_namespace, workload_kind, workload_name, container_name,
                 image_digest, capability, granted, probed)
);
CREATE INDEX IF NOT EXISTS idx_runtime_capabilities_last_reported
    ON runtime_capabilities (last_reported);

-- Whether the capability probe was attached, and on which hook
-- (cap_capable sees every check; the security_capable fallback misses
-- commoncap's direct ones), per heartbeat. A change of either restarts the
-- gap-free run like any other probe change.
ALTER TABLE runtime_coverage ADD COLUMN IF NOT EXISTS cap_probe BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE runtime_coverage ADD COLUMN IF NOT EXISTS cap_hook VARCHAR NULL;

-- Whether a workload container running `image` had its capability checks
-- watched for its whole life, for the last `window_hours`. Stricter than
-- kg_runtime_coverage, which also accepts a container backfilled from
-- /proc: capabilities have no backfill, so a container already running
-- when the probe attached may have used a capability (at startup) that
-- was never seen. Covered only when:
--   * kg_runtime_coverage covers it (probes, drops, heartbeats, window);
--   * every instance in the window had the capability probe on, on the
--     cap_capable hook (the security_capable fallback misses checks);
--   * every instance in the window was captured from its start with no
--     gap since (start_mode 'start', covered_since = tracking_since), which
--     a probe or hook change breaks.
-- Otherwise covered=false with kg_runtime_coverage's reason, or
-- capabilities_not_tracked, capabilities_partial_hook,
-- capabilities_not_seen_since_start.
CREATE OR REPLACE FUNCTION kg_capability_coverage(
    p_cluster text, p_ns text, p_kind text, p_name text, p_container text, p_image text,
    p_window_hours integer)
RETURNS TABLE (covered boolean, observed_since timestamp, reason text)
LANGUAGE sql STABLE AS $fn$
WITH r AS (
    SELECT * FROM kg_runtime_coverage(p_cluster, p_ns, p_kind, p_name, p_container, p_image,
                                      p_window_hours)
),
c AS (
    SELECT COALESCE(bool_and(cap_probe), false) AS all_cap,
           COALESCE(bool_and(cap_hook = 'cap_capable'), false) AS full_hook,
           COALESCE(bool_and(start_mode = 'start' AND covered_since = tracking_since), false)
               AS whole_life
    FROM runtime_coverage
    WHERE cluster_id = p_cluster AND pod_namespace = p_ns AND workload_kind = p_kind
      AND workload_name = p_name AND container_name = p_container AND image_digest = p_image
      AND last_heartbeat >= timezone('UTC', now())
          - make_interval(hours => GREATEST(p_window_hours, 0))
)
SELECT (r.covered AND c.all_cap AND c.full_hook AND c.whole_life) AS covered,
       r.observed_since,
       CASE WHEN NOT r.covered THEN r.reason
            WHEN NOT c.all_cap THEN 'capabilities_not_tracked'
            WHEN NOT c.full_hook THEN 'capabilities_partial_hook'
            WHEN NOT c.whole_life THEN 'capabilities_not_seen_since_start'
       END AS reason
FROM r, c
$fn$;
