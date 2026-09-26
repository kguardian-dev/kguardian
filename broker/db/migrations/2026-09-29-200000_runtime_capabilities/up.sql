-- Capability use per workload container (#1533 P2-7).
--
-- The controller counts every capability check a container's tasks make
-- (security_capable, or cap_capable), per capability and verdict, and posts
-- the count since its previous post to POST /runtime/capabilities.
-- CAP_OPT_NOAUDIT checks (the kernel asking whether a task would be
-- privileged, not the task needing it) and runc's own setup are not
-- counted. One row per (workload, container, image digest, capability,
-- verdict); counts add up across replicas and posts.
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
    count          BIGINT    NOT NULL DEFAULT 0,
    last_pod_name  VARCHAR   NULL,
    first_seen     TIMESTAMP NOT NULL,
    last_seen      TIMESTAMP NOT NULL,
    last_reported  TIMESTAMP NOT NULL,
    PRIMARY KEY (cluster_id, pod_namespace, workload_kind, workload_name, container_name,
                 image_digest, capability, granted)
);
CREATE INDEX IF NOT EXISTS idx_runtime_capabilities_last_reported
    ON runtime_capabilities (last_reported);

-- Whether the capability probe was attached, per heartbeat. A change
-- restarts the gap-free run like any other probe change.
ALTER TABLE runtime_coverage ADD COLUMN IF NOT EXISTS cap_probe BOOLEAN NOT NULL DEFAULT false;

-- Whether a workload container running `image` had its capability checks
-- watched continuously for the last `window_hours`: the runtime coverage
-- (kg_runtime_coverage: probes, drops, heartbeats, from start or backfill)
-- AND the capability probe on every instance in the window. Only then is
-- "never used capability X" evidence. Otherwise covered=false with
-- kg_runtime_coverage's reason, or capabilities_not_tracked.
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
    SELECT COALESCE(bool_and(cap_probe), false) AS all_cap
    FROM runtime_coverage
    WHERE cluster_id = p_cluster AND pod_namespace = p_ns AND workload_kind = p_kind
      AND workload_name = p_name AND container_name = p_container AND image_digest = p_image
      AND last_heartbeat >= timezone('UTC', now())
          - make_interval(hours => GREATEST(p_window_hours, 0))
)
SELECT (r.covered AND c.all_cap) AS covered,
       r.observed_since,
       CASE WHEN NOT r.covered THEN r.reason
            WHEN NOT c.all_cap THEN 'capabilities_not_tracked'
       END AS reason
FROM r, c
$fn$;
