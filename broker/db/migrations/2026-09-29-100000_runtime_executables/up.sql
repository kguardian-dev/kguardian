-- Runtime executable and shared-library inventory (#1533 P1-2).
--
-- The controller observes, per container, which files are executed
-- (execve) and which shared libraries are mapped, and posts the distinct
-- set to POST /runtime/executables. A path is recorded once per
-- (workload, container, image digest), not per pod or per event, so the
-- table grows with what a workload actually runs, not with pod churn or
-- exec rate. retention.rs prunes rows not seen within
-- RUNTIME_INVENTORY_RETENTION_DAYS (default 30).
--
-- image_digest is part of the key because a rollout changes what is on
-- disk: the same path under a new digest is a different file. '' means
-- the controller could not resolve the digest (the row still counts for
-- the workload view; it cannot join to an SBOM).
CREATE TABLE IF NOT EXISTS runtime_executables (
    cluster_id     VARCHAR   NOT NULL DEFAULT 'primary',
    -- Same (namespace, kind, name) workload key as workload_containers.
    pod_namespace  VARCHAR   NOT NULL,
    workload_kind  VARCHAR   NOT NULL,
    workload_name  VARCHAR   NOT NULL,
    container_name VARCHAR   NOT NULL,
    image_digest   VARCHAR   NOT NULL,
    kind           VARCHAR   NOT NULL CHECK (kind IN ('exec', 'lib')),
    path           VARCHAR   NOT NULL,
    -- false when the kernel-side path walk was cut short (buffer or depth
    -- limit): the path is a suffix, not the full absolute path.
    path_complete  BOOLEAN   NOT NULL DEFAULT true,
    -- ebpf = observed at runtime; backfill = read from /proc for a process
    -- that was already running when the controller started. An eBPF
    -- sighting is the stronger evidence and is never downgraded.
    source         VARCHAR   NOT NULL CHECK (source IN ('ebpf', 'backfill')),
    -- Where the file lived as it ran (controller runtime_inventory::Origin),
    -- least to most suspicious: unknown, image (overlayfs lower layer),
    -- otherFs (a volume, or a non-overlay rootfs), deleted, writableLayer
    -- (the container's overlayfs upper layer), memfd. The most suspicious
    -- sighting wins and is never downgraded; deleted/writableLayer/memfd
    -- are what P2-5 drift reads ("the image did not ship this").
    origin         VARCHAR   NOT NULL DEFAULT 'unknown' CHECK (origin IN
                       ('unknown', 'image', 'otherFs', 'deleted', 'writableLayer', 'memfd')),
    last_pod_name  VARCHAR   NULL,
    first_seen     TIMESTAMP NOT NULL,
    last_seen      TIMESTAMP NOT NULL,
    PRIMARY KEY (cluster_id, pod_namespace, workload_kind, workload_name, container_name,
                 image_digest, kind, path)
);
-- "Which of this image's files actually run" (GET /images/{digest}/runtime
-- and the P1-5 SBOM join on digest + path).
CREATE INDEX IF NOT EXISTS idx_runtime_executables_digest
    ON runtime_executables (image_digest, kind, path);
-- The retention scan.
CREATE INDEX IF NOT EXISTS idx_runtime_executables_last_seen
    ON runtime_executables (last_seen);

-- Capture coverage per container instance (#1533 P1-2, read by P1-5).
--
-- Runtime rows alone cannot say "this was watched and never ran": a path
-- is re-posted only hourly and a node with the feature off writes
-- nothing. So each controller heartbeats every container it tracks
-- (POST /runtime/coverage, every heartbeat_secs, default 300), whether or
-- not anything new ran.
--
-- start_mode: 'start' = the container started after the probe attached,
-- so its first exec was seen; 'backfill' = it was already running, and
-- capture begins at the /proc backfill (tracking_since). covered_since is
-- the start of the current gap-free run: tracking_since until a gap (a
-- reported kernel drop or overflow, a probe or mode change, or a
-- heartbeat later than 3 x heartbeat_secs + 60 s) moves it to the
-- heartbeat that ended the gap.
CREATE TABLE IF NOT EXISTS runtime_coverage (
    cluster_id     VARCHAR   NOT NULL DEFAULT 'primary',
    container_id   VARCHAR   NOT NULL,
    pod_namespace  VARCHAR   NOT NULL,
    workload_kind  VARCHAR   NOT NULL,
    workload_name  VARCHAR   NOT NULL,
    container_name VARCHAR   NOT NULL,
    image_digest   VARCHAR   NOT NULL,
    pod_name       VARCHAR   NOT NULL,
    node_name      VARCHAR   NOT NULL,
    mode           VARCHAR   NOT NULL CHECK (mode IN ('exec', 'full')),
    exec_probe     BOOLEAN   NOT NULL,
    lib_probe      BOOLEAN   NOT NULL,
    start_mode     VARCHAR   NOT NULL CHECK (start_mode IN ('start', 'backfill')),
    tracking_since TIMESTAMP NOT NULL,
    covered_since  TIMESTAMP NOT NULL,
    last_heartbeat TIMESTAMP NOT NULL,
    heartbeat_secs INTEGER   NOT NULL CHECK (heartbeat_secs > 0),
    gaps           INTEGER   NOT NULL DEFAULT 0,
    last_gap       VARCHAR   NULL,
    last_gap_at    TIMESTAMP NULL,
    ended          BOOLEAN   NOT NULL DEFAULT false,
    PRIMARY KEY (cluster_id, container_id)
);
CREATE INDEX IF NOT EXISTS idx_runtime_coverage_workload
    ON runtime_coverage (cluster_id, pod_namespace, workload_kind, workload_name, container_name,
                         image_digest);
CREATE INDEX IF NOT EXISTS idx_runtime_coverage_pod
    ON runtime_coverage (cluster_id, pod_namespace, pod_name);
CREATE INDEX IF NOT EXISTS idx_runtime_coverage_last_heartbeat
    ON runtime_coverage (last_heartbeat);

-- Whether a workload container running `image` was watched continuously
-- for the last `window_hours`, for "installed but never observed" (P1-5).
--
-- Covered when all of these hold:
--   * at least one instance heartbeated within the window;
--   * every such instance had the exec AND library probes loaded (exec
--     mode cannot vouch for a library never being loaded);
--   * every such instance is still heartbeating on time, or ended cleanly;
--   * every such instance was covered for its whole life (captured from
--     its start, no gap since) or continuously since before the window;
--   * no live pod of the workload runs the container without a fresh
--     heartbeat (a node with the feature off, an opted-out pod);
--   * coverage began at least window_hours ago (observed_since).
-- Otherwise not covered, with the reason in P1-5's vocabulary:
--   no_runtime_data (no instance), probes_missing, capture_gap.
-- Timestamps are naive UTC, like every broker table.
CREATE OR REPLACE FUNCTION kg_runtime_coverage(
    p_cluster text, p_ns text, p_kind text, p_name text, p_container text, p_image text,
    p_window_hours integer)
RETURNS TABLE (covered boolean, observed_since timestamp, reason text)
LANGUAGE sql STABLE AS $fn$
WITH w AS (
    SELECT timezone('UTC', now()) AS now_,
           timezone('UTC', now()) - make_interval(hours => GREATEST(p_window_hours, 0)) AS start_
),
inst AS (
    SELECT c.exec_probe, c.lib_probe, c.tracking_since, c.covered_since,
           (c.ended OR c.last_heartbeat
               >= w.now_ - make_interval(secs => 3 * c.heartbeat_secs + 60)) AS on_time,
           (c.start_mode = 'start' AND c.covered_since = c.tracking_since) AS whole_life
    FROM runtime_coverage c, w
    WHERE c.cluster_id = p_cluster AND c.pod_namespace = p_ns AND c.workload_kind = p_kind
      AND c.workload_name = p_name AND c.container_name = p_container
      AND c.image_digest = p_image AND c.last_heartbeat >= w.start_
),
agg AS (
    SELECT count(*) AS n,
           COALESCE(bool_or(NOT exec_probe OR NOT lib_probe), false) AS probes_missing,
           COALESCE(bool_or(NOT on_time), false) AS late_beat,
           COALESCE(bool_or(NOT whole_life AND covered_since > (SELECT start_ FROM w)), false)
               AS gap_in_window,
           min(CASE WHEN whole_life THEN tracking_since ELSE covered_since END) AS since
    FROM inst
),
untracked AS (
    SELECT count(*) AS n
    FROM pod_details p, w
    WHERE NOT p.is_dead AND p.pod_namespace = p_ns
      AND COALESCE(p.workload_kind, 'Pod') = p_kind
      AND COALESCE(p.workload_name, p.pod_name) = p_name
      AND EXISTS (
          SELECT 1 FROM jsonb_array_elements(
              COALESCE(p.pod_obj::jsonb -> 'spec' -> 'containers', '[]'::jsonb)) e
          WHERE e ->> 'name' = p_container)
      AND NOT EXISTS (
          SELECT 1 FROM runtime_coverage c
          WHERE c.cluster_id = p_cluster AND c.pod_namespace = p_ns
            AND c.pod_name = p.pod_name AND c.container_name = p_container AND NOT c.ended
            AND c.last_heartbeat >= w.now_ - make_interval(secs => 3 * c.heartbeat_secs + 60))
)
SELECT
    (a.n > 0 AND NOT a.probes_missing AND NOT a.late_beat AND NOT a.gap_in_window
        AND u.n = 0 AND a.since <= w.start_) AS covered,
    a.since AS observed_since,
    CASE
        WHEN a.n = 0 THEN 'no_runtime_data'
        WHEN a.probes_missing THEN 'probes_missing'
        WHEN a.late_beat OR a.gap_in_window OR u.n > 0 OR a.since > w.start_ THEN 'capture_gap'
        ELSE NULL
    END AS reason
FROM agg a, untracked u, w
$fn$;
