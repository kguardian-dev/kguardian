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
