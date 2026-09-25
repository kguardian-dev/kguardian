-- Image inventory (#1533 P0-2/P0-3).
--
-- The controller has always posted the whole Pod to /pod/spec, and the
-- broker has always compacted it to labels + hostNetwork before storage
-- (get.rs compact_pod_obj), so container image references, the digests
-- in status.containerStatuses[].imageID and every securityContext were
-- thrown away at ingest. The controller now sends a small typed
-- `containers` list and a `pod_security` block alongside the pod; these
-- two tables are where they land. Neither stores the manifest.
--
-- Growth is bounded by what is RUNNING, not by time or pod churn:
--   images               one row per distinct digest
--   workload_containers  one row per (workload, container)
-- and retention.rs prunes rows not refreshed within
-- IMAGE_INVENTORY_RETENTION_DAYS (default 30).
--
-- cluster_id: every row is 'primary' until multi-cluster ingest lands.
-- On workload_containers it is part of the key (a workload is per
-- cluster). On images it is NOT: a digest names the same content in any
-- cluster, so the digest alone stays the key and cluster_id records the
-- cluster that last reported it.

CREATE TABLE IF NOT EXISTS images (
    digest       VARCHAR   PRIMARY KEY,           -- sha256:<hex> / sha512:<hex>
    cluster_id   VARCHAR   NOT NULL DEFAULT 'primary',
    repository   VARCHAR   NULL,                  -- docker.io/library/nginx
    tags         TEXT[]    NOT NULL DEFAULT '{}', -- every tag seen for it, capped
    -- repo    = status.imageID repo@digest (registry-resolvable)
    -- config  = bare image config digest (no repo digest on the node)
    -- pinned  = digest pinned in the spec, container not started yet
    digest_kind  VARCHAR   NOT NULL,
    first_seen   TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    last_seen    TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc')
);
CREATE INDEX IF NOT EXISTS idx_images_last_seen ON images (last_seen);

CREATE TABLE IF NOT EXISTS workload_containers (
    cluster_id       VARCHAR   NOT NULL DEFAULT 'primary',
    -- Same (namespace, kind, name) key as workload_syscalls and the
    -- SeccompProfile workloadRef: the controller's owner-ref resolution
    -- (ReplicaSet->Deployment, Job->CronJob). A pod with no owner is
    -- keyed ('Pod', pod_name).
    pod_namespace    VARCHAR   NOT NULL,
    workload_kind    VARCHAR   NOT NULL,
    workload_name    VARCHAR   NOT NULL,
    container_name   VARCHAR   NOT NULL,
    container_kind   VARCHAR   NOT NULL,          -- init | regular | ephemeral
    image_ref        VARCHAR   NOT NULL,          -- as written in the spec
    image_digest     VARCHAR   NULL,              -- NULL until the kubelet reports one
    security_context JSONB     NOT NULL DEFAULT '{}'::jsonb,
    pod_security     JSONB     NOT NULL DEFAULT '{}'::jsonb,
    last_pod_name    VARCHAR   NULL,              -- the pod that last reported it
    first_seen       TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    updated_at       TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    PRIMARY KEY (cluster_id, pod_namespace, workload_kind, workload_name, container_name)
);
-- "Which workloads run this digest" (GET /images/{digest}, the GC's
-- NOT EXISTS) and the GC's own scan.
CREATE INDEX IF NOT EXISTS idx_workload_containers_digest ON workload_containers (image_digest);
CREATE INDEX IF NOT EXISTS idx_workload_containers_updated_at ON workload_containers (updated_at);
