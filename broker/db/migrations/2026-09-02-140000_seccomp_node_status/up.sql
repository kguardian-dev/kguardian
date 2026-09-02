-- One row per node running the seccomp distributor, listing the profile
-- files it currently has on disk (as their localhostProfile paths, which
-- already encode namespace/kind/name/hash). The distributor re-POSTs the
-- full list after every pass, so the row is a replace, not an append.
--
-- Used to compute per-profile distribution readiness: a profile is Ready
-- when every live node (COUNT(DISTINCT node_name) in pod_details) reports
-- its current path. Referencing a profile before it is Ready risks a pod
-- landing on a node that does not have the file yet -> CreateContainerError.
CREATE TABLE IF NOT EXISTS seccomp_node_status (
    node_name  VARCHAR   NOT NULL PRIMARY KEY,
    paths      JSONB     NOT NULL DEFAULT '[]'::jsonb,
    updated_at TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc')
);
