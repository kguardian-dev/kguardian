-- Node catalog (docs/design/node-catalog.md): the broker grants each
-- inventory digest to exactly one node that runs it, and stores the SBOM
-- that node's cataloger produced as source 'node'. New tables, one new
-- function, and kg_pkg_in_use redefined to ignore source 'node' (end of
-- file): nothing here locks or rewrites an existing table, so the
-- migration is safe at startup behind long reads. Every statement is
-- IF NOT EXISTS / OR REPLACE, so a re-run is a no-op.
--
-- Unlike the older tables, the times here are timestamptz and compared
-- with the database's now() only: lease expiry, backoff and skip expiry
-- must never depend on a node's or a replica's clock.

-- One row per inventory digest a node has offered. state:
--   pending  claimable (new, released, or a per-node refusal)
--   claimed  granted to `node` under `claim_token` until lease_expires_at
--   done     an SBOM was stored (or a newer one already was)
--   failed   timeout / oom / error; claimable again at next_attempt_at
CREATE TABLE IF NOT EXISTS node_catalog_claims (
    inventory_digest VARCHAR     PRIMARY KEY,
    -- os/arch[/variant] the SBOM was cataloged for, and the platform
    -- manifest when the node could resolve it.
    platform         VARCHAR     NULL,
    manifest_digest  VARCHAR     NULL,
    state            VARCHAR     NOT NULL DEFAULT 'pending'
                     CHECK (state IN ('pending', 'claimed', 'done', 'failed')),
    -- The node holding (or that last held) the claim.
    node             VARCHAR     NULL,
    claim_token      UUID        NULL,
    lease_expires_at TIMESTAMPTZ NULL,
    -- Grants so far, and consecutive timeout/oom/error failures (the
    -- backoff step: 1 h, 6 h, then 24 h).
    attempts         INTEGER     NOT NULL DEFAULT 0,
    failures         INTEGER     NOT NULL DEFAULT 0,
    next_attempt_at  TIMESTAMPTZ NULL,
    -- Why the last attempt ended without an SBOM (or no_packages_found /
    -- superseded on a done row).
    reason           VARCHAR     NULL,
    -- {node: when it was skipped}. A node is not granted this digest for
    -- 24 h after that time (compared with now(); stale entries are
    -- dropped whenever the row is written).
    skipped_nodes    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    -- {node: {"n": pid_gone/drift failures, "since": first of them}}: at
    -- 3 within 24 h the node goes into skipped_nodes.
    node_retries     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    -- Catalog epoch (cataloger generation). Grants need a node epoch at
    -- least this; a done row is re-granted to a node with a higher one.
    epoch            BIGINT      NOT NULL DEFAULT 0,
    -- full | partial | os_only, why it is not full, and the cataloger's
    -- stats (cataloger/PROTOCOL.md 4.1), from the page that completed
    -- the SBOM.
    completeness     VARCHAR     NULL,
    partial_reasons  TEXT[]      NOT NULL DEFAULT '{}',
    stats            JSONB       NOT NULL DEFAULT '{}'::jsonb,
    sbom_set_id      VARCHAR     NULL,
    content_hash     VARCHAR     NULL,
    -- Running containers of the digest (refreshed by the leader's
    -- supply-chain pass); higher is granted first.
    priority         INTEGER     NOT NULL DEFAULT 0,
    cataloged_at     TIMESTAMPTZ NULL,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_node_catalog_claims_state
    ON node_catalog_claims (state, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_node_catalog_claims_lease
    ON node_catalog_claims (lease_expires_at) WHERE state = 'claimed';

-- The platform each node reported with its last offer. A node missing
-- here counts as a platform mismatch (fail closed).
CREATE TABLE IF NOT EXISTS node_catalog_platforms (
    node     VARCHAR     PRIMARY KEY,
    platform VARCHAR     NOT NULL,
    seen_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Per-package flags of a node SBOM, keyed name@version (the in-use
-- package key). bit 1 files_truncated, bit 2 interpreted_content. A side
-- table, not a column on image_sbom_components: ADD COLUMN there would
-- take an ACCESS EXCLUSIVE lock at startup.
CREATE TABLE IF NOT EXISTS node_sbom_package_flags (
    digest  VARCHAR  NOT NULL,
    pkg_key VARCHAR  NOT NULL,
    flags   SMALLINT NOT NULL,
    PRIMARY KEY (digest, pkg_key)
);

-- Whether a live pod on node p_node runs digest p_digest, from the data
-- the controller already posts to /pod/spec:
--   pod_details   (pod_name, pod_namespace, node_name, is_dead,
--                  workload_kind, workload_name)
--   workload_containers (pod_namespace, workload_kind, workload_name,
--                  image_digest, state, last_seen, last_pod_name)
-- joined on the workload key the inventory itself uses: a pod with an
-- owner is (namespace, workload_kind, workload_name), a bare pod is
-- (namespace, 'Pod', pod_name). The inventory row must be running by the
-- inventory's own state rule, and either refreshed within the running
-- window or last reported by this very pod.
--
-- The inventory is per workload, not per pod, so during a rollout that
-- runs two digests of one container on different nodes, a node running
-- either passes for both. The controller only offers digests it runs
-- locally; this check bounds what a stolen catalog token can post to
-- digests of workloads with a live pod on that node.
CREATE OR REPLACE FUNCTION kg_digest_runs_on_node(
    p_digest text, p_node text, p_window_secs double precision)
RETURNS boolean LANGUAGE sql STABLE AS $fn$
    SELECT EXISTS (
        SELECT 1 FROM workload_containers wc
        JOIN pod_details pd
          ON pd.pod_namespace = wc.pod_namespace
         AND pd.workload_kind = wc.workload_kind
         AND pd.workload_name = wc.workload_name
        WHERE wc.image_digest = p_digest AND pd.node_name = p_node AND NOT pd.is_dead
          AND (wc.state IS NULL OR wc.state = 'running'
               OR (wc.state = 'waiting' AND wc.state_reason = 'CrashLoopBackOff'))
          AND (wc.last_seen >= timezone('UTC', now()) - make_interval(secs => p_window_secs)
               OR wc.last_pod_name = pd.pod_name)
    ) OR EXISTS (
        SELECT 1 FROM workload_containers wc
        JOIN pod_details pd
          ON pd.pod_name = wc.workload_name
         AND pd.pod_namespace = wc.pod_namespace
        WHERE wc.image_digest = p_digest AND wc.workload_kind = 'Pod'
          AND (NULLIF(pd.workload_kind, '') IS NULL OR NULLIF(pd.workload_name, '') IS NULL)
          AND pd.node_name = p_node AND NOT pd.is_dead
          AND (wc.state IS NULL OR wc.state = 'running'
               OR (wc.state = 'waiting' AND wc.state_reason = 'CrashLoopBackOff'))
          AND (wc.last_seen >= timezone('UTC', now()) - make_interval(secs => p_window_secs)
               OR wc.last_pod_name = pd.pod_name)
    )
$fn$;

-- Node SBOMs feed no in-use verdict yet: kg_pkg_in_use (2026-09-28-200000)
-- as it was, except that a source 'node' file list never makes a package
-- installed_not_observed. The platform / completeness / flag guard that
-- lets them in is design section 5 (a later migration). Unchanged for
-- every other source.
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
