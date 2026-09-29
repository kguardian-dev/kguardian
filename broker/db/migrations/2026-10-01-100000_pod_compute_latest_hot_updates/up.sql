-- Keep pod_compute_latest the size of the live container set.
--
-- The table is meant to be one row per live container, upserted every
-- sample interval (5 s). On the dev cluster it held 15 k live rows in
-- 86 GB: 116 M dead tuples, 74 GB of heap and 9.7 GB of indexes, and the
-- reads on it (GET /compute/latest, the workload profile's compute block,
-- the stale prune) were being cancelled by the 30 s statement timeout.
--
-- Cause: none of its 741 M updates was HOT. Every upsert writes a new
-- `updated_at`, and `updated_at` was indexed, so Postgres could never
-- update a row in place on its page. Each upsert wrote a new heap tuple
-- AND a new entry in all four indexes, leaving the old ones for VACUUM to
-- find. At ~3 000 upserts a second that is more than autovacuum clears
-- (its last pass took 45 minutes and removed 1.3 M tuples), so the table
-- grew without bound. node_compute_latest has the same write pattern with
-- nothing indexed that changes, and all of its 15.5 M updates are HOT.
--
-- 1. Drop idx_pod_compute_latest_updated_at. Its only reader is the stale
--    prune in retention.rs, which runs every 10 minutes. On a healthy
--    table (a few MB) that prune is a sequential scan and a top-N sort,
--    milliseconds, the same shape node_compute_latest's prune already
--    uses without an index. With no changing column indexed, every
--    upsert can be HOT: the row keeps its index entries (container_uid,
--    namespace and node never change for a container) and the old
--    version is reclaimed by page pruning during ordinary reads and
--    writes, with no VACUUM involved.
--
-- 2. Drop idx_pod_compute_latest_node. Nothing filters this table by
--    node: GET /compute/latest filters by namespace and joins
--    node_compute_latest on ITS primary key, the workload profile filters
--    by namespace and pod name, and the prune filters by updated_at. It
--    had 0 scans on the dev cluster while costing 3.3 GB and a write on
--    every non-HOT update. The namespace index stays; both readers use it.
--
-- 3. fillfactor = 50. A HOT update needs room on the row's own page. Every
--    row here is rewritten every interval, so a page packed full (the
--    default, 100) forces the next update of any row on it off the page
--    and into the indexes again. Half a page left free fits one new
--    version of every row on the page between prunes. The cost is a table
--    twice the minimum size, which for a few MB is nothing next to the
--    alternative.
--
-- 4. Per-table autovacuum for a small table with this churn. Page pruning
--    does most of the work now, but it cannot remove dead line pointers,
--    index entries left by stale-container deletes, or keep the
--    visibility map current. A scale factor of 0 with a fixed threshold
--    makes autovacuum visit the table on every round (autovacuum_naptime,
--    1 minute by default) whatever the cluster size, instead of waiting
--    for 20% of the table to die, and a cost delay of 0 lets that pass
--    finish in well under a second rather than being throttled on a table
--    that is being rewritten while it waits. The TOAST table gets the same
--    two thresholds: a `blame` list long enough to be TOASTed is rewritten
--    out of line on every upsert, and that churn is invisible to the main
--    table's counters. Analyze is left at its defaults: the update rate
--    crosses the default threshold every round anyway, and what the
--    planner needs (row count, namespace spread) barely moves.
--
-- 5. TRUNCATE to give back what is already lost. The table is a live cache
--    the Controllers refill on their next sample (5 s), so emptying it
--    costs the UI one poll of empty gauges. It also means every page is
--    rewritten under the new fillfactor, which ALTER TABLE alone does not
--    do. VACUUM FULL would keep the rows but cannot run inside a
--    transaction (diesel runs each migration in one), and it holds an
--    ACCESS EXCLUSIVE lock while it copies an 86 GB table, blocking every
--    upsert and read for the whole copy. TRUNCATE takes the same lock for
--    an instant.
--
-- Safe during a rolling update: once it holds the lock nothing here scans
-- the table, so an older Broker's upserts wait only an instant, and its
-- writes and prune work the same without the two indexes. Getting the
-- lock is the risk. TRUNCATE needs ACCESS EXCLUSIVE, and while that
-- request is queued every later upsert and read queues behind it,
-- holding a pool connection each. Nothing bounds the wait on its own: an
-- anti-wraparound autovacuum, for one, does not yield to the request. So
-- `lock_timeout` gives up after 5 s; the transaction rolls back, the
-- Broker's migration retry loop tries again, and at worst the new pod
-- crash-loops while the old one keeps serving.
--
-- On a table that is already badly bloated, the old Broker's reads and
-- prunes can outlast 5 s every time, so that rollout stays stuck. Recover
-- by running `SET lock_timeout = '5s'; TRUNCATE pod_compute_latest;` from
-- psql until it succeeds, or by scaling the old Broker down for a moment;
-- the migration then finds an empty table (docs/installation.mdx, Upgrade).
--
-- None of this helps if something holds back the database's xmin horizon
-- (a long transaction, an abandoned replication slot, a reader replica
-- with hot_standby_feedback): neither page pruning nor VACUUM can remove a
-- version an old snapshot might still see.
SET LOCAL lock_timeout = '5s';

TRUNCATE pod_compute_latest;

DROP INDEX IF EXISTS idx_pod_compute_latest_updated_at;
DROP INDEX IF EXISTS idx_pod_compute_latest_node;

ALTER TABLE pod_compute_latest SET (
    fillfactor = 50,
    autovacuum_vacuum_scale_factor = 0,
    autovacuum_vacuum_threshold = 1000,
    autovacuum_vacuum_cost_delay = 0,
    toast.autovacuum_vacuum_scale_factor = 0,
    toast.autovacuum_vacuum_threshold = 1000
);
