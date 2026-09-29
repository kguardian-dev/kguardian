-- The cluster-wide GET /pod/traffic reads the pod_traffic table
-- "most recent first": ORDER BY time_stamp DESC, uuid DESC LIMIT N
-- (see broker/src/get.rs::pod_traffic). The 2026-06-01 index migration
-- covered the dedup / per-pod / per-ip lookups but NOT this ordering, so
-- the endpoint fell back to a parallel seq-scan + full sort of the entire
-- table (millions of rows / multi-GB) on every call — tens of seconds and
-- a response large enough to overrun the mcp-server's body cap.
--
-- A btree on (time_stamp DESC, uuid DESC) matches the ORDER BY exactly, so
-- the bounded query becomes an index scan of the first N rows instead of a
-- whole-table sort.
--
-- Built here only while the table is small (256 MiB of heap by default;
-- the session setting kguardian.inline_index_max_bytes overrides it, which
-- is how the tests force either path). A plain CREATE INDEX holds a SHARE
-- lock that blocks every insert for the whole build, and an install
-- upgrading with a large table would sit in that build past the liveness
-- probe (docs/installation.mdx, Upgrade). On a larger table this skips,
-- and the Broker builds the same index CONCURRENTLY after startup
-- (broker/src/background_index.rs). Fresh installs have empty tables and
-- always get it here. lock_timeout: a queued SHARE lock request blocks
-- every later insert too, so give up after 5 s and let the migration
-- retry rather than wait behind a long transaction.
SET LOCAL lock_timeout = '5s';

DO $$
DECLARE
    max_bytes bigint := COALESCE(
        NULLIF(current_setting('kguardian.inline_index_max_bytes', true), '')::bigint,
        256 * 1024 * 1024);
BEGIN
    IF pg_relation_size('pod_traffic') > max_bytes THEN
        RAISE NOTICE 'pod_traffic is % bytes; its indexes are built CONCURRENTLY by the Broker after startup',
            pg_relation_size('pod_traffic');
    ELSE
        CREATE INDEX IF NOT EXISTS idx_pod_traffic_time_stamp
          ON pod_traffic (time_stamp DESC, uuid DESC);
    END IF;
END
$$;
