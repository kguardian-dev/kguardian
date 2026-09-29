-- pod_traffic / pod_syscalls only had their primary-key indexes (uuid),
-- so the broker's hot query paths were full sequential scans of tables
-- that grow into the millions of rows:
--   * get_row() dedup runs on EVERY inserted traffic event, filtering on
--     (pod_ip, pod_port, traffic_type, traffic_in_out_ip,
--      traffic_in_out_port, decision)
--   * /pod/traffic/<name> (frontend per-pod view) filters on pod_name
--   * /pod/ip/<ip> filters on pod_ip
--   * /pod/syscalls/<name> filters on pod_name
-- The frontend fetches per-pod traffic + syscalls for every pod when a
-- view loads, so those seqscans burst-saturate the broker — observed in
-- production as a liveness-probe crash-loop under UI load, and slow
-- ingest (the dedup seqscan ran per insert). Index the actual shapes.
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
        CREATE INDEX IF NOT EXISTS idx_pod_traffic_pod_name ON pod_traffic (pod_name);
        CREATE INDEX IF NOT EXISTS idx_pod_traffic_pod_ip ON pod_traffic (pod_ip);
        CREATE INDEX IF NOT EXISTS idx_pod_traffic_dedup
          ON pod_traffic (pod_ip, pod_port, traffic_type, traffic_in_out_ip, traffic_in_out_port, decision);
    END IF;
END
$$;

DO $$
DECLARE
    max_bytes bigint := COALESCE(
        NULLIF(current_setting('kguardian.inline_index_max_bytes', true), '')::bigint,
        256 * 1024 * 1024);
BEGIN
    IF pg_relation_size('pod_syscalls') > max_bytes THEN
        RAISE NOTICE 'pod_syscalls is % bytes; its indexes are built CONCURRENTLY by the Broker after startup',
            pg_relation_size('pod_syscalls');
    ELSE
        CREATE INDEX IF NOT EXISTS idx_pod_syscalls_pod_name ON pod_syscalls (pod_name);
    END IF;
END
$$;
