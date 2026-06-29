-- Make HTTP/L7 dedup authoritative at the database level.
--
-- Previously the broker relied on a check-then-insert (SELECT exists(...)
-- then INSERT). That is not atomic: concurrent batches (multiple controller
-- DaemonSet pods, or one controller re-emitting after its in-memory cache is
-- cleared on restart) both pass the existence check before either commits and
-- both insert -> duplicate rows. It also never deduped within a single batch.
--
-- A unique index on the content columns lets us switch the insert to
-- ON CONFLICT DO NOTHING, which collapses duplicates atomically regardless of
-- batching, concurrency, or controller restarts.
--
-- COALESCE so NULL columns collapse to one row instead of being treated as
-- distinct (Postgres considers NULLs distinct in a plain unique index).
CREATE UNIQUE INDEX IF NOT EXISTS pod_http_traffic_content_uidx
  ON pod_http_traffic (
    COALESCE(pod_ip, ''),
    COALESCE(pod_port, ''),
    COALESCE(traffic_type, ''),
    COALESCE(traffic_in_out_ip, ''),
    COALESCE(traffic_in_out_port, ''),
    COALESCE(http_method, ''),
    COALESCE(http_path, '')
  );
