-- Peer identity resolved at INGEST time (v4 peer-attribution fix).
--
-- pod_traffic rows used to store only the peer's IP; every consumer
-- (map, generators, GET /pod/ip/{ip}) resolved IP -> pod at READ time
-- against pod_details, which is keyed by pod_name and upserted, so IP
-- ownership history is lost. Pod IPs are recycled constantly (hourly
-- Jobs) and a row from July resolved to whichever pod holds the
-- address today: the map drew autobrr -> cmangos-database for flows
-- that predate autobrr by weeks, and Job labels leaked into policies.
--
-- The broker now stamps the peer's identity on the row when the flow
-- arrives (the same thing Cilium Hubble does: the Endpoint identity is
-- captured with the flow and never recomputed from the IP later).
--
--   peer_kind          'pod' | 'node' (host-network pod) | 'service';
--                      NULL = unresolved (external, legacy, or the
--                      peer's spec never arrived within the late-
--                      resolve window)
--   peer_namespace     the peer pod's / Service's namespace
--   peer_name          the peer pod's / Service's name
--   peer_uid           pod_obj.metadata.uid / service_spec.metadata.uid
--   peer_workload_kind the peer pod's owning controller kind (Job pods
--   peer_workload_name   group under their CronJob on the map)
--   peer_resolved_at   when the identity was stamped
--
-- Every column is nullable and appended AFTER time_stamp so the
-- positional Queryable/Insertable ordering of
-- broker/src/types.rs::PodTraffic stays aligned with the physical
-- column order. ADD COLUMN of a nullable column with no default is a
-- catalog-only change in Postgres: no rewrite of the multi-million-row
-- table.
--
-- Deliberately NO backfill: resolving today's table against today's
-- pod_details would re-create exactly the bug. Rows written before
-- this migration keep peer_* = NULL and consumers fall back to the
-- by-IP lookup with the start-time guard (GET /pod/ip/{ip}?at=).
--
-- No new index: the late-resolve pass reads
--   WHERE peer_kind IS NULL AND time_stamp > now - window
--   ORDER BY time_stamp DESC LIMIT n
-- which the existing idx_pod_traffic_time_stamp (time_stamp DESC,
-- uuid DESC) serves as a bounded range scan, and no consumer filters
-- per-pod reads by peer_kind (they read every row for the pod, via
-- idx_pod_traffic_pod_name). A (pod_name, peer_kind) btree over 6.7M
-- rows is not cheap and would serve nothing.
ALTER TABLE pod_traffic
  ADD COLUMN IF NOT EXISTS peer_kind VARCHAR,
  ADD COLUMN IF NOT EXISTS peer_namespace VARCHAR,
  ADD COLUMN IF NOT EXISTS peer_name VARCHAR,
  ADD COLUMN IF NOT EXISTS peer_uid VARCHAR,
  ADD COLUMN IF NOT EXISTS peer_workload_kind VARCHAR,
  ADD COLUMN IF NOT EXISTS peer_workload_name VARCHAR,
  ADD COLUMN IF NOT EXISTS peer_resolved_at TIMESTAMP;

-- When the pod started (pod_obj.status.startTime, as naive UTC). The
-- start-time guard needs it: a flow must never resolve to a pod that
-- started AFTER the flow was observed. A real column rather than a
-- read-time derivation because compact_pod_obj strips `status` from
-- the stored manifest at write time; the value is captured on
-- /pod/spec before the compaction runs. NULL = unknown (row last
-- written by an older broker, or a manifest without status.startTime)
-- and is NOT excluded by the guard — it just ranks after any candidate
-- with a known start. No backfill is possible: existing rows hold no
-- status. Live pods fill in on their next watch upsert (every pod is
-- re-posted when the controller restarts). Appended last for the same
-- positional reason as above.
ALTER TABLE pod_details ADD COLUMN IF NOT EXISTS started_at TIMESTAMP;
