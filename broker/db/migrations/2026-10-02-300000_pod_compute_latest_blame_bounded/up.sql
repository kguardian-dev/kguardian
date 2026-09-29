-- Keep pod_compute_latest's rows small enough to never be TOASTed.
--
-- After the HOT fix (2026-10-01-100000_pod_compute_latest_hot_updates) the
-- heap stayed the size of the live container set, but with autovacuum
-- stopped on the dev cluster the table still grew by about 1 GB an hour:
-- 740 MB of its 982 MB was the TOAST table, and one VACUUM removed 481 k
-- dead TOAST tuples against 18 k dead heap tuples. The `blame` column held
-- the Controller's whole culprit list, up to 20 entries and ~4 KB of JSONB,
-- which does not compress below the ~2 KB TOAST threshold (pod UIDs and
-- ReplicaSet hashes are random). A TOASTed value is written out of line
-- as new TOAST rows on every upsert and the old ones are left dead; HOT
-- does not apply to them, and only VACUUM reclaims them.
--
-- The Broker now keeps the heaviest five culprits, at most 1 KB of JSON
-- (`bound_blame` in src/compute_types.rs), so the row stays inline: with
-- ordinary names uncompressed, and at the longest names Kubernetes allows
-- compressed in place, with no TOAST writes either way. These two columns
-- record what it left off, so the UI's blame shares are taken over
-- everything the Controller sent (its own top 20 per container,
-- SAMPLE_BLAME_LIMIT) rather than over the five kept, and the panel can
-- say that more culprits exist. 0 is the truth for rows written before this
-- migration, by a Broker that did not truncate. An older Broker still
-- upserting during a rolling update never sets these columns, so a row it
-- rewrites keeps the new Broker's last counts next to its own full list
-- until the rollout finishes: shares a little low, for a few minutes.
--
-- ADD COLUMN with a constant default is catalog-only (no rewrite, no scan),
-- so this is instant on any size of table once it has the lock.
-- `lock_timeout` for the same reason as the HOT migration: a queued ACCESS
-- EXCLUSIVE request stalls every later upsert and read behind it, so give
-- up after 5 s and let the migration retry loop try again.
--
-- The dead TOAST rows already there are reclaimed by the next VACUUM (the
-- Broker's own maintenance pass, src/maintenance.rs, when autovacuum is not
-- keeping up); every row's next upsert moves its value back inline.
SET LOCAL lock_timeout = '5s';

ALTER TABLE pod_compute_latest
    ADD COLUMN IF NOT EXISTS blame_omitted INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS blame_omitted_wait_ns BIGINT NOT NULL DEFAULT 0;
