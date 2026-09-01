-- pod_details stores exactly ONE address per pod (`pod_ip`), which was
-- correct while every pod was single-stack. A dual-stack pod has both
-- an IPv4 and an IPv6 address; the controller writes whichever kubelet
-- reports as the primary (status.podIP) and the other one is simply
-- lost. Traffic observed on the second family then fails the
-- /pod/ip/<ip> lookup (broker/src/get.rs::pod_ip), and because that
-- lookup returning None is not an error — it is the advisor's signal
-- that the peer is external — policy generation silently degrades the
-- flow from a podSelector to a raw ipBlock. Nothing logs, nothing
-- fails; the generated policy is just quietly weaker than it should be.
--
-- `pod_ips` holds EVERY address the pod has, as a JSONB array of
-- canonicalised strings: lowercase with the longest zero-run
-- compressed to "::" for IPv6, and a plain dotted quad for IPv4
-- (IPv4-mapped forms like "::ffff:10.0.0.1" are un-mapped to
-- "10.0.0.1"). Canonicalisation matters as much as the extra column:
-- one IPv6 address has many spellings ("FD00::1",
-- "fd00:0:0:0:0:0:0:1", "fd00::1") and a string-equality or
-- containment match hits none of the variants. The broker normalises
-- on both the write and the read path (broker/src/ip.rs); the
-- controller — also Rust, via network::canonicalize_ip — emits the
-- same form, so the two ends agree. See broker/src/ip.rs for the full
-- cross-component contract.
--
-- Why a real column and not an expression index over pod_obj: pod_obj
-- looks like it already carries this data (it is the serialised Pod,
-- and status.podIPs is exactly the list we want), but the broker runs
-- compact_pod_obj() before storage (broker/src/get.rs) which removes
-- `status` wholesale to keep the row small — that slimming was added
-- deliberately to stop /pod/info ballooning to multi-MB responses.
-- status.podIPs is therefore NOT present in any stored row, and an
-- index over it would match nothing. Undoing the compaction to make
-- the shortcut work would trade a known-fixed performance problem for
-- a query convenience.
--
-- `pod_ip` is intentionally KEPT rather than replaced. The broker and
-- the controller are versioned and released independently
-- (RELEASES.md), so a controller old enough to post only `pod_ip` must
-- keep working against a broker new enough to have this column. The
-- lookup matches EITHER the legacy scalar or membership in the array,
-- and the write path always includes `pod_ip` in `pod_ips` so the two
-- can never disagree about the primary address.
ALTER TABLE pod_details ADD COLUMN IF NOT EXISTS pod_ips JSONB;

-- Backfill from the column we already have, so every existing row
-- resolves through the new predicate the moment this migration lands
-- instead of waiting for the controller to re-post each pod. Rows
-- written before canonicalisation existed keep whatever spelling they
-- were given: for IPv4 (all of them, in practice — this column
-- predates dual-stack support) the canonical form is byte-identical,
-- so no rewrite is needed. Guarded on NULL so re-running the migration
-- against a partially-migrated database cannot clobber real data.
UPDATE pod_details
   SET pod_ips = jsonb_build_array(pod_ip)
 WHERE pod_ips IS NULL
   AND pod_ip IS NOT NULL
   AND pod_ip <> '';

-- GIN with jsonb_path_ops: smaller and faster than the default
-- jsonb_ops for the only operator this lookup uses (`@>`
-- containment). The key-existence operators (?, ?|, ?&) that
-- jsonb_ops additionally supports are never used against this column.
CREATE INDEX IF NOT EXISTS idx_pod_details_pod_ips
  ON pod_details USING GIN (pod_ips jsonb_path_ops);

-- The lookup is `WHERE pod_ip = $1 OR pod_ips @> $2`. Postgres can
-- only turn an OR across two columns into a BitmapOr when BOTH sides
-- are indexable; with pod_details.pod_ip unindexed (it never was — the
-- 2026-06-01 index migration covered pod_traffic.pod_ip, a different
-- table) the planner would fall back to a sequential scan of
-- pod_details for every peer resolution the advisor performs. One
-- btree makes the whole predicate index-driven.
CREATE INDEX IF NOT EXISTS idx_pod_details_pod_ip
  ON pod_details (pod_ip);
