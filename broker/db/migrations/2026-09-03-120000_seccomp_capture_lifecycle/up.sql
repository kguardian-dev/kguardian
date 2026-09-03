-- Capture tier the controller was running for this pod when it last
-- upserted the row: one of full | high | medium | low | custom. Only
-- `full` records every syscall; the lower tiers allowlist-filter in BPF
-- and a profile built from them is INCOMPLETE and will ERRNO calls the
-- app really makes. NULL means "unknown" — a controller predating tiers
-- (or an invalid value) — and capture completeness treats that as
-- `low`, never as complete.
--
-- Added last so the positional Queryable/Insertable ordering of
-- broker/src/types.rs::PodDetail stays aligned with the physical column
-- order. AsChangeset skips None, so an older controller that omits the
-- field never nulls a value a newer one wrote.
ALTER TABLE pod_details ADD COLUMN IF NOT EXISTS capture_level VARCHAR;

-- Lifecycle of a generated profile. Nothing reaches a node unless the
-- operator has PUBLISHED the workload's profile: the distributor polls
-- `GET /seccomp/profiles?state=published` and only writes those.
-- Unpublishing flips state back to draft; files already on nodes are
-- left in place (never deleted) but stop being refreshed.
--
-- `forced` records that the profile was published while its capture was
-- incomplete (`{ "force": true }` on the publish call) — i.e. the
-- operator was told the profile would block syscalls and chose to go
-- ahead. It is the flag an incident review looks for first.
CREATE TABLE IF NOT EXISTS workload_seccomp_state (
    pod_namespace VARCHAR   NOT NULL,
    workload_kind VARCHAR   NOT NULL,
    workload_name VARCHAR   NOT NULL,
    state         VARCHAR   NOT NULL DEFAULT 'draft',  -- 'draft' | 'published'
    published_at  TIMESTAMP,
    published_by  VARCHAR,
    forced        BOOLEAN   NOT NULL DEFAULT false,
    PRIMARY KEY (pod_namespace, workload_kind, workload_name)
);

-- The override audit trail now also carries lifecycle actions. `op`
-- (introduced with the table) only ever held 'put' | 'delete'; `action`
-- is the canonical verb from here on — 'put' | 'delete' for override
-- writes, 'publish' | 'unpublish' | 'enforce' | 'audit' for lifecycle
-- calls — and existing rows are backfilled from `op` so a reader can
-- rely on `action` alone. `op` is kept (and still written) so nothing
-- that filters on it breaks.
ALTER TABLE seccomp_override_audit ADD COLUMN IF NOT EXISTS action VARCHAR NOT NULL DEFAULT '';
UPDATE seccomp_override_audit SET action = op WHERE action = '';
