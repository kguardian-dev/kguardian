-- Give back the space seccomp_crs lost to rewrites of unchanged rows.
--
-- The table mirrors one row per SeccompProfile CR. On the dev cluster it
-- held 3 live rows in 16 GB (3.6 M dead tuples), and the COUNT(*) that
-- GET /seccomp/profiles runs over it was being cancelled by the 30 s
-- statement timeout. The rows were not changing: every Controller PUT
-- every CR's mirror on every reconcile, and the Broker's upsert rewrote
-- the row each time: a new tuple, syscall list included, per PUT whether
-- or not anything in it differed. The Controller now sends only on change
-- or every tenth pass (#1744), and the Broker now skips the write when the
-- incoming mirror equals the stored one (`upsert_cr_mirror` in
-- src/seccomp.rs), so the table stops growing. That does not shrink what
-- is already there, and on a 3-row table a sequential scan still reads
-- every one of those 16 GB.
--
-- TRUNCATE rather than copying the live rows out and back: finding 3 rows
-- in 16 GB is a full scan, minutes on a large database, run before the
-- Broker starts serving, and VACUUM FULL cannot run inside the migration's
-- transaction. The mirror is not a source of truth: the Controllers
-- re-send every CR within ten reconciles (about five minutes at the
-- default resync; MIRROR_REFRESH_PASSES in the Controller's
-- seccomp_distributor.rs, written for exactly this "the Broker lost the
-- row" case), and older Controllers on every reconcile.
--
-- Emptying the mirror is visible while it refills, so it is done only on a
-- table that is actually bloated. Until a workload's CR is mirrored again
-- its profile has no `cr`: it reports the medium finding
-- `syscalls.no_enforcing_profile` (and the findings gauge counts it), and
-- because the profile snapshot includes the CR, the snapshotter records
-- one profile version without it and another when it returns. Nothing
-- marks the mirror as incomplete, so the profile cannot tell this apart
-- from a CR that was really deleted.
--
-- 256 MB of heap, TOAST and indexes is the line. A healthy row is a few
-- KB (the longest allow list is a few hundred syscall names), so ten
-- thousand CRs stay under 100 MB, while the bloat this cleans up was
-- 16 GB. A healthy install, however large, keeps its rows.
--
-- `lock_timeout` for the same reason as the pod_compute_latest migration:
-- a queued ACCESS EXCLUSIVE request makes every later reader wait behind
-- it. Past 5 s the migration fails and the Broker's retry loop tries again.
SET LOCAL lock_timeout = '5s';

DO $$
BEGIN
    IF pg_total_relation_size('seccomp_crs') > 256 * 1024 * 1024 THEN
        TRUNCATE seccomp_crs;
    END IF;
END
$$;
