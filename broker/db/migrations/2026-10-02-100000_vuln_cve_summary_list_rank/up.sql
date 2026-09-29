-- GET /vulnerabilities lists CVEs in tier order (P0, then not yet
-- computed, then P1, P2, Background), then severity, then id. No index
-- served that order: idx_vuln_cve_summary_tier sorts a NULL tier last, so
-- every page was a scan of the scope plus a top-N sort (20 ms first page
-- at 150 k CVEs).
--
-- The list rank is that order as one ascending number, tier position * 10
-- + (5 - severity). With vuln_id after it, the keyset "rows after the last
-- one" is the row comparison (rank, vuln_id) > (r, id), which the index
-- reads as a range: first and deep pages both read only the page (0.04 ms
-- and 0.06 ms at 150 k CVEs).
--
-- The mapping is total. A tier other than 0..3 (nothing writes one today)
-- takes the not-yet-computed position, never one below a known tier, and
-- severity is clamped to 0..5, so the cursor built from the rank always
-- parses. The expression must stay identical to cve_list_rank_sql! in
-- supplychain_read.rs, or the planner cannot use the index; a unit test
-- compares the two and a live test checks the plan.
--
-- An expression index rather than a stored column: adding a stored
-- generated column rewrites the table under an ACCESS EXCLUSIVE lock
-- (1.2 s at 300 k rows, every read waiting), while CREATE INDEX takes a
-- SHARE lock, so reads go on and only the summary rebuild waits for the
-- build (0.35 s per index at 300 k rows, 102 MB). The table is a rebuilt
-- summary, one row per CVE cluster-wide and per (namespace, CVE).
-- lock_timeout bounds the wait for the locks (a rebuild in flight holds
-- the table for its transaction): the migration rolls back and the
-- Broker's migration retry tries again.
--
-- idx_vuln_cve_summary_upper lets GET /vulnerabilities/{id}/exposure find
-- the stored spellings of an id case-insensitively without a scan.
--
-- The index the severity-first order used is dropped by the next
-- migration (2026-10-02-100100), not here: DROP INDEX needs an ACCESS
-- EXCLUSIVE lock, and a drop that timed out here would roll back these
-- builds with it.
SET LOCAL lock_timeout = '5s';

CREATE INDEX IF NOT EXISTS idx_vuln_cve_summary_list ON vuln_cve_summary (
    scope_namespace,
    (((CASE WHEN tier = 0 THEN 0 WHEN tier BETWEEN 1 AND 3 THEN tier + 1 ELSE 1 END) * 10 + (5 - LEAST(GREATEST(severity_rank, 0), 5)))::smallint),
    vuln_id
);
CREATE INDEX IF NOT EXISTS idx_vuln_cve_summary_upper
    ON vuln_cve_summary (upper(vuln_id));
