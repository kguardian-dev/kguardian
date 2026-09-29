-- idx_vuln_cve_summary_order (scope, severity DESC, vuln_id) served the
-- CVE list's old severity-first order. The list is now in tier order,
-- read off idx_vuln_cve_summary_list (2026-10-02-100000), and nothing
-- reads by this index; it only costs a write per row on every summary
-- rebuild.
--
-- Its own migration, after the builds: DROP INDEX needs an ACCESS
-- EXCLUSIVE lock on the table, and while that request waits behind a
-- long reader, every new reader queues behind it. A short lock_timeout
-- keeps that queue to a second. If it gives up, only this drop rolls
-- back: the new indexes are already committed, and the Broker's
-- migration retry tries the drop again.
SET LOCAL lock_timeout = '1s';

DROP INDEX IF EXISTS idx_vuln_cve_summary_order;
