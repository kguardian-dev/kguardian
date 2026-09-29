DROP INDEX IF EXISTS idx_vuln_cve_summary_upper;
DROP INDEX IF EXISTS idx_vuln_cve_summary_list;
CREATE INDEX IF NOT EXISTS idx_vuln_cve_summary_order
    ON vuln_cve_summary (scope_namespace, severity_rank DESC, vuln_id);
