-- Drop the indexes before the column: dropping the column would take
-- idx_pod_details_pod_ips with it anyway, but being explicit keeps the
-- down migration readable and leaves idx_pod_details_pod_ip (which is
-- on a column that survives) correctly accounted for.
DROP INDEX IF EXISTS idx_pod_details_pod_ips;
DROP INDEX IF EXISTS idx_pod_details_pod_ip;
ALTER TABLE pod_details DROP COLUMN IF EXISTS pod_ips;
