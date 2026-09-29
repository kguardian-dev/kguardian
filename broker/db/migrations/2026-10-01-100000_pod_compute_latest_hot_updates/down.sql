-- Back to the original indexes and storage defaults. The rows the up
-- migration truncated are not restored; the Controllers refill the table on
-- their next sample.
ALTER TABLE pod_compute_latest RESET (
    fillfactor,
    autovacuum_vacuum_scale_factor,
    autovacuum_vacuum_threshold,
    autovacuum_vacuum_cost_delay,
    toast.autovacuum_vacuum_scale_factor,
    toast.autovacuum_vacuum_threshold
);

CREATE INDEX IF NOT EXISTS idx_pod_compute_latest_node ON pod_compute_latest (node);
CREATE INDEX IF NOT EXISTS idx_pod_compute_latest_updated_at ON pod_compute_latest (updated_at);
