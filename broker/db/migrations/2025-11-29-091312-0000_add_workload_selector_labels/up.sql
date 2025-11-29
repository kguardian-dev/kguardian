-- Add workload_selector_labels column to pod_details table
ALTER TABLE pod_details ADD COLUMN workload_selector_labels JSON;
