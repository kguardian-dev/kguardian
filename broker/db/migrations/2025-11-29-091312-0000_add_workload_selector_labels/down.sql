-- Remove workload_selector_labels column from pod_details table
ALTER TABLE pod_details DROP COLUMN workload_selector_labels;
