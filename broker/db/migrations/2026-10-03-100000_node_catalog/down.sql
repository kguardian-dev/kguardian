DROP FUNCTION IF EXISTS kg_digest_runs_on_node(text, text, double precision);
DROP TABLE IF EXISTS node_sbom_package_flags;
DROP TABLE IF EXISTS node_catalog_platforms;
DROP INDEX IF EXISTS idx_node_catalog_claims_lease;
DROP INDEX IF EXISTS idx_node_catalog_claims_state;
DROP TABLE IF EXISTS node_catalog_claims;
-- SBOM rows the node catalog stored live in the supply-chain tables under
-- source 'node'; without the catalog nothing refreshes or expires them
-- by the catalog's rules, so they go with it.
DELETE FROM image_sbom_components WHERE source = 'node';
DELETE FROM image_sbom_pages WHERE source = 'node';
DELETE FROM supplychain_image_links WHERE source = 'node';
DELETE FROM vuln_sources WHERE source = 'node';
