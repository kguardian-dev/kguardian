-- Image signature and attestation discovery (#1533 P2-1).
--
-- The supplychain component verifies the cosign signatures and Sigstore
-- attestations of every running image digest and posts one result per
-- digest (POST /images/{digest}/attestation). This table holds the latest
-- result for each digest; the full contract is in
-- broker/src/attestation.rs.
--
-- Growth is bounded by `images` (one row per digest at most, and ingest
-- refuses a digest the inventory does not hold). The broker's attestation
-- retention pass (attestation.rs) deletes rows whose digest left the
-- inventory and rows not re-checked within IMAGE_ATTESTATION_RETENTION_DAYS
-- (default 7). No foreign key to `images`: like the other supply-chain
-- tables, this one is cleaned by its own pass, so nothing that truncates
-- or rewrites the inventory has to know about it.
CREATE TABLE IF NOT EXISTS image_attestations (
    digest        VARCHAR   PRIMARY KEY,
    repository    VARCHAR   NOT NULL,
    -- verified | key_signed | unsigned | invalid | unknown
    verdict       VARCHAR   NOT NULL,
    reason        VARCHAR   NULL,
    -- public-good | custom:<sha256 prefix of trusted_root.json>
    trust_root    VARCHAR   NULL,
    -- self | index (signature found on the index that lists the digest)
    signed_via    VARCHAR   NULL,
    signed_digest VARCHAR   NULL,
    signatures    JSONB     NOT NULL DEFAULT '[]'::jsonb,
    attestations  JSONB     NOT NULL DEFAULT '[]'::jsonb,
    -- When the component checked (its clock, at most 60 s ahead of ours).
    checked_at    TIMESTAMP NOT NULL,
    received_at   TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc')
);
-- GET /attestations?verdict= and the retention sweep.
CREATE INDEX IF NOT EXISTS idx_image_attestations_verdict ON image_attestations (verdict, digest);
CREATE INDEX IF NOT EXISTS idx_image_attestations_checked_at ON image_attestations (checked_at);
