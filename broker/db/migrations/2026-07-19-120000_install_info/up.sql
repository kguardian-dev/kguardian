-- Single-row table holding this installation's anonymous identifier for
-- the version check-in (see broker/src/version_check.rs). The id is a
-- random UUID generated on first startup — it carries no cluster or user
-- information and exists only so repeated check-ins from the same install
-- can be counted once.
CREATE TABLE IF NOT EXISTS install_info (
    install_id VARCHAR PRIMARY KEY,
    created_at TIMESTAMP NOT NULL DEFAULT (timezone('utc', now()))
);
