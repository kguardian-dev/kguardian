-- One row per node: coarse environment facts the controller derives
-- from its own Node object (provider/distro/CNI/IP family/OS family),
-- aggregated into the anonymous telemetry check-in (contract v2, see
-- docs/telemetry.mdx). Tiny table (node count rows), upserted on
-- controller start. IF NOT EXISTS keeps re-runs harmless.
CREATE TABLE IF NOT EXISTS node_facts (
    node_name VARCHAR PRIMARY KEY,
    provider VARCHAR NOT NULL,
    distro VARCHAR NOT NULL,
    cni VARCHAR NOT NULL,
    ip_family VARCHAR NOT NULL,
    node_os VARCHAR NOT NULL,
    time_stamp TIMESTAMP NOT NULL
);
