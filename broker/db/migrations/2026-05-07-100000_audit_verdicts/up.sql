-- Per-flow audit verdicts emitted by the kguardian-evaluator.
-- One row per (flow, policy, direction) tuple where verdict = WouldDeny.
-- Allows the broker to expose /audit/verdicts queries and serve the
-- frontend's "Would-Deny" view without round-tripping the evaluator.
--
-- Retention: the broker spawns a background tokio task on startup
-- (broker/src/retention.rs) that runs
--   DELETE FROM audit_verdicts
--   WHERE observed_at < timezone('UTC', NOW()) - INTERVAL '<N> days';
-- The timezone('UTC', NOW()) form gives a UTC-naive timestamp on the
-- right-hand side so the comparison is stable regardless of the
-- postgres session timezone (observed_at is set to UTC by the broker
-- via chrono::Utc::now().naive_utc()).
-- Defaults: 30-day window, hourly cleanup pass. Tune via
-- AUDIT_VERDICTS_RETENTION_DAYS and AUDIT_VERDICTS_RETENTION_INTERVAL_SECS
-- env vars; set days=0 to disable. The idx_audit_verdicts_observed_at
-- index below supports the DELETE's range scan.
CREATE TABLE audit_verdicts (
  id              BIGSERIAL PRIMARY KEY,
  policy_uid      VARCHAR     NOT NULL,
  policy_namespace VARCHAR    NOT NULL,
  policy_name     VARCHAR     NOT NULL,
  direction       VARCHAR     NOT NULL,            -- "Ingress" | "Egress"
  src_namespace   VARCHAR,
  src_pod         VARCHAR,
  dst_namespace   VARCHAR,
  dst_pod         VARCHAR,
  dst_port        INTEGER     NOT NULL,
  protocol        VARCHAR     NOT NULL,            -- "TCP" | "UDP" | "SCTP"
  reason          VARCHAR,
  observed_at     TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Time-series queries: "show me what would-have-been-denied for policy X
-- in the last hour" hits this index hard.
CREATE INDEX idx_audit_verdicts_policy_time
  ON audit_verdicts (policy_uid, observed_at DESC);

-- Coarse aggregation: "how many denies per policy in the last day".
CREATE INDEX idx_audit_verdicts_observed_at
  ON audit_verdicts (observed_at DESC);
