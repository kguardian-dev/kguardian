-- Per-flow audit verdicts emitted by the kguardian-evaluator.
-- One row per (flow, policy, direction) tuple where verdict = WouldDeny.
-- Allows the broker to expose /audit/verdicts queries and serve the
-- frontend's "Would-Deny" view without round-tripping the evaluator.
--
-- Retention: this table grows monotonically with would-deny traffic.
-- A follow-up will add either pg_partman partitioning on observed_at
-- or a scheduled DELETE WHERE observed_at < NOW() - INTERVAL '30 days'.
-- Until then operators on busy clusters should add their own cleanup.
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
