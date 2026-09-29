-- When each leader-only background loop last completed a pass, on any
-- replica (leader.rs Cadence). A replica that becomes the leader runs a
-- loop's pass promptly only if the last one is an interval old, so a
-- leader hand-off neither skips a pass nor repeats one just done. One row
-- per loop; finished_at is the database's own clock.
CREATE TABLE IF NOT EXISTS leader_task_runs (
    task        VARCHAR   PRIMARY KEY,
    finished_at TIMESTAMP NOT NULL
);
