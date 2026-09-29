SET LOCAL lock_timeout = '5s';

ALTER TABLE pod_compute_latest
    DROP COLUMN IF EXISTS blame_omitted_wait_ns,
    DROP COLUMN IF EXISTS blame_omitted;
