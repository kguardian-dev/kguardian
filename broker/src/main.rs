use std::error::Error;

use actix_cors::Cors;
use actix_web::{get, web, App, HttpResponse, HttpServer};
use api::{
    add_pod_details, add_pods, add_pods_batch, add_pods_syscalls, add_svc_details,
    establish_connection, get_audit_verdicts, get_pod_by_ip, get_pod_by_name, get_pod_details,
    get_pod_syscall_name, get_pod_traffic, get_pod_traffic_name, get_pods_by_node, get_svc_by_ip,
    get_svc_details, mark_pod_dead, spawn_retention, AuditClient,
};

use diesel::r2d2;
use telemetry::init_logging;
mod telemetry;

use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use std::time::Instant;
use tracing::{info, warn};
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./db/migrations");

/// Process-start instant used for the broker_uptime_seconds metric.
/// Set lazily on first /metrics call rather than at static init so
/// tests can construct the broker many times without observing a
/// stale shared start time.
static UPTIME_ANCHOR: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

type DB = diesel::pg::Pg;

fn run_migrations(
    connection: &mut impl MigrationHarness<DB>,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    connection.run_pending_migrations(MIGRATIONS)?;
    Ok(())
}

/// Default pool size — r2d2's own default is 10, which can be the
/// bottleneck under heavy ingest: the audit forwarder alone has a
/// 16-permit semaphore, and each in-flight evaluator round-trip needs
/// a pool connection to persist results. 16 here roughly balances
/// the two; operators can tune via DB_POOL_MAX_SIZE env when /metrics
/// shows pool-acquire contention.
const DEFAULT_DB_POOL_MAX_SIZE: u32 = 16;

fn db_pool_max_size() -> u32 {
    std::env::var("DB_POOL_MAX_SIZE")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .map(|n| n.max(1))
        .unwrap_or(DEFAULT_DB_POOL_MAX_SIZE)
}

/// Default migration-retry budget. The charts wait-for-db init
/// container handles "DB not started" via TCP probe, so this loop
/// only absorbs the gap between TCP-ready and postgres-accepting-
/// queries — typically 10-30s on slow / small nodes. 10 attempts ×
/// the loop's 2-second sleep = ~20s of patience.
const DEFAULT_DB_MIGRATION_MAX_RETRIES: u32 = 10;

/// Default bind address for the broker HTTP server. Operators
/// changing the chart's broker.container.port previously needed to
/// know to ALSO set this — now wired via LISTEN_ADDR env.
const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:9090";

/// Read LISTEN_ADDR env var with trim + empty fallback. Same env
/// trim defense as every other env reader in the broker (a pasted
/// "0.0.0.0:9090\n" would otherwise fail bind with a confusing
/// parse error far from the env read site).
fn listen_addr() -> String {
    std::env::var("LISTEN_ADDR")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_LISTEN_ADDR.to_string())
}

/// Read DB_MIGRATION_MAX_RETRIES with trim + clamp. Extracted out
/// of main() for the same testability reason as db_pool_max_size.
fn db_migration_max_retries() -> u32 {
    std::env::var("DB_MIGRATION_MAX_RETRIES")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .map(|n| n.max(1))
        .unwrap_or(DEFAULT_DB_MIGRATION_MAX_RETRIES)
}

#[actix_web::main]
async fn main() -> Result<(), std::io::Error> {
    init_logging();
    let manager = establish_connection();
    let max_size = db_pool_max_size();
    info!(max_size, "constructing DB connection pool");
    let pool = r2d2::Pool::builder()
        .max_size(max_size)
        .build(manager)
        .expect("Failed to create pool.");
    // RUN the migration schema with retries. The chart's wait-for-db
    // init container handles the "DB pod not started" case via TCP
    // probe, so this loop's real purpose is to absorb the gap
    // between TCP-ready and postgres-accepting-queries — which can
    // be 10-30s on slow / small nodes during initdb. 10 attempts at
    // 2s spacing gives ~20s of patience; bump via env if needed.
    let max_retries = db_migration_max_retries();
    info!(max_retries, "running embedded migrations");
    for attempt in 1..=max_retries {
        match pool.get() {
            Ok(mut conn) => match run_migrations(&mut conn) {
                Ok(()) => {
                    info!("DB setup success");
                    break;
                }
                Err(e) => {
                    if attempt == max_retries {
                        panic!("DB migration failed after {} attempts: {}", max_retries, e);
                    }
                    warn!(
                        "DB migration attempt {}/{} failed: {}. Retrying in 2s...",
                        attempt, max_retries, e
                    );
                }
            },
            Err(e) => {
                if attempt == max_retries {
                    panic!(
                        "Failed to get DB connection after {} attempts: {}",
                        max_retries, e
                    );
                }
                warn!(
                    "DB connection attempt {}/{} failed: {}. Retrying in 2s...",
                    attempt, max_retries, e
                );
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    let audit_client = AuditClient::from_env();
    if audit_client.enabled() {
        info!(url = %audit_client.base_url(), "audit evaluator integration enabled");
    } else {
        info!("audit evaluator integration disabled (set EVALUATOR_URL to enable)");
    }

    // Background pruner for audit_verdicts. Runs in-process so the
    // broker is self-contained — no separate CronJob needed in the
    // chart. Disable by setting AUDIT_VERDICTS_RETENTION_DAYS=0.
    spawn_retention(pool.clone());

    let listen_addr = listen_addr();
    info!(addr = %listen_addr, "broker HTTP server starting");
    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .wrap(cors)
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(audit_client.clone()))
            .service(add_pods)
            .service(add_pods_batch)
            .service(add_pod_details)
            .service(add_pods_syscalls)
            .service(get_pod_traffic)
            .service(get_pod_details)
            .service(add_svc_details)
            .service(get_pod_by_ip)
            .service(get_pod_by_name)
            .service(get_svc_details)
            .service(get_svc_by_ip)
            .service(get_pod_traffic_name)
            .service(get_pod_syscall_name)
            .service(get_pods_by_node)
            .service(get_audit_verdicts)
            .service(mark_pod_dead)
            .service(health_check)
            .service(metrics)
    })
    .bind(listen_addr)?
    .run()
    .await
}

// Verifying schema state on /health (rather than just connectivity) is
// what makes the broker self-heal when the database is replaced or
// wiped beneath us. Without this, /health passes on pool.get() while
// every real query 500s with "relation does not exist" — silent for
// hours. With it, the kubelet sees a failing liveness probe, restarts
// the pod, and the startup-migration retry repopulates the schema.
#[get("/health")]
pub async fn health_check(
    pool: web::Data<r2d2::Pool<r2d2::ConnectionManager<diesel::PgConnection>>>,
) -> HttpResponse {
    let pool_inner = pool.get_ref().clone();
    let result =
        tokio::task::spawn_blocking(move || -> Result<bool, Box<dyn Error + Send + Sync>> {
            // Short timeout so a saturated pool doesn't block past the
            // kubelet probe timeout (chart default 5s). Returning 503
            // here gives the kubelet a clear "Database unavailable"
            // signal — and the same response body operators see — vs
            // a vague "probe timed out" log entry when pool.get()
            // hangs for the r2d2 default 30s. Same defense applied
            // to /metrics.
            let mut conn = pool_inner.get_timeout(std::time::Duration::from_millis(500))?;
            // Empty pending list ⇒ schema is current. Anything else
            // means the DB is fresh or behind, e.g. because the database
            // pod was replaced after broker startup.
            Ok(conn.pending_migrations(MIGRATIONS)?.is_empty())
        })
        .await;

    match result {
        Ok(Ok(true)) => HttpResponse::Ok()
            .content_type("application/json")
            .body("Healthy!"),
        Ok(Ok(false)) => HttpResponse::ServiceUnavailable()
            .content_type("application/json")
            .body("Database schema not up to date"),
        Ok(Err(_)) | Err(_) => HttpResponse::ServiceUnavailable()
            .content_type("application/json")
            .body("Database unavailable"),
    }
}

/// Build the Prometheus text-format payload for the broker. Pure
/// formatting — no I/O — so it's testable in isolation without
/// spinning up the actix runtime.
pub(crate) fn render_metrics_text(
    schema_ready: u8,
    db_reachable: u8,
    audit_enabled: u8,
    audit_inflight_available: usize,
    db_pool_idle: u32,
    db_pool_max: u32,
    uptime_secs: u64,
) -> String {
    format!(
        concat!(
            "# HELP broker_db_schema_ready 1 if all embedded migrations are applied, 0 otherwise (kubelet uses this via /health)\n",
            "# TYPE broker_db_schema_ready gauge\n",
            "broker_db_schema_ready {schema_ready}\n",
            "# HELP broker_db_reachable 1 if a connection from the pool was acquired during the last metrics scrape\n",
            "# TYPE broker_db_reachable gauge\n",
            "broker_db_reachable {db_reachable}\n",
            "# HELP broker_audit_enabled 1 if EVALUATOR_URL is configured and audit calls fire\n",
            "# TYPE broker_audit_enabled gauge\n",
            "broker_audit_enabled {audit_enabled}\n",
            "# HELP broker_audit_inflight_available Number of free permits on the audit semaphore (saturation = configured cap - this)\n",
            "# TYPE broker_audit_inflight_available gauge\n",
            "broker_audit_inflight_available {audit_inflight_available}\n",
            "# HELP broker_db_pool_idle Idle connections in the r2d2 pool (saturation = broker_db_pool_max - this)\n",
            "# TYPE broker_db_pool_idle gauge\n",
            "broker_db_pool_idle {db_pool_idle}\n",
            "# HELP broker_db_pool_max Configured max_size of the r2d2 pool (DB_POOL_MAX_SIZE env / broker.dbPoolMaxSize value)\n",
            "# TYPE broker_db_pool_max gauge\n",
            "broker_db_pool_max {db_pool_max}\n",
            "# HELP broker_uptime_seconds Process uptime\n",
            "# TYPE broker_uptime_seconds counter\n",
            "broker_uptime_seconds {uptime_secs}\n",
        ),
        schema_ready = schema_ready,
        db_reachable = db_reachable,
        audit_enabled = audit_enabled,
        audit_inflight_available = audit_inflight_available,
        db_pool_idle = db_pool_idle,
        db_pool_max = db_pool_max,
        uptime_secs = uptime_secs,
    )
}

/// Plain-text Prometheus metrics scrape endpoint. Forward-compatible
/// with the chart's `broker.metrics.serviceMonitor.enabled` toggle
/// — operators can now enable that without the prometheus-operator
/// 404'ing. Surfaces three things from the broker's own state:
///   - schema readiness (the /health check, exposed as a gauge)
///   - DB reachability (separate from schema — DB up but migrations
///     pending is a distinct state from DB unreachable)
///   - audit semaphore saturation (the cap from #c05b7835 — operators
///     need to see when it's pegged to know they should bump
///     AUDIT_INFLIGHT_PERMITS)
#[get("/metrics")]
pub async fn metrics(
    pool: web::Data<r2d2::Pool<r2d2::ConnectionManager<diesel::PgConnection>>>,
    audit: web::Data<api::AuditClient>,
) -> HttpResponse {
    let pool_inner = pool.get_ref().clone();
    let schema_state = tokio::task::spawn_blocking(
        move || -> Result<(bool, bool), Box<dyn Error + Send + Sync>> {
            // Short timeout — /metrics is scraped frequently, must
            // not block on pool acquisition under saturation. Falling
            // back to db_reachable=0 (which exposes the saturation
            // via broker_db_pool_idle elsewhere in the same payload)
            // is the right signal: when the pool is full, the broker
            // is effectively unhealthy for new clients, and Prometheus
            // should see that immediately rather than waiting 30s.
            let mut conn = pool_inner.get_timeout(std::time::Duration::from_millis(100))?;
            // db_reachable = pool.get_timeout() succeeded
            // schema_ready = pending_migrations() returns Ok(empty)
            Ok((true, conn.pending_migrations(MIGRATIONS)?.is_empty()))
        },
    )
    .await;

    let (db_reachable, schema_ready) = match schema_state {
        Ok(Ok((db, schema))) => (db, schema),
        // Pool acquire failed or pending_migrations errored — DB
        // either unreachable or schema query broken; both surface
        // as "not reachable" + "not ready" so a single alert
        // (db_reachable=0) catches connectivity AND a single alert
        // (schema_ready=0) catches schema state.
        _ => (false, false),
    };

    let audit_inflight = audit.get_ref().available_permits();
    // r2d2 pool state — paired metrics let operators compute
    // saturation = max - idle. broker_db_pool_idle pegged at 0 for
    // sustained time means the pool is fully utilised; bump
    // DB_POOL_MAX_SIZE.
    let pool_state = pool.get_ref().state();
    let db_pool_idle = pool_state.idle_connections;
    let db_pool_max = pool.get_ref().max_size();
    let uptime_secs = UPTIME_ANCHOR.get_or_init(Instant::now).elapsed().as_secs();

    let body = render_metrics_text(
        u8::from(schema_ready),
        u8::from(db_reachable),
        u8::from(audit.get_ref().enabled()),
        audit_inflight,
        db_pool_idle,
        db_pool_max,
        uptime_secs,
    );

    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4; charset=utf-8")
        .body(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    // render_metrics_text is the pure formatter behind /metrics.
    // Lock the wire format — Prometheus is permissive about
    // whitespace but strict about the line shape: # HELP, # TYPE,
    // metric_name<space>value, newline. A regression in the format
    // string would silently break operator dashboards.

    #[test]
    fn renders_all_metric_names() {
        let body = render_metrics_text(1, 1, 1, 16, 16, 16, 0);
        for name in [
            "broker_db_schema_ready",
            "broker_db_reachable",
            "broker_audit_enabled",
            "broker_audit_inflight_available",
            "broker_db_pool_idle",
            "broker_db_pool_max",
            "broker_uptime_seconds",
        ] {
            assert!(body.contains(name), "missing metric: {name}");
        }
    }

    #[test]
    fn each_metric_has_help_and_type() {
        let body = render_metrics_text(1, 1, 1, 16, 16, 16, 0);
        // Each metric must have a # HELP and a # TYPE line.
        for name in [
            "broker_db_schema_ready",
            "broker_db_reachable",
            "broker_audit_enabled",
            "broker_audit_inflight_available",
            "broker_db_pool_idle",
            "broker_db_pool_max",
            "broker_uptime_seconds",
        ] {
            let help_line = format!("# HELP {name}");
            let type_line = format!("# TYPE {name}");
            assert!(body.contains(&help_line), "missing HELP for {name}");
            assert!(body.contains(&type_line), "missing TYPE for {name}");
        }
    }

    #[test]
    fn renders_zero_state() {
        // All-zero state: DB unreachable, audit disabled, no permits available,
        // pool saturated (0 idle).
        let body = render_metrics_text(0, 0, 0, 0, 0, 0, 0);
        assert!(body.contains("\nbroker_db_schema_ready 0\n"));
        assert!(body.contains("\nbroker_db_reachable 0\n"));
        assert!(body.contains("\nbroker_audit_enabled 0\n"));
        assert!(body.contains("\nbroker_audit_inflight_available 0\n"));
        assert!(body.contains("\nbroker_db_pool_idle 0\n"));
        assert!(body.contains("\nbroker_db_pool_max 0\n"));
        assert!(body.contains("\nbroker_uptime_seconds 0\n"));
    }

    #[test]
    fn renders_populated_state() {
        let body = render_metrics_text(1, 1, 1, 16, 12, 16, 12345);
        assert!(body.contains("\nbroker_db_schema_ready 1\n"));
        assert!(body.contains("\nbroker_audit_inflight_available 16\n"));
        // 12 idle out of 16 max = 4 in use; pin both so saturation is computable
        assert!(body.contains("\nbroker_db_pool_idle 12\n"));
        assert!(body.contains("\nbroker_db_pool_max 16\n"));
        assert!(body.contains("\nbroker_uptime_seconds 12345\n"));
    }

    #[test]
    fn wire_shape_is_prometheus_compatible() {
        // Each non-comment line must look like `<name> <value>\n`.
        let body = render_metrics_text(1, 1, 0, 8, 4, 16, 60);
        for line in body.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<_> = line.split_whitespace().collect();
            assert_eq!(
                parts.len(),
                2,
                "non-comment line not `name value`: {line:?}"
            );
            // Value must parse as a number (gauge or counter).
            assert!(
                parts[1].parse::<f64>().is_ok(),
                "value not numeric: {line:?}",
            );
        }
    }

    // db_pool_max_size is the env-var-driven tunable for the r2d2
    // pool. Wrong default would silently bottleneck the broker (pool
    // exhaustion blocks ingest, hides as latency rather than failure).
    // Test isolates env state to avoid cross-test contamination.

    /// Run `f` with the given env-var value temporarily set, then
    /// restore whatever was there before. Shared by every env-driven
    /// tunable test in this module — pool size, migration retries,
    /// listen addr. Tests in a parallel test runner run concurrently
    /// so this isolation matters even though each test targets a
    /// different env var: if we leave a value set, a NEXT test (in
    /// a different binary invocation but same /tmp env state — rare,
    /// but possible) might be affected. The same pattern is reused
    /// in retention.rs (with_env, scoped to retention env vars).
    fn with_env<F: FnOnce()>(key: &str, value: Option<&str>, f: F) {
        let prev = std::env::var(key).ok();
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        f();
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    // Thin wrappers preserve the existing call sites (each test
    // wrote `with_pool_env(...)`, `with_retries_env(...)`,
    // `with_listen_env(...)`) — converging them on the same shared
    // body without churn through the test bodies.
    fn with_pool_env<F: FnOnce()>(value: Option<&str>, f: F) {
        with_env("DB_POOL_MAX_SIZE", value, f);
    }

    #[test]
    fn pool_size_defaults_when_unset() {
        with_pool_env(None, || {
            assert_eq!(db_pool_max_size(), DEFAULT_DB_POOL_MAX_SIZE);
        });
    }

    #[test]
    fn pool_size_explicit_override() {
        with_pool_env(Some("32"), || {
            assert_eq!(db_pool_max_size(), 32);
        });
    }

    #[test]
    fn pool_size_zero_floors_to_one() {
        // 0 is documented-invalid (r2d2 panics on max_size=0 at
        // build time). Operators sometimes typo 0; clamp instead
        // of crashing the broker.
        with_pool_env(Some("0"), || {
            assert_eq!(db_pool_max_size(), 1);
        });
    }

    #[test]
    fn pool_size_garbage_falls_back_to_default() {
        // Non-numeric values fall back to the safe default rather
        // than crashing the broker. Operator can spot the typo via
        // the info-level startup log (constructing DB connection
        // pool max_size=<N>) — N=16 indicates the env didn't take.
        with_pool_env(Some("not-a-number"), || {
            assert_eq!(db_pool_max_size(), DEFAULT_DB_POOL_MAX_SIZE);
        });
    }

    #[test]
    fn pool_size_trims_whitespace() {
        // Same operator-paste defense applied across all env reads
        // (broker EVALUATOR_URL, controller / evaluator / mcp-server
        // / llm-bridge env reads). A trailing newline mustn't
        // silently fall back to the default.
        with_pool_env(Some("  32\n"), || {
            assert_eq!(db_pool_max_size(), 32);
        });
    }

    // Mirror coverage for the iteration-127 db_migration_max_retries
    // extraction. Same env-var-driven tunable pattern as the pool
    // size; same defenses pinned.

    fn with_retries_env<F: FnOnce()>(value: Option<&str>, f: F) {
        with_env("DB_MIGRATION_MAX_RETRIES", value, f);
    }

    #[test]
    fn migration_retries_default_when_unset() {
        with_retries_env(None, || {
            assert_eq!(db_migration_max_retries(), DEFAULT_DB_MIGRATION_MAX_RETRIES);
        });
    }

    #[test]
    fn migration_retries_explicit_override() {
        with_retries_env(Some("20"), || {
            assert_eq!(db_migration_max_retries(), 20);
        });
    }

    #[test]
    fn migration_retries_zero_floors_to_one() {
        // 0 retries would mean "give up immediately on first failure"
        // — practically zero patience, useless given the loop's 2s
        // sleep purpose. Operators sometimes typo 0 meaning "no
        // retries needed"; clamp to 1.
        with_retries_env(Some("0"), || {
            assert_eq!(db_migration_max_retries(), 1);
        });
    }

    #[test]
    fn migration_retries_garbage_falls_back_to_default() {
        with_retries_env(Some("not-a-number"), || {
            assert_eq!(db_migration_max_retries(), DEFAULT_DB_MIGRATION_MAX_RETRIES);
        });
    }

    #[test]
    fn migration_retries_trims_whitespace() {
        with_retries_env(Some("  20\n"), || {
            assert_eq!(db_migration_max_retries(), 20);
        });
    }

    // listen_addr is the bind-address env reader added in iteration
    // 130 to wire the chart's broker.container.port through to the
    // Rust binary. Same env-trim defense + default-fallback pattern.

    fn with_listen_env<F: FnOnce()>(value: Option<&str>, f: F) {
        with_env("LISTEN_ADDR", value, f);
    }

    #[test]
    fn listen_addr_defaults_when_unset() {
        with_listen_env(None, || {
            assert_eq!(listen_addr(), DEFAULT_LISTEN_ADDR);
        });
    }

    #[test]
    fn listen_addr_honors_override() {
        with_listen_env(Some("0.0.0.0:8080"), || {
            assert_eq!(listen_addr(), "0.0.0.0:8080");
        });
    }

    #[test]
    fn listen_addr_empty_falls_back_to_default() {
        // Operator setting LISTEN_ADDR="" (or set then unset back)
        // shouldnt produce an empty bind string that .bind() rejects.
        with_listen_env(Some(""), || {
            assert_eq!(listen_addr(), DEFAULT_LISTEN_ADDR);
        });
    }

    #[test]
    fn listen_addr_whitespace_only_falls_back_to_default() {
        // Same as empty — whitespace-only is operator-paste artefact,
        // treat as "use default".
        with_listen_env(Some("  \n"), || {
            assert_eq!(listen_addr(), DEFAULT_LISTEN_ADDR);
        });
    }

    #[test]
    fn listen_addr_trims_surrounding_whitespace() {
        // Pasted value with trailing newline round-trips clean.
        with_listen_env(Some("  0.0.0.0:9090\n"), || {
            assert_eq!(listen_addr(), "0.0.0.0:9090");
        });
    }
}
