//! Anonymous version check-in ("phone home") and the `/version` endpoint.
//!
//! Once a day the broker asks the kguardian version service what the
//! latest released versions are. The request doubles as the project's
//! usage telemetry: the service's access logs are the only place the
//! project learns an install exists. The exchange is deliberately
//! minimal and documented verbatim in docs/telemetry — every field is
//! listed below, and nothing else is sent:
//!
//! - `install`: random UUID generated on first startup (install_info
//!   table). No cluster or user information — it only deduplicates
//!   repeated check-ins from the same install.
//! - `broker`: this broker's crate version.
//! - `chart`: Helm chart version (CHART_VERSION env, set by the chart).
//! - `k8s`: Kubernetes version (KUBE_VERSION env, captured by the chart
//!   at install/upgrade time from `.Capabilities.KubeVersion`).
//! - `nodes`: count of distinct live nodes observed by the controller —
//!   a coarse install-size signal, not an inventory.
//! - `arch`: the broker's CPU architecture (compile-time constant).
//!
//! Operators disable it with `telemetry.enabled: false` in the chart
//! (TELEMETRY_ENABLED=false on the deployment); the loop then never
//! starts and no request is ever made. Failures are silent-by-design:
//! air-gapped or egress-restricted clusters just never report, at debug
//! log level, with no retry storm (next attempt is next interval).
//!
//! The useful half of the exchange is surfaced at `GET /version`: the
//! current versions plus the latest-known ones, so the frontend can show
//! an update notice and the MCP layer can answer "am I up to date?".

use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;
use tracing::{debug, info, warn};

use actix_web::{get, web, HttpResponse, Responder};

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
type DbError = Box<dyn std::error::Error + Send + Sync>;

/// Default check-in endpoint. Overridable for testing/self-hosting via
/// TELEMETRY_ENDPOINT; an unreachable endpoint is harmless (see module
/// docs — failures are silent and unretried until the next interval).
const DEFAULT_ENDPOINT: &str = "https://version.kguardian.dev/v1/check";
/// Default cadence: daily. More often would be needless load on both
/// sides; less often makes the update notice stale.
const DEFAULT_INTERVAL_SECS: u64 = 24 * 60 * 60;
/// Floor for operator-supplied intervals. Anything under an hour is
/// almost certainly a typo and would hammer the shared service.
const MIN_INTERVAL_SECS: u64 = 60 * 60;
/// Warmup before the first check so a crash-looping broker (which never
/// stays up this long) generates no check-in traffic at all.
const STARTUP_DELAY_SECS: u64 = 120;
/// Per-request deadline. The check-in is fire-and-forget; a slow or
/// blackholed endpoint must never tie up the task past this.
const REQUEST_TIMEOUT_SECS: u64 = 10;

/// True unless TELEMETRY_ENABLED is explicitly falsy. Default-on is a
/// deliberate, documented choice (docs/telemetry) — the chart surfaces
/// the setting and NOTES.txt announces it at install time.
pub(crate) fn telemetry_enabled() -> bool {
    match std::env::var("TELEMETRY_ENABLED") {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "false" | "0" | "no" | "off"
        ),
        Err(_) => true,
    }
}

pub(crate) fn telemetry_endpoint() -> String {
    std::env::var("TELEMETRY_ENDPOINT")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string())
}

pub(crate) fn telemetry_interval() -> Duration {
    let secs = std::env::var("TELEMETRY_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_INTERVAL_SECS)
        .max(MIN_INTERVAL_SECS);
    Duration::from_secs(secs)
}

/// Chart version as injected by the Helm chart. Absent when the broker
/// runs outside the chart (dev, docker-compose) — sent as "unknown"
/// rather than omitted so the service can count non-chart installs.
fn chart_version() -> String {
    std::env::var("CHART_VERSION")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn kube_version() -> String {
    std::env::var("KUBE_VERSION")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Latest-known versions as reported by the version service, plus when
/// we learned them. None until the first successful check-in.
#[derive(Clone, Serialize)]
pub struct CheckOutcome {
    /// Component name → latest released version (e.g. "chart" → "1.13.2").
    pub latest: HashMap<String, String>,
    /// UTC timestamp of the successful check.
    pub checked_at: chrono::NaiveDateTime,
}

/// Shared state between the check-in loop and `GET /version`. A plain
/// std RwLock: writes are ~daily and reads are request-scoped, so
/// contention is nil and no guard is held across an await point.
#[derive(Default)]
pub struct VersionCheckState {
    outcome: RwLock<Option<CheckOutcome>>,
}

#[derive(Deserialize)]
struct CheckResponse {
    /// The service replies {"latest": {"chart": "...", "broker": "...", ...}}.
    latest: HashMap<String, String>,
}

/// Wire shape of `GET /version`.
#[derive(Serialize)]
struct VersionInfo {
    broker: String,
    chart: String,
    telemetry_enabled: bool,
    /// Latest-known versions from the last successful check-in; null
    /// until one succeeds (or forever, when telemetry is disabled —
    /// the endpoint still reports current versions).
    latest: Option<HashMap<String, String>>,
    checked_at: Option<chrono::NaiveDateTime>,
    /// True when the latest chart version differs from the running one.
    /// Plain inequality, not semver ordering: the service only ever
    /// reports current stable versions, so "different" means "behind"
    /// in practice, and inequality can't be fooled by pre-release tags.
    update_available: bool,
}

/// Compute the update flag from current vs latest chart version.
/// Extracted for testability. Unknown current version (outside the
/// chart) or no data yet → false: never nag when we can't compare.
pub(crate) fn update_available(
    current_chart: &str,
    latest: Option<&HashMap<String, String>>,
) -> bool {
    if current_chart == "unknown" {
        return false;
    }
    latest
        .and_then(|l| l.get("chart"))
        .map(|latest_chart| latest_chart != current_chart)
        .unwrap_or(false)
}

#[get("/version")]
pub async fn get_version(state: web::Data<VersionCheckState>) -> impl Responder {
    let outcome = state.outcome.read().map(|o| o.clone()).unwrap_or_default();
    let chart = chart_version();
    HttpResponse::Ok().json(VersionInfo {
        update_available: update_available(&chart, outcome.as_ref().map(|o| &o.latest)),
        broker: env!("CARGO_PKG_VERSION").to_string(),
        chart,
        telemetry_enabled: telemetry_enabled(),
        latest: outcome.as_ref().map(|o| o.latest.clone()),
        checked_at: outcome.as_ref().map(|o| o.checked_at),
    })
}

/// Read the install id, creating it on first run. Runs on the blocking
/// pool (diesel is sync).
fn get_or_create_install_id(pool: &DbPool) -> Result<String, DbError> {
    use crate::schema::install_info::dsl::*;
    let mut conn = pool.get()?;
    if let Some(existing) = install_info
        .select(install_id)
        .first::<String>(&mut conn)
        .optional()?
    {
        return Ok(existing);
    }
    let fresh = uuid::Uuid::new_v4().to_string();
    // Two brokers racing on first boot both INSERT; the loser's conflict
    // is ignored and the winner's row is re-read so every replica reports
    // the same id.
    diesel::insert_into(install_info)
        .values(install_id.eq(&fresh))
        .on_conflict_do_nothing()
        .execute(&mut conn)?;
    Ok(install_info.select(install_id).first::<String>(&mut conn)?)
}

/// Count of distinct live nodes the controller has reported pods on.
/// Coarse install-size signal for the check-in; 0 when nothing has been
/// observed yet. sql_query keeps it independent of diesel dsl helpers,
/// matching the retention module's style.
fn live_node_count(pool: &DbPool) -> Result<i64, DbError> {
    use diesel::sql_query;
    use diesel::sql_types::BigInt;

    #[derive(diesel::QueryableByName)]
    struct CountRow {
        #[diesel(sql_type = BigInt)]
        n: i64,
    }

    let mut conn = pool.get()?;
    let row: CountRow =
        sql_query("SELECT COUNT(DISTINCT node_name) AS n FROM pod_details WHERE is_dead = false")
            .get_result(&mut conn)?;
    Ok(row.n)
}

/// The full query-parameter set for a check-in. Pure so the tests can
/// pin exactly what leaves the process — this list and docs/telemetry
/// must stay in lockstep.
pub(crate) fn check_params(install: &str, nodes: i64) -> Vec<(&'static str, String)> {
    vec![
        ("install", install.to_string()),
        ("broker", env!("CARGO_PKG_VERSION").to_string()),
        ("chart", chart_version()),
        ("k8s", kube_version()),
        ("nodes", nodes.to_string()),
        ("arch", std::env::consts::ARCH.to_string()),
    ]
}

async fn run_check(
    pool: &DbPool,
    client: &reqwest::Client,
    endpoint: &str,
) -> Result<CheckOutcome, DbError> {
    let p = pool.clone();
    let install = tokio::task::spawn_blocking(move || get_or_create_install_id(&p)).await??;
    let p = pool.clone();
    let nodes = tokio::task::spawn_blocking(move || live_node_count(&p))
        .await?
        .unwrap_or(0);

    let response = client
        .get(endpoint)
        .query(&check_params(&install, nodes))
        .send()
        .await?
        .error_for_status()?
        .json::<CheckResponse>()
        .await?;

    Ok(CheckOutcome {
        latest: response.latest,
        checked_at: chrono::Utc::now().naive_utc(),
    })
}

/// Spawn the daily check-in loop. Returns immediately. No task is
/// spawned at all when telemetry is disabled — disabled means zero
/// requests, not suppressed ones.
pub fn spawn(pool: DbPool, state: web::Data<VersionCheckState>) {
    if !telemetry_enabled() {
        info!("version check-in disabled (TELEMETRY_ENABLED=false) — no requests will be made");
        return;
    }
    let endpoint = telemetry_endpoint();
    let interval = telemetry_interval();
    info!(
        endpoint,
        interval_secs = interval.as_secs(),
        "version check-in scheduled (anonymous; see docs/telemetry — disable with telemetry.enabled=false)"
    );

    actix_web::rt::spawn(async move {
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .user_agent(concat!("kguardian-broker/", env!("CARGO_PKG_VERSION")))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                // Building a client is config-static; failure here is a
                // build/packaging bug, not a runtime condition.
                warn!("version check-in disabled: HTTP client build failed: {e}");
                return;
            }
        };
        tokio::time::sleep(Duration::from_secs(STARTUP_DELAY_SECS)).await;
        loop {
            match run_check(&pool, &client, &endpoint).await {
                Ok(outcome) => {
                    let newer = update_available(&chart_version(), Some(&outcome.latest));
                    if newer {
                        if let Some(latest_chart) = outcome.latest.get("chart") {
                            info!(
                                current = chart_version(),
                                latest = latest_chart.as_str(),
                                "a newer kguardian chart release is available"
                            );
                        }
                    }
                    if let Ok(mut guard) = state.outcome.write() {
                        *guard = Some(outcome);
                    }
                }
                // Silent-by-design: egress-restricted and air-gapped
                // clusters land here every interval. debug!, not warn! —
                // an unreachable telemetry endpoint is a supported
                // configuration, not a fault.
                Err(e) => debug!("version check-in skipped: {e}"),
            }
            tokio::time::sleep(interval).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Env-mutating tests share this lock (std::env is process-global).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_env<F: FnOnce()>(key: &str, value: Option<&str>, f: F) {
        let _guard = ENV_LOCK.lock().unwrap();
        let saved = std::env::var(key).ok();
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        f();
        match saved {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn enabled_by_default() {
        with_env("TELEMETRY_ENABLED", None, || {
            assert!(telemetry_enabled());
        });
    }

    #[test]
    fn disabled_by_falsy_values() {
        for v in ["false", "FALSE", " False ", "0", "no", "off"] {
            with_env("TELEMETRY_ENABLED", Some(v), || {
                assert!(!telemetry_enabled(), "{v:?} must disable telemetry");
            });
        }
    }

    #[test]
    fn arbitrary_values_stay_enabled() {
        // Only explicit falsy values disable; a typo like "flase" keeps
        // the documented default rather than silently flipping behavior.
        for v in ["true", "1", "yes", "flase", ""] {
            with_env("TELEMETRY_ENABLED", Some(v), || {
                assert!(telemetry_enabled(), "{v:?} must stay enabled");
            });
        }
    }

    #[test]
    fn endpoint_default_and_override() {
        with_env("TELEMETRY_ENDPOINT", None, || {
            assert_eq!(telemetry_endpoint(), DEFAULT_ENDPOINT);
        });
        with_env(
            "TELEMETRY_ENDPOINT",
            Some("  https://example.test/v1  "),
            || {
                assert_eq!(telemetry_endpoint(), "https://example.test/v1");
            },
        );
        // Empty override falls back rather than producing an unusable URL.
        with_env("TELEMETRY_ENDPOINT", Some("   "), || {
            assert_eq!(telemetry_endpoint(), DEFAULT_ENDPOINT);
        });
    }

    #[test]
    fn interval_default_and_floor() {
        with_env("TELEMETRY_INTERVAL_SECS", None, || {
            assert_eq!(
                telemetry_interval(),
                Duration::from_secs(DEFAULT_INTERVAL_SECS)
            );
        });
        with_env("TELEMETRY_INTERVAL_SECS", Some("60"), || {
            assert_eq!(
                telemetry_interval(),
                Duration::from_secs(MIN_INTERVAL_SECS),
                "sub-hour intervals must clamp to the floor"
            );
        });
        with_env("TELEMETRY_INTERVAL_SECS", Some("garbage"), || {
            assert_eq!(
                telemetry_interval(),
                Duration::from_secs(DEFAULT_INTERVAL_SECS)
            );
        });
    }

    #[test]
    fn check_params_send_exactly_the_documented_fields() {
        // This is the wire contract with docs/telemetry: if a field is
        // added or removed here, the docs page MUST change in the same
        // commit — this test is the tripwire.
        with_env("CHART_VERSION", Some("9.9.9"), || {
            let params = check_params("abc-123", 4);
            let keys: Vec<&str> = params.iter().map(|(k, _)| *k).collect();
            assert_eq!(keys, ["install", "broker", "chart", "k8s", "nodes", "arch"]);
            let map: HashMap<_, _> = params.into_iter().collect();
            assert_eq!(map["install"], "abc-123");
            assert_eq!(map["broker"], env!("CARGO_PKG_VERSION"));
            assert_eq!(map["chart"], "9.9.9");
            assert_eq!(map["nodes"], "4");
            assert_eq!(map["arch"], std::env::consts::ARCH);
        });
    }

    /// Real-network proof that the reqwest `rustls` feature gives a
    /// working HTTPS stack (TLS backend + roots). Ignored by default so
    /// CI and offline runs never depend on the network; run explicitly
    /// with `cargo test -- --ignored` when touching the TLS setup.
    #[test]
    #[ignore = "requires network egress"]
    fn https_stack_performs_a_real_request() {
        let status = actix_web::rt::System::new().block_on(async {
            reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("client build")
                .get("https://api.github.com/zen")
                .header("User-Agent", "kguardian-broker-test")
                .send()
                .await
                .expect("HTTPS request must succeed")
                .status()
        });
        assert!(status.is_success(), "unexpected status {status}");
    }

    #[test]
    fn update_available_comparisons() {
        let latest = |v: &str| {
            let mut m = HashMap::new();
            m.insert("chart".to_string(), v.to_string());
            m
        };
        assert!(update_available("1.13.1", Some(&latest("1.13.2"))));
        assert!(!update_available("1.13.2", Some(&latest("1.13.2"))));
        // No data yet → never nag.
        assert!(!update_available("1.13.2", None));
        // Outside the chart (no CHART_VERSION) → never nag.
        assert!(!update_available("unknown", Some(&latest("1.13.2"))));
        // Service response missing the chart key → never nag.
        assert!(!update_available("1.13.2", Some(&HashMap::new())));
    }
}
