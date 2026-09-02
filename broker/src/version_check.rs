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

/// Chart version as injected by the Helm chart, normalized to the base
/// semver. Flux-installed charts report `.Chart.Version` with build
/// metadata appended (e.g. "1.14.1+a1f714b25358"); semver defines the
/// `+meta` suffix as ignorable for comparison, and keeping it would both
/// fragment the telemetry's version-spread grouping and false-positive
/// `update_available` against the service's bare "1.14.1". Absent when
/// the broker runs outside the chart (dev, docker-compose) — sent as
/// "unknown" rather than omitted so the service can count non-chart
/// installs.
fn chart_version() -> String {
    std::env::var("CHART_VERSION")
        .ok()
        .map(|v| strip_build_metadata(v.trim()).to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Drop a semver build-metadata suffix ("1.14.1+a1f714b" → "1.14.1").
fn strip_build_metadata(version: &str) -> &str {
    version.split('+').next().unwrap_or(version)
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
    // Compare base versions: build metadata is defined by semver as
    // ignorable, and callers may pass a raw Flux-style "1.14.1+<sha>"
    // (chart_version() already normalizes, but stay safe on both sides).
    latest
        .and_then(|l| l.get("chart"))
        .map(|latest_chart| {
            strip_build_metadata(latest_chart) != strip_build_metadata(current_chart)
        })
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

/// Cluster-environment wire shape for GET /cluster/environment: the
/// same coarse per-column aggregates the telemetry check-in sends
/// (env_signals), exposed so the UI and assistant can align policy
/// generation with the cluster CNI (issue #1413). `nodes` counts
/// node_facts rows — 0 means no controller has reported yet, and every
/// enum degrades to "unknown"; consumers MUST treat unknown as
/// "behave exactly as before".
#[derive(Serialize)]
pub struct ClusterEnvironment {
    pub cni: String,
    pub ip_family: String,
    pub provider: String,
    pub distro: String,
    pub node_os: String,
    pub nodes: i64,
}

/// Always 200: DB trouble degrades to all-unknown/0 like env_signals —
/// an environment hint must never break a page load.
#[get("/cluster/environment")]
pub async fn get_cluster_environment(pool: web::Data<DbPool>) -> impl Responder {
    let p = pool.get_ref().clone();
    let (signals, nodes) = tokio::task::spawn_blocking(move || {
        let signals = env_signals(&p);
        let nodes = node_fact_count(&p).unwrap_or(0);
        (signals, nodes)
    })
    .await
    .unwrap_or_else(|_| (EnvSignals::default(), 0));
    HttpResponse::Ok().json(ClusterEnvironment {
        cni: signals.cni,
        ip_family: signals.ip_family,
        provider: signals.provider,
        distro: signals.distro,
        node_os: signals.node_os,
        nodes,
    })
}

/// Rows in node_facts — how many controllers have reported facts.
fn node_fact_count(pool: &DbPool) -> Result<i64, DbError> {
    use crate::schema::node_facts::dsl as nf;
    use diesel::prelude::*;
    let mut conn = pool.get()?;
    Ok(nf::node_facts.count().get_result::<i64>(&mut conn)?)
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

/// Contract-v2 environment signals: coarse enums aggregated from the
/// per-node facts the controller reports, plus a pods bucket and the
/// chart's feature-flag list. Every value is a fixed enum/bucket string
/// — the version service re-whitelists them all (docs/telemetry.mdx).
pub(crate) struct EnvSignals {
    provider: String,
    distro: String,
    cni: String,
    ip_family: String,
    node_os: String,
    pods_bucket: String,
    features: String,
}

impl Default for EnvSignals {
    fn default() -> Self {
        Self {
            provider: "unknown".into(),
            distro: "unknown".into(),
            cni: "unknown".into(),
            ip_family: "unknown".into(),
            node_os: "unknown".into(),
            pods_bucket: "unknown".into(),
            features: "none".into(),
        }
    }
}

/// Most frequent value in a column, ties broken alphabetically for
/// determinism; "unknown" when the table is empty.
fn mode(values: &[String]) -> String {
    use std::collections::BTreeMap;
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for v in values {
        *counts.entry(v.as_str()).or_default() += 1;
    }
    counts
        .into_iter()
        .max_by_key(|(_, n)| *n)
        .map(|(v, _)| v.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Cluster IP family from per-node families: any node dual — or a mix
/// of v4-only and v6-only nodes — means the cluster speaks both.
fn aggregate_ip_family(values: &[String]) -> String {
    let dual = values.iter().any(|v| v == "dual");
    let v4 = values.iter().any(|v| v == "ipv4");
    let v6 = values.iter().any(|v| v == "ipv6");
    if dual || (v4 && v6) {
        "dual".to_string()
    } else {
        mode(values)
    }
}

/// Order-of-magnitude bucket for the pods count. Must stay within the
/// version service's BUCKET pattern.
pub(crate) fn bucketize(n: i64) -> String {
    match n {
        i64::MIN..=0 => "0".to_string(),
        1..=9 => "1-9".to_string(),
        10..=99 => "10-99".to_string(),
        100..=999 => "100-999".to_string(),
        1000..=9999 => "1000-9999".to_string(),
        _ => "10000+".to_string(),
    }
}

/// FEATURES env: comma-separated flag slugs the chart injects
/// ("ai,audit"). Anything outside [a-z0-9_,] disables the field to
/// "none" rather than shipping junk upstream.
fn features() -> String {
    features_from(std::env::var("FEATURES").ok().as_deref())
}

fn features_from(raw: Option<&str>) -> String {
    let Some(v) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
        return "none".to_string();
    };
    if v.len() <= 400
        && v.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b',')
    {
        v.to_string()
    } else {
        "none".to_string()
    }
}

/// Aggregate the node_facts table (plus pod count + FEATURES env) into
/// the check-in's environment signals. Any DB error degrades to
/// defaults — telemetry must never fail the check-in.
fn env_signals(pool: &DbPool) -> EnvSignals {
    use crate::schema::node_facts::dsl as nf;
    use crate::schema::pod_details::dsl as pd;
    use diesel::prelude::*;

    let mut out = EnvSignals {
        features: features(),
        ..EnvSignals::default()
    };
    let Ok(mut conn) = pool.get() else {
        return out;
    };
    if let Ok(rows) = nf::node_facts
        .select((
            nf::provider,
            nf::distro,
            nf::cni,
            nf::ip_family,
            nf::node_os,
        ))
        .load::<(String, String, String, String, String)>(&mut conn)
    {
        if !rows.is_empty() {
            let col = |i: usize| -> Vec<String> {
                rows.iter()
                    .map(|r| match i {
                        0 => r.0.clone(),
                        1 => r.1.clone(),
                        2 => r.2.clone(),
                        3 => r.3.clone(),
                        _ => r.4.clone(),
                    })
                    .collect()
            };
            out.provider = mode(&col(0));
            out.distro = mode(&col(1));
            out.cni = mode(&col(2));
            out.ip_family = aggregate_ip_family(&col(3));
            out.node_os = mode(&col(4));
        }
    }
    if let Ok(n) = pd::pod_details
        .filter(pd::is_dead.eq(false))
        .count()
        .get_result::<i64>(&mut conn)
    {
        out.pods_bucket = bucketize(n);
    }
    out
}

/// The full query-parameter set for a check-in. Pure so the tests can
/// pin exactly what leaves the process — this list and docs/telemetry
/// must stay in lockstep.
pub(crate) fn check_params(
    install: &str,
    nodes: i64,
    env: &EnvSignals,
) -> Vec<(&'static str, String)> {
    vec![
        ("install", install.to_string()),
        ("broker", env!("CARGO_PKG_VERSION").to_string()),
        ("chart", chart_version()),
        ("k8s", kube_version()),
        ("nodes", nodes.to_string()),
        ("arch", std::env::consts::ARCH.to_string()),
        ("provider", env.provider.clone()),
        ("distro", env.distro.clone()),
        ("cni", env.cni.clone()),
        ("ip_family", env.ip_family.clone()),
        ("node_os", env.node_os.clone()),
        ("pods_bucket", env.pods_bucket.clone()),
        ("features", env.features.clone()),
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
    let p = pool.clone();
    let env = tokio::task::spawn_blocking(move || env_signals(&p)).await?;

    let response = client
        .get(endpoint)
        .query(&check_params(&install, nodes, &env))
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

    fn with_env<F: FnOnce()>(key: &str, value: Option<&str>, f: F) {
        // Crate-wide lock: std::env is process-global, so exclusion must
        // span every test module, not just this one.
        let _guard = crate::test_support::env_lock();
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
            let params = check_params("abc-123", 4, &EnvSignals::default());
            let keys: Vec<&str> = params.iter().map(|(k, _)| *k).collect();
            assert_eq!(
                keys,
                [
                    "install",
                    "broker",
                    "chart",
                    "k8s",
                    "nodes",
                    "arch",
                    "provider",
                    "distro",
                    "cni",
                    "ip_family",
                    "node_os",
                    "pods_bucket",
                    "features",
                ]
            );
            let map: HashMap<_, _> = params.into_iter().collect();
            assert_eq!(map["install"], "abc-123");
            assert_eq!(map["broker"], env!("CARGO_PKG_VERSION"));
            assert_eq!(map["chart"], "9.9.9");
            assert_eq!(map["nodes"], "4");
            assert_eq!(map["arch"], std::env::consts::ARCH);
            // v2 defaults: coarse "unknown"/"none" — never absent, so
            // the wire shape is identical whether or not the controller
            // ever reported node facts.
            assert_eq!(map["provider"], "unknown");
            assert_eq!(map["features"], "none");
            assert_eq!(map["pods_bucket"], "unknown");
        });
    }

    #[test]
    fn cluster_environment_serializes_the_documented_shape() {
        // Wire contract for GET /cluster/environment — the UI and
        // assistant key on exactly these fields (docs/api-reference).
        let env = ClusterEnvironment {
            cni: "cilium".into(),
            ip_family: "dual".into(),
            provider: "baremetal".into(),
            distro: "talos".into(),
            node_os: "talos".into(),
            nodes: 3,
        };
        let v: serde_json::Value = serde_json::to_value(&env).unwrap();
        // serde_json::Value maps iterate in key order — compare as a
        // sorted set; field presence is the contract, not order.
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        assert_eq!(
            keys,
            ["cni", "distro", "ip_family", "node_os", "nodes", "provider"]
        );
        assert_eq!(v["cni"], "cilium");
        assert_eq!(v["nodes"], 3);
    }

    #[test]
    fn env_signals_default_degrades_to_all_unknown() {
        // The unknown-degradation pin: consumers treat "unknown" as
        // "behave exactly as before", so the no-facts default must be
        // unknown everywhere (features excepted — it is env-sourced).
        let d = EnvSignals::default();
        assert_eq!(
            (
                d.cni.as_str(),
                d.ip_family.as_str(),
                d.provider.as_str(),
                d.distro.as_str(),
                d.node_os.as_str()
            ),
            ("unknown", "unknown", "unknown", "unknown", "unknown")
        );
    }

    #[test]
    fn bucketize_matches_the_worker_pattern() {
        assert_eq!(bucketize(0), "0");
        assert_eq!(bucketize(-3), "0");
        assert_eq!(bucketize(1), "1-9");
        assert_eq!(bucketize(99), "10-99");
        assert_eq!(bucketize(100), "100-999");
        assert_eq!(bucketize(9999), "1000-9999");
        assert_eq!(bucketize(50_000), "10000+");
    }

    #[test]
    fn ip_family_aggregation_detects_dual_from_mixed_nodes() {
        let v = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(aggregate_ip_family(&v(&["ipv4", "ipv4"])), "ipv4");
        assert_eq!(aggregate_ip_family(&v(&["ipv4", "dual"])), "dual");
        assert_eq!(aggregate_ip_family(&v(&["ipv4", "ipv6"])), "dual");
        assert_eq!(aggregate_ip_family(&v(&["ipv6"])), "ipv6");
        assert_eq!(aggregate_ip_family(&[]), "unknown");
    }

    #[test]
    fn features_env_is_whitelisted_or_none() {
        assert_eq!(features_from(None), "none");
        assert_eq!(features_from(Some("  ")), "none");
        assert_eq!(features_from(Some("ai,audit")), "ai,audit");
        assert_eq!(features_from(Some("AI;DROP TABLE")), "none");
    }

    #[test]
    fn mode_breaks_ties_deterministically() {
        let v = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(mode(&v(&["aws", "gcp", "aws"])), "aws");
        // Equal counts: the max_by_key over a BTreeMap keeps the LAST
        // maximal entry in key order — pinned so status output can't
        // flap between runs.
        assert_eq!(mode(&v(&["aws", "gcp"])), "gcp");
        assert_eq!(mode(&[]), "unknown");
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
    fn chart_version_strips_build_metadata() {
        // Flux reports .Chart.Version with build metadata; the base
        // version must be what we send and compare (the raw form caused
        // a permanent update_available=true false positive in 1.12.1).
        with_env("CHART_VERSION", Some("1.14.1+a1f714b25358"), || {
            assert_eq!(chart_version(), "1.14.1");
        });
        with_env("CHART_VERSION", Some("1.14.1"), || {
            assert_eq!(chart_version(), "1.14.1");
        });
        // A degenerate "+meta"-only value strips to empty → unknown.
        with_env("CHART_VERSION", Some("+abc"), || {
            assert_eq!(chart_version(), "unknown");
        });
    }

    #[test]
    fn update_available_ignores_build_metadata() {
        let latest = |v: &str| {
            let mut m = HashMap::new();
            m.insert("chart".to_string(), v.to_string());
            m
        };
        // Same base version with metadata on either side → no update.
        assert!(!update_available("1.14.1+a1f714b", Some(&latest("1.14.1"))));
        assert!(!update_available("1.14.1", Some(&latest("1.14.1+meta"))));
        // Genuinely behind, metadata present → still flags.
        assert!(update_available("1.14.0+a1f714b", Some(&latest("1.14.1"))));
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
