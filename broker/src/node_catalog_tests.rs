use super::*;
use actix_web::http::{header, StatusCode};
use actix_web::{middleware::from_fn, test as atest, App};
use chrono::TimeZone;
use serde_json::json;
use std::io::Write;

fn d(i: u32) -> String {
    format!("sha256:{:064x}", i)
}

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 3, 12, 0, 0).unwrap()
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(bytes).unwrap();
    e.finish().unwrap()
}

/// An upload body: `names` as components (the first flagged), optionally
/// one page of a set.
fn upload_json(
    digest: &str,
    epoch: i64,
    names: &[&str],
    page: Option<(i64, i64)>,
) -> serde_json::Value {
    let comps: Vec<serde_json::Value> = names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            json!({
                "name": n, "version": "1.0", "type": "apk", "class": "os-pkgs",
                "purl": format!("pkg:apk/alpine/{n}@1.0"),
                "file_paths": [format!("/usr/bin/{n}")],
                "files_truncated": i == 0,
                "interpreted_content": false,
            })
        })
        .collect();
    let mut v = json!({
        "schema_version": 1,
        "image": {"digest": digest, "digest_kind": "manifest"},
        "source": "node",
        "scanner": {"name": "kguardian-cataloger", "vendor": "kguardian", "version": "0.1.0"},
        "scanned_at": (Utc::now() - chrono::Duration::hours(2) + chrono::Duration::minutes(epoch)).to_rfc3339(),
        "format": "kguardian-cataloger",
        "components": comps,
        "epoch": epoch,
        "completeness": "full",
        "partial_reasons": [],
        "stats": {"files": 12, "duration_ms": 1840, "budgets": {"max_files": 2000000}},
        "platform": "linux/arm64",
    });
    if let Some((index, total)) = page {
        v["page"] = json!({"set_id": format!("scan-{epoch}"), "index": index, "total": total});
    }
    v
}

// ---------------------------------------------------------------------
// Pure
// ---------------------------------------------------------------------

#[test]
fn config_parses_the_kill_switch_and_retention() {
    assert!(parse_grants(None));
    assert!(parse_grants(Some("true")));
    assert!(parse_grants(Some("yes")));
    for off in ["false", " FALSE ", "0", "no", "off"] {
        assert!(!parse_grants(Some(off)), "{off}");
    }
    assert_eq!(parse_retention_days(None), 14);
    assert_eq!(parse_retention_days(Some(" 3 ")), 3);
    assert_eq!(parse_retention_days(Some("0")), 0);
    assert_eq!(parse_retention_days(Some("x")), 14);
}

#[test]
fn nodes_and_platforms_are_validated() {
    assert!(valid_node("ip-10-0-1-2.ec2.internal"));
    assert!(!valid_node(""));
    assert!(!valid_node("Node_A"));
    assert!(!valid_node(&"a".repeat(254)));
    assert!(valid_platform("linux/amd64"));
    assert!(valid_platform("linux/arm64/v8"));
    assert!(!valid_platform("linux"));
    assert!(!valid_platform("linux/arm64/v8/x"));
    assert!(!valid_platform("linux//arm64"));
    assert!(!valid_platform("Linux/AMD64"));
}

#[test]
fn offers_are_sorted_deduplicated_and_bounded() {
    let r = |offer: Vec<String>| ClaimRequest {
        node: " node-a ".into(),
        platform: "Linux/ARM64".into(),
        epoch: 1,
        offer,
    };
    let o = validate_offer(r(vec![d(3), d(1), d(3), d(2)])).unwrap();
    assert_eq!(o.digests, [d(1), d(2), d(3)]);
    assert_eq!(o.node, "node-a");
    assert_eq!(o.platform, "linux/arm64");
    assert_eq!(
        validate_offer(r(vec!["sha256:nope".into()]))
            .unwrap_err()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        validate_offer(r((0..=MAX_OFFER as u32).map(d).collect()))
            .unwrap_err()
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let mut bad_epoch = r(vec![]);
    bad_epoch.epoch = -1;
    assert!(validate_offer(bad_epoch).is_err());
}

#[test]
fn every_reason_has_one_class() {
    for r in BACKOFF_REASONS {
        assert_eq!(classify(r), Some(FailClass::Backoff));
    }
    for r in RETRY_REASONS {
        assert_eq!(classify(r), Some(FailClass::Retry));
    }
    for r in PER_NODE_REASONS {
        assert_eq!(classify(r), Some(FailClass::PerNode));
        assert!(SKIPPED_REASONS.contains(&r), "{r} has no skipped label");
    }
    assert_eq!(classify("no_packages_found"), Some(FailClass::Terminal));
    assert_eq!(classify("made-up"), None);
    assert_eq!(classify(""), None);
    // Every failure label the counters accept is a real reason.
    for r in FAILED_REASONS {
        assert!(matches!(
            classify(r),
            Some(FailClass::Backoff | FailClass::Retry)
        ));
    }
}

#[test]
fn backoff_is_one_six_then_twenty_four_hours() {
    assert_eq!(backoff_secs(1), 3600);
    assert_eq!(backoff_secs(2), 6 * 3600);
    assert_eq!(backoff_secs(3), 24 * 3600);
    assert_eq!(backoff_secs(9), 24 * 3600);
    assert_eq!(backoff_secs(0), 3600);
}

#[test]
fn state_machine_backoff_counts_consecutive_failures() {
    let r = release(
        0,
        BTreeMap::new(),
        BTreeMap::new(),
        "a",
        FailClass::Backoff,
        t0(),
    );
    assert_eq!(
        (r.state, r.failures, r.backoff_secs),
        ("failed", 1, Some(3600))
    );
    let r = release(
        1,
        BTreeMap::new(),
        BTreeMap::new(),
        "a",
        FailClass::Backoff,
        t0(),
    );
    assert_eq!((r.failures, r.backoff_secs), (2, Some(6 * 3600)));
    let r = release(
        2,
        BTreeMap::new(),
        BTreeMap::new(),
        "a",
        FailClass::Backoff,
        t0(),
    );
    assert_eq!(r.backoff_secs, Some(24 * 3600));
    assert!(!r.skipped && r.skipped_nodes.is_empty());
}

#[test]
fn state_machine_retry_cap_skips_the_node_on_the_third_failure() {
    let mut skipped = BTreeMap::new();
    let mut retries = BTreeMap::new();
    for i in 1..=3 {
        let r = release(
            0,
            skipped,
            retries,
            "a",
            FailClass::Retry,
            t0() + chrono::Duration::minutes(i),
        );
        assert_eq!(r.state, "pending", "released to others at once");
        assert_eq!(r.backoff_secs, None);
        assert_eq!(r.skipped, i == 3, "attempt {i}");
        skipped = r.skipped_nodes;
        retries = r.node_retries;
    }
    assert!(skipped.contains_key("a"));
    assert!(
        !retries.contains_key("a"),
        "the count restarts after the skip"
    );
    // Another node's count is its own.
    let r = release(0, skipped, retries, "b", FailClass::Retry, t0());
    assert_eq!(r.node_retries["b"].n, 1);
    assert!(!r.skipped);
}

#[test]
fn state_machine_retry_window_is_24_hours() {
    let mut retries = BTreeMap::new();
    retries.insert("a".to_string(), NodeRetry { n: 2, since: t0() });
    // Two failures a day and a minute ago no longer count.
    let later = t0() + chrono::Duration::hours(24) + chrono::Duration::minutes(1);
    let r = release(0, BTreeMap::new(), retries, "a", FailClass::Retry, later);
    assert!(!r.skipped);
    assert_eq!(r.node_retries["a"], NodeRetry { n: 1, since: later });
}

#[test]
fn state_machine_per_node_skip_expires_after_24_hours() {
    let r = release(
        3,
        BTreeMap::new(),
        BTreeMap::new(),
        "a",
        FailClass::PerNode,
        t0(),
    );
    assert_eq!((r.state, r.failures), ("pending", 3), "failures untouched");
    assert!(r.skipped);
    assert_eq!(r.skipped_nodes["a"], t0());
    // The next write a day later drops the stale entry.
    let r = release(
        0,
        r.skipped_nodes,
        BTreeMap::new(),
        "b",
        FailClass::PerNode,
        t0() + chrono::Duration::hours(25),
    );
    assert!(!r.skipped_nodes.contains_key("a"));
    assert!(r.skipped_nodes.contains_key("b"));
}

#[test]
fn state_machine_terminal_is_done() {
    let r = release(
        1,
        BTreeMap::new(),
        BTreeMap::new(),
        "a",
        FailClass::Terminal,
        t0(),
    );
    assert_eq!(r.state, "done");
    assert!(!r.skipped);
}

#[test]
fn epochs_never_go_backwards() {
    assert!(accepts_epoch(2, 2));
    assert!(accepts_epoch(2, 3));
    assert!(!accepts_epoch(3, 2));
    // The grant takes GREATEST(row, node) and only when node >= row.
    assert!(GRANT_SQL.contains("$3 >= epoch"));
    assert!(GRANT_SQL.contains("epoch = GREATEST(c.epoch, $3)"));
    assert!(GRANT_SQL.contains("(state = 'done'    AND epoch < $3)"));
    assert!(FINALIZE_SQL.contains("epoch = GREATEST(epoch, $3)"));
}

#[test]
fn the_claim_sql_uses_only_the_database_clock_and_skips_locked_rows() {
    for sql in [
        GRANT_SQL,
        OFFER_INSERT_SQL,
        UPSERT_PLATFORM_SQL,
        FINALIZE_SQL,
    ] {
        assert!(!sql.contains("$now"), "{sql}");
    }
    assert!(GRANT_SQL.contains("LIMIT 1"));
    assert!(GRANT_SQL.contains("FOR UPDATE SKIP LOCKED"));
    assert!(GRANT_SQL.contains("kg_digest_runs_on_node(inventory_digest, $2, $4)"));
    assert!(GRANT_SQL.contains("(skipped_nodes ->> $2)::timestamptz > now() - interval '24 hours'"));
    assert!(OFFER_INSERT_SQL.contains("ON CONFLICT DO NOTHING"));
}

#[test]
fn updates_are_validated() {
    let u = |action: &str, reason: Option<&str>| ClaimUpdate {
        action: action.into(),
        node: "a".into(),
        reason: reason.map(str::to_string),
    };
    assert_eq!(validate_update(&u("renew", None)), Ok(Action::Renew));
    assert_eq!(
        validate_update(&u("fail", Some("oom"))),
        Ok(Action::Release("oom".into(), FailClass::Backoff))
    );
    assert_eq!(
        validate_update(&u("skip", Some("deferred_pressure"))),
        Ok(Action::Release(
            "deferred_pressure".into(),
            FailClass::PerNode
        ))
    );
    assert!(validate_update(&u("skip", Some("oom"))).is_err());
    assert!(validate_update(&u("fail", Some("because"))).is_err());
    assert!(validate_update(&u("fail", None)).is_err());
    assert!(validate_update(&u("done", None)).is_err());
}

fn parse(v: serde_json::Value) -> Result<Upload, PrepareError> {
    let digest = v["image"]["digest"].as_str().unwrap().to_string();
    prepare_upload(&digest, &serde_json::to_vec(&v).unwrap(), false, t0())
}

#[test]
fn uploads_are_node_scanned_and_carry_their_flags_and_meta() {
    let mut v = upload_json(&d(1), 3, &["busybox", "musl"], None);
    v["sbom_trust"] = json!("verified");
    v["scanner"]["name"] = json!("someone-else");
    v["components"][1]["interpreted_content"] = json!(true);
    v["image"]["platform_manifests"] = json!({"linux/arm64": d(9)});
    let up = parse(v).unwrap();
    let h = &up.payload.header;
    assert_eq!(h.source, "node");
    assert_eq!(h.sbom_trust.as_deref(), Some("scanned"), "trust is fixed");
    assert_eq!(h.scanner_name.as_deref(), Some("kguardian-cataloger"));
    assert_eq!(up.payload.rows[0].flags, Some(FLAG_FILES_TRUNCATED));
    assert_eq!(up.payload.rows[1].flags, Some(FLAG_INTERPRETED_CONTENT));
    assert_eq!(up.meta.epoch, 3);
    assert_eq!(up.meta.completeness, "full");
    assert_eq!(up.meta.platform.as_deref(), Some("linux/arm64"));
    assert_eq!(up.meta.manifest_digest, Some(d(9)));
    assert_eq!(up.meta.stats["budgets"]["max_files"], 2000000);
}

#[test]
fn uploads_refuse_other_sources_and_need_an_epoch() {
    let mut v = upload_json(&d(1), 1, &["a"], None);
    v["source"] = json!("trivy-operator");
    match parse(v) {
        Err(PrepareError::Reject(supplychain::Reject::Invalid(m))) => {
            assert_eq!(m, "source must be one of node")
        }
        other => panic!("{other:?}"),
    }
    let mut v = upload_json(&d(1), 1, &["a"], None);
    v.as_object_mut().unwrap().remove("epoch");
    assert!(matches!(parse(v), Err(PrepareError::Json(_))));
    let mut v = upload_json(&d(1), 1, &["a"], None);
    v["completeness"] = json!("complete!");
    assert_eq!(
        parse(v).unwrap().meta.completeness,
        "partial",
        "fails closed"
    );
    let mut v = upload_json(&d(1), 1, &["a"], None);
    v.as_object_mut().unwrap().remove("completeness");
    assert_eq!(parse(v).unwrap().meta.completeness, "partial");
}

#[test]
fn the_catalog_route_keeps_4096_paths_and_the_generic_route_16() {
    let paths: Vec<String> = (0..MAX_CATALOG_PATHS + 5)
        .map(|i| format!("/usr/lib/libx{i}.so"))
        .collect();
    let mut v = upload_json(&d(1), 1, &["big", "small"], None);
    v["components"][0]["file_paths"] = json!(paths);
    v["components"][0]["files_truncated"] = json!(false);
    let up = parse(v).unwrap();
    assert_eq!(up.payload.rows[0].file_paths.len(), MAX_CATALOG_PATHS);
    assert_eq!(
        up.payload.rows[0].flags,
        Some(FLAG_FILES_TRUNCATED),
        "cutting paths marks the package truncated"
    );
    assert_eq!(up.payload.rows[1].flags, None);
    // The supply-chain route, same component: still 16.
    let generic = json!({
        "schema_version": 1, "image": {"digest": d(1)}, "source": "trivy-operator",
        "scanned_at": "2026-10-03T08:00:00Z",
        "components": [{"name": "big", "file_paths": paths}],
    });
    let p =
        supplychain::normalise_sbom(&d(1), serde_json::from_value(generic).unwrap(), t0()).unwrap();
    assert_eq!(p.rows[0].file_paths.len(), supplychain::MAX_FILE_PATHS);
    assert_eq!(p.rows[0].flags, None);
}

#[test]
fn a_page_over_the_path_budget_is_413_not_parsed() {
    let per = MAX_CATALOG_PATHS;
    let n = MAX_CATALOG_PATHS_PER_PAGE / per + 1;
    let comps: Vec<serde_json::Value> = (0..n)
        .map(|c| json!({"name": format!("p{c}"), "file_paths": (0..per).map(|i| format!("/b/{i}")).collect::<Vec<_>>()}))
        .collect();
    let mut v = upload_json(&d(1), 1, &[], None);
    v["components"] = json!(comps);
    let body = serde_json::to_vec(&v).unwrap();
    assert!(body.len() < MAX_CATALOG_DECOMPRESSED_BYTES);
    match prepare_upload(&d(1), &body, false, t0()) {
        Err(PrepareError::TooMany(m)) => assert!(m.contains("file paths"), "{m}"),
        other => panic!("{other:?}"),
    }
    // A fresh parse gets a fresh budget.
    assert!(parse(upload_json(&d(1), 1, &["a"], None)).is_ok());
}

#[test]
fn stats_are_bounded() {
    assert_eq!(bound_stats(None), json!({}));
    assert_eq!(bound_stats(Some(json!([1, 2]))), json!({}));
    let small = json!({"files": 1, "budgets": {"max_files": 2}});
    assert_eq!(bound_stats(Some(small.clone())), small);
    let big = json!({"files": 1, "syft_version": "v1.52.0", "blob": "x".repeat(MAX_STATS_BYTES), "budgets": {"a": 1}});
    assert_eq!(
        bound_stats(Some(big)),
        json!({"files": 1, "syft_version": "v1.52.0"})
    );
}

#[test]
fn the_sources_split_keeps_ingest_closed_and_lets_matchers_name_node() {
    use supplychain::{INGEST_SOURCES, KNOWN_SBOM_SOURCES};
    assert_eq!(INGEST_SOURCES, ["trivy-operator", "grype", "registry"]);
    assert_eq!(&KNOWN_SBOM_SOURCES[..3], &INGEST_SOURCES[..]);
    assert!(KNOWN_SBOM_SOURCES.contains(&NODE_SOURCE));
    assert!(!INGEST_SOURCES.contains(&NODE_SOURCE));
    // The supply-chain SBOM route still refuses `node`, with the old message.
    let v = json!({
        "schema_version": 1, "image": {"digest": d(1)}, "source": "node",
        "scanned_at": "2026-10-03T08:00:00Z", "components": [],
    });
    match supplychain::normalise_sbom(&d(1), serde_json::from_value(v).unwrap(), t0()) {
        Err(supplychain::Reject::Invalid(m)) => {
            assert_eq!(m, "source must be one of trivy-operator, grype, registry")
        }
        other => panic!("{other:?}"),
    }
    // A matcher's findings may name the node SBOM they came from.
    let v = json!({
        "schema_version": 1, "image": {"digest": d(1)}, "source": "grype",
        "scanned_at": "2026-10-03T08:00:00Z", "vulnerabilities": [],
        "sbom_source": ["node", "registry", "made-up"],
    });
    let p = supplychain::normalise_vulnerabilities(&d(1), serde_json::from_value(v).unwrap(), t0())
        .unwrap();
    assert_eq!(p.header.sbom_sources, ["node", "registry"]);
}

#[test]
fn the_catalog_routes_declare_their_scopes() {
    use crate::auth::{declared_access, Access, Scope};
    use actix_web::http::Method;
    let cat = Some(Access::Requires(Scope::Catalog));
    let read = Some(Access::Requires(Scope::Read));
    assert_eq!(declared_access(&Method::POST, "/catalog/claims"), cat);
    assert_eq!(
        declared_access(&Method::PUT, "/catalog/claims/{digest}"),
        cat
    );
    assert_eq!(
        declared_access(&Method::POST, "/catalog/images/{digest}/sbom"),
        cat
    );
    assert_eq!(declared_access(&Method::GET, "/catalog/coverage"), read);
    assert_eq!(declared_access(&Method::GET, "/catalog/status"), read);
    assert_eq!(declared_access(&Method::GET, "/catalog/claims"), None);
}

#[test]
fn metrics_render_every_series_with_closed_labels() {
    let body = render_metrics_with(CatalogConfig {
        grants: false,
        retention_days: 14,
    });
    for name in [
        "kguardian_node_catalog_granted_total{reason=\"pending\"}",
        "kguardian_node_catalog_cataloged_total{reason=\"full\"}",
        "kguardian_node_catalog_failed_total{reason=\"oom\"}",
        "kguardian_node_catalog_skipped_total{reason=\"retry_cap\"}",
        "kguardian_node_catalog_scan_duration_seconds_bucket{le=\"+Inf\"}",
        "kguardian_node_catalog_scan_duration_seconds_count",
        "kguardian_node_catalog_grants_enabled 0",
    ] {
        assert!(body.contains(name), "missing {name}:\n{body}");
    }
    // Every line is a comment or `name{labels} value` / `name value`.
    for line in body.lines() {
        assert!(
            line.starts_with("# ") || line.split(' ').count() == 2,
            "bad line {line:?}"
        );
    }
    // Unknown labels are dropped, never minted.
    FAILED.inc("made-up");
    assert_eq!(FAILED.get("made-up"), 0);
}

// ---------------------------------------------------------------------
// HTTP without a database
// ---------------------------------------------------------------------

const CAT_TOK: &str = "catalog-token-0123456789";
const READ_TOK: &str = "read-token-0123456789";
const ADMIN_TOK: &str = "admin-token-0123456789";

fn auth(pairs: &[(&str, &str)]) -> AuthConfig {
    let owned: Vec<(String, String)> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    AuthConfig::from_lookup(move |k| owned.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.clone()))
        .unwrap()
}

macro_rules! status {
    ($app:expr, $req:expr) => {
        match atest::try_call_service(&$app, $req.to_request()).await {
            Ok(r) => r.status(),
            Err(e) => e.as_response_error().status_code(),
        }
    };
}

fn req(method: &str, path: &str, token: &str) -> atest::TestRequest {
    atest::TestRequest::default()
        .method(actix_web::http::Method::from_bytes(method.as_bytes()).unwrap())
        .uri(path)
        .insert_header((header::AUTHORIZATION, format!("Bearer {token}")))
        .insert_header((header::CONTENT_TYPE, "application/json"))
}

#[actix_web::test]
async fn catalog_writes_are_503_until_the_catalog_token_is_configured() {
    // Admin carries the catalog scope, but without BROKER_TOKEN_CATALOG the
    // writes refuse: the controller has no token to post with.
    let app = atest::init_service(
        App::new()
            .wrap(from_fn(crate::auth::authenticate))
            .app_data(web::Data::new(auth(&[("BROKER_TOKEN_ADMIN", ADMIN_TOK)])))
            .configure(crate::routes::configure),
    )
    .await;
    for (m, p) in [
        ("POST", "/catalog/claims".to_string()),
        ("PUT", format!("/catalog/claims/{}", d(1))),
        ("POST", format!("/catalog/images/{}/sbom", d(1))),
    ] {
        assert_eq!(
            status!(app, req(m, &p, ADMIN_TOK)),
            StatusCode::SERVICE_UNAVAILABLE,
            "{m} {p}"
        );
    }
}

#[actix_web::test]
async fn catalog_refusals_happen_before_the_database() {
    let app = atest::init_service(
        App::new()
            .wrap(from_fn(crate::auth::authenticate))
            .app_data(web::Data::new(auth(&[
                ("BROKER_TOKEN_CATALOG", CAT_TOK),
                ("BROKER_TOKEN_READ", READ_TOK),
            ])))
            .app_data(web::Data::new(crate::ReadBudget::with_budget_kib(
                1024,
                std::time::Duration::from_secs(1),
            )))
            .configure(crate::routes::configure),
    )
    .await;
    let up = format!("/catalog/images/{}/sbom", d(1));
    // The read token cannot write, the catalog token cannot read.
    assert_eq!(
        status!(app, req("POST", &up, READ_TOK)),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status!(app, req("GET", "/catalog/coverage", CAT_TOK)),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status!(app, req("POST", "/catalog/images/sha256:x/sbom", CAT_TOK)),
        StatusCode::BAD_REQUEST
    );
    // No claim header, or a malformed one.
    assert_eq!(
        status!(app, req("POST", &up, CAT_TOK)),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        status!(
            app,
            req("POST", &up, CAT_TOK).insert_header((CLAIM_HEADER, "not-a-uuid"))
        ),
        StatusCode::BAD_REQUEST
    );
    let tok = uuid::Uuid::new_v4().to_string();
    // Over the catalog's compressed limit.
    assert_eq!(
        status!(
            app,
            req("POST", &up, CAT_TOK)
                .insert_header((CLAIM_HEADER, tok.as_str()))
                .insert_header((header::CONTENT_LENGTH, MAX_CATALOG_COMPRESSED_BYTES + 1))
        ),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        status!(
            app,
            req("PUT", &format!("/catalog/claims/{}", d(1)), CAT_TOK)
                .insert_header((CLAIM_HEADER, tok.as_str()))
                .set_json(json!({"action": "fail", "node": "a", "reason": "nope"}))
        ),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        status!(
            app,
            req("POST", "/catalog/claims", CAT_TOK)
                .set_json(json!({"node": "Bad_Node", "platform": "linux/amd64", "epoch": 1}))
        ),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        status!(app, req("GET", "/catalog/status", READ_TOK)),
        StatusCode::BAD_REQUEST
    );
}

// ---------------------------------------------------------------------
// Live database: ignored by default, run by CI's `cargo test -- --ignored`
// against Postgres with the shipped migrations.
// ---------------------------------------------------------------------

const TEST_MIGRATIONS: diesel_migrations::EmbeddedMigrations =
    diesel_migrations::embed_migrations!("./db/migrations");

const NS: &str = "nc-test";
const WINDOW: i64 = 900;

fn url() -> String {
    std::env::var("KG_TEST_DATABASE_URL").expect("set KG_TEST_DATABASE_URL to run this test")
}

fn live_conn() -> PgConnection {
    use diesel::connection::SimpleConnection;
    use diesel_migrations::MigrationHarness;
    let mut conn = PgConnection::establish(&url()).expect("connect");
    conn.run_pending_migrations(TEST_MIGRATIONS)
        .expect("apply the shipped migrations");
    conn.batch_execute(&format!(
        "TRUNCATE node_catalog_claims, node_catalog_platforms, node_sbom_package_flags, \
            vuln_sources, image_vulnerabilities, image_sbom_components, image_sbom_pages, \
            supplychain_image_links, images, workload_containers; \
         DELETE FROM pod_details WHERE pod_namespace = '{NS}';"
    ))
    .expect("reset");
    conn
}

fn exec(conn: &mut PgConnection, sql: &str) {
    use diesel::connection::SimpleConnection;
    conn.batch_execute(sql).expect(sql);
}

fn count(conn: &mut PgConnection, sql: &str) -> i64 {
    #[derive(QueryableByName)]
    struct C {
        #[diesel(sql_type = BigInt)]
        n: i64,
    }
    sql_query(sql).get_result::<C>(conn).expect(sql).n
}

fn text(conn: &mut PgConnection, sql: &str) -> Option<String> {
    #[derive(QueryableByName)]
    struct T {
        #[diesel(sql_type = Nullable<Text>)]
        t: Option<String>,
    }
    sql_query(sql).get_result::<T>(conn).expect(sql).t
}

/// Digest `digest` run by Deployment `wl` (container `c`, state running),
/// with one live pod on each of `nodes`.
fn seed(conn: &mut PgConnection, digest: &str, wl: &str, nodes: &[&str]) {
    exec(
        conn,
        &format!(
            "INSERT INTO images (digest, repository, tags, digest_kind) \
               VALUES ('{digest}', 'docker.io/library/{wl}', ARRAY['1'], 'repo') ON CONFLICT DO NOTHING; \
             INSERT INTO workload_containers (pod_namespace, workload_kind, workload_name, \
               container_name, container_kind, image_ref, image_digest, state) \
             VALUES ('{NS}', 'Deployment', '{wl}', 'c', 'regular', '{wl}:1', '{digest}', 'running') \
             ON CONFLICT DO NOTHING;"
        ),
    );
    for n in nodes {
        exec(
            conn,
            &format!(
                "INSERT INTO pod_details (pod_name, pod_ip, pod_namespace, time_stamp, node_name, \
                   is_dead, workload_kind, workload_name) \
                 VALUES ('{wl}-{n}', '10.0.0.1', '{NS}', timezone('UTC', now()), '{n}', false, \
                   'Deployment', '{wl}') ON CONFLICT (pod_name) DO NOTHING;"
            ),
        );
    }
}

fn offer(node: &str, epoch: i64, digests: &[String]) -> Offer {
    let mut digests = digests.to_vec();
    digests.sort();
    Offer {
        node: node.into(),
        platform: "linux/amd64".into(),
        epoch,
        digests,
    }
}

fn grant(conn: &mut PgConnection, node: &str, epoch: i64, digests: &[String]) -> Option<Grant> {
    claim(conn, &offer(node, epoch, digests), true, WINDOW).unwrap()
}

fn token(g: &Grant) -> uuid::Uuid {
    uuid::Uuid::parse_str(&g.claim_token).unwrap()
}

fn upload(conn: &mut PgConnection, g: &Grant, v: serde_json::Value) -> Result<Uploaded, DbError> {
    let up = normalise_upload(&g.digest, serde_json::from_value(v).unwrap(), Utc::now()).unwrap();
    store_upload(conn, &g.digest, &token(g), up)
}

fn is_stale(r: Result<impl std::fmt::Debug, DbError>) -> bool {
    matches!(r, Err(e) if e.downcast_ref::<StaleClaim>().is_some())
}

fn state_of(conn: &mut PgConnection, digest: &str) -> String {
    text(
        conn,
        &format!("SELECT state AS t FROM node_catalog_claims WHERE inventory_digest = '{digest}'"),
    )
    .unwrap()
}

fn expire_lease(conn: &mut PgConnection, digest: &str) {
    exec(
        conn,
        &format!(
            "UPDATE node_catalog_claims SET lease_expires_at = now() - interval '1 second' \
             WHERE inventory_digest = '{digest}'"
        ),
    );
}

#[test]
#[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
fn live_database_fifty_concurrent_claimers_get_one_grant_per_digest() {
    const DIGESTS: u32 = 20;
    const CLAIMERS: usize = 50;
    let mut conn = live_conn();
    let nodes: Vec<String> = (0..CLAIMERS).map(|i| format!("node-{i}")).collect();
    let node_refs: Vec<&str> = nodes.iter().map(String::as_str).collect();
    let digests: Vec<String> = (1..=DIGESTS).map(d).collect();
    for (i, dg) in digests.iter().enumerate() {
        seed(&mut conn, dg, &format!("w{i}"), &node_refs);
    }
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(CLAIMERS));
    let handles: Vec<_> = (0..CLAIMERS)
        .map(|t| {
            let barrier = barrier.clone();
            let node = nodes[t].clone();
            // Overlapping windows of 10 digests.
            let mine: Vec<String> = (0..10)
                .map(|k| d(((t + k) % DIGESTS as usize) as u32 + 1))
                .collect();
            std::thread::spawn(move || {
                let mut c = PgConnection::establish(&url()).unwrap();
                barrier.wait();
                grant(&mut c, &node, 1, &mine).map(|g| (g, node))
            })
        })
        .collect();
    let mut granted: Vec<(Grant, String)> = handles
        .into_iter()
        .filter_map(|h| h.join().unwrap())
        .collect();
    let mut seen = std::collections::BTreeSet::new();
    for (g, _) in &granted {
        assert!(seen.insert(g.digest.clone()), "{} granted twice", g.digest);
    }
    // Sweep up what the race left: still one grant per digest.
    loop {
        let before = granted.len();
        for n in &nodes {
            if let Some(g) = grant(&mut conn, n, 1, &digests) {
                assert!(seen.insert(g.digest.clone()), "{} granted twice", g.digest);
                granted.push((g, n.clone()));
            }
        }
        if granted.len() == before {
            break;
        }
    }
    assert_eq!(granted.len(), DIGESTS as usize);
    assert_eq!(
        count(
            &mut conn,
            "SELECT count(*) AS n FROM node_catalog_claims WHERE state = 'claimed'"
        ),
        DIGESTS as i64
    );
    // Each row names the node its grant went to.
    for (g, n) in &granted {
        assert_eq!(
            text(
                &mut conn,
                &format!(
                    "SELECT node AS t FROM node_catalog_claims WHERE inventory_digest = '{}'",
                    g.digest
                )
            )
            .as_deref(),
            Some(n.as_str())
        );
    }
    assert_eq!(
        count(
            &mut conn,
            "SELECT count(*) AS n FROM node_catalog_platforms"
        ),
        CLAIMERS as i64,
        "every offer records its node's platform"
    );
}

#[test]
#[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
fn live_database_a_locked_row_is_skipped_not_waited_on() {
    let mut conn = live_conn();
    seed(&mut conn, &d(1), "a", &["n1"]);
    seed(&mut conn, &d(2), "b", &["n1"]);
    // Insert both rows, grant nothing.
    claim(&mut conn, &offer("n1", 1, &[d(1), d(2)]), false, WINDOW).unwrap();
    let mut holder = PgConnection::establish(&url()).unwrap();
    holder
        .transaction::<_, diesel::result::Error, _>(|h| {
            exec(
                h,
                &format!(
                    "SELECT 1 FROM node_catalog_claims WHERE inventory_digest = '{}' FOR UPDATE",
                    d(1)
                ),
            );
            // A claimer that would wait on the lock fails this timeout.
            exec(&mut conn, "SET statement_timeout = '2s'");
            let g = grant(&mut conn, "n1", 1, &[d(1), d(2)]).expect("the unlocked digest");
            assert_eq!(g.digest, d(2));
            assert_eq!(grant(&mut conn, "n1", 1, &[d(1)]), None);
            exec(&mut conn, "SET statement_timeout = 0");
            Ok(())
        })
        .unwrap();
    // Released: now it is claimable.
    assert_eq!(grant(&mut conn, "n1", 1, &[d(1)]).unwrap().digest, d(1));
}

#[test]
#[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
fn live_database_an_expired_lease_is_regranted_and_the_old_token_is_stale() {
    let mut conn = live_conn();
    seed(&mut conn, &d(1), "a", &["n1", "n2"]);
    let first = grant(&mut conn, "n1", 1, &[d(1)]).unwrap();
    assert!((first.lease_expires_at - Utc::now()).num_seconds() > LEASE_SECS - 60);
    assert_eq!(grant(&mut conn, "n2", 1, &[d(1)]), None, "held");
    // Renew keeps it.
    let r = update_claim(&mut conn, &d(1), &token(&first), "n1", &Action::Renew).unwrap();
    assert_eq!(r.state, "claimed");
    // Another node cannot renew or fail it with this token.
    assert!(is_stale(update_claim(
        &mut conn,
        &d(1),
        &token(&first),
        "n2",
        &Action::Renew
    )));
    expire_lease(&mut conn, &d(1));
    assert!(is_stale(update_claim(
        &mut conn,
        &d(1),
        &token(&first),
        "n1",
        &Action::Renew
    )));
    let second = grant(&mut conn, "n2", 1, &[d(1)]).expect("re-granted after expiry");
    assert_ne!(second.claim_token, first.claim_token);
    assert!(GRANTED.get("lease_expired") > 0);
    assert!(is_stale(upload(
        &mut conn,
        &first,
        upload_json(&d(1), 1, &["a"], None)
    )));
    let u = upload(&mut conn, &second, upload_json(&d(1), 1, &["a"], None)).unwrap();
    assert_eq!(u.claim, "done");
    assert_eq!(
        count(
            &mut conn,
            "SELECT attempts::bigint AS n FROM node_catalog_claims"
        ),
        2
    );
}

#[test]
#[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
fn live_database_the_final_page_with_a_stale_token_is_409_and_writes_nothing() {
    let mut conn = live_conn();
    seed(&mut conn, &d(1), "a", &["n1"]);
    let g = grant(&mut conn, "n1", 1, &[d(1)]).unwrap();
    let u = upload(&mut conn, &g, upload_json(&d(1), 1, &["a"], Some((0, 2)))).unwrap();
    assert!(matches!(
        u.outcome,
        Outcome::Staged {
            received: 1,
            total: 2
        }
    ));
    assert_eq!(u.claim, "claimed");
    expire_lease(&mut conn, &d(1));
    assert!(is_stale(upload(
        &mut conn,
        &g,
        upload_json(&d(1), 1, &["b"], Some((1, 2)))
    )));
    assert_eq!(
        count(
            &mut conn,
            "SELECT count(*) AS n FROM vuln_sources WHERE source = 'node'"
        ),
        0
    );
    assert_eq!(
        count(&mut conn, "SELECT count(*) AS n FROM image_sbom_pages"),
        1,
        "the refused page was not staged"
    );
    assert_eq!(state_of(&mut conn, &d(1)), "claimed");
    // A live lease (a fresh grant) completes the set.
    let g2 = grant(&mut conn, "n1", 1, &[d(1)]).unwrap();
    let u = upload(&mut conn, &g2, upload_json(&d(1), 1, &["b"], Some((1, 2)))).unwrap();
    assert_eq!(u.claim, "done");
    assert!(matches!(u.outcome, Outcome::Stored { items: 2 }));
    // The token is spent.
    assert!(is_stale(upload(
        &mut conn,
        &g2,
        upload_json(&d(1), 1, &["b"], Some((1, 2)))
    )));
}

#[test]
#[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
fn live_database_epochs_never_go_backwards() {
    let mut conn = live_conn();
    seed(&mut conn, &d(1), "a", &["n1", "n2"]);
    let g = grant(&mut conn, "n1", 2, &[d(1)]).unwrap();
    assert_eq!(
        count(&mut conn, "SELECT epoch AS n FROM node_catalog_claims"),
        2
    );
    assert!(
        is_stale(upload(&mut conn, &g, upload_json(&d(1), 1, &["a"], None))),
        "an older epoch cannot write"
    );
    upload(&mut conn, &g, upload_json(&d(1), 2, &["a"], None)).unwrap();
    assert_eq!(state_of(&mut conn, &d(1)), "done");
    // Done at epoch 2: an older or equal node gets nothing; a newer one
    // re-catalogs it.
    assert_eq!(grant(&mut conn, "n2", 1, &[d(1)]), None);
    assert_eq!(grant(&mut conn, "n2", 2, &[d(1)]), None);
    let g3 = grant(&mut conn, "n2", 3, &[d(1)]).expect("a newer epoch re-grants a done digest");
    assert_eq!(
        count(&mut conn, "SELECT epoch AS n FROM node_catalog_claims"),
        3
    );
    // Released at epoch 3, a node still at 2 cannot take it back.
    update_claim(
        &mut conn,
        &d(1),
        &token(&g3),
        "n2",
        &Action::Release("pid_gone".into(), FailClass::Retry),
    )
    .unwrap();
    assert_eq!(state_of(&mut conn, &d(1)), "pending");
    assert_eq!(grant(&mut conn, "n1", 2, &[d(1)]), None);
    assert!(grant(&mut conn, "n1", 3, &[d(1)]).is_some());
}

#[test]
#[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
fn live_database_skips_retry_caps_and_backoff_follow_the_database_clock() {
    let mut conn = live_conn();
    seed(&mut conn, &d(1), "a", &["n1", "n2"]);
    let release_by = |conn: &mut PgConnection, node: &str, reason: &str| {
        let g = grant(conn, node, 1, &[d(1)]).expect("claimable");
        update_claim(
            conn,
            &d(1),
            &token(&g),
            node,
            &Action::Release(reason.into(), classify(reason).unwrap()),
        )
        .unwrap()
    };
    // Per-node: n1 is skipped, n2 is not.
    release_by(&mut conn, "n1", "lsm_denied");
    assert_eq!(grant(&mut conn, "n1", 1, &[d(1)]), None);
    // The skip is a timestamp: 25 h old, it no longer applies.
    exec(
        &mut conn,
        "UPDATE node_catalog_claims SET skipped_nodes = jsonb_build_object('n1', \
             to_jsonb(now() - interval '25 hours'))",
    );
    // pid_gone: released at once, 3 per node, then n1 is skipped.
    release_by(&mut conn, "n1", "pid_gone");
    release_by(&mut conn, "n1", "drift");
    release_by(&mut conn, "n1", "pid_gone");
    assert_eq!(grant(&mut conn, "n1", 1, &[d(1)]), None, "retry cap");
    assert!(text(
        &mut conn,
        "SELECT skipped_nodes ->> 'n1' AS t FROM node_catalog_claims"
    )
    .is_some());
    // n2 still can; a timeout backs off an hour for everyone.
    let r = release_by(&mut conn, "n2", "timeout");
    assert_eq!(r.state, "failed");
    let wait = (r.next_attempt_at.unwrap() - Utc::now()).num_seconds();
    assert!((3500..=3600).contains(&wait), "{wait}");
    assert_eq!(grant(&mut conn, "n2", 1, &[d(1)]), None, "backing off");
    exec(
        &mut conn,
        "UPDATE node_catalog_claims SET next_attempt_at = now() - interval '1 second'",
    );
    let r = release_by(&mut conn, "n2", "oom");
    let wait = (r.next_attempt_at.unwrap() - Utc::now()).num_seconds();
    assert!((6 * 3600 - 100..=6 * 3600).contains(&wait), "{wait}");
    // no_packages_found ends it.
    exec(
        &mut conn,
        "UPDATE node_catalog_claims SET next_attempt_at = now() - interval '1 second'",
    );
    release_by(&mut conn, "n2", "no_packages_found");
    assert_eq!(state_of(&mut conn, &d(1)), "done");
    assert_eq!(grant(&mut conn, "n2", 1, &[d(1)]), None);
}

#[test]
#[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
fn live_database_the_kill_switch_stops_grants_but_not_uploads() {
    let mut conn = live_conn();
    seed(&mut conn, &d(1), "a", &["n1"]);
    seed(&mut conn, &d(2), "b", &["n1"]);
    let held = grant(&mut conn, "n1", 1, &[d(1)]).unwrap();
    assert_eq!(
        claim(&mut conn, &offer("n1", 1, &[d(1), d(2)]), false, WINDOW).unwrap(),
        None,
        "grants off"
    );
    // The offer is still recorded.
    assert_eq!(state_of(&mut conn, &d(2)), "pending");
    // The lease granted before the switch still completes.
    update_claim(&mut conn, &d(1), &token(&held), "n1", &Action::Renew).unwrap();
    let u = upload(&mut conn, &held, upload_json(&d(1), 1, &["a"], None)).unwrap();
    assert_eq!(u.claim, "done");
}

#[test]
#[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
fn live_database_a_node_that_does_not_run_the_digest_is_refused() {
    let mut conn = live_conn();
    seed(&mut conn, &d(1), "a", &["n1"]);
    // n2 runs other things only.
    seed(&mut conn, &d(2), "b", &["n2"]);
    assert_eq!(grant(&mut conn, "n2", 1, &[d(1)]), None);
    // A digest the inventory never saw is not even recorded.
    assert_eq!(grant(&mut conn, "n2", 1, &[d(99)]), None);
    assert_eq!(
        count(
            &mut conn,
            &format!(
                "SELECT count(*) AS n FROM node_catalog_claims WHERE inventory_digest = '{}'",
                d(99)
            )
        ),
        0
    );
    // A dead pod does not count.
    exec(
        &mut conn,
        "UPDATE pod_details SET is_dead = true WHERE pod_name = 'a-n1'",
    );
    assert_eq!(grant(&mut conn, "n1", 1, &[d(1)]), None);
    exec(
        &mut conn,
        "UPDATE pod_details SET is_dead = false WHERE pod_name = 'a-n1'",
    );
    // Nor a container that is not running.
    exec(
        &mut conn,
        "UPDATE workload_containers SET state = 'terminated' WHERE workload_name = 'a'",
    );
    assert_eq!(grant(&mut conn, "n1", 1, &[d(1)]), None);
    exec(
        &mut conn,
        "UPDATE workload_containers SET state = 'running', \
             last_seen = timezone('UTC', now()) - interval '2 hours' WHERE workload_name = 'a'",
    );
    // Stale inventory row: only the pod that last reported it keeps it.
    assert_eq!(grant(&mut conn, "n1", 1, &[d(1)]), None);
    exec(
        &mut conn,
        "UPDATE workload_containers SET last_pod_name = 'a-n1' WHERE workload_name = 'a'",
    );
    assert!(grant(&mut conn, "n1", 1, &[d(1)]).is_some());
    // A bare pod is keyed ('Pod', pod_name).
    exec(
        &mut conn,
        &format!(
            "INSERT INTO images (digest, digest_kind) VALUES ('{0}', 'repo'); \
             INSERT INTO workload_containers (pod_namespace, workload_kind, workload_name, \
               container_name, container_kind, image_ref, image_digest, state) \
             VALUES ('{NS}', 'Pod', 'solo', 'c', 'regular', 'x:1', '{0}', 'running'); \
             INSERT INTO pod_details (pod_name, pod_ip, pod_namespace, time_stamp, node_name, is_dead) \
             VALUES ('solo', '10.0.0.9', '{NS}', timezone('UTC', now()), 'n3', false);",
            d(3)
        ),
    );
    assert_eq!(grant(&mut conn, "n1", 1, &[d(3)]), None);
    assert_eq!(grant(&mut conn, "n3", 1, &[d(3)]).unwrap().digest, d(3));
}

#[test]
#[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
fn live_database_flags_retention_and_priorities() {
    let mut conn = live_conn();
    seed(&mut conn, &d(1), "a", &["n1"]);
    seed(&mut conn, &d(2), "b", &["n1"]);
    exec(
        &mut conn,
        &format!(
            "INSERT INTO workload_containers (pod_namespace, workload_kind, workload_name, \
               container_name, container_kind, image_ref, image_digest, state) \
             VALUES ('{NS}', 'Deployment', 'b', 'c2', 'regular', 'b:1', '{}', 'running')",
            d(2)
        ),
    );
    claim(&mut conn, &offer("n1", 1, &[d(1), d(2)]), false, WINDOW).unwrap();
    refresh_priorities(&mut conn, WINDOW).unwrap();
    // Two running containers beat one.
    assert_eq!(
        grant(&mut conn, "n1", 1, &[d(1), d(2)]).unwrap().digest,
        d(2)
    );
    let g = grant(&mut conn, "n1", 1, &[d(1)]).unwrap();
    let mut v = upload_json(&d(1), 1, &["busybox", "python3"], None);
    v["components"][1]["interpreted_content"] = json!(true);
    upload(&mut conn, &g, v).unwrap();
    #[derive(QueryableByName, Debug, PartialEq)]
    struct F {
        #[diesel(sql_type = Text)]
        pkg_key: String,
        #[diesel(sql_type = diesel::sql_types::SmallInt)]
        flags: i16,
    }
    let flags: Vec<F> =
        sql_query("SELECT pkg_key, flags FROM node_sbom_package_flags ORDER BY pkg_key")
            .load(&mut conn)
            .unwrap();
    assert_eq!(
        flags,
        [
            F {
                pkg_key: "busybox@1.0".into(),
                flags: FLAG_FILES_TRUNCATED
            },
            F {
                pkg_key: "python3@1.0".into(),
                flags: FLAG_INTERPRETED_CONTENT
            },
        ]
    );
    refresh_gauges(&mut conn, WINDOW).unwrap();
    assert_eq!(QUEUE_DEPTH.load(Ordering::Relaxed), 1);
    assert!(render_metrics().contains("kguardian_node_catalog_coverage_ratio 0.5"));
    // A Trivy SBOM for the same digest is kept by the node retention.
    exec(
        &mut conn,
        &format!(
            "INSERT INTO vuln_sources (digest, source, kind, digest_kind, scanned_at, content_hash, item_count) \
             VALUES ('{0}', 'trivy-operator', 'sbom', 'manifest', timezone('UTC', now()), 'x', 0)",
            d(1)
        ),
    );
    assert_eq!(retention_batch(&mut conn, 14, 50).unwrap(), 0, "still seen");
    exec(
        &mut conn,
        &format!(
            "UPDATE images SET last_seen = timezone('UTC', now()) - interval '15 days' \
             WHERE digest = '{}'",
            d(1)
        ),
    );
    assert_eq!(retention_batch(&mut conn, 14, 50).unwrap(), 1);
    for (sql, want) in [
        ("SELECT count(*) AS n FROM node_catalog_claims", 1),
        ("SELECT count(*) AS n FROM node_sbom_package_flags", 0),
        (
            "SELECT count(*) AS n FROM image_sbom_components WHERE source = 'node'",
            0,
        ),
        (
            "SELECT count(*) AS n FROM vuln_sources WHERE source = 'node'",
            0,
        ),
        (
            "SELECT count(*) AS n FROM vuln_sources WHERE source = 'trivy-operator'",
            1,
        ),
    ] {
        assert_eq!(count(&mut conn, sql), want, "{sql}");
    }
    exec(
        &mut conn,
        "UPDATE node_catalog_platforms SET seen_at = now() - interval '15 days'",
    );
    assert_eq!(prune_platforms(&mut conn, 14).unwrap(), 1);
}

#[test]
#[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
fn live_database_migration_is_reversible_and_idempotent() {
    use diesel::connection::SimpleConnection;
    use diesel_migrations::MigrationHarness;
    let mut conn = live_conn();
    let up = include_str!("../db/migrations/2026-10-03-100000_node_catalog/up.sql");
    // Re-running up over itself is a no-op.
    conn.batch_execute(up).unwrap();
    let tables = |conn: &mut PgConnection| {
        count(
            conn,
            "SELECT count(*) AS n FROM pg_tables WHERE tablename IN \
             ('node_catalog_claims', 'node_catalog_platforms', 'node_sbom_package_flags')",
        )
    };
    assert_eq!(tables(&mut conn), 3);
    let reverted = conn.revert_last_migration(TEST_MIGRATIONS).unwrap();
    assert_eq!(reverted.to_string(), "20261003100000");
    assert_eq!(tables(&mut conn), 0);
    assert_eq!(
        count(
            &mut conn,
            "SELECT count(*) AS n FROM pg_proc WHERE proname = 'kg_digest_runs_on_node'"
        ),
        0
    );
    conn.run_pending_migrations(TEST_MIGRATIONS).unwrap();
    assert_eq!(tables(&mut conn), 3);
    conn.batch_execute(up).unwrap();
    assert!(conn.pending_migrations(TEST_MIGRATIONS).unwrap().is_empty());
}

/// The whole HTTP path with a real pool: claim, renew, paged gzip
/// upload, then the node SBOM in /images, the CycloneDX export, coverage
/// and status.
#[actix_web::test]
#[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
async fn live_database_http_node_sbom_end_to_end() {
    let mut conn = live_conn();
    seed(&mut conn, &d(7), "api", &["n1"]);
    drop(conn);
    let pool = r2d2::Pool::builder()
        .max_size(2)
        .build(ConnectionManager::<PgConnection>::new(url()))
        .unwrap();
    let app = atest::init_service(
        App::new()
            .wrap(from_fn(crate::auth::authenticate))
            .app_data(web::Data::new(auth(&[
                ("BROKER_TOKEN_CATALOG", CAT_TOK),
                ("BROKER_TOKEN_READ", READ_TOK),
            ])))
            .app_data(web::Data::new(pool))
            .app_data(web::Data::new(crate::ReadBudget::with_budget_kib(
                64 * 1024,
                std::time::Duration::from_secs(1),
            )))
            .configure(crate::routes::configure),
    )
    .await;
    let body: serde_json::Value = atest::call_and_read_body_json(
        &app,
        req("POST", "/catalog/claims", CAT_TOK)
            .set_json(json!({"node": "n1", "platform": "linux/arm64", "epoch": 1, "offer": [d(7)]}))
            .to_request(),
    )
    .await;
    assert_eq!(body["grantsEnabled"], true);
    let tok = body["grant"]["claimToken"].as_str().unwrap().to_string();
    assert_eq!(body["grant"]["digest"], d(7));
    assert_eq!(body["grant"]["leaseSeconds"], LEASE_SECS);
    let put = format!("/catalog/claims/{}", d(7));
    let body: serde_json::Value = atest::call_and_read_body_json(
        &app,
        req("PUT", &put, CAT_TOK)
            .insert_header((CLAIM_HEADER, tok.as_str()))
            .set_json(json!({"action": "renew", "node": "n1"}))
            .to_request(),
    )
    .await;
    assert_eq!(body["state"], "claimed");
    let up = format!("/catalog/images/{}/sbom", d(7));
    for (i, names) in [(1, ["musl"]), (0, ["busybox"])] {
        let b = serde_json::to_vec(&upload_json(&d(7), 1, &names, Some((i, 2)))).unwrap();
        let resp = atest::call_service(
            &app,
            req("POST", &up, CAT_TOK)
                .insert_header((CLAIM_HEADER, tok.as_str()))
                .insert_header((header::CONTENT_ENCODING, "gzip"))
                .set_payload(gzip(&b))
                .to_request(),
        )
        .await;
        let status = resp.status();
        let out: serde_json::Value = atest::read_body_json(resp).await;
        if i == 1 {
            assert_eq!(status, StatusCode::ACCEPTED, "{out}");
            assert_eq!(out["claim"], "claimed");
        } else {
            assert_eq!(status, StatusCode::OK, "{out}");
            assert_eq!(
                out,
                json!({"status": "stored", "items": 2, "claim": "done"})
            );
        }
    }
    // Renewing a done claim: the token is spent.
    assert_eq!(
        status!(
            app,
            req("PUT", &put, CAT_TOK)
                .insert_header((CLAIM_HEADER, tok.as_str()))
                .set_json(json!({"action": "renew", "node": "n1"}))
        ),
        StatusCode::CONFLICT
    );
    let images: serde_json::Value =
        atest::call_and_read_body_json(&app, req("GET", "/images", READ_TOK).to_request()).await;
    let item = &images["items"][0];
    assert_eq!(item["digest"], d(7));
    assert_eq!(item["sbomSources"], json!(["node"]));
    assert_eq!(item["nodeCatalog"]["state"], "done");
    assert_eq!(item["nodeCatalog"]["platform"], "linux/arm64");
    assert_eq!(item["nodeCatalog"]["completeness"], "full");
    assert!(item["nodeCatalog"]["catalogedAt"].is_string());
    let sbom: serde_json::Value = atest::call_and_read_body_json(
        &app,
        req("GET", &format!("/images/{}/sbom", d(7)), READ_TOK).to_request(),
    )
    .await;
    assert_eq!(sbom["report"]["source"], "node", "{sbom}");
    assert_eq!(sbom["report"]["sbomTrust"], "scanned");
    let cdx: serde_json::Value = atest::call_and_read_body_json(
        &app,
        req("GET", &format!("/images/{}/sbom/cyclonedx", d(7)), READ_TOK).to_request(),
    )
    .await;
    let names: Vec<&str> = cdx["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["busybox", "musl"], "{cdx}");
    let cov: serde_json::Value = atest::call_and_read_body_json(
        &app,
        req("GET", "/catalog/coverage", READ_TOK).to_request(),
    )
    .await;
    assert_eq!(cov["runningImages"], 1);
    assert_eq!(cov["node"], 1);
    assert_eq!(cov["coverageRatio"], 1.0);
    assert_eq!(cov["byState"]["done"], 1);
    assert_eq!(cov["byCompleteness"]["full"], 1);
    assert_eq!(cov["platforms"]["linux/arm64"], 1);
    assert_eq!(cov["tokenConfigured"], true);
    let st: serde_json::Value = atest::call_and_read_body_json(
        &app,
        req("GET", "/catalog/status?node=n1", READ_TOK).to_request(),
    )
    .await;
    assert_eq!(st["platform"], "linux/arm64");
    assert_eq!(st["cataloged"], 1);
    assert_eq!(st["claims"], json!([]));
}
