use super::*;
use chrono::TimeZone;
use serde_json::json;
use std::io::Write;

fn d(i: u32) -> String {
    format!("sha256:{:064x}", i)
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 27, 12, 0, 0).unwrap()
}

fn vulns_json(
    digest: &str,
    scanned_at: &str,
    ids: &[(&str, &str, Option<&str>)],
) -> serde_json::Value {
    json!({
        "schema_version": 1,
        "image": {"digest": digest, "ref": "ghcr.io/example/api:2.4.1", "registry": "ghcr.io",
                  "repository": "example/api", "tag": "2.4.1", "digest_kind": "manifest"},
        "source": "trivy-operator",
        "scanner": {"name": "Trivy", "vendor": "Aqua Security", "version": "0.58.1"},
        "scanned_at": scanned_at,
        "os": {"family": "alpine", "name": "3.20.3"},
        "observed_in": [{"namespace": "shop", "kind": "ReplicaSet", "name": "api-7c9d8f6b5", "container": "api"}],
        "vulnerabilities": ids.iter().map(|(id, sev, fix)| json!({
            "id": id,
            "package": {"name": format!("pkg-{id}"), "version": "1.0.0", "type": "npm",
                        "purl": format!("pkg:npm/pkg-{id}@1.0.0")},
            "fixed_version": fix,
            "severity": sev,
            "score": 7.5,
            "cvss": {"nvd": {"v3_score": 7.5, "v3_vector": "CVSS:3.1/AV:N"}},
            "title": "t",
            "primary_url": "https://example.invalid/x",
            "file_paths": ["app/node_modules/x/package.json"]
        })).collect::<Vec<_>>()
    })
}

fn parse_vulns(v: serde_json::Value) -> WireImageVulnerabilities {
    serde_json::from_value(v).unwrap()
}

fn sbom_json(
    digest: &str,
    scanned_at: &str,
    names: &[&str],
    page: Option<(&str, i64, i64)>,
) -> serde_json::Value {
    let mut v = json!({
        "schema_version": 1,
        "image": {"digest": digest, "digest_kind": "unknown"},
        "source": "trivy-operator",
        "scanner": {"name": "Trivy", "version": "0.74.0"},
        "scanned_at": scanned_at,
        "format": "CycloneDX",
        "spec_version": "1.6",
        "components": names.iter().map(|n| json!({
            "name": n, "version": "1", "purl": format!("pkg:deb/debian/{n}@1"), "type": "debian",
            "licenses": ["MIT"], "file_paths": [format!("/usr/lib/{n}.so")]
        })).collect::<Vec<_>>()
    });
    if let Some((set, index, total)) = page {
        v["page"] = json!({"set_id": set, "index": index, "total": total});
    }
    v
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(bytes).unwrap();
    e.finish().unwrap()
}

// ---------------------------------------------------------------------
// Pure
// ---------------------------------------------------------------------

#[test]
fn repositories_normalise_like_the_inventory() {
    let n = |r: Option<&str>, p: &str| normalise_repository(r, Some(p));
    assert_eq!(
        n(Some("index.docker.io"), "library/nginx").unwrap(),
        "docker.io/library/nginx"
    );
    assert_eq!(
        n(Some("docker.io"), "nginx").unwrap(),
        "docker.io/library/nginx"
    );
    assert_eq!(n(None, "bitnami/redis").unwrap(), "docker.io/bitnami/redis");
    assert_eq!(
        n(Some("GHCR.io"), "example/api").unwrap(),
        "ghcr.io/example/api"
    );
    assert_eq!(n(None, "quay.io/org/app").unwrap(), "quay.io/org/app");
    assert_eq!(
        n(Some("registry-1.docker.io"), "org/app").unwrap(),
        "docker.io/org/app"
    );
    assert_eq!(normalise_repository(Some("ghcr.io"), None), None);
    assert_eq!(normalise_repository(Some("ghcr.io"), Some(" ")), None);
}

#[test]
fn severities_rank_and_unknown_is_kept() {
    assert_eq!(severity_rank("critical"), ("CRITICAL".into(), 5));
    assert_eq!(severity_rank(" High "), ("HIGH".into(), 4));
    assert_eq!(severity_rank("NONE"), ("NONE".into(), 1));
    assert_eq!(severity_rank("bogus"), ("UNKNOWN".into(), 0));
    assert_eq!(severity_from_rank(3), "MEDIUM");
    assert_eq!(severity_from_rank(0), "UNKNOWN");
}

#[test]
fn vulnerabilities_normalise_and_bound() {
    let mut v = vulns_json(
        &d(1),
        "2026-09-20T08:00:00Z",
        &[("CVE-1", "high", Some("2.0"))],
    );
    v["vulnerabilities"][0]["file_paths"] =
        json!((0..40).map(|i| format!("/p/{i}")).collect::<Vec<_>>());
    v["vulnerabilities"][0]["title"] = json!(format!("x\u{0007}{}", "y".repeat(2000)));
    v["image"]["platform_manifests"] = json!({"linux/amd64": d(2), "unknown/unknown": "garbage"});
    let p = normalise_vulnerabilities(&d(1), parse_vulns(v), now()).unwrap();
    assert_eq!(p.header.kind, "vulnerabilities");
    assert_eq!(
        p.header.norm_repository.as_deref(),
        Some("ghcr.io/example/api")
    );
    assert_eq!(p.header.manifest_digests, vec![d(2)]);
    assert_eq!(p.header.os_family.as_deref(), Some("alpine"));
    assert_eq!(p.header.item_count, 1);
    let r = &p.rows[0];
    assert_eq!((r.severity.as_str(), r.severity_rank), ("HIGH", 4));
    assert_eq!(r.file_paths.len(), MAX_FILE_PATHS);
    let title = r.title.as_ref().unwrap();
    assert!(title.len() <= LEN_TITLE && !title.contains('\u{0007}'));
    assert_eq!(r.fixed_version.as_deref(), Some("2.0"));
}

#[test]
fn vulnerabilities_contract_violations_are_refused() {
    let base = || vulns_json(&d(1), "2026-09-20T08:00:00Z", &[("CVE-1", "LOW", None)]);
    // Path and body disagree.
    assert!(matches!(
        normalise_vulnerabilities(&d(9), parse_vulns(base()), now()),
        Err(Reject::Invalid(_))
    ));
    let mut v = base();
    v["schema_version"] = json!(2);
    assert!(matches!(
        normalise_vulnerabilities(&d(1), parse_vulns(v), now()),
        Err(Reject::Invalid(m)) if m.contains("schema_version")
    ));
    let mut v = base();
    v["source"] = json!("Trivy Operator!");
    assert!(normalise_vulnerabilities(&d(1), parse_vulns(v), now()).is_err());
    // A far-future scan would block every later one.
    let v = vulns_json(&d(1), "2027-01-01T00:00:00Z", &[]);
    assert!(matches!(
        normalise_vulnerabilities(&d(1), parse_vulns(v), now()),
        Err(Reject::Invalid(m)) if m.contains("future")
    ));
    let mut v = base();
    v["vulnerabilities"][0]["id"] = json!("  ");
    assert!(normalise_vulnerabilities(&d(1), parse_vulns(v), now()).is_err());
    let mut v = base();
    v["image"]["digest"] = json!("sha256:short");
    assert!(normalise_vulnerabilities("sha256:short", parse_vulns(v), now()).is_err());
}

#[test]
fn too_many_findings_is_413() {
    let mut v = vulns_json(&d(1), "2026-09-20T08:00:00Z", &[]);
    let one = json!({"id": "CVE-1", "package": {"name": "p", "version": "1"}, "severity": "LOW"});
    v["vulnerabilities"] = json!(vec![one; MAX_VULNERABILITIES + 1]);
    assert!(matches!(
        normalise_vulnerabilities(&d(1), parse_vulns(v), now()),
        Err(Reject::TooLarge(_))
    ));
}

#[test]
fn sbom_pages_are_validated() {
    let ok = |pg| {
        let v = sbom_json(&d(1), "2026-09-20T08:00:00Z", &["a"], pg);
        normalise_sbom(&d(1), serde_json::from_value(v).unwrap(), now())
    };
    assert!(ok(None).is_ok());
    assert!(ok(Some(("set-1", 0, 2))).is_ok());
    assert!(ok(Some(("set-1", 2, 2))).is_err());
    assert!(ok(Some(("set-1", -1, 2))).is_err());
    assert!(ok(Some(("set-1", 0, 0))).is_err());
    assert!(ok(Some(("set-1", 0, MAX_SBOM_PAGES + 1))).is_err());
    assert!(ok(Some(("bad set", 0, 1))).is_err());
}

#[test]
fn gzip_round_trips_and_bombs_are_refused_at_the_ceiling() {
    let body = br#"{"hello":"world"}"#;
    assert_eq!(inflate_bounded(&gzip(body), 1024).unwrap(), body);
    // 64 MiB of zeros compresses to ~64 KiB: well under the 1 MiB wire cap.
    let bomb = gzip(&vec![0u8; 64 * 1024 * 1024]);
    assert!(
        bomb.len() < MAX_COMPRESSED_BYTES,
        "bomb is {} bytes",
        bomb.len()
    );
    assert!(matches!(
        inflate_bounded(&bomb, 8 * 1024 * 1024),
        Err(BodyError::TooLarge(_))
    ));
    // Exactly at the ceiling is fine; one byte over is not.
    let exact = gzip(&vec![1u8; 4096]);
    assert!(inflate_bounded(&exact, 4096).is_ok());
    assert!(matches!(
        inflate_bounded(&exact, 4095),
        Err(BodyError::TooLarge(_))
    ));
    assert!(matches!(
        inflate_bounded(b"definitely not gzip", 1024),
        Err(BodyError::Corrupt(_))
    ));
}

#[test]
fn decompressed_ceiling_parses_and_clamps() {
    assert_eq!(parse_max_decompressed(None), DEFAULT_MAX_DECOMPRESSED_BYTES);
    assert_eq!(
        parse_max_decompressed(Some("nope")),
        DEFAULT_MAX_DECOMPRESSED_BYTES
    );
    assert_eq!(parse_max_decompressed(Some("1")), MAX_COMPRESSED_BYTES);
    assert_eq!(
        parse_max_decompressed(Some("999999999999")),
        128 * 1024 * 1024
    );
    assert_eq!(parse_max_decompressed(Some(" 2097152 ")), 2 * 1024 * 1024);
}

fn auth(pairs: &[(&str, &str)]) -> AuthConfig {
    let owned: Vec<(String, String)> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    AuthConfig::from_lookup(move |k| owned.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.clone()))
        .unwrap()
}

const SC_TOK: &str = "supplychain-token-0123456789";
const READ_TOK: &str = "read-token-0123456789";

#[test]
fn ingest_needs_scoped_auth() {
    assert!(!ingest_allowed(None));
    assert!(!ingest_allowed(Some(&AuthConfig::default())));
    // The legacy shared token is read + ingest only: not scoped for this.
    assert!(!ingest_allowed(Some(&auth(&[(
        "BROKER_AUTH_TOKEN",
        "legacy-token-0123456789"
    )]))));
    assert!(ingest_allowed(Some(&auth(&[(
        "BROKER_TOKEN_SUPPLYCHAIN",
        SC_TOK
    )]))));
    assert!(ingest_allowed(Some(&auth(&[(
        "BROKER_TOKEN_ADMIN",
        "admin-token-0123456789"
    )]))));
}

// ---------------------------------------------------------------------
// Through the real router, no database: every refusal happens before a
// connection is needed.
// ---------------------------------------------------------------------

use actix_web::http::StatusCode;
use actix_web::{middleware::from_fn, test as atest, App};

macro_rules! app {
    ($cfg:expr) => {
        atest::init_service(
            App::new()
                .wrap(from_fn(crate::auth::authenticate))
                .app_data(web::Data::new($cfg))
                .configure(crate::routes::configure),
        )
        .await
    };
}

fn post(path: &str, body: Vec<u8>, gz: bool, token: &str) -> atest::TestRequest {
    let mut r = atest::TestRequest::post()
        .uri(path)
        .insert_header((header::AUTHORIZATION, format!("Bearer {token}")))
        .insert_header((header::CONTENT_TYPE, "application/json"));
    if gz {
        r = r.insert_header((header::CONTENT_ENCODING, "gzip"));
    }
    r.set_payload(body)
}

/// Status of one request; a middleware refusal comes back as `Err`.
macro_rules! status {
    ($app:expr, $req:expr) => {
        match atest::try_call_service(&$app, $req.to_request()).await {
            Ok(r) => r.status(),
            Err(e) => e.as_response_error().status_code(),
        }
    };
}

#[actix_web::test]
async fn ingest_refusals_happen_before_the_database() {
    let path = format!("/images/{}/vulnerabilities", d(1));
    let good = serde_json::to_vec(&vulns_json(&d(1), "2026-09-20T08:00:00Z", &[])).unwrap();

    // Auth off: refused outright.
    let open = app!(AuthConfig::default());
    let r = atest::TestRequest::post()
        .uri(&path)
        .set_payload(gzip(&good))
        .insert_header((header::CONTENT_ENCODING, "gzip"));
    assert_eq!(status!(open, r), StatusCode::FORBIDDEN);

    let app = app!(auth(&[
        ("BROKER_TOKEN_SUPPLYCHAIN", SC_TOK),
        ("BROKER_TOKEN_READ", READ_TOK)
    ]));
    // Read token: wrong scope.
    assert_eq!(
        status!(app, post(&path, gzip(&good), true, READ_TOK)),
        StatusCode::FORBIDDEN
    );
    // Compressed body over 1 MiB.
    let noise: Vec<u8> = (0..(MAX_COMPRESSED_BYTES + 10))
        .map(|i| (i as u32).wrapping_mul(2654435761).to_le_bytes()[1])
        .collect();
    assert_eq!(
        status!(app, post(&path, noise.clone(), true, SC_TOK)),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    // Uncompressed body over 1 MiB.
    assert_eq!(
        status!(app, post(&path, noise, false, SC_TOK)),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    // A bomb: small on the wire, over the inflate ceiling.
    let bomb = gzip(&vec![b' '; max_decompressed_bytes() + 1]);
    assert!(bomb.len() < MAX_COMPRESSED_BYTES);
    assert_eq!(
        status!(app, post(&path, bomb, true, SC_TOK)),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    // Not gzip despite the header.
    assert_eq!(
        status!(app, post(&path, b"{}".to_vec(), true, SC_TOK)),
        StatusCode::BAD_REQUEST
    );
    // Unsupported encoding.
    let r = atest::TestRequest::post()
        .uri(&path)
        .insert_header((header::AUTHORIZATION, format!("Bearer {SC_TOK}")))
        .insert_header((header::CONTENT_ENCODING, "br"))
        .set_payload(good.clone());
    assert_eq!(status!(app, r), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    // Path digest != body digest.
    let other = format!("/images/{}/vulnerabilities", d(2));
    assert_eq!(
        status!(app, post(&other, gzip(&good), true, SC_TOK)),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    // Malformed JSON.
    assert_eq!(
        status!(app, post(&path, gzip(b"{"), true, SC_TOK)),
        StatusCode::BAD_REQUEST
    );
    // A valid body gets as far as the (absent) pool.
    assert_eq!(
        status!(app, post(&path, gzip(&good), true, SC_TOK)),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

// ---------------------------------------------------------------------
// Live database: ignored by default, run by CI's `cargo test -- --ignored`
// against Postgres with the shipped migrations.
// ---------------------------------------------------------------------

const TEST_MIGRATIONS: diesel_migrations::EmbeddedMigrations =
    diesel_migrations::embed_migrations!("./db/migrations");

const NS: &str = "sc-test";

fn live_conn() -> PgConnection {
    use diesel::connection::SimpleConnection;
    use diesel_migrations::MigrationHarness;
    let Ok(url) = std::env::var("KG_TEST_DATABASE_URL") else {
        panic!("set KG_TEST_DATABASE_URL to run this test");
    };
    let mut conn = PgConnection::establish(&url).expect("connect");
    conn.run_pending_migrations(TEST_MIGRATIONS)
        .expect("apply the shipped migrations");
    conn.batch_execute(&format!(
        "TRUNCATE vuln_sources, image_vulnerabilities, image_sbom_components, image_sbom_pages, \
            supplychain_image_links, images, workload_containers; \
         DELETE FROM pod_traffic WHERE pod_namespace = '{NS}'; \
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

#[allow(clippy::too_many_arguments)]
/// An inventory digest run by (NS, kind, name, container), last seen
/// `age_days` ago, in state `running`.
fn seed_inventory(
    conn: &mut PgConnection,
    digest: &str,
    repo: &str,
    tag: &str,
    kind: &str,
    name: &str,
    container: &str,
    age_days: i64,
) {
    exec(
        conn,
        &format!(
            "INSERT INTO images (digest, repository, tags, digest_kind) \
               VALUES ('{digest}', '{repo}', ARRAY['{tag}'], 'repo') ON CONFLICT DO NOTHING; \
             INSERT INTO workload_containers (pod_namespace, workload_kind, workload_name, \
               container_name, container_kind, image_ref, image_digest, state, last_seen) \
             VALUES ('{NS}', '{kind}', '{name}', '{container}', 'regular', '{repo}:{tag}', \
               '{digest}', 'running', timezone('UTC', NOW()) - INTERVAL '{age_days} days');"
        ),
    );
}

fn store_v(conn: &mut PgConnection, v: serde_json::Value) -> Outcome {
    let digest = v["image"]["digest"].as_str().unwrap().to_string();
    let p = normalise_vulnerabilities(&digest, parse_vulns(v), Utc::now()).unwrap();
    store_vulnerabilities(conn, p).unwrap()
}

fn store_s(conn: &mut PgConnection, v: serde_json::Value) -> Result<Outcome, DbError> {
    let digest = v["image"]["digest"].as_str().unwrap().to_string();
    let p = normalise_sbom(&digest, serde_json::from_value(v).unwrap(), Utc::now()).unwrap();
    store_sbom(conn, p)
}

fn component_names(conn: &mut PgConnection, digest: &str) -> Vec<String> {
    #[derive(QueryableByName)]
    struct N {
        #[diesel(sql_type = Text)]
        name: String,
    }
    sql_query("SELECT name FROM image_sbom_components WHERE digest = $1 ORDER BY id")
        .bind::<Text, _>(digest)
        .load::<N>(conn)
        .unwrap()
        .into_iter()
        .map(|n| n.name)
        .collect()
}

fn links(conn: &mut PgConnection) -> Vec<(String, String, String)> {
    #[derive(QueryableByName)]
    struct L {
        #[diesel(sql_type = Text)]
        digest: String,
        #[diesel(sql_type = Text)]
        image_digest: String,
        #[diesel(sql_type = Text)]
        join_kind: String,
    }
    sql_query(
        "SELECT digest, image_digest, join_kind FROM supplychain_image_links \
         ORDER BY digest, image_digest",
    )
    .load::<L>(conn)
    .unwrap()
    .into_iter()
    .map(|l| (l.digest, l.image_digest, l.join_kind))
    .collect()
}

#[test]
#[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
fn live_database_vulnerabilities_are_idempotent_and_never_overwritten_by_older_scans() {
    let mut conn = live_conn();
    let newer = vulns_json(
        &d(1),
        "2026-09-20T08:00:00Z",
        &[("CVE-2", "CRITICAL", Some("2.0")), ("CVE-1", "LOW", None)],
    );
    assert_eq!(
        store_v(&mut conn, newer.clone()),
        Outcome::Stored { items: 2 }
    );
    let ids_before = count(
        &mut conn,
        "SELECT sum(id)::bigint AS n FROM image_vulnerabilities",
    );
    // The same payload again: nothing rewritten.
    assert_eq!(store_v(&mut conn, newer.clone()), Outcome::Unchanged);
    assert_eq!(
        count(
            &mut conn,
            "SELECT sum(id)::bigint AS n FROM image_vulnerabilities"
        ),
        ids_before
    );
    // An older scan with different content: ignored.
    let older = vulns_json(&d(1), "2026-09-19T08:00:00Z", &[("CVE-9", "HIGH", None)]);
    assert!(matches!(store_v(&mut conn, older), Outcome::Stale { .. }));
    assert_eq!(
        count(
            &mut conn,
            "SELECT count(*) AS n FROM image_vulnerabilities WHERE vuln_id = 'CVE-9'"
        ),
        0
    );
    // A newer scan replaces the set.
    let newest = vulns_json(&d(1), "2026-09-21T08:00:00Z", &[("CVE-3", "MEDIUM", None)]);
    assert_eq!(store_v(&mut conn, newest), Outcome::Stored { items: 1 });
    assert_eq!(
        count(&mut conn, "SELECT count(*) AS n FROM image_vulnerabilities"),
        1
    );
    assert_eq!(
        count(&mut conn, "SELECT count(*) AS n FROM vuln_sources"),
        1
    );
}

#[test]
#[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
fn live_database_paged_sbom_assembles_out_of_order_with_duplicates() {
    let mut conn = live_conn();
    let at = "2026-09-20T08:00:00Z";
    let page = |i: i64, names: &[&str]| sbom_json(&d(5), at, names, Some(("set-a", i, 3)));
    assert_eq!(
        store_s(&mut conn, page(2, &["e", "f"])).unwrap(),
        Outcome::Staged {
            received: 1,
            total: 3
        }
    );
    assert_eq!(
        store_s(&mut conn, page(0, &["a", "b"])).unwrap(),
        Outcome::Staged {
            received: 2,
            total: 3
        }
    );
    assert_eq!(
        store_s(&mut conn, page(0, &["a", "b"])).unwrap(),
        Outcome::DuplicatePage {
            received: 2,
            total: 3
        }
    );
    // Nothing is visible until the set is complete.
    assert!(component_names(&mut conn, &d(5)).is_empty());
    assert_eq!(
        store_s(&mut conn, page(1, &["c", "d"])).unwrap(),
        Outcome::Stored { items: 6 }
    );
    // Page order, then order within the page.
    assert_eq!(
        component_names(&mut conn, &d(5)),
        ["a", "b", "c", "d", "e", "f"]
    );
    assert_eq!(
        count(&mut conn, "SELECT count(*) AS n FROM image_sbom_pages"),
        0
    );
    // A late re-send of a page of the live set changes nothing.
    assert_eq!(
        store_s(&mut conn, page(1, &["c", "d"])).unwrap(),
        Outcome::Unchanged
    );
    assert_eq!(
        count(&mut conn, "SELECT count(*) AS n FROM image_sbom_pages"),
        0
    );

    // A newer set staged, then an older set's page arrives: stale, and
    // the older set's pages are not kept.
    let newer = |i: i64| sbom_json(&d(5), "2026-09-22T08:00:00Z", &["x"], Some(("set-c", i, 2)));
    let older = |i: i64| sbom_json(&d(5), "2026-09-21T08:00:00Z", &["y"], Some(("set-b", i, 2)));
    assert_eq!(
        store_s(&mut conn, older(0)).unwrap(),
        Outcome::Staged {
            received: 1,
            total: 2
        }
    );
    assert_eq!(
        store_s(&mut conn, newer(0)).unwrap(),
        Outcome::Staged {
            received: 1,
            total: 2
        }
    );
    assert_eq!(
        count(
            &mut conn,
            "SELECT count(*) AS n FROM image_sbom_pages WHERE set_id = 'set-b'"
        ),
        0,
        "the newer set drops the older incomplete one"
    );
    assert!(matches!(
        store_s(&mut conn, older(1)).unwrap(),
        Outcome::Stale { .. }
    ));
    assert_eq!(
        component_names(&mut conn, &d(5)),
        ["a", "b", "c", "d", "e", "f"]
    );
    assert_eq!(
        store_s(&mut conn, newer(1)).unwrap(),
        Outcome::Stored { items: 2 }
    );
    assert_eq!(component_names(&mut conn, &d(5)), ["x", "x"]);
    // An SBOM older than the live one, sent whole: stale.
    let old_whole = sbom_json(&d(5), "2026-09-01T08:00:00Z", &["old"], None);
    assert!(matches!(
        store_s(&mut conn, old_whole).unwrap(),
        Outcome::Stale { .. }
    ));

    // Pages that disagree on total are refused.
    let a = sbom_json(&d(6), at, &["a"], Some(("set-z", 0, 2)));
    let b = sbom_json(&d(6), at, &["b"], Some(("set-z", 1, 3)));
    store_s(&mut conn, a).unwrap();
    let err = store_s(&mut conn, b).unwrap_err();
    assert!(err.downcast_ref::<SetConflict>().is_some(), "{err}");
    // An unpaged SBOM is stored directly and is idempotent.
    let whole = sbom_json(&d(7), at, &["p", "q"], None);
    assert_eq!(
        store_s(&mut conn, whole.clone()).unwrap(),
        Outcome::Stored { items: 2 }
    );
    assert_eq!(store_s(&mut conn, whole).unwrap(), Outcome::Unchanged);
}

#[test]
#[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
fn live_database_joins_by_image_id_then_platform_manifest_then_workload_tag() {
    let mut conn = live_conn();
    // 1. image_id: the kubelet reported the payload's own digest.
    seed_inventory(
        &mut conn,
        &d(11),
        "docker.io/library/nginx",
        "1.27",
        "Deployment",
        "web",
        "nginx",
        0,
    );
    let mut v = vulns_json(&d(11), "2026-09-20T08:00:00Z", &[("CVE-A", "HIGH", None)]);
    v["observed_in"] = json!([]);
    store_v(&mut conn, v);
    // 2. platform_manifest: payload is an index, the kubelet ran the amd64
    //    manifest.
    seed_inventory(
        &mut conn,
        &d(12),
        "quay.io/org/tool",
        "v1",
        "DaemonSet",
        "tool",
        "tool",
        0,
    );
    let mut v = vulns_json(&d(20), "2026-09-20T08:00:00Z", &[("CVE-B", "HIGH", None)]);
    v["image"]["digest_kind"] = json!("index");
    v["image"]["platform_manifests"] = json!({"linux/amd64": d(12), "linux/arm64": d(13)});
    v["observed_in"] = json!([]);
    store_v(&mut conn, v);
    // 3. workload_tag: payload digest unknown to the inventory, no platform
    //    manifests; Trivy names the ReplicaSet, the inventory the Deployment.
    seed_inventory(
        &mut conn,
        &d(14),
        "ghcr.io/example/api",
        "2.4.1",
        "Deployment",
        "api",
        "api",
        0,
    );
    exec(
        &mut conn,
        &format!(
            "UPDATE workload_containers SET pod_namespace = 'shop' WHERE image_digest = '{}'",
            d(14)
        ),
    );
    store_v(
        &mut conn,
        vulns_json(&d(30), "2026-09-20T08:00:00Z", &[("CVE-C", "LOW", None)]),
    );
    // Same workload but a different tag in the inventory: no tag link.
    seed_inventory(
        &mut conn,
        &d(15),
        "ghcr.io/example/other",
        "9",
        "Deployment",
        "other",
        "other",
        0,
    );
    let mut v = vulns_json(&d(31), "2026-09-20T08:00:00Z", &[]);
    v["image"]["repository"] = json!("example/other");
    v["image"]["tag"] = json!("8");
    v["observed_in"] = json!([{"namespace": NS, "kind": "ReplicaSet", "name": "other-5d4f", "container": "other"}]);
    store_v(&mut conn, v);
    // The tag rule is not consulted when a digest rule matched: payload
    // d(11) observed in shop/api would otherwise also tag-link d(14).
    let mut v = vulns_json(&d(11), "2026-09-21T08:00:00Z", &[("CVE-A", "HIGH", None)]);
    v["image"]["repository"] = json!("example/api");
    store_v(&mut conn, v);

    assert_eq!(
        links(&mut conn),
        vec![
            (d(11), d(11), "image_id".to_string()),
            (d(20), d(12), "platform_manifest".to_string()),
            (d(30), d(14), "workload_tag".to_string()),
        ]
    );

    // A digest the inventory learns after the scan is linked by the
    // periodic pass.
    store_v(
        &mut conn,
        vulns_json(&d(40), "2026-09-20T08:00:00Z", &[("CVE-D", "HIGH", None)]),
    );
    seed_inventory(
        &mut conn,
        &d(40),
        "docker.io/library/redis",
        "7",
        "StatefulSet",
        "redis",
        "redis",
        0,
    );
    let (changed, next) = relink_batch(&mut conn, None, 100).unwrap();
    assert!(changed >= 1);
    assert_eq!(next, None);
    assert!(links(&mut conn).contains(&(d(40), d(40), "image_id".to_string())));
    // Idempotent: a second pass changes nothing.
    assert_eq!(relink_batch(&mut conn, None, 100).unwrap().0, 0);
    // Batching walks every key.
    let (_, next) = relink_batch(&mut conn, None, 2).unwrap();
    assert!(next.is_some());

    // Reads report the rule.
    let page = crate::supplychain_read::image_vulnerabilities(
        &mut conn,
        &d(12),
        None,
        None,
        None,
        None,
        10,
    )
    .unwrap();
    assert_eq!(page.reports.len(), 1);
    assert_eq!(page.reports[0].join, "platform_manifest");
    assert_eq!(page.reports[0].report_digest, d(20));
    assert_eq!(page.items[0].id, "CVE-B");
    assert_eq!(page.items[0].in_use, None);
    assert_eq!(page.items[0].in_use_state, "unknown");
    // Asking by the payload's own (index) digest answers too.
    let page = crate::supplychain_read::image_vulnerabilities(
        &mut conn,
        &d(20),
        None,
        None,
        None,
        None,
        10,
    )
    .unwrap();
    assert_eq!(page.reports[0].join, "report_digest");
    // No data is an empty report list, not a clean bill of health.
    let page = crate::supplychain_read::image_vulnerabilities(
        &mut conn,
        &d(99),
        None,
        None,
        None,
        None,
        10,
    )
    .unwrap();
    assert!(page.reports.is_empty() && page.items.is_empty());
}

#[test]
#[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
fn live_database_reads_filter_page_and_group() {
    let mut conn = live_conn();
    seed_inventory(
        &mut conn,
        &d(1),
        "ghcr.io/example/api",
        "2.4.1",
        "Deployment",
        "api",
        "api",
        0,
    );
    seed_inventory(
        &mut conn,
        &d(2),
        "ghcr.io/example/web",
        "1",
        "Deployment",
        "web",
        "web",
        0,
    );
    // web's container stopped long ago: not running.
    exec(&mut conn, &format!("UPDATE workload_containers SET last_seen = timezone('UTC', NOW()) - INTERVAL '2 days', state = 'terminated' WHERE image_digest = '{}'", d(2)));
    let mut v = vulns_json(
        &d(1),
        "2026-09-20T08:00:00Z",
        &[
            ("CVE-1", "CRITICAL", Some("2")),
            ("CVE-2", "HIGH", None),
            ("CVE-3", "LOW", None),
            ("CVE-4", "HIGH", Some("3")),
        ],
    );
    v["observed_in"] = json!([]);
    store_v(&mut conn, v);
    let mut v = vulns_json(
        &d(2),
        "2026-09-20T08:00:00Z",
        &[("CVE-1", "CRITICAL", Some("2"))],
    );
    v["observed_in"] = json!([]);
    store_v(&mut conn, v);

    use crate::supplychain_read::{image_vulnerabilities, list_cves};
    // Severity-first pagination walks every finding exactly once.
    let mut seen = Vec::new();
    let mut after = None;
    loop {
        let p = image_vulnerabilities(&mut conn, &d(1), None, None, None, after, 1).unwrap();
        seen.extend(p.items.iter().map(|f| f.id.clone()));
        match p.next_after {
            Some(c) => {
                let (r, id) = c.split_once('.').unwrap();
                after = Some((r.parse().unwrap(), id.parse().unwrap()));
            }
            None => break,
        }
    }
    assert_eq!(seen, ["CVE-1", "CVE-2", "CVE-4", "CVE-3"]);
    let high = image_vulnerabilities(&mut conn, &d(1), None, Some(&[4]), None, None, 10).unwrap();
    assert_eq!(high.items.len(), 2);
    let fixable =
        image_vulnerabilities(&mut conn, &d(1), None, None, Some(true), None, 10).unwrap();
    assert_eq!(
        fixable
            .items
            .iter()
            .map(|f| f.id.as_str())
            .collect::<Vec<_>>(),
        ["CVE-1", "CVE-4"]
    );
    assert!(fixable.items.iter().all(|f| f.fixable));

    let all = list_cves(&mut conn, None, None, None, false, None, 10).unwrap();
    let ids: Vec<&str> = all.items.iter().map(|c| c.summary.id.as_str()).collect();
    assert_eq!(ids, ["CVE-1", "CVE-2", "CVE-4", "CVE-3"]);
    let c1 = &all.items[0].summary;
    assert_eq!(
        (c1.images, c1.workloads, c1.running_workloads, c1.namespaces),
        (2, 2, 1, 1)
    );
    assert_eq!(c1.weakest_join, "image_id");
    assert!(c1.fixable);
    assert_eq!(all.items[0].in_use_state, "unknown");
    let page1 = list_cves(&mut conn, None, None, None, false, None, 2).unwrap();
    let cur = page1.next_after.unwrap();
    let (r, id) = cur.split_once('.').unwrap();
    let page2 = list_cves(
        &mut conn,
        None,
        None,
        None,
        false,
        Some((r.parse().unwrap(), id.to_string())),
        2,
    )
    .unwrap();
    assert_eq!(
        page2
            .items
            .iter()
            .map(|c| c.summary.id.as_str())
            .collect::<Vec<_>>(),
        ["CVE-4", "CVE-3"]
    );
    assert!(page2.next_after.is_none());
    let crit = list_cves(&mut conn, Some(&[5]), Some(true), Some(NS), true, None, 10).unwrap();
    assert_eq!(crit.items.len(), 1);
    assert_eq!(crit.items[0].summary.running_workloads, 1);
    assert!(
        list_cves(&mut conn, None, None, Some("elsewhere"), false, None, 10)
            .unwrap()
            .items
            .is_empty()
    );

    // SBOM components page by id; the export is a CycloneDX document.
    store_s(
        &mut conn,
        sbom_json(&d(1), "2026-09-20T08:00:00Z", &["a", "b", "c"], None),
    )
    .unwrap();
    let p = crate::supplychain_read::image_sbom(&mut conn, &d(1), None, 0, 2).unwrap();
    assert_eq!(p.items.len(), 2);
    assert_eq!(p.report.as_ref().unwrap().join, "image_id");
    let p2 = crate::supplychain_read::image_sbom(&mut conn, &d(1), None, p.next_after.unwrap(), 2)
        .unwrap();
    assert_eq!(
        p2.items.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
        ["c"]
    );
    let report = p.report.unwrap();
    let doc = crate::supplychain_read::cyclonedx_document(&d(1), &report, &p.items);
    assert_eq!(doc["bomFormat"], "CycloneDX");
    assert_eq!(doc["components"][0]["purl"], "pkg:deb/debian/a@1");
    assert_eq!(
        doc["components"][0]["licenses"][0]["license"]["name"],
        "MIT"
    );
}

#[test]
#[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
fn live_database_exposure_reports_images_workloads_and_observed_ingress() {
    let mut conn = live_conn();
    seed_inventory(
        &mut conn,
        &d(1),
        "ghcr.io/example/api",
        "1",
        "Deployment",
        "api",
        "api",
        0,
    );
    seed_inventory(
        &mut conn,
        &d(1),
        "ghcr.io/example/api",
        "1",
        "Deployment",
        "quiet",
        "api",
        0,
    );
    seed_inventory(
        &mut conn,
        &d(1),
        "ghcr.io/example/api",
        "1",
        "Deployment",
        "nopods",
        "api",
        0,
    );
    let mut v = vulns_json(
        &d(1),
        "2026-09-20T08:00:00Z",
        &[("CVE-X", "HIGH", Some("2"))],
    );
    v["observed_in"] = json!([]);
    store_v(&mut conn, v);
    exec(
        &mut conn,
        &format!(
            "INSERT INTO pod_details (pod_name, pod_ip, pod_namespace, time_stamp, node_name, is_dead, \
                 workload_kind, workload_name) VALUES \
               ('sc-api-1', '10.9.0.1', '{NS}', timezone('UTC', NOW()), 'n1', false, 'Deployment', 'api'), \
               ('sc-quiet-1', '10.9.0.2', '{NS}', timezone('UTC', NOW()), 'n1', false, 'Deployment', 'quiet'); \
             INSERT INTO pod_traffic (uuid, pod_name, pod_namespace, pod_ip, traffic_type, \
                 traffic_in_out_ip, time_stamp, peer_kind, peer_namespace, peer_name) VALUES \
               ('sc-t1', 'sc-api-1', '{NS}', '10.9.0.1', 'INGRESS', '10.9.9.9', timezone('UTC', NOW()), 'pod', 'other', 'client'), \
               ('sc-t2', 'sc-api-1', '{NS}', '10.9.0.1', 'INGRESS', '8.8.8.8', timezone('UTC', NOW()), NULL, NULL, NULL), \
               ('sc-t3', 'sc-api-1', '{NS}', '10.9.0.1', 'EGRESS', '1.1.1.1', timezone('UTC', NOW()), NULL, NULL, NULL), \
               ('sc-t4', 'sc-quiet-1', '{NS}', '10.9.0.2', 'INGRESS', '10.9.0.9', timezone('UTC', NOW()), 'pod', '{NS}', 'same-ns'), \
               ('sc-t5', 'sc-quiet-1', '{NS}', '10.9.0.2', 'INGRESS', '192.168.1.10', timezone('UTC', NOW()), 'node', NULL, 'n1'), \
               ('sc-t6', 'sc-quiet-1', '{NS}', '10.9.0.2', 'INGRESS', '9.9.9.9', timezone('UTC', NOW()) - INTERVAL '30 days', NULL, NULL, NULL);"
        ),
    );
    let e = crate::supplychain_read::vulnerability_exposure(&mut conn, "CVE-X", 168)
        .unwrap()
        .unwrap();
    assert_eq!(e.severity, "HIGH");
    assert!(e.fixable);
    assert_eq!(e.images.len(), 1);
    assert_eq!(e.images[0].join, "image_id");
    assert_eq!(e.workloads.len(), 3);
    let by = |n: &str| e.workloads.iter().find(|w| w.name == n).unwrap();
    let api = &by("api").network;
    assert_eq!(api.pods_observed, 1);
    assert_eq!(api.ingress_from_other_namespaces, 1);
    assert_eq!(api.ingress_from_unattributed_peers, 1);
    assert_eq!(api.ingress_from_public_ips, 1);
    assert_eq!(api.exposed, Some(true));
    let quiet = &by("quiet").network;
    // Same-namespace and node (probe) ingress, plus an internet peer
    // outside the window: none of it is exposure.
    assert_eq!(quiet.ingress_from_nodes, 1);
    assert_eq!(quiet.exposed, Some(false));
    assert_eq!(by("nopods").network.exposed, None, "no pods = unknown");
    assert!(by("api").running);
    assert_eq!(by("api").in_use_state, "unknown");
    assert_eq!(e.namespaces.len(), 1);
    let ns = &e.namespaces[0];
    assert_eq!(
        (
            ns.workloads,
            ns.running_workloads,
            ns.exposed_workloads,
            ns.unknown_exposure_workloads
        ),
        (3, 3, 1, 1)
    );
    assert!(
        crate::supplychain_read::vulnerability_exposure(&mut conn, "CVE-NOPE", 168)
            .unwrap()
            .is_none()
    );
}

#[test]
#[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
fn live_database_gc_removes_payloads_nothing_runs_and_expires_pages() {
    let mut conn = live_conn();
    let running_window = 900;
    // Running now: kept.
    seed_inventory(&mut conn, &d(1), "r/a", "1", "Deployment", "live", "c", 0);
    // Stopped 40 days ago: removed.
    seed_inventory(&mut conn, &d(2), "r/b", "1", "Deployment", "gone", "c", 40);
    exec(
        &mut conn,
        &format!(
            "UPDATE workload_containers SET state = 'terminated' WHERE image_digest = '{}'",
            d(2)
        ),
    );
    // Stopped 10 days ago: kept (inside 30 days).
    seed_inventory(
        &mut conn,
        &d(3),
        "r/c",
        "1",
        "Deployment",
        "recent",
        "c",
        10,
    );
    exec(
        &mut conn,
        &format!(
            "UPDATE workload_containers SET state = 'terminated' WHERE image_digest = '{}'",
            d(3)
        ),
    );
    for i in [1, 2, 3, 4, 5] {
        let mut v = vulns_json(&d(i), "2026-09-20T08:00:00Z", &[("CVE-1", "LOW", None)]);
        v["observed_in"] = json!([]);
        store_v(&mut conn, v);
        store_s(
            &mut conn,
            sbom_json(&d(i), "2026-09-20T08:00:00Z", &["a"], None),
        )
        .unwrap();
    }
    // d(4): never linked, received long ago: removed. d(5): never linked
    // but just received: inside the grace, kept.
    exec(&mut conn, &format!("UPDATE vuln_sources SET received_at = timezone('UTC', NOW()) - INTERVAL '3 days' WHERE digest IN ('{}', '{}')", d(2), d(4)));
    // A stale incomplete page set and a fresh one.
    store_s(
        &mut conn,
        sbom_json(
            &d(8),
            "2026-09-20T08:00:00Z",
            &["p"],
            Some(("old-set", 0, 2)),
        ),
    )
    .unwrap();
    store_s(
        &mut conn,
        sbom_json(
            &d(9),
            "2026-09-20T08:00:00Z",
            &["p"],
            Some(("new-set", 0, 2)),
        ),
    )
    .unwrap();
    exec(&mut conn, "UPDATE image_sbom_pages SET received_at = timezone('UTC', NOW()) - INTERVAL '2 hours' WHERE set_id = 'old-set'");
    assert_eq!(expire_pages_batch(&mut conn, 3600, 10).unwrap(), 1);
    assert_eq!(
        count(
            &mut conn,
            "SELECT count(*) AS n FROM image_sbom_pages WHERE set_id = 'new-set'"
        ),
        1
    );

    // Batch of one: one payload per call.
    assert_eq!(gc_batch(&mut conn, 30, 24, running_window, 1).unwrap(), 1);
    assert_eq!(gc_batch(&mut conn, 30, 24, running_window, 10).unwrap(), 1);
    assert_eq!(gc_batch(&mut conn, 30, 24, running_window, 10).unwrap(), 0);
    #[derive(QueryableByName)]
    struct D {
        #[diesel(sql_type = Text)]
        digest: String,
    }
    let left: Vec<String> = sql_query(
        "SELECT DISTINCT digest FROM vuln_sources WHERE kind = 'vulnerabilities' ORDER BY digest",
    )
    .load::<D>(&mut conn)
    .unwrap()
    .into_iter()
    .map(|r| r.digest)
    .collect();
    assert_eq!(left, vec![d(1), d(3), d(5)]);
    for table in [
        "image_vulnerabilities",
        "image_sbom_components",
        "supplychain_image_links",
    ] {
        assert_eq!(
            count(
                &mut conn,
                &format!(
                    "SELECT count(*) AS n FROM {table} WHERE digest IN ('{}', '{}')",
                    d(2),
                    d(4)
                )
            ),
            0,
            "{table}"
        );
    }
    // Once the inventory prunes a digest, its payloads follow after the grace.
    exec(&mut conn, &format!("DELETE FROM workload_containers WHERE image_digest = '{}'; UPDATE vuln_sources SET received_at = timezone('UTC', NOW()) - INTERVAL '3 days' WHERE digest = '{}'", d(3), d(3)));
    assert_eq!(gc_batch(&mut conn, 30, 24, running_window, 10).unwrap(), 1);
}

/// The whole HTTP path with a real pool: gzip bodies, auth, paging.
#[actix_web::test]
#[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
async fn live_database_http_ingest_end_to_end() {
    drop(live_conn());
    let url = std::env::var("KG_TEST_DATABASE_URL").unwrap();
    let pool = r2d2::Pool::builder()
        .max_size(2)
        .build(ConnectionManager::<PgConnection>::new(url))
        .unwrap();
    let app = atest::init_service(
        App::new()
            .wrap(from_fn(crate::auth::authenticate))
            .app_data(web::Data::new(auth(&[
                ("BROKER_TOKEN_SUPPLYCHAIN", SC_TOK),
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
    let sbom_path = format!("/images/{}/sbom", d(5));
    for (i, names) in [(1, ["c"]), (0, ["a"]), (1, ["c"]), (2, ["e"])] {
        let body = serde_json::to_vec(&sbom_json(
            &d(5),
            "2026-09-20T08:00:00Z",
            &names,
            Some(("s1", i, 3)),
        ))
        .unwrap();
        let resp = atest::call_service(
            &app,
            post(&sbom_path, gzip(&body), true, SC_TOK).to_request(),
        )
        .await;
        assert!(resp.status().is_success(), "page {i}: {}", resp.status());
    }
    let req = atest::TestRequest::get()
        .uri(&sbom_path)
        .insert_header((header::AUTHORIZATION, format!("Bearer {READ_TOK}")))
        .to_request();
    let body: serde_json::Value = atest::call_and_read_body_json(&app, req).await;
    let names: Vec<&str> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["a", "c", "e"]);
    // A bomb through the same route: 413, nothing stored.
    let bomb = gzip(&vec![b' '; max_decompressed_bytes() + 1]);
    assert_eq!(
        status!(app, post(&sbom_path, bomb, true, SC_TOK)),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let vpath = format!("/images/{}/vulnerabilities", d(5));
    let body = serde_json::to_vec(&vulns_json(
        &d(5),
        "2026-09-20T08:00:00Z",
        &[("CVE-1", "HIGH", None)],
    ))
    .unwrap();
    let resp =
        atest::call_service(&app, post(&vpath, gzip(&body), true, SC_TOK).to_request()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let out: serde_json::Value = atest::read_body_json(resp).await;
    assert_eq!(out, json!({"status": "stored", "items": 1}));
    let resp =
        atest::call_service(&app, post(&vpath, gzip(&body), true, SC_TOK).to_request()).await;
    let out: serde_json::Value = atest::read_body_json(resp).await;
    assert_eq!(out, json!({"status": "unchanged"}));
    let req = atest::TestRequest::get()
        .uri(&format!("{vpath}?severity=HIGH&fixable=false"))
        .insert_header((header::AUTHORIZATION, format!("Bearer {READ_TOK}")))
        .to_request();
    let body: serde_json::Value = atest::call_and_read_body_json(&app, req).await;
    assert_eq!(body["items"][0]["id"], "CVE-1");
    assert_eq!(body["items"][0]["inUse"], serde_json::Value::Null);
    assert_eq!(body["items"][0]["inUseState"], "unknown");
}

#[test]
fn grype_signals_are_bounded_and_absent_stays_unknown() {
    let mut v = vulns_json(
        &d(1),
        "2026-09-20T08:00:00Z",
        &[("CVE-1", "HIGH", None), ("CVE-2", "LOW", None)],
    );
    v["source"] = json!("grype");
    v["sbom_source"] = json!("registry");
    v["db_updated_at"] = json!("2026-09-19T00:00:00Z");
    v["vulnerabilities"][0]["kev"] = json!(true);
    v["vulnerabilities"][0]["kev_date_added"] = json!("2024-03-29T00:00:00Z");
    v["vulnerabilities"][0]["epss"] = json!(0.97);
    v["vulnerabilities"][0]["epss_percentile"] = json!(1.5);
    let p = normalise_vulnerabilities(&d(1), parse_vulns(v), now()).unwrap();
    assert_eq!(p.header.sbom_source.as_deref(), Some("registry"));
    assert!(p.header.db_updated_at.is_some());
    assert_eq!(p.rows[0].kev, Some(true));
    assert_eq!(p.rows[0].epss, Some(0.97));
    assert_eq!(p.rows[0].epss_percentile, None, "out of range is unknown");
    assert_eq!((p.rows[1].kev, p.rows[1].epss), (None, None));
}

#[test]
#[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
fn live_database_sources_sit_side_by_side_and_registry_sboms_win() {
    let mut conn = live_conn();
    seed_inventory(
        &mut conn,
        &d(1),
        "ghcr.io/example/api",
        "1",
        "Deployment",
        "api",
        "api",
        0,
    );
    let mut trivy = vulns_json(&d(1), "2026-09-20T08:00:00Z", &[("CVE-1", "HIGH", None)]);
    trivy["observed_in"] = json!([]);
    store_v(&mut conn, trivy);
    let mut grype = vulns_json(
        &d(1),
        "2026-09-21T08:00:00Z",
        &[("CVE-1", "HIGH", Some("2")), ("CVE-2", "LOW", None)],
    );
    grype["source"] = json!("grype");
    grype["sbom_source"] = json!("registry");
    grype["observed_in"] = json!([]);
    grype["vulnerabilities"][0]["kev"] = json!(true);
    grype["vulnerabilities"][0]["epss"] = json!(0.5);
    store_v(&mut conn, grype);
    // Each source replaces only its own set.
    assert_eq!(
        count(
            &mut conn,
            "SELECT count(*) AS n FROM image_vulnerabilities WHERE source = 'trivy-operator'"
        ),
        1
    );
    assert_eq!(
        count(
            &mut conn,
            "SELECT count(*) AS n FROM image_vulnerabilities WHERE source = 'grype'"
        ),
        2
    );
    let page = crate::supplychain_read::image_vulnerabilities(
        &mut conn,
        &d(1),
        None,
        None,
        None,
        None,
        10,
    )
    .unwrap();
    assert_eq!(page.reports.len(), 2);
    let g = page.reports.iter().find(|r| r.source == "grype").unwrap();
    assert_eq!(g.sbom_source.as_deref(), Some("registry"));
    let kev = page
        .items
        .iter()
        .find(|f| f.source == "grype" && f.id == "CVE-1")
        .unwrap();
    assert_eq!((kev.kev, kev.epss), (Some(true), Some(0.5)));
    let trivy_row = page
        .items
        .iter()
        .find(|f| f.source == "trivy-operator")
        .unwrap();
    assert_eq!(trivy_row.kev, None, "Trivy never says: unknown");
    let only = crate::supplychain_read::image_vulnerabilities(
        &mut conn,
        &d(1),
        Some("trivy-operator"),
        None,
        None,
        None,
        10,
    )
    .unwrap();
    assert_eq!(only.items.len(), 1);
    let cves =
        crate::supplychain_read::list_cves(&mut conn, None, None, None, false, None, 10).unwrap();
    let c1 = cves.items.iter().find(|c| c.summary.id == "CVE-1").unwrap();
    assert_eq!(
        (c1.summary.kev, c1.summary.max_epss),
        (Some(true), Some(0.5))
    );
    assert!(c1.summary.fixable);
    let c2 = cves.items.iter().find(|c| c.summary.id == "CVE-2").unwrap();
    assert_eq!(c2.summary.kev, None);

    // Two SBOMs for one digest: the registry one is served whatever the
    // scan times, and its attestation is stored as sent (unverified).
    store_s(
        &mut conn,
        sbom_json(&d(1), "2026-09-22T08:00:00Z", &["trivy-pkg"], None),
    )
    .unwrap();
    let mut reg = sbom_json(&d(1), "2026-09-20T08:00:00Z", &["registry-pkg"], None);
    reg["source"] = json!("registry");
    reg["scanner"] = json!({"name": "registry", "vendor": "oci-referrer"});
    reg["attestation"] = json!({"mechanism": "oci-referrer", "artifact_digest": d(77),
        "media_type": "application/vnd.cyclonedx+json",
        "predicate_type": "https://cyclonedx.org/bom", "verified": false});
    store_s(&mut conn, reg).unwrap();
    let p = crate::supplychain_read::image_sbom(&mut conn, &d(1), None, 0, 10).unwrap();
    let report = p.report.unwrap();
    assert_eq!(report.source, "registry");
    let att = report.attestation.as_ref().unwrap();
    assert_eq!(att["verified"], json!(false));
    assert_eq!(att["artifact_digest"], json!(d(77)));
    assert_eq!(p.items[0].name, "registry-pkg");
    let t = crate::supplychain_read::image_sbom(&mut conn, &d(1), Some("trivy-operator"), 0, 10)
        .unwrap();
    assert_eq!(t.items[0].name, "trivy-pkg");
}
