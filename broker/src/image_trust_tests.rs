use super::*;
use actix_web::{App, HttpRequest, HttpServer};

fn r(policy: &str, ns: &str, workload: &str, verdict: &str, reason: &str) -> TrustResult {
    TrustResult {
        policy: policy.into(),
        namespace: ns.into(),
        workload: workload.into(),
        container: "app".into(),
        digest: format!("sha256:{}", "a".repeat(64)),
        image: "ghcr.io/example/api".into(),
        verdict: verdict.into(),
        reason: (!reason.is_empty()).then(|| reason.to_string()),
    }
}

fn sample() -> Vec<TrustResult> {
    vec![
        r("shop/signed", "shop", "Deployment/api", "Trusted", ""),
        r(
            "shop/signed",
            "shop",
            "Deployment/cart",
            "WouldDeny",
            "unsigned",
        ),
        r(
            "cluster/all",
            "shop",
            "Deployment/api",
            "Unknown",
            "not-checked",
        ),
        r(
            "shop/signed",
            "shop",
            "StatefulSet/db",
            "WouldDeny",
            "invalid",
        ),
    ]
}

#[test]
fn shape_orders_counts_filters_and_bounds() {
    let a = shape(
        Some("2026-09-27T12:00:00Z".into()),
        sample(),
        None,
        None,
        10,
    );
    assert!(a.available && !a.truncated);
    assert_eq!((a.total, a.would_deny, a.unknown, a.trusted), (4, 2, 1, 1));
    assert_eq!(a.policies, vec!["cluster/all", "shop/signed"]);
    let v: Vec<&str> = a.results.iter().map(|r| r.verdict.as_str()).collect();
    assert_eq!(v, vec!["WouldDeny", "WouldDeny", "Unknown", "Trusted"]);

    // One workload: kind is case-insensitive, name exact.
    let a = shape(None, sample(), Some("deployment"), Some("api"), 10);
    assert_eq!(a.total, 2);
    assert!(a.results.iter().all(|r| r.workload == "Deployment/api"));
    assert_eq!(a.evaluated_at, None);

    // Counts cover everything that matched, the list is cut.
    let a = shape(None, sample(), None, None, 1);
    assert!(a.truncated);
    assert_eq!(a.results.len(), 1);
    assert_eq!(a.would_deny, 2);
}

/// An unrecognised verdict (a newer evaluator) counts and sorts as
/// Unknown: it can never make the answer look all-Trusted.
#[test]
fn shape_counts_an_unknown_verdict_as_unknown() {
    let a = shape(
        None,
        vec![
            r("p", "shop", "Deployment/a", "Trusted", ""),
            r("p", "shop", "Deployment/b", "Maybe", ""),
        ],
        None,
        None,
        10,
    );
    assert_eq!((a.total, a.would_deny, a.unknown, a.trusted), (2, 0, 1, 1));
    assert_eq!(a.results[0].verdict, "Maybe");
    assert_eq!(a.results[1].verdict, "Trusted");
}

/// A fake evaluator on a free loopback port. Returns its base URL.
async fn fake_evaluator(status: u16, body: &'static str) -> String {
    let srv = HttpServer::new(move || {
        App::new().route(
            "/image-trust",
            web::get().to(move |req: HttpRequest| async move {
                // Echo the auth header and query so tests can check them.
                let auth = req
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                HttpResponse::build(actix_web::http::StatusCode::from_u16(status).unwrap())
                    .insert_header(("x-seen-auth", auth))
                    .insert_header(("x-seen-query", req.query_string().to_string()))
                    .content_type("application/json")
                    .body(body)
            }),
        )
    })
    .workers(1)
    .bind("127.0.0.1:0")
    .unwrap();
    let addr = srv.addrs()[0];
    actix_web::rt::spawn(srv.run());
    format!("http://{addr}")
}

#[actix_web::test]
async fn fetch_reads_results_and_forwards_filters() {
    let url = fake_evaluator(
        200,
        r#"{"evaluatedAt":"2026-09-27T12:00:00Z","results":[{"policy":"shop/signed","namespace":"shop","workload":"Deployment/cart","container":"app","digest":"sha256:aa","image":"ghcr.io/x","verdict":"WouldDeny","reason":"unsigned"}]}"#,
    )
    .await;
    let (at, res) = fetch(&url, None, Some("shop"), Some("WouldDeny"))
        .await
        .unwrap();
    assert_eq!(at.as_deref(), Some("2026-09-27T12:00:00Z"));
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].reason.as_deref(), Some("unsigned"));
}

#[actix_web::test]
async fn fetch_failures_are_unavailable_never_empty() {
    for (status, want) in [
        (404, "image trust evaluation is off"),
        (401, "refused the broker's read token"),
        (403, "refused the broker's read token"),
        (500, "answered with status 500"),
    ] {
        let url = fake_evaluator(status, "{}").await;
        let reason = fetch(&url, None, None, None).await.unwrap_err();
        assert!(reason.contains(want), "{status}: {reason}");
    }
    let url = fake_evaluator(200, "not json").await;
    assert!(fetch(&url, None, None, None)
        .await
        .unwrap_err()
        .contains("sent an invalid response"));
    // Nothing listening.
    let reason = fetch("http://127.0.0.1:1", None, None, None)
        .await
        .unwrap_err();
    assert!(reason.contains("could not be reached"));
    // The route turns every one of these into `available: false`.
    let a = unavailable(reason);
    assert!(!a.available && a.results.is_empty() && a.evaluated_at.is_none());
}

#[test]
fn read_token_prefers_the_scoped_token() {
    let _g = crate::test_support::env_lock();
    std::env::remove_var("BROKER_TOKEN_READ");
    std::env::set_var("BROKER_AUTH_TOKEN", "shared-token-0123456789");
    assert_eq!(read_token().as_deref(), Some("shared-token-0123456789"));
    std::env::set_var("BROKER_TOKEN_READ", "  read-token-0123456789 ");
    assert_eq!(read_token().as_deref(), Some("read-token-0123456789"));
    std::env::remove_var("BROKER_TOKEN_READ");
    std::env::remove_var("BROKER_AUTH_TOKEN");
    assert_eq!(read_token(), None);
}

/// A fake evaluator that answers only when handed the right token and
/// echoes the query it saw.
async fn token_checking_evaluator() -> String {
    let srv = HttpServer::new(|| {
        App::new().route(
            "/image-trust",
            web::get().to(|req: HttpRequest| async move {
                let ok = req
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    == Some("Bearer read-token-0123456789");
                if !ok {
                    return HttpResponse::Unauthorized().finish();
                }
                let q = serde_json::to_string(req.query_string()).unwrap();
                HttpResponse::Ok()
                    .content_type("application/json")
                    .body(format!(
                        r#"{{"evaluatedAt":null,"results":[{{"policy":{q},"namespace":"shop","workload":"Deployment/api","container":"app","digest":"sha256:aa","verdict":"Unknown"}}]}}"#
                    ))
            }),
        )
    })
    .workers(1)
    .bind("127.0.0.1:0")
    .unwrap();
    let addr = srv.addrs()[0];
    actix_web::rt::spawn(srv.run());
    format!("http://{addr}")
}

#[actix_web::test]
async fn fetch_sends_the_token_and_the_filters() {
    let url = token_checking_evaluator().await;
    let (at, res) = fetch(
        &url,
        Some("read-token-0123456789"),
        Some("shop"),
        Some("Unknown"),
    )
    .await
    .unwrap();
    assert!(at.is_none());
    assert_eq!(res[0].policy, "namespace=shop&verdict=Unknown");
    assert!(fetch(&url, Some("wrong"), None, None)
        .await
        .unwrap_err()
        .contains("refused the broker's read token"));
    assert!(fetch(&url, None, None, None).await.is_err());
}

/// A slow evaluator is reported as a timeout, not as unreachable.
#[actix_web::test]
async fn fetch_timeout_says_timed_out() {
    let srv = HttpServer::new(|| {
        App::new().route(
            "/image-trust",
            web::get().to(|| async {
                actix_web::rt::time::sleep(TIMEOUT + std::time::Duration::from_secs(2)).await;
                HttpResponse::Ok().body("{}")
            }),
        )
    })
    .workers(1)
    .bind("127.0.0.1:0")
    .unwrap();
    let addr = srv.addrs()[0];
    actix_web::rt::spawn(srv.run());
    let reason = fetch(&format!("http://{addr}"), None, None, None)
        .await
        .unwrap_err();
    assert!(
        reason.contains("did not answer within 10000 ms"),
        "{reason}"
    );
}

fn audit_client(url: Option<&str>) -> crate::audit::AuditClient {
    let _g = crate::test_support::env_lock();
    match url {
        Some(u) => std::env::set_var("EVALUATOR_URL", u),
        None => std::env::remove_var("EVALUATOR_URL"),
    }
    let c = crate::audit::AuditClient::from_env();
    std::env::remove_var("EVALUATOR_URL");
    c
}

/// The workload profile's imageTrust (contract v1.9): no evaluator is
/// unavailable; otherwise the namespace's results, shaped to the workload.
#[actix_web::test]
async fn for_workload_reads_the_namespace_and_keeps_the_workload() {
    let a = for_workload(None, &budget(), "shop", "Deployment", "cart").await;
    assert!(!a.available && a.reason.unwrap().contains("no evaluator is configured"));
    let off = audit_client(None);
    assert!(
        !for_workload(Some(&off), &budget(), "shop", "Deployment", "cart")
            .await
            .available
    );

    let url = token_checking_evaluator().await;
    // token_checking_evaluator answers 401 without its token (none is set
    // here): the profile gets "unavailable" with the reason, never an
    // empty list.
    let a = for_workload(
        Some(&audit_client(Some(&url))),
        &budget(),
        "shop",
        "Deployment",
        "api",
    )
    .await;
    assert!(!a.available);
    assert!(a
        .reason
        .unwrap()
        .contains("refused the broker's read token"));

    let body = r#"{"evaluatedAt":"2026-09-27T12:00:00Z","results":[
        {"policy":"shop/p","namespace":"shop","workload":"Deployment/cart","container":"app","digest":"sha256:aa","verdict":"WouldDeny","reason":"unsigned"},
        {"policy":"shop/p","namespace":"shop","workload":"Deployment/api","container":"app","digest":"sha256:bb","verdict":"Trusted"}]}"#;
    let url = fake_evaluator(200, body).await;
    let a = for_workload(
        Some(&audit_client(Some(&url))),
        &budget(),
        "shop",
        "Deployment",
        "cart",
    )
    .await;
    assert!(a.available);
    assert_eq!((a.total, a.would_deny, a.trusted), (1, 1, 0));
    assert_eq!(a.results[0].workload, "Deployment/cart");
}

/// A namespace answer larger than the profile's 1 MiB cap is unavailable
/// (GET /image-trust?namespace= still reads up to 16 MiB).
#[actix_web::test]
async fn for_workload_refuses_an_oversized_answer() {
    let big: &'static str = Box::leak(
        format!(
            r#"{{"evaluatedAt":null,"results":[],"pad":"{}"}}"#,
            "x".repeat(PROFILE_MAX_EVALUATOR_BODY)
        )
        .into_boxed_str(),
    );
    let url = fake_evaluator(200, big).await;
    let a = for_workload(
        Some(&audit_client(Some(&url))),
        &budget(),
        "shop",
        "Deployment",
        "cart",
    )
    .await;
    assert!(!a.available);
    assert!(a.reason.unwrap().contains("larger than 1048576 bytes"));
}

fn budget() -> crate::read_budget::ReadBudget {
    crate::read_budget::ReadBudget::with_budget_kib(64 * 1024, std::time::Duration::from_millis(0))
}

/// A fake evaluator that counts requests and answers after `delay`.
async fn counting_evaluator(
    delay: std::time::Duration,
    body: &'static str,
) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let h = hits.clone();
    let srv = HttpServer::new(move || {
        let h = h.clone();
        App::new().route(
            "/image-trust",
            web::get().to(move || {
                let h = h.clone();
                async move {
                    h.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    actix_web::rt::time::sleep(delay).await;
                    HttpResponse::Ok()
                        .content_type("application/json")
                        .body(body)
                }
            }),
        )
    })
    .workers(1)
    .bind("127.0.0.1:0")
    .unwrap();
    let addr = srv.addrs()[0];
    actix_web::rt::spawn(srv.run());
    (format!("http://{addr}"), hits)
}

const ONE_DENY: &str = r#"{"evaluatedAt":"2026-09-27T12:00:00Z","results":[
    {"policy":"shop/p","namespace":"shop","workload":"Deployment/cart","container":"app","digest":"sha256:aa","verdict":"WouldDeny","reason":"unsigned"}]}"#;

/// A stalled evaluator costs the profile at most PROFILE_TIMEOUT, and the
/// answer is unavailable (unknown), never a hang or an empty list.
#[actix_web::test]
async fn for_workload_gives_up_on_a_stalled_evaluator() {
    let (url, _) = counting_evaluator(std::time::Duration::from_secs(8), ONE_DENY).await;
    let started = std::time::Instant::now();
    let a = for_workload(
        Some(&audit_client(Some(&url))),
        &budget(),
        "shop",
        "Deployment",
        "cart",
    )
    .await;
    let took = started.elapsed();
    assert!(!a.available);
    assert!(
        a.reason
            .as_deref()
            .unwrap()
            .contains("did not answer within 2000 ms"),
        "{:?}",
        a.reason
    );
    assert!(
        took < PROFILE_TIMEOUT + std::time::Duration::from_millis(800),
        "took {took:?}"
    );
}

/// Repeated profile reads of one namespace hit the evaluator once per TTL;
/// a failure is cached too (shorter TTL), so a down evaluator is not
/// hammered. The budget is charged only for a real read.
#[actix_web::test]
async fn for_workload_caches_per_namespace() {
    let (url, hits) = counting_evaluator(std::time::Duration::ZERO, ONE_DENY).await;
    let audit = audit_client(Some(&url));
    let b = budget();
    for name in ["cart", "cart", "api"] {
        let a = for_workload(Some(&audit), &b, "shop", "Deployment", name).await;
        assert!(a.available);
    }
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "one read for the namespace"
    );
    // Another namespace is another read.
    for_workload(Some(&audit), &b, "other", "Deployment", "cart").await;
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 2);

    // A cache hit needs no budget: an exhausted budget still serves it.
    let empty =
        crate::read_budget::ReadBudget::with_budget_kib(1, std::time::Duration::from_millis(0));
    let _all = empty.acquire(1).await.unwrap(); // the whole budget is in use
    let a = for_workload(Some(&audit), &empty, "shop", "Deployment", "cart").await;
    assert!(a.available, "cache hit served without a budget charge");
    // A miss with no budget is unavailable (shed), not cached.
    let a = for_workload(Some(&audit), &empty, "third", "Deployment", "cart").await;
    assert!(!a.available && a.reason.unwrap().contains("shedding"));
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 2);

    // Unavailable is cached as well.
    let down = audit_client(Some("http://127.0.0.1:1"));
    let a1 = for_workload(Some(&down), &b, "shop", "Deployment", "cart").await;
    assert!(!a1.available);
    let key = ("http://127.0.0.1:1".to_string(), "shop".to_string());
    let f = cache().lock().unwrap().entries.get(&key).cloned().unwrap();
    assert!(f.usable(std::time::Instant::now()));
    assert!(matches!(
        f.cell.get(),
        Some(Done::Value { value: Err(_), .. })
    ));
}

/// A finished flight with `value`, at `at`.
fn done_flight(at: std::time::Instant, value: Fetched) -> std::sync::Arc<Flight> {
    let bytes = estimate_bytes(&value);
    let f = Flight::default();
    f.cell.set(Done::Value { at, value, bytes }).ok().unwrap();
    std::sync::Arc::new(f)
}

/// TTLs, the entry bound and the byte bound, on the cache itself.
#[test]
fn cache_ttls_and_bounds() {
    let t0 = std::time::Instant::now();
    let k = |i: usize| ("http://e".to_string(), format!("ns{i}"));
    let ok = done_flight(t0, Ok((None, std::sync::Arc::new(vec![]))));
    let err = done_flight(t0, Err("down".into()));
    assert!(ok.usable(t0 + CACHE_TTL - std::time::Duration::from_millis(1)));
    assert!(!ok.usable(t0 + CACHE_TTL));
    assert!(err.usable(t0 + CACHE_TTL_UNAVAILABLE - std::time::Duration::from_millis(1)));
    assert!(!err.usable(t0 + CACHE_TTL_UNAVAILABLE));
    assert!(
        Flight::default().usable(t0 + CACHE_TTL * 100),
        "a running read is always joined"
    );

    // Entry bound: finished entries evicted oldest first.
    let mut c = Cache::default();
    for i in 0..CACHE_MAX_ENTRIES {
        c.entries.insert(
            k(i),
            done_flight(
                t0 + std::time::Duration::from_millis(i as u64),
                Ok((None, std::sync::Arc::new(vec![]))),
            ),
        );
    }
    c.flight(&k(9999), t0);
    assert_eq!(c.entries.len(), CACHE_MAX_ENTRIES);
    assert!(
        !c.entries.contains_key(&k(0)),
        "the oldest entry went first"
    );
    // All running: a new key is served uncached, the bound holds.
    let mut busy = Cache::default();
    for i in 0..CACHE_MAX_ENTRIES {
        busy.entries
            .insert(k(i), std::sync::Arc::new(Flight::default()));
    }
    let f = busy.flight(&k(7777), t0);
    assert_eq!(busy.entries.len(), CACHE_MAX_ENTRIES);
    assert!(!busy.entries.contains_key(&k(7777)));
    assert!(f.cell.get().is_none());

    // Byte bound: big answers evict the oldest until under the cap.
    let big = |n: usize| {
        (0..n)
            .map(|i| TrustResult {
                policy: "p".repeat(1024),
                namespace: "ns".into(),
                workload: format!("Deployment/w{i}"),
                container: "app".into(),
                digest: "sha256:aa".into(),
                image: "i".repeat(1024),
                verdict: "Trusted".into(),
                reason: None,
            })
            .collect::<Vec<_>>()
    };
    let mut c = Cache::default();
    let per = 3000; // ~6.5 MiB each
    for i in 0..4 {
        let key = k(i);
        let f = done_flight(
            t0 + std::time::Duration::from_secs(i as u64),
            Ok((None, std::sync::Arc::new(big(per)))),
        );
        c.entries.insert(key.clone(), f.clone());
        c.settle(&key, &f);
        assert!(
            c.bytes() <= CACHE_MAX_BYTES,
            "after {i}: {} bytes",
            c.bytes()
        );
    }
    assert!(c.entries.contains_key(&k(3)), "the newest is kept");
    assert!(!c.entries.contains_key(&k(0)), "the oldest went");
    // One answer larger than the whole cap is served but not kept.
    let huge = done_flight(t0, Ok((None, std::sync::Arc::new(big(9000)))));
    c.entries.insert(k(50), huge.clone());
    c.settle(&k(50), &huge);
    assert!(!c.entries.contains_key(&k(50)));
    // A shed read is never kept.
    let shed = std::sync::Arc::new(Flight::default());
    shed.cell.set(Done::Shed).ok().unwrap();
    c.entries.insert(k(60), shed.clone());
    c.settle(&k(60), &shed);
    assert!(!c.entries.contains_key(&k(60)));
}

/// Concurrent cold requests for one namespace share one read and one
/// budget charge (single-flight).
#[actix_web::test]
async fn for_workload_is_single_flight() {
    let (url, hits) = counting_evaluator(std::time::Duration::from_millis(400), ONE_DENY).await;
    let audit = std::sync::Arc::new(audit_client(Some(&url)));
    // Room for exactly one 1 MiB read: a second charge would be shed.
    let b = std::sync::Arc::new(crate::read_budget::ReadBudget::with_budget_kib(
        1024,
        std::time::Duration::from_millis(0),
    ));
    let tasks: Vec<_> = (0..10)
        .map(|_| {
            let (audit, b) = (audit.clone(), b.clone());
            actix_web::rt::spawn(async move {
                for_workload(Some(&audit), &b, "sf", "Deployment", "cart").await
            })
        })
        .collect();
    for t in tasks {
        let a = t.await.unwrap();
        assert!(a.available, "{:?}", a.reason);
        assert_eq!(a.would_deny, 1);
    }
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "exactly one evaluator read"
    );
}

/// A reason shown to API clients never carries the evaluator's address or
/// the HTTP client's error text.
fn assert_user_safe(reason: &str) {
    for bad in [
        "http",
        "://",
        "127.0.0.1",
        "localhost",
        "?namespace",
        "error sending",
        "tcp",
        "os error",
    ] {
        assert!(
            !reason.to_ascii_lowercase().contains(bad),
            "{bad:?} in {reason:?}"
        );
    }
    // No host:port (a colon followed by digits).
    let b = reason.as_bytes();
    for i in 0..b.len().saturating_sub(1) {
        assert!(
            !(b[i] == b':' && b[i + 1].is_ascii_digit()),
            "a port in {reason:?}"
        );
    }
}

#[test]
fn every_cause_reason_is_user_safe() {
    let t = std::time::Duration::from_millis(2_000);
    for c in [
        Cause::Timeout,
        Cause::Connect,
        Cause::Request,
        Cause::Status(502),
        Cause::BodyTimeout,
        Cause::BodyRead,
        Cause::Invalid,
    ] {
        let r = c.reason(t);
        assert_user_safe(&r);
        assert!(r.starts_with("the evaluator"), "{r}");
    }
    assert_eq!(
        Cause::Connect.reason(t),
        "the evaluator could not be reached: connection failed"
    );
    assert_eq!(
        Cause::Status(502).reason(t),
        "the evaluator answered with status 502"
    );
}

/// Real failures: a closed port, a stall, a bad status and a bad body
/// all give a safe reason, never the URL or the client's error text.
#[actix_web::test]
async fn real_failures_give_user_safe_reasons() {
    for base in [
        "http://127.0.0.1:1",
        "http://127.0.0.1:9",
        "http://localhost:1",
    ] {
        let r = fetch_bounded(
            base,
            None,
            Some("shop"),
            None,
            1024,
            std::time::Duration::from_millis(1_500),
        )
        .await
        .unwrap_err();
        assert_user_safe(&r);
        assert!(
            r.starts_with("the evaluator could not be reached")
                || r.starts_with("the evaluator did not answer"),
            "{r}"
        );
    }
    let (stall, _) = counting_evaluator(std::time::Duration::from_secs(5), ONE_DENY).await;
    let r = fetch_bounded(
        &stall,
        None,
        Some("shop"),
        None,
        1024,
        std::time::Duration::from_millis(300),
    )
    .await
    .unwrap_err();
    assert_user_safe(&r);
    assert_eq!(r, "the evaluator did not answer within 300 ms");
    for (status, body, want) in [
        (500, "{}", "the evaluator answered with status 500"),
        (
            200,
            "<html>not json</html>",
            "the evaluator sent an invalid response",
        ),
    ] {
        let url = fake_evaluator(status, body).await;
        let r = fetch(&url, None, Some("shop"), None).await.unwrap_err();
        assert_user_safe(&r);
        assert_eq!(r, want);
    }
}
