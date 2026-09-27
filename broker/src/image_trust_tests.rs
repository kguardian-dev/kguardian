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
        (500, "answered 500"),
    ] {
        let url = fake_evaluator(status, "{}").await;
        let reason = fetch(&url, None, None, None).await.unwrap_err();
        assert!(reason.contains(want), "{status}: {reason}");
    }
    let url = fake_evaluator(200, "not json").await;
    assert!(fetch(&url, None, None, None)
        .await
        .unwrap_err()
        .contains("did not parse"));
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
    assert!(reason.contains("did not answer within 10 s"), "{reason}");
}
