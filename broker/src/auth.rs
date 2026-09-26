//! Scoped bearer-token authentication for the broker HTTP API.
//!
//! Off unless a token is configured, so existing deployments keep the
//! original no-auth behaviour. When on, every route declares the access
//! it needs in [`ROUTES`], and the middleware enforces it:
//!
//! | scope         | who holds it                         | grants                     |
//! |---------------|--------------------------------------|----------------------------|
//! | `read`        | frontend proxy, llm-bridge, CLI      | read                       |
//! | `ingest`      | controller                           | ingest + read              |
//! | `supplychain` | supply-chain component (vuln/attest) | supplychain + read         |
//! | `admin`       | operators, break-glass               | everything                 |
//!
//! `supplychain` is its own token so a compromised pod holding the
//! ingest (or read) token can't post a forged "clean" scan result.
//!
//! Tokens come from the environment (the chart mounts them from one
//! Secret with a key per scope):
//!
//! - `BROKER_TOKEN_READ`, `BROKER_TOKEN_INGEST`,
//!   `BROKER_TOKEN_SUPPLYCHAIN`, `BROKER_TOKEN_ADMIN`
//! - `BROKER_AUTH_TOKEN`: the pre-scopes single shared token. Grants
//!   read + ingest, i.e. what it granted before scopes existed.
//!
//! Any one of them being set turns auth on. `/health` and `/metrics` stay
//! open (kubelet probes and Prometheus can't carry the header).
//!
//! Two middlewares, split around routing so the decision can never
//! disagree with the router:
//!
//! - [`authenticate`] wraps the App: 404 for a path that matches no
//!   route, 401 without a valid token, else records the token's scopes.
//! - [`authorize`] wraps EACH route (resource-level, after routing) and
//!   checks the matched route's entry in [`ROUTES`]: 403 without the
//!   scope, 403 for everyone on a route with no entry.
//!
//! `tests::every_route_in_the_source_declares_its_access` fails for any
//! route that lacks a [`ROUTES`] entry or the [`AUTHORIZE_WRAP`] wrap.
//! Adding a route means adding one line here and the `wrap` on it.

use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::{header, Method};
use actix_web::middleware::Next;
use actix_web::{web, Error, HttpMessage, HttpResponse};
use tracing::{error, warn};

/// A permission a token can carry and a route can require.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Read,
    Ingest,
    SupplyChain,
    Admin,
}

impl Scope {
    fn bit(self) -> u8 {
        match self {
            Scope::Read => 1,
            Scope::Ingest => 2,
            Scope::SupplyChain => 4,
            Scope::Admin => 8,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Read => "read",
            Scope::Ingest => "ingest",
            Scope::SupplyChain => "supplychain",
            Scope::Admin => "admin",
        }
    }
}

/// What a route needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// No token needed, even with auth on.
    Open,
    /// A token carrying this scope.
    Requires(Scope),
}

/// One route's declared access. `pattern` is the actix match pattern
/// exactly as registered (full path, scopes included).
#[derive(Debug)]
pub struct RouteRule {
    pub method: &'static str,
    pub pattern: &'static str,
    pub access: Access,
}

const fn rule(method: &'static str, pattern: &'static str, access: Access) -> RouteRule {
    RouteRule {
        method,
        pattern,
        access,
    }
}

const OPEN: Access = Access::Open;
const READ: Access = Access::Requires(Scope::Read);
const INGEST: Access = Access::Requires(Scope::Ingest);
const SUPPLYCHAIN: Access = Access::Requires(Scope::SupplyChain);
const ADMIN: Access = Access::Requires(Scope::Admin);

/// Every broker route and the access it needs. Keep sorted by area.
pub const ROUTES: &[RouteRule] = &[
    // Probes and scrape.
    rule("GET", "/health", OPEN),
    rule("GET", "/metrics", OPEN),
    // Controller writes.
    rule("POST", "/pod/traffic/batch", INGEST),
    rule("POST", "/pod/spec", INGEST),
    rule("POST", "/pod/mark_dead", INGEST),
    rule("POST", "/pod/syscalls", INGEST),
    rule("POST", "/svc/spec", INGEST),
    rule("POST", "/node/facts", INGEST),
    rule("POST", "/pod/compute/batch", INGEST),
    rule("POST", "/pod/compute/history/batch", INGEST),
    rule("POST", "/seccomp/node-status", INGEST),
    rule("POST", "/seccomp/denials", INGEST),
    rule("POST", "/runtime/executables", INGEST),
    rule("PUT", "/seccomp/crs/{namespace}/{name}", INGEST),
    rule("DELETE", "/seccomp/crs/{namespace}/{name}", INGEST),
    // Reads: UI, assistant, CLI (and the controller's reconciler and
    // seccomp distributor, whose ingest token includes read).
    rule("GET", "/pod/traffic", READ),
    rule("GET", "/pod/traffic/{name}", READ),
    rule("GET", "/pod/info", READ),
    rule("GET", "/pod/list/{node}", READ),
    rule("GET", "/pod/name/{name}", READ),
    rule("GET", "/pod/ip/{ip}", READ),
    rule("GET", "/pod/syscalls/{name}", READ),
    rule("GET", "/svc/info", READ),
    rule("GET", "/svc/ip/{ip}", READ),
    rule("GET", "/audit/verdicts", READ),
    rule("GET", "/compute/latest", READ),
    rule("GET", "/compute/history/{pod_uid}", READ),
    rule("GET", "/compute/contention", READ),
    rule("GET", "/compute/findings", READ),
    rule("GET", "/compute/nodes", READ),
    rule("GET", "/version", READ),
    rule("GET", "/cluster/environment", READ),
    rule("GET", "/seccomp/profiles", READ),
    rule("GET", "/seccomp/profiles/{namespace}/{kind}/{name}", READ),
    rule(
        "GET",
        "/seccomp/profiles/{namespace}/{kind}/{name}/export",
        READ,
    ),
    // POST only because the export options travel in a body; it reads.
    rule(
        "POST",
        "/seccomp/profiles/{namespace}/{kind}/{name}/export",
        READ,
    ),
    rule(
        "GET",
        "/seccomp/profile-file/{namespace}/{kind}/{name}/{hash}",
        READ,
    ),
    rule("GET", "/seccomp/denials", READ),
    // Image inventory (#1533).
    rule("GET", "/images", READ),
    rule("GET", "/images/{digest}", READ),
    rule(
        "GET",
        "/workloads/{namespace}/{kind}/{name}/containers",
        READ,
    ),
    // Runtime executable / library inventory (#1533 P1-2).
    rule("GET", "/workloads/{namespace}/{kind}/{name}/runtime", READ),
    rule("GET", "/images/{digest}/runtime", READ),
    // Workload security profile (#1533 P0-5).
    rule("GET", "/workloads", READ),
    rule("GET", "/workloads/{namespace}/{kind}/{name}/profile", READ),
    rule(
        "GET",
        "/workloads/{namespace}/{kind}/{name}/profile/versions",
        READ,
    ),
    rule(
        "GET",
        "/workloads/{namespace}/{kind}/{name}/profile/versions/{revision}",
        READ,
    ),
    rule(
        "GET",
        "/workloads/{namespace}/{kind}/{name}/profile/diff",
        READ,
    ),
    // Supply chain (#1533 P1-3). Writes need the supplychain token, which
    // the ingest and read tokens don't carry.
    rule("POST", "/images/{digest}/vulnerabilities", SUPPLYCHAIN),
    rule("POST", "/images/{digest}/sbom", SUPPLYCHAIN),
    rule("GET", "/images/{digest}/vulnerabilities", READ),
    rule("GET", "/images/{digest}/sbom", READ),
    rule("GET", "/images/{digest}/sbom/cyclonedx", READ),
    rule("GET", "/vulnerabilities", READ),
    rule("GET", "/vulnerabilities/{id}/exposure", READ),
    // Export bundle (#1533 P2-4). GET only generates documents, so READ.
    // POST returns the same bundle and records it as the workload's drift
    // baseline: a write that says "this is what the operator accepted", so
    // it takes the operator (admin) token, never the read one.
    rule("GET", "/workloads/{namespace}/{kind}/{name}/export", READ),
    rule("POST", "/workloads/{namespace}/{kind}/{name}/export", ADMIN),
];

/// The declared access for `method` on the registered `pattern`, if any.
pub fn declared_access(method: &Method, pattern: &str) -> Option<Access> {
    ROUTES
        .iter()
        .find(|r| r.pattern == pattern && r.method == method.as_str())
        .map(|r| r.access)
}

/// Env var → the scopes a token from it carries.
const TOKEN_SOURCES: &[(&str, &[Scope])] = &[
    ("BROKER_TOKEN_READ", &[Scope::Read]),
    ("BROKER_TOKEN_INGEST", &[Scope::Ingest, Scope::Read]),
    (
        "BROKER_TOKEN_SUPPLYCHAIN",
        &[Scope::SupplyChain, Scope::Read],
    ),
    (
        "BROKER_TOKEN_ADMIN",
        &[Scope::Admin, Scope::Read, Scope::Ingest, Scope::SupplyChain],
    ),
    // Pre-scopes shared token: exactly what it granted before.
    ("BROKER_AUTH_TOKEN", &[Scope::Read, Scope::Ingest]),
];

/// Tokens shorter than this draw a startup warning.
const MIN_TOKEN_LEN: usize = 16;

#[derive(Clone)]
struct Credential {
    token: Vec<u8>,
    scopes: u8,
}

/// The configured tokens. Cloned into each worker via `app_data`.
#[derive(Clone, Default)]
pub struct AuthConfig {
    credentials: Vec<Credential>,
    /// Env var names that supplied a token, for the startup log.
    sources: Vec<&'static str>,
}

impl AuthConfig {
    /// Read tokens from the environment. Empty or whitespace-only values
    /// count as unset. Errors when two variables carry the same token:
    /// that silently merges their scopes (a read client would gain
    /// ingest), which is a misconfiguration to refuse, not to guess at.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub(crate) fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let mut cfg = AuthConfig::default();
        for (var, scopes) in TOKEN_SOURCES {
            let Some(token) = lookup(var)
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
            else {
                continue;
            };
            if let Some(i) = cfg
                .credentials
                .iter()
                .position(|c| ct_eq(&c.token, token.as_bytes()))
            {
                return Err(format!(
                    "{var} and {} hold the same token; each scope needs its own",
                    cfg.sources[i]
                ));
            }
            if token.len() < MIN_TOKEN_LEN {
                warn!(
                    var,
                    "broker auth token is shorter than {MIN_TOKEN_LEN} characters; use `openssl rand -hex 32`"
                );
            }
            cfg.credentials.push(Credential {
                token: token.into_bytes(),
                scopes: scopes.iter().fold(0, |acc, s| acc | s.bit()),
            });
            cfg.sources.push(var);
        }
        Ok(cfg)
    }

    pub fn enabled(&self) -> bool {
        !self.credentials.is_empty()
    }

    /// Whether some configured token carries `scope`. Supply-chain ingest
    /// runs only when one carries `supplychain`, i.e. auth is scoped.
    pub fn configures(&self, scope: Scope) -> bool {
        self.credentials.iter().any(|c| c.scopes & scope.bit() != 0)
    }

    /// Env var names that configured a token (never the tokens).
    pub fn sources(&self) -> &[&'static str] {
        &self.sources
    }

    /// Union of scopes for `presented`, or `None` if it matches no token.
    /// Compares against every configured token without short-circuiting,
    /// so the time taken doesn't reveal which (if any) matched.
    fn scopes_for(&self, presented: &[u8]) -> Option<u8> {
        let mut scopes = 0u8;
        let mut matched = 0u8;
        for c in &self.credentials {
            let hit = ct_eq(&c.token, presented) as u8;
            matched |= hit;
            scopes |= c.scopes & 0u8.wrapping_sub(hit);
        }
        (matched == 1).then_some(scopes)
    }
}

/// Constant-time equality. Runs over the longer input and folds the
/// length difference into the result, so neither content nor where it
/// first differs leaks through timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let n = a.len().max(b.len());
    let mut diff = (a.len() ^ b.len()) as u64;
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= (x ^ y) as u64;
    }
    diff == 0
}

fn bearer(req: &ServiceRequest) -> Option<&[u8]> {
    let value = req.headers().get(header::AUTHORIZATION)?.as_bytes();
    let rest = value
        .strip_prefix(b"Bearer ")
        .or_else(|| value.strip_prefix(b"bearer "))?;
    Some(rest.trim_ascii())
}

fn unauthorized() -> Error {
    actix_web::error::InternalError::from_response(
        "missing or invalid bearer token",
        HttpResponse::Unauthorized()
            .insert_header((header::WWW_AUTHENTICATE, "Bearer"))
            .body("missing or invalid bearer token"),
    )
    .into()
}

fn forbidden(msg: String) -> Error {
    actix_web::error::InternalError::from_response(msg.clone(), HttpResponse::Forbidden().body(msg))
        .into()
}

fn not_found() -> Error {
    actix_web::error::InternalError::from_response("not found", HttpResponse::NotFound().finish())
        .into()
}

/// Scopes the presented token carries, set by [`authenticate`] for
/// [`authorize`] to check.
#[derive(Clone, Copy)]
struct Granted(u8);

/// The resource-level middleware every route attaches with
/// `wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"`
/// (or `.wrap(...)` on a builder). The route tests check for exactly
/// this string on every route.
pub const AUTHORIZE_WRAP: &str = "::actix_web::middleware::from_fn(crate::auth::authorize)";

/// App-level half: authentication. Runs BEFORE routing, so it makes no
/// authorisation decision from the path. It only:
///
/// - lets `/health` and `/metrics` through without a token,
/// - answers 404 itself when the path matches no registered pattern,
///   so "no pattern" can never fall through to a handler,
/// - otherwise requires a valid token (401) and records its scopes.
///
/// The path is the one the router matches on (`match_info()`, the
/// requoted path), not the raw request path. The first version of this
/// middleware used `req.match_pattern()`, which before routing falls
/// back to the RAW path: `/pod/traffic/%62atch` matched no pattern there
/// while the router decoded it to `/pod/traffic/batch`, so any valid
/// token reached any handler.
///
/// OPTIONS gets no exemption: real CORS preflights are answered by the
/// Cors middleware outside this one and never get here.
pub async fn authenticate(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let Some(cfg) = req.app_data::<web::Data<AuthConfig>>().cloned() else {
        return next.call(req).await;
    };
    if !cfg.enabled() {
        return next.call(req).await;
    }

    let routed_path = req.match_info().as_str().to_owned();
    let Some(pattern) = req.request().resource_map().match_pattern(&routed_path) else {
        return Err(not_found());
    };
    if declared_access(req.method(), &pattern) == Some(Access::Open) {
        return next.call(req).await;
    }

    let Some(scopes) = bearer(&req).and_then(|t| cfg.scopes_for(t)) else {
        return Err(unauthorized());
    };
    req.extensions_mut().insert(Granted(scopes));
    next.call(req).await
}

/// Resource-level half: authorisation. Runs AFTER routing, inside the
/// resource the router actually picked, so `match_pattern()` is that
/// resource's own pattern and cannot disagree with the dispatch.
pub async fn authorize(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let Some(cfg) = req.app_data::<web::Data<AuthConfig>>().cloned() else {
        return next.call(req).await;
    };
    if !cfg.enabled() {
        return next.call(req).await;
    }

    let pattern = req.match_pattern();
    let access = pattern
        .as_deref()
        .and_then(|p| declared_access(req.method(), p));
    let granted = req.extensions().get::<Granted>().map(|g| g.0);

    match access {
        Some(Access::Open) => {}
        Some(Access::Requires(scope)) => {
            // No Granted means authenticate never ran for this request;
            // refuse rather than assume.
            let Some(scopes) = granted else {
                return Err(unauthorized());
            };
            if scopes & scope.bit() == 0 {
                warn!(
                    method = %req.method(),
                    path = %req.path(),
                    required = scope.as_str(),
                    "broker request refused: token lacks the required scope"
                );
                return Err(forbidden(format!(
                    "token lacks the '{}' scope",
                    scope.as_str()
                )));
            }
        }
        None => {
            // A route nobody declared (for this method): refuse it for
            // everyone, admin included, rather than guess.
            error!(
                pattern = pattern.as_deref().unwrap_or("<none>"),
                method = %req.method(),
                "broker route has no declared scope in auth::ROUTES; refusing"
            );
            return Err(forbidden("route has no declared scope".to_string()));
        }
    }

    next.call(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http::StatusCode, middleware::from_fn, test as atest, App};

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| owned.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.clone())
    }

    const READ_TOK: &str = "read-token-0123456789";
    const INGEST_TOK: &str = "ingest-token-0123456789";
    const SC_TOK: &str = "supplychain-token-0123456789";
    const ADMIN_TOK: &str = "admin-token-0123456789";

    fn scoped() -> AuthConfig {
        AuthConfig::from_lookup(lookup(&[
            ("BROKER_TOKEN_READ", READ_TOK),
            ("BROKER_TOKEN_INGEST", INGEST_TOK),
            ("BROKER_TOKEN_SUPPLYCHAIN", SC_TOK),
            ("BROKER_TOKEN_ADMIN", ADMIN_TOK),
        ]))
        .unwrap()
    }

    #[test]
    fn ct_eq_matches_only_identical_inputs() {
        assert!(ct_eq(b"s3cret-token", b"s3cret-token"));
        assert!(!ct_eq(b"s3cret-token", b"s3cret-toker"));
        assert!(!ct_eq(b"short", b"longer-token"));
        assert!(!ct_eq(b"abc", b"abc\0"));
        assert!(!ct_eq(b"", b"x"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn blank_values_leave_auth_disabled() {
        let cfg = AuthConfig::from_lookup(lookup(&[
            ("BROKER_AUTH_TOKEN", "   "),
            ("BROKER_TOKEN_READ", ""),
        ]))
        .unwrap();
        assert!(!cfg.enabled());
        assert!(!AuthConfig::from_lookup(|_| None).unwrap().enabled());
    }

    #[test]
    fn each_token_carries_its_scopes() {
        let cfg = scoped();
        let s = |t: &str| cfg.scopes_for(t.as_bytes()).unwrap();
        assert_eq!(s(READ_TOK), Scope::Read.bit());
        assert_eq!(s(INGEST_TOK), Scope::Ingest.bit() | Scope::Read.bit());
        assert_eq!(s(SC_TOK), Scope::SupplyChain.bit() | Scope::Read.bit());
        assert_eq!(s(ADMIN_TOK), 0b1111);
        assert_eq!(cfg.scopes_for(b"nope"), None);
        assert_eq!(cfg.scopes_for(b""), None);
    }

    #[test]
    fn legacy_shared_token_grants_read_and_ingest_only() {
        let cfg =
            AuthConfig::from_lookup(lookup(&[("BROKER_AUTH_TOKEN", "legacy-token-0123456789")]))
                .unwrap();
        assert!(cfg.enabled());
        let s = cfg.scopes_for(b"legacy-token-0123456789").unwrap();
        assert_eq!(s, Scope::Read.bit() | Scope::Ingest.bit());
        assert_eq!(s & Scope::SupplyChain.bit(), 0);
    }

    #[test]
    fn the_same_token_for_two_scopes_is_refused() {
        let err = AuthConfig::from_lookup(lookup(&[
            ("BROKER_TOKEN_READ", "same-token-0123456789"),
            ("BROKER_TOKEN_INGEST", "same-token-0123456789"),
        ]))
        .err()
        .expect("duplicate tokens must be refused");
        assert!(
            err.contains("BROKER_TOKEN_READ") && err.contains("BROKER_TOKEN_INGEST"),
            "{err}"
        );
    }

    #[test]
    fn from_env_reads_the_process_environment() {
        let _guard = crate::test_support::env_lock();
        let prev = std::env::var("BROKER_TOKEN_READ").ok();
        std::env::set_var("BROKER_TOKEN_READ", "   ");
        assert!(!AuthConfig::from_env()
            .unwrap()
            .sources()
            .contains(&"BROKER_TOKEN_READ"));
        std::env::set_var("BROKER_TOKEN_READ", READ_TOK);
        assert!(AuthConfig::from_env()
            .unwrap()
            .sources()
            .contains(&"BROKER_TOKEN_READ"));
        match prev {
            Some(v) => std::env::set_var("BROKER_TOKEN_READ", v),
            None => std::env::remove_var("BROKER_TOKEN_READ"),
        }
    }

    #[test]
    fn the_route_table_has_no_duplicates() {
        for (i, a) in ROUTES.iter().enumerate() {
            for b in &ROUTES[i + 1..] {
                assert!(
                    !(a.method == b.method && a.pattern == b.pattern),
                    "duplicate route rule {} {}",
                    a.method,
                    a.pattern
                );
            }
        }
    }

    // ---- source scan: every route has a ROUTES entry AND the wrap ------

    struct FoundRoute {
        method: String,
        path: String,
        file: String,
        wrapped: bool,
    }

    /// Every actix route declared in `src`: route attribute macros
    /// (`#[get("..", wrap = "..")]`, `#[actix_web::put(..)]`, ...) and
    /// `web::resource("..")` builders with their `.route(web::<m>())`
    /// verbs and `.wrap(..)`. Paths inside a `web::scope` are relative, so
    /// the check matches them as a suffix of a declared pattern.
    fn routes_in_source() -> Vec<FoundRoute> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut found = Vec::new();
        for entry in std::fs::read_dir(&dir).expect("read src") {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let file = path.file_name().unwrap().to_string_lossy().to_string();
            if file == "auth.rs" {
                // This scanner's own string literals look like routes.
                continue;
            }
            let src = std::fs::read_to_string(&path).unwrap();
            // Code lines only: comments mention route syntax too.
            let lines: Vec<&str> = src
                .lines()
                .map(str::trim)
                .filter(|l| !l.starts_with("//"))
                .collect();
            let quoted = |s: &str| s.split('"').nth(1).map(str::to_string);
            let has_authorize = |s: &str| {
                s.contains("from_fn(crate::auth::authorize)")
                    || s.contains("from_fn(api::auth::authorize)")
            };
            for (i, line) in lines.iter().enumerate() {
                for method in ["get", "post", "put", "delete", "patch"] {
                    if line.starts_with(&format!("#[{method}("))
                        || line.starts_with(&format!("#[actix_web::{method}("))
                    {
                        // The attribute may span lines (rustfmt); take it
                        // up to its closing `)]`.
                        let mut attr = String::new();
                        for l in &lines[i..] {
                            attr.push_str(l);
                            if l.ends_with(")]") {
                                break;
                            }
                        }
                        found.push(FoundRoute {
                            method: method.to_uppercase(),
                            path: quoted(&attr).unwrap(),
                            file: file.clone(),
                            wrapped: has_authorize(&attr),
                        });
                    }
                }
                if line.contains("web::resource(\"") {
                    let p = quoted(&line[line.find("web::resource(").unwrap()..]).unwrap();
                    let body: Vec<&str> = lines[i..]
                        .iter()
                        .copied()
                        .take_while(|l| !l.starts_with('}'))
                        .collect();
                    let wrapped = body.iter().any(|l| has_authorize(l));
                    let mut any = false;
                    for next in &body {
                        for method in ["get", "post", "put", "delete", "patch"] {
                            if next.contains(&format!("web::{method}()")) {
                                found.push(FoundRoute {
                                    method: method.to_uppercase(),
                                    path: p.clone(),
                                    file: file.clone(),
                                    wrapped,
                                });
                                any = true;
                            }
                        }
                    }
                    assert!(any, "{file}: resource {p} has no recognisable verb");
                }
            }
        }
        found
    }

    #[test]
    fn every_route_in_the_source_declares_its_access() {
        let found = routes_in_source();
        assert!(
            found.len() >= ROUTES.len(),
            "scan found only {} routes",
            found.len()
        );
        for f in &found {
            assert!(
                ROUTES
                    .iter()
                    .any(|r| r.method == f.method && r.pattern.ends_with(f.path.as_str())),
                "{}: {} {} has no entry in auth::ROUTES. Declare the scope it needs \
                 (read / ingest / supplychain / admin, or Open) before registering it.",
                f.file,
                f.method,
                f.path
            );
            assert!(
                f.wrapped,
                "{}: {} {} lacks the per-route authorisation wrap. Add wrap = \"{}\" \
                 (or .wrap(...) on the resource builder); without it any valid token \
                 of any scope reaches the handler.",
                f.file, f.method, f.path, AUTHORIZE_WRAP
            );
        }
        for r in ROUTES {
            assert!(
                found
                    .iter()
                    .any(|f| f.method == r.method && r.pattern.ends_with(f.path.as_str())),
                "auth::ROUTES has {} {} but no such route exists in the source",
                r.method,
                r.pattern
            );
        }
    }

    // ---- behaviour through the real route registration ----------------

    async fn ok() -> HttpResponse {
        HttpResponse::Ok().body("handler reached")
    }

    fn concrete(pattern: &str) -> String {
        let mut out = String::new();
        let mut in_param = false;
        for ch in pattern.chars() {
            match ch {
                '{' => in_param = true,
                '}' => {
                    in_param = false;
                    out.push('x');
                }
                _ if !in_param => out.push(ch),
                _ => {}
            }
        }
        out
    }

    /// The server's middleware stack (Cors outside authenticate) around
    /// the real `routes::configure`, plus stand-ins for main.rs's
    /// /health and /metrics and one route that is registered but not in
    /// ROUTES.
    macro_rules! app {
        ($cfg:expr) => {
            atest::init_service(
                App::new()
                    .wrap(from_fn(authenticate))
                    .wrap(
                        actix_cors::Cors::default()
                            .allow_any_origin()
                            .allow_any_method()
                            .allow_any_header()
                            .max_age(3600),
                    )
                    .app_data(web::Data::new($cfg))
                    .configure(crate::routes::configure)
                    .service(
                        web::resource("/health")
                            .wrap(from_fn(authorize))
                            .route(web::get().to(ok)),
                    )
                    .service(
                        web::resource("/metrics")
                            .wrap(from_fn(authorize))
                            .route(web::get().to(ok)),
                    )
                    .service(
                        web::resource("/undeclared")
                            .wrap(from_fn(authorize))
                            .route(web::get().to(ok)),
                    ),
            )
            .await
        };
    }

    fn request(method: &str, path: &str, token: Option<&str>) -> atest::TestRequest {
        let mut req = atest::TestRequest::default()
            .method(Method::from_bytes(method.as_bytes()).unwrap())
            .uri(path);
        if let Some(t) = token {
            req = req.insert_header((header::AUTHORIZATION, format!("Bearer {t}")));
        }
        req
    }

    /// Status of one request; a middleware refusal comes back as `Err`.
    macro_rules! status_of {
        ($app:expr, $method:expr, $path:expr, $token:expr) => {
            match atest::try_call_service(&$app, request($method, $path, $token).to_request()).await
            {
                Ok(resp) => resp.status(),
                Err(e) => e.as_response_error().status_code(),
            }
        };
    }

    fn allowed(s: StatusCode) -> bool {
        s != StatusCode::UNAUTHORIZED && s != StatusCode::FORBIDDEN && s != StatusCode::NOT_FOUND
    }

    #[actix_web::test]
    async fn every_declared_route_enforces_its_scope() {
        let app = app!(scoped());
        for r in ROUTES {
            let path = concrete(r.pattern);
            let anon = status_of!(app, r.method, &path, None);
            let bad = status_of!(app, r.method, &path, Some("wrong-token-0123456789"));
            let read = status_of!(app, r.method, &path, Some(READ_TOK));
            let ingest = status_of!(app, r.method, &path, Some(INGEST_TOK));
            let sc = status_of!(app, r.method, &path, Some(SC_TOK));
            let admin = status_of!(app, r.method, &path, Some(ADMIN_TOK));
            let label = format!("{} {}", r.method, r.pattern);
            match r.access {
                Access::Open => {
                    assert!(
                        allowed(anon) && allowed(bad),
                        "{label}: open route refused ({anon}/{bad})"
                    );
                }
                Access::Requires(scope) => {
                    assert_eq!(anon, StatusCode::UNAUTHORIZED, "{label}: no token");
                    assert_eq!(bad, StatusCode::UNAUTHORIZED, "{label}: wrong token");
                    // Handlers here have no DB pool, so "reached" shows
                    // as 400/500 — anything but 401/403/404.
                    assert!(allowed(admin), "{label}: admin refused ({admin})");
                    let expect = |tok_scopes: &[Scope]| tok_scopes.contains(&scope);
                    assert_eq!(
                        allowed(read),
                        expect(&[Scope::Read]),
                        "{label}: read token got {read}"
                    );
                    assert_eq!(
                        allowed(ingest),
                        expect(&[Scope::Ingest, Scope::Read]),
                        "{label}: ingest token got {ingest}"
                    );
                    assert_eq!(
                        allowed(sc),
                        expect(&[Scope::SupplyChain, Scope::Read]),
                        "{label}: supplychain token got {sc}"
                    );
                    if !allowed(read) {
                        assert_eq!(
                            read,
                            StatusCode::FORBIDDEN,
                            "{label}: valid token, wrong scope"
                        );
                    }
                }
            }
        }
    }

    /// Regression for the review's C1: percent-encoding a character of an
    /// ingest route made the pre-routing check see "no pattern" (raw path)
    /// while the router decoded it and dispatched to the ingest handler,
    /// so a read token could write. Every one of these must be refused
    /// for a read token, and must still route (reach the handler) for an
    /// admin token, proving the decoding really happens.
    #[actix_web::test]
    async fn percent_encoded_paths_get_the_scope_of_the_route_they_decode_to() {
        let app = app!(scoped());
        let cases = [
            ("POST", "/pod/traffic/%62atch"),
            ("POST", "/pod/traffic/%62%61tch"),
            ("POST", "/node/%66acts"),
            ("POST", "/pod/mark%5Fdead"),
            ("POST", "/pod/mark%5fdead"),
            ("POST", "/pod/%73pec"),
            ("POST", "/pod/compute/%62atch"),
            ("POST", "/pod/%63ompute/batch"),
            ("POST", "/seccomp/%64enials"),
            ("POST", "/seccomp/node%2Dstatus"),
            ("PUT", "/seccomp/%63rs/a/b"),
            ("DELETE", "/seccomp/%63rs/a/b"),
            ("POST", "/images/x/%76ulnerabilities"),
            ("POST", "/images/x/%73bom"),
        ];
        for (method, path) in cases {
            let read = status_of!(app, method, path, Some(READ_TOK));
            assert_eq!(
                read,
                StatusCode::FORBIDDEN,
                "{method} {path} with read token"
            );
            let anon = status_of!(app, method, path, None);
            assert_eq!(anon, StatusCode::UNAUTHORIZED, "{method} {path} anonymous");
            let admin = status_of!(app, method, path, Some(ADMIN_TOK));
            assert!(
                allowed(admin),
                "{method} {path} should route for admin, got {admin}"
            );
        }
    }

    #[actix_web::test]
    async fn an_encoded_undeclared_route_is_still_refused_for_admin() {
        let app = app!(scoped());
        for path in [
            "/undeclared",
            "/un%64eclared",
            "/%75ndeclared",
            "/UN%64eclared",
        ] {
            let s = status_of!(app, "GET", path, Some(ADMIN_TOK));
            assert!(
                s == StatusCode::FORBIDDEN || s == StatusCode::NOT_FOUND,
                "GET {path} with admin reached the undeclared handler ({s})"
            );
        }
        assert_eq!(
            status_of!(app, "GET", "/un%64eclared", Some(ADMIN_TOK)),
            StatusCode::FORBIDDEN
        );
    }

    /// Encoded slashes, mixed-case hex and double encoding decode to no
    /// route for the method used (the router keeps %2F and %25 encoded):
    /// 404 for every token, never a handler. Anonymous callers may see
    /// 401 instead where the decoded path matches some route's pattern
    /// for another method (`/pod/traffic/%2562atch` is a valid GET
    /// `/pod/traffic/{name}`); both refuse.
    #[actix_web::test]
    async fn paths_that_decode_to_no_route_are_404_and_never_reach_a_handler() {
        let app = app!(scoped());
        let cases = [
            ("POST", "/pod/traffic%2Fbatch"),
            ("POST", "/pod/traffic%2fbatch"),
            ("POST", "/pod%2Ftraffic%2Fbatch"),
            ("POST", "/pod%2ftraffic/batch"),
            ("POST", "/pod/traffic/%2562atch"),
            ("POST", "/pod/mark%255Fdead"),
            ("POST", "/node%2Ffacts"),
            ("PUT", "/seccomp/crs%2Fa/b"),
            ("GET", "/nope"),
            ("GET", "/%2e%2e/pod/info"),
        ];
        for (method, path) in cases {
            for token in [Some(READ_TOK), Some(INGEST_TOK), Some(ADMIN_TOK)] {
                let s = status_of!(app, method, path, token);
                assert_eq!(s, StatusCode::NOT_FOUND, "{method} {path} token={token:?}");
            }
            let anon = status_of!(app, method, path, None);
            assert!(
                anon == StatusCode::NOT_FOUND || anon == StatusCode::UNAUTHORIZED,
                "{method} {path} anonymous: {anon}"
            );
        }
    }

    #[actix_web::test]
    async fn auth_disabled_passes_everything_through() {
        let app = app!(AuthConfig::default());
        for r in ROUTES {
            let s = status_of!(app, r.method, &concrete(r.pattern), None);
            if r.access == SUPPLYCHAIN {
                // The one deliberate exception: supply-chain ingest refuses
                // to run without scoped auth (supplychain::ingest_allowed),
                // so an open broker can't be fed forged scan results.
                assert_eq!(
                    s,
                    StatusCode::FORBIDDEN,
                    "{} {}: supply-chain ingest must refuse with auth disabled",
                    r.method,
                    r.pattern
                );
                continue;
            }
            assert!(
                s != StatusCode::UNAUTHORIZED && s != StatusCode::FORBIDDEN,
                "{} {}: {s} with auth disabled",
                r.method,
                r.pattern
            );
        }
    }

    /// OPTIONS: a CORS preflight is answered by the Cors layer with an
    /// empty body before any auth or handler runs; a bare OPTIONS (not a
    /// preflight) gets no exemption and no route serves it. Neither
    /// reaches a handler.
    #[actix_web::test]
    async fn options_never_reaches_a_handler_or_returns_data() {
        let app = app!(scoped());
        for path in [
            "/pod/traffic/batch",
            "/pod/mark_dead",
            "/pod/info",
            "/undeclared",
        ] {
            let req = atest::TestRequest::default()
                .method(Method::OPTIONS)
                .uri(path)
                .insert_header((header::ORIGIN, "https://evil.example"))
                .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
                .to_request();
            let resp = atest::call_service(&app, req).await;
            assert!(
                resp.status().is_success(),
                "preflight {path}: {}",
                resp.status()
            );
            let body = atest::read_body(resp).await;
            assert!(
                body.is_empty(),
                "preflight {path} returned a body: {body:?}"
            );

            assert_eq!(
                status_of!(app, "OPTIONS", path, None),
                StatusCode::UNAUTHORIZED,
                "bare OPTIONS {path} anonymous"
            );
            let with_token = status_of!(app, "OPTIONS", path, Some(ADMIN_TOK));
            assert!(
                with_token == StatusCode::NOT_FOUND || with_token == StatusCode::FORBIDDEN,
                "bare OPTIONS {path} with admin: {with_token}"
            );
        }
    }
}
