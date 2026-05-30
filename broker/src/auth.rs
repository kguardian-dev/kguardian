//! Optional bearer-token authentication for the broker HTTP API.
//!
//! The broker API is otherwise unauthenticated — it has historically
//! relied on being an in-cluster-only service. That leaves its write
//! endpoints (pod traffic / syscalls / specs) open to any workload that
//! can route to the Service, which can forge rows and poison audit
//! verdicts. When `BROKER_AUTH_TOKEN` is set, every endpoint except
//! `/health` and `/metrics` requires `Authorization: Bearer <token>`.
//!
//! Unset (the default) preserves the original no-auth behaviour so
//! existing deployments are unaffected — this is strictly opt-in.
//!
//! `/health` is exempt because kubelet probes can't carry the header;
//! `/metrics` is exempt because Prometheus scrapes it and the gauges are
//! low-sensitivity. Browser clients (the frontend talks to the broker
//! directly) can't safely hold a static token, so enabling this is
//! intended for the controller + mcp-server server-to-server paths.

use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Next;
use actix_web::{web, Error};

/// Holds the optional shared secret the broker checks incoming requests
/// against. Cloned into each worker via `app_data`.
#[derive(Clone)]
pub struct AuthConfig {
    token: Option<String>,
}

impl AuthConfig {
    /// Read the token from `BROKER_AUTH_TOKEN`. Empty / whitespace-only
    /// is treated as unset (auth disabled), matching how the provider
    /// keys are handled elsewhere.
    pub fn from_env() -> Self {
        let token = std::env::var("BROKER_AUTH_TOKEN")
            .ok()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty());
        AuthConfig { token }
    }

    pub fn enabled(&self) -> bool {
        self.token.is_some()
    }
}

/// Constant-time comparison so a wrong token can't be recovered byte by
/// byte via response timing.
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// True if the request is allowed to skip the bearer check: unset token
/// (auth disabled), a CORS preflight, or the probe/metrics endpoints.
fn is_exempt(req: &ServiceRequest) -> bool {
    req.method() == actix_web::http::Method::OPTIONS
        || req.path() == "/health"
        || req.path() == "/metrics"
}

/// True if the `Authorization: Bearer <token>` header matches `expected`.
fn bearer_ok(req: &ServiceRequest, expected: &str) -> bool {
    req.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|t| ct_eq(t.trim(), expected))
        .unwrap_or(false)
}

/// actix `from_fn` middleware enforcing the optional bearer token.
pub async fn require_bearer(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let expected = req
        .app_data::<web::Data<AuthConfig>>()
        .and_then(|c| c.token.clone());

    if let Some(expected) = expected {
        if !is_exempt(&req) && !bearer_ok(&req, &expected) {
            return Err(actix_web::error::ErrorUnauthorized(
                "missing or invalid bearer token",
            ));
        }
    }

    next.call(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_matches_only_identical_strings() {
        assert!(ct_eq("s3cret-token", "s3cret-token"));
        assert!(!ct_eq("s3cret-token", "s3cret-toker"));
        assert!(!ct_eq("short", "longer-token"));
        assert!(!ct_eq("", "x"));
        assert!(ct_eq("", ""));
    }

    #[test]
    fn from_env_treats_blank_as_disabled() {
        // Saved/restored around the test to avoid cross-test bleed; the
        // broker reads this once at startup in production.
        let prev = std::env::var("BROKER_AUTH_TOKEN").ok();
        std::env::set_var("BROKER_AUTH_TOKEN", "   ");
        assert!(!AuthConfig::from_env().enabled());
        std::env::set_var("BROKER_AUTH_TOKEN", "real-token");
        assert!(AuthConfig::from_env().enabled());
        match prev {
            Some(v) => std::env::set_var("BROKER_AUTH_TOKEN", v),
            None => std::env::remove_var("BROKER_AUTH_TOKEN"),
        }
    }
}
