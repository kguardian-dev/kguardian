//! The Broker's catalog routes, as the Controller speaks them. Every
//! request and response type for `/catalog/*` is here and nowhere else,
//! so aligning with `broker/src/node_catalog.rs` is one file.
//!
//! | Route | Body | Answer |
//! |---|---|---|
//! | `POST /catalog/claims` | [`ClaimRequest`] | 200 [`ClaimResponse`] (always 200; no grant is `grant: null`) |
//! | `PUT /catalog/claims/{digest}` + `X-Kguardian-Claim` | [`ClaimUpdate`] | 200 [`ClaimUpdateResponse`] |
//! | `POST /catalog/images/{digest}/sbom` + `X-Kguardian-Claim` | [`SbomPage`] | 202 staged / 200 stored |
//!
//! Status codes the loop acts on: 409 stale token, lease or epoch; 503
//! catalog token not configured on the Broker (or its upload queue is
//! full, with a short `Retry-After`); 404 a Broker without the routes;
//! 429 staging full; other 5xx transient.

use serde::{Deserialize, Serialize};

/// Header carrying the claim token on renew/fail and uploads.
pub const CLAIM_HEADER: &str = "X-Kguardian-Claim";
/// Most digests one offer may carry (the Broker answers 413 above it).
pub const MAX_OFFER: usize = 512;
/// Most `partial_reasons` the Broker keeps.
pub const MAX_PARTIAL_REASONS: usize = 16;
/// Most file paths the catalog route keeps per component.
pub const MAX_PATHS_PER_COMPONENT: usize = 4096;
/// Most file paths in one upload request.
pub const MAX_PATHS_PER_PAGE: usize = 200_000;
/// Components per page (the Broker takes up to 10 000; the producer
/// convention is 2 000).
pub const COMPONENTS_PER_PAGE: usize = 2_000;
/// Most pages in one SBOM set.
pub const MAX_PAGES: usize = 128;
/// Encoded page ceiling. The Broker takes 8 MiB on the wire; pages are
/// sent uncompressed, with headroom.
pub const MAX_PAGE_BYTES: usize = 7 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClaimRequest {
    pub node: String,
    /// `os/arch[/variant]`, lower case.
    pub platform: String,
    pub epoch: i64,
    pub offer: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    pub digest: String,
    pub claim_token: String,
    /// RFC 3339, the Broker's database clock. Logged only: the Controller
    /// renews on its own 60 s cadence and never compares clocks.
    #[serde(default)]
    pub lease_expires_at: Option<String>,
    #[serde(default)]
    pub lease_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimResponse {
    #[serde(default = "default_true")]
    pub grants_enabled: bool,
    #[serde(default)]
    pub grant: Option<Grant>,
}

fn default_true() -> bool {
    true
}

/// `PUT /catalog/claims/{digest}` actions. There is no `done`: the upload
/// that completes the SBOM set marks the claim done.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Renew,
    Fail,
    Skip,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClaimUpdate {
    pub action: Action,
    pub node: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimUpdateResponse {
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub lease_expires_at: Option<String>,
    #[serde(default)]
    pub next_attempt_at: Option<String>,
}

/// Why a claim ended without an SBOM: the Broker's closed set (anything
/// else is 422). The retry class is the Broker's; the Controller only
/// picks the word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FailReason {
    // Backoff 1 h, 6 h, then 24 h.
    Timeout,
    Oom,
    Error,
    // Released to other nodes at once (3 per node per 24 h).
    PidGone,
    Drift,
    ExitedBeforeCatalog,
    // Per-node, non-blocking (24 h skip of this node).
    Sandboxed,
    LazySnapshotter,
    UnsupportedRootfs,
    KernelUnsupported,
    LsmDenied,
    CapsUnavailable,
    DeferredPressure,
    WorkerUnavailable,
    // Terminal for the digest.
    NoPackagesFound,
}

impl FailReason {
    pub fn as_str(self) -> &'static str {
        match self {
            FailReason::Timeout => "timeout",
            FailReason::Oom => "oom",
            FailReason::Error => "error",
            FailReason::PidGone => "pid_gone",
            FailReason::Drift => "drift",
            FailReason::ExitedBeforeCatalog => "exited_before_catalog",
            FailReason::Sandboxed => "sandboxed",
            FailReason::LazySnapshotter => "lazy_snapshotter",
            FailReason::UnsupportedRootfs => "unsupported_rootfs",
            FailReason::KernelUnsupported => "kernel_unsupported",
            FailReason::LsmDenied => "lsm_denied",
            FailReason::CapsUnavailable => "caps_unavailable",
            FailReason::DeferredPressure => "deferred_pressure",
            FailReason::WorkerUnavailable => "worker_unavailable",
            FailReason::NoPackagesFound => "no_packages_found",
        }
    }

    /// Per-node reasons go out as `skip`; the Broker's `skip` accepts
    /// only these.
    pub fn action(self) -> Action {
        match self {
            FailReason::Sandboxed
            | FailReason::LazySnapshotter
            | FailReason::UnsupportedRootfs
            | FailReason::KernelUnsupported
            | FailReason::LsmDenied
            | FailReason::CapsUnavailable
            | FailReason::DeferredPressure
            | FailReason::WorkerUnavailable => Action::Skip,
            _ => Action::Fail,
        }
    }

    /// A worker `reason` (PROTOCOL.md 4.4) as a Broker reason. `busy` is
    /// not here: it is a local retry, never reported. Unknown reasons,
    /// and the ones that are a Controller or version bug, are `error`.
    pub fn from_worker(reason: &str) -> FailReason {
        match reason {
            "timeout" => FailReason::Timeout,
            "oom" => FailReason::Oom,
            "no_packages_found" => FailReason::NoPackagesFound,
            "lsm_denied" => FailReason::LsmDenied,
            "kernel_unsupported" => FailReason::KernelUnsupported,
            "caps_unavailable" => FailReason::CapsUnavailable,
            // too_many_components, output_too_large, bad_request,
            // unsupported_protocol, error, and anything newer.
            _ => FailReason::Error,
        }
    }
}

/// `ImageSBOM.image` for a node SBOM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SbomImage {
    pub digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    /// The inventory digest keys the SBOM (design section 2).
    pub index_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Scanner {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Page {
    pub set_id: String,
    pub index: i64,
    pub total: i64,
}

/// One component as the catalog route takes it: `WireComponent` plus the
/// two per-package flags, which the route stores in
/// `node_sbom_package_flags` rather than in the generic component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Component {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub comp_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_version: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub licenses: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_paths: Vec<String>,
    #[serde(default)]
    pub files_truncated: bool,
    #[serde(default)]
    pub interpreted_content: bool,
}

/// One upload request: `ImageSBOM` v1 plus the catalog route's own
/// top-level fields, sent identically on every page (the Broker keeps
/// the ones from the page that completes the set).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SbomPage {
    pub schema_version: i64,
    pub image: SbomImage,
    pub source: &'static str,
    pub sbom_trust: &'static str,
    pub scanner: Scanner,
    /// RFC 3339 UTC.
    pub scanned_at: String,
    pub format: &'static str,
    pub page: Page,
    pub components: Vec<Component>,
    pub epoch: i64,
    pub completeness: String,
    pub partial_reasons: Vec<String>,
    pub stats: serde_json::Value,
    pub platform: String,
}

pub const SBOM_SOURCE: &str = "node";
pub const SBOM_TRUST: &str = "scanned";
pub const SBOM_FORMAT: &str = "kguardian-cataloger";

#[cfg(test)]
mod tests {
    use super::*;

    /// The shapes the Broker's node_catalog.rs reads, pinned as JSON so a
    /// rename on either side shows up here.
    #[test]
    fn claim_request_and_grant_match_the_broker_wire_shape() {
        let req = ClaimRequest {
            node: "ip-10-0-1-5".into(),
            platform: "linux/arm64".into(),
            epoch: 1,
            offer: vec![format!("sha256:{}", "a".repeat(64))],
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "node": "ip-10-0-1-5", "platform": "linux/arm64", "epoch": 1,
                "offer": [format!("sha256:{}", "a".repeat(64))]
            })
        );

        let r: ClaimResponse = serde_json::from_str(
            r#"{"grantsEnabled":true,"grant":{"digest":"sha256:x","claimToken":"0b8f","leaseExpiresAt":"2026-10-03T10:15:00Z","leaseSeconds":900}}"#,
        )
        .unwrap();
        let g = r.grant.unwrap();
        assert_eq!(g.digest, "sha256:x");
        assert_eq!(g.claim_token, "0b8f");
        assert_eq!(g.lease_seconds, Some(900));

        let none: ClaimResponse =
            serde_json::from_str(r#"{"grantsEnabled":false,"grant":null}"#).unwrap();
        assert!(!none.grants_enabled);
        assert!(none.grant.is_none());
    }

    #[test]
    fn updates_carry_the_action_node_and_reason() {
        let u = ClaimUpdate {
            action: FailReason::LazySnapshotter.action(),
            node: "n1".into(),
            reason: Some(FailReason::LazySnapshotter.as_str().into()),
        };
        assert_eq!(
            serde_json::to_value(&u).unwrap(),
            serde_json::json!({"action":"skip","node":"n1","reason":"lazy_snapshotter"})
        );
        let renew = ClaimUpdate {
            action: Action::Renew,
            node: "n1".into(),
            reason: None,
        };
        assert_eq!(
            serde_json::to_value(&renew).unwrap(),
            serde_json::json!({"action":"renew","node":"n1"})
        );
        assert_eq!(FailReason::Drift.action(), Action::Fail);
        assert_eq!(FailReason::NoPackagesFound.action(), Action::Fail);
    }

    #[test]
    fn worker_reasons_map_onto_the_broker_set() {
        assert_eq!(FailReason::from_worker("oom"), FailReason::Oom);
        assert_eq!(
            FailReason::from_worker("too_many_components"),
            FailReason::Error
        );
        assert_eq!(
            FailReason::from_worker("output_too_large"),
            FailReason::Error
        );
        assert_eq!(FailReason::from_worker("bad_request"), FailReason::Error);
        assert_eq!(FailReason::from_worker("something_new"), FailReason::Error);
        assert_eq!(FailReason::from_worker("lsm_denied"), FailReason::LsmDenied);
    }
}
