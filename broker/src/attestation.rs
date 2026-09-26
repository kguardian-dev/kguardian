//! Image signature and attestation results (#1533 P2-1).
//!
//! The supplychain component verifies the cosign signatures and Sigstore
//! attestations of every running image digest and posts one result per
//! digest. This module stores the latest result per digest and serves it.
//! The broker never verifies anything itself and never trusts a result
//! from a token without the `supplychain` scope.
//!
//! # Routes
//!
//! | route | scope | |
//! |---|---|---|
//! | `POST /images/{digest}/attestation` | supplychain | replace the result for a digest |
//! | `GET /images/{digest}/attestation` | read | the stored result |
//! | `GET /attestations` | read | a keyset page of summaries, filterable by verdict/repository |
//!
//! # Ingest rules
//!
//! - The body is plain JSON (`Content-Encoding` absent or `identity`; 415
//!   otherwise), at most [`MAX_BODY_BYTES`], read in full under a
//!   [`BODY_DEADLINE`] before any database work, so a slow sender holds
//!   no connection.
//! - Lists are capped while parsing ([`MAX_SIGNATURES`],
//!   [`MAX_ATTESTATIONS`]; 413 beyond), strings are truncated, enums are
//!   checked (422).
//! - `checked_at` more than [`MAX_FUTURE_SKEW_SECS`] ahead is refused (422),
//!   so a skewed clock cannot pin a result forever.
//! - A stored result is replaced only by a strictly newer `checked_at`. An
//!   equal `checked_at` with identical content is a no-op (200); anything
//!   else is 409. A digest the inventory does not know is 404.
//!
//! # Retention
//!
//! [`spawn_retention`] runs hourly. It deletes results whose digest left
//! the image inventory (inventory retention dropped it: nothing runs it),
//! and results not re-checked within `IMAGE_ATTESTATION_RETENTION_DAYS`
//! (default 7; 0 keeps them): the component re-checks every running digest
//! daily, so an old row means the component stopped, and a stale verdict
//! should not be shown.

use crate::image_inventory::is_valid_digest;
use crate::read_budget::{cost_kib, ReadBudget};
use actix_web::{get, http::header, web, HttpRequest, HttpResponse, Responder};
use chrono::{DateTime, NaiveDateTime, Utc};
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use diesel::sql_query;
use diesel::sql_types::{BigInt, Bool, Jsonb, Nullable, Text, Timestamp};
use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::time::Duration;
use tracing::{info, warn};

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
type DbError = Box<dyn std::error::Error + Send + Sync>;

/// Largest accepted body. A result is a few KiB; the component trims
/// its own payload to this size.
pub const MAX_BODY_BYTES: usize = 256 * 1024;
/// The whole body must arrive within this.
pub const BODY_DEADLINE: Duration = Duration::from_secs(30);
pub const MAX_SIGNATURES: usize = 32;
pub const MAX_ATTESTATIONS: usize = 64;
pub const MAX_FUTURE_SKEW_SECS: i64 = 60;
/// Wire schema this broker understands.
pub const SCHEMA_VERSION: i64 = 1;

const MAX_URI: usize = 1024; // issuer, SAN, builder, source repo
const MAX_SHORT: usize = 128; // reasons, formats, refs
const MAX_DETAIL: usize = 256;
const TOO_MANY: &str = "too many items";

/// `key_signed`: signed with a public key the component does not hold,
/// so the signature exists but was not checked.
/// Reason codes accepted in `reason` and in a signature's or attestation's
/// `error`: exactly supplychain's (test/fixtures/contracts).
pub const REASONS: [&str; 18] = [
    "bad_signature",
    "blocked_address",
    "blocked_realm",
    "digest_mismatch",
    "local_hostname",
    "malformed",
    "network",
    "no_repo_digest",
    "private_address",
    "rate_limited",
    "registry_auth",
    "registry_error",
    "timeout",
    "too_large",
    "trust_root_unavailable",
    "unsupported_format",
    "untrusted_key",
    "untrusted_root",
];

pub const VERDICTS: [&str; 5] = ["verified", "key_signed", "unsigned", "invalid", "unknown"];

// ---------------------------------------------------------------------
// Wire format (snake_case in, camelCase out)
// ---------------------------------------------------------------------

/// Reads a JSON array into at most `N` items, failing with
/// [`TOO_MANY`] beyond; `null` reads as empty.
fn bounded_vec<'de, D, T, const N: usize>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct V<T, const N: usize>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for V<T, N> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "an array of at most {N} items")
        }
        fn visit_unit<E: de::Error>(self) -> Result<Vec<T>, E> {
            Ok(Vec::new())
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Vec<T>, A::Error> {
            let mut out = Vec::new();
            while let Some(x) = s.next_element()? {
                if out.len() == N {
                    return Err(de::Error::custom(TOO_MANY));
                }
                out.push(x);
            }
            Ok(out)
        }
    }
    d.deserialize_any(V::<T, N>(PhantomData))
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all(deserialize = "snake_case", serialize = "camelCase"))]
pub struct Provenance {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_repo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all(deserialize = "snake_case", serialize = "camelCase"))]
pub struct Signature {
    pub format: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// `keyless` (Fulcio certificate) or `key` (a configured public key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub san: Option<String>,
    /// The configured key that verified the signature, and the sha256
    /// (hex) of its DER public key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_fingerprint: Option<String>,
    /// The key hint a key-signed bundle carries, verified or not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrated_time: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tlog_index: Option<i64>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all(deserialize = "snake_case", serialize = "camelCase"))]
pub struct Attestation {
    pub predicate_type: String,
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
    /// `keyless` (Fulcio certificate) or `key` (a configured public key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub san: Option<String>,
    /// The configured key that verified the signature, and the sha256
    /// (hex) of its DER public key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_fingerprint: Option<String>,
    /// The key hint a key-signed bundle carries, verified or not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrated_time: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tlog_index: Option<i64>,
}

/// `POST /images/{digest}/attestation` body.
#[derive(Debug, Deserialize)]
pub struct AttestationPost {
    pub schema_version: i64,
    pub digest: String,
    pub repository: String,
    pub checked_at: DateTime<Utc>,
    pub verdict: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub trust_root: Option<String>,
    #[serde(default)]
    pub signed_via: Option<String>,
    #[serde(default)]
    pub signed_digest: Option<String>,
    #[serde(default, deserialize_with = "bounded_vec::<_, _, MAX_SIGNATURES>")]
    pub signatures: Vec<Signature>,
    #[serde(default, deserialize_with = "bounded_vec::<_, _, MAX_ATTESTATIONS>")]
    pub attestations: Vec<Attestation>,
}

fn cap(s: &mut Option<String>, max: usize) {
    if let Some(v) = s {
        if v.len() > max {
            let mut end = max;
            while !v.is_char_boundary(end) {
                end -= 1;
            }
            v.truncate(end);
        }
        if v.is_empty() {
            *s = None;
        }
    }
}

fn cap_str(v: &mut String, max: usize) {
    let mut o = Some(std::mem::take(v));
    cap(&mut o, max);
    *v = o.unwrap_or_default();
}

/// A machine token: `[a-z0-9_:.-]`, bounded.
fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_SHORT
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_:.-".contains(&b))
}

/// Why a post is refused.
#[derive(Debug, PartialEq)]
pub enum Reject {
    BadRequest(String),
    TooLarge(String),
    Unprocessable(String),
}

impl Reject {
    fn into_response(self) -> HttpResponse {
        match self {
            Reject::BadRequest(m) => HttpResponse::BadRequest().body(m),
            Reject::TooLarge(m) => HttpResponse::PayloadTooLarge().body(m),
            Reject::Unprocessable(m) => HttpResponse::UnprocessableEntity().body(m),
        }
    }
}

/// Caps the signer fields and drops the identity of an unverified
/// signature (it has none worth storing); the key hint is kept, since it
/// only says which key the signature claims.
fn too_long(v: &Option<String>, max: usize, what: &str) -> Result<(), Reject> {
    match v {
        Some(s) if s.len() > max => Err(Reject::Unprocessable(format!(
            "{what} of a verified signer is longer than {max} bytes; refusing to store it truncated"
        ))),
        _ => Ok(()),
    }
}

fn cap_signer(
    kind: &mut Option<String>,
    issuer: &mut Option<String>,
    san: &mut Option<String>,
    key_name: &mut Option<String>,
    key_fingerprint: &mut Option<String>,
    key_hint: &mut Option<String>,
    verified: bool,
) -> Result<(), Reject> {
    // A verified identity is matched by trust policies, so it is stored
    // whole or refused: a truncated SAN could match a policy the real one
    // does not.
    if verified {
        too_long(issuer, MAX_URI, "issuer")?;
        too_long(san, MAX_URI, "san")?;
        too_long(key_name, MAX_SHORT, "key_name")?;
        too_long(key_fingerprint, 64, "key_fingerprint")?;
    }
    if let Some(k) = kind.as_deref() {
        if !k.is_empty() && !SIGNER_KINDS.contains(&k) {
            return Err(Reject::Unprocessable(format!(
                "signer_kind must be one of {SIGNER_KINDS:?}"
            )));
        }
    }
    cap(kind, MAX_SHORT);
    cap(issuer, MAX_URI);
    cap(san, MAX_URI);
    cap(key_name, MAX_SHORT);
    cap(key_fingerprint, 64);
    cap(key_hint, MAX_SHORT);
    if !verified {
        *kind = None;
        *issuer = None;
        *san = None;
        *key_name = None;
        *key_fingerprint = None;
    }
    Ok(())
}

pub const SIGNER_KINDS: [&str; 2] = ["keyless", "key"];

/// Refused in every ingested string: control characters, the Unicode
/// line/paragraph separators, and the bidirectional/invisible format
/// controls that make an identity display as something else (U+200E/F,
/// U+202A-E, U+2066-9, U+FEFF). supplychain neutralises the same set.
pub fn refused_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{2028}' | '\u{2029}' | '\u{200E}' | '\u{200F}' | '\u{FEFF}'
        )
        || ('\u{202A}'..='\u{202E}').contains(&c)
        || ('\u{2066}'..='\u{2069}').contains(&c)
}

/// A control character or a Unicode line/paragraph separator (U+2028,
/// U+2029) in any string is refused: these values end up in generated YAML
/// and comments, where one would start a new line, and a truncated or
/// stripped identity must never pass for the real one. supplychain
/// neutralises signer-supplied values before posting, so a refusal here
/// means a broken or hostile client.
fn check_text(p: &AttestationPost) -> Result<(), Reject> {
    fn bad(s: &str) -> bool {
        s.chars().any(refused_char)
    }
    fn opt(v: &Option<String>) -> &str {
        v.as_deref().unwrap_or("")
    }
    let mut fields: Vec<(String, &str)> = vec![
        ("digest".into(), &p.digest),
        ("repository".into(), &p.repository),
        ("reason".into(), opt(&p.reason)),
        ("trust_root".into(), opt(&p.trust_root)),
        ("signed_via".into(), opt(&p.signed_via)),
        ("signed_digest".into(), opt(&p.signed_digest)),
    ];
    for (i, s) in p.signatures.iter().enumerate() {
        for (k, v) in [
            ("format", s.format.as_str()),
            ("source", &s.source),
            ("error", opt(&s.error)),
            ("detail", opt(&s.detail)),
            ("subject", opt(&s.subject)),
            ("signer_kind", opt(&s.signer_kind)),
            ("issuer", opt(&s.issuer)),
            ("san", opt(&s.san)),
            ("key_name", opt(&s.key_name)),
            ("key_fingerprint", opt(&s.key_fingerprint)),
            ("key_hint", opt(&s.key_hint)),
        ] {
            fields.push((format!("signatures[{i}].{k}"), v));
        }
    }
    for (i, a) in p.attestations.iter().enumerate() {
        for (k, v) in [
            ("predicate_type", a.predicate_type.as_str()),
            ("format", &a.format),
            ("source", &a.source),
            ("error", opt(&a.error)),
            ("detail", opt(&a.detail)),
            ("subject", opt(&a.subject)),
            ("payload_sha256", opt(&a.payload_sha256)),
            ("signer_kind", opt(&a.signer_kind)),
            ("issuer", opt(&a.issuer)),
            ("san", opt(&a.san)),
            ("key_name", opt(&a.key_name)),
            ("key_fingerprint", opt(&a.key_fingerprint)),
            ("key_hint", opt(&a.key_hint)),
        ] {
            fields.push((format!("attestations[{i}].{k}"), v));
        }
        if let Some(pr) = &a.provenance {
            for (k, v) in [
                ("builder_id", opt(&pr.builder_id)),
                ("build_type", opt(&pr.build_type)),
                ("source_repo", opt(&pr.source_repo)),
                ("source_commit", opt(&pr.source_commit)),
                ("source_ref", opt(&pr.source_ref)),
            ] {
                fields.push((format!("attestations[{i}].provenance.{k}"), v));
            }
        }
    }
    match fields.into_iter().find(|(_, v)| bad(v)) {
        Some((name, _)) => Err(Reject::Unprocessable(format!(
            "{name} contains a control, line-separator or bidi/format character"
        ))),
        None => Ok(()),
    }
}

/// Parses and validates a body for `path_digest`. Pure: no I/O.
pub fn parse_post(
    path_digest: &str,
    body: &[u8],
    now: DateTime<Utc>,
) -> Result<AttestationPost, Reject> {
    let mut p: AttestationPost = serde_json::from_slice(body).map_err(|e| {
        if e.to_string().contains(TOO_MANY) {
            Reject::TooLarge(format!(
                "at most {MAX_SIGNATURES} signatures and {MAX_ATTESTATIONS} attestations"
            ))
        } else {
            Reject::BadRequest(format!("invalid body: {e}"))
        }
    })?;
    check_text(&p)?;
    if p.schema_version != SCHEMA_VERSION {
        return Err(Reject::Unprocessable(format!(
            "schema_version {} is not supported (want {SCHEMA_VERSION})",
            p.schema_version
        )));
    }
    if p.digest != path_digest {
        return Err(Reject::Unprocessable(
            "body digest does not match the path".into(),
        ));
    }
    if !VERDICTS.contains(&p.verdict.as_str()) {
        return Err(Reject::Unprocessable(format!(
            "verdict must be one of {VERDICTS:?}"
        )));
    }
    if p.checked_at > now + chrono::Duration::seconds(MAX_FUTURE_SKEW_SECS) {
        return Err(Reject::Unprocessable(
            "checked_at is in the future; refusing it so it cannot block newer results".into(),
        ));
    }
    if p.repository.is_empty() || p.repository.len() > MAX_URI {
        return Err(Reject::Unprocessable(
            "repository is empty or too long".into(),
        ));
    }
    let known = |field: String, v: &Option<String>| -> Result<(), Reject> {
        match v.as_deref() {
            Some(r) if !r.is_empty() && !REASONS.contains(&r) => Err(Reject::Unprocessable(
                format!("{field}: {r:?} is not a known reason code"),
            )),
            _ => Ok(()),
        }
    };
    known("reason".into(), &p.reason)?;
    for (i, s) in p.signatures.iter().enumerate() {
        known(format!("signatures[{i}].error"), &s.error)?;
    }
    for (i, a) in p.attestations.iter().enumerate() {
        known(format!("attestations[{i}].error"), &a.error)?;
    }
    for tok in [&p.reason, &p.trust_root, &p.signed_via]
        .into_iter()
        .flatten()
    {
        if !tok.is_empty() && !is_token(tok) {
            return Err(Reject::Unprocessable(format!(
                "{tok:?} is not a valid token"
            )));
        }
    }
    cap(&mut p.reason, MAX_SHORT);
    cap(&mut p.trust_root, MAX_SHORT);
    cap(&mut p.signed_via, MAX_SHORT);
    if let Some(d) = p.signed_digest.as_deref() {
        if !d.is_empty() && !is_valid_digest(d) {
            return Err(Reject::Unprocessable(
                "signed_digest is not a digest".into(),
            ));
        }
    }
    cap(&mut p.signed_digest, MAX_SHORT + 64);
    for s in &mut p.signatures {
        cap_str(&mut s.format, MAX_SHORT);
        cap_str(&mut s.source, MAX_SHORT);
        cap(&mut s.error, MAX_SHORT);
        cap(&mut s.detail, MAX_DETAIL);
        cap(&mut s.subject, MAX_SHORT + 64);
        cap_signer(
            &mut s.signer_kind,
            &mut s.issuer,
            &mut s.san,
            &mut s.key_name,
            &mut s.key_fingerprint,
            &mut s.key_hint,
            s.verified,
        )?;
    }
    for a in &mut p.attestations {
        cap_str(&mut a.predicate_type, MAX_URI);
        cap_str(&mut a.format, MAX_SHORT);
        cap_str(&mut a.source, MAX_SHORT);
        cap(&mut a.error, MAX_SHORT);
        cap(&mut a.detail, MAX_DETAIL);
        cap(&mut a.subject, MAX_SHORT + 64);
        cap(&mut a.payload_sha256, 64);
        cap_signer(
            &mut a.signer_kind,
            &mut a.issuer,
            &mut a.san,
            &mut a.key_name,
            &mut a.key_fingerprint,
            &mut a.key_hint,
            a.verified,
        )?;
        if let (true, Some(pr)) = (a.verified, &a.provenance) {
            // Provenance of a verified attestation is matched by policies
            // too: whole or refused.
            too_long(&pr.builder_id, MAX_URI, "provenance.builder_id")?;
            too_long(&pr.source_repo, MAX_URI, "provenance.source_repo")?;
            too_long(&pr.source_ref, MAX_URI, "provenance.source_ref")?;
        }
        if let Some(pr) = &mut a.provenance {
            cap(&mut pr.builder_id, MAX_URI);
            cap(&mut pr.build_type, MAX_URI);
            cap(&mut pr.source_repo, MAX_URI);
            cap(&mut pr.source_commit, MAX_SHORT);
            cap(&mut pr.source_ref, MAX_URI);
        }
        if !a.verified {
            a.provenance = None; // unverified claims are not shown as facts
        }
    }
    check_verdict(&p)?;
    Ok(p)
}

/// The verdict must agree with the signatures it was derived from.
fn check_verdict(p: &AttestationPost) -> Result<(), Reject> {
    let verified = p.signatures.iter().any(|s| s.verified);
    let untrusted_key = p
        .signatures
        .iter()
        .any(|s| s.error.as_deref() == Some("untrusted_key"));
    let ok = match p.verdict.as_str() {
        "verified" => verified,
        "unsigned" => p.signatures.is_empty(),
        "invalid" => !p.signatures.is_empty() && !verified,
        "key_signed" => untrusted_key && !verified,
        _ => !verified, // unknown
    };
    if ok {
        Ok(())
    } else {
        Err(Reject::Unprocessable(format!(
            "verdict {} does not match the signatures sent",
            p.verdict
        )))
    }
}

/// Result of storing a post.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Stored,
    Unchanged,
    /// An equal or newer result is already stored.
    Stale,
    /// The digest is not in the image inventory.
    UnknownDigest,
}

#[derive(QueryableByName)]
struct Existing {
    #[diesel(sql_type = Timestamp)]
    checked_at: NaiveDateTime,
    #[diesel(sql_type = Bool)]
    same: bool,
}

#[derive(QueryableByName)]
struct Found {
    #[diesel(sql_type = Bool)]
    found: bool,
}

const EXISTING_SQL: &str = "SELECT checked_at, \
    (repository = $2 AND verdict = $3 AND reason IS NOT DISTINCT FROM $4 \
     AND trust_root IS NOT DISTINCT FROM $5 AND signed_via IS NOT DISTINCT FROM $6 \
     AND signed_digest IS NOT DISTINCT FROM $7 AND signatures = $8 AND attestations = $9) AS same \
    FROM image_attestations WHERE digest = $1 FOR UPDATE";

const UPSERT_SQL: &str = "INSERT INTO image_attestations \
    (digest, repository, verdict, reason, trust_root, signed_via, signed_digest, signatures, attestations, checked_at, received_at) \
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, timezone('UTC', NOW())) \
    ON CONFLICT (digest) DO UPDATE SET repository = EXCLUDED.repository, verdict = EXCLUDED.verdict, \
    reason = EXCLUDED.reason, trust_root = EXCLUDED.trust_root, signed_via = EXCLUDED.signed_via, \
    signed_digest = EXCLUDED.signed_digest, signatures = EXCLUDED.signatures, \
    attestations = EXCLUDED.attestations, checked_at = EXCLUDED.checked_at, received_at = EXCLUDED.received_at";

/// Stores `p` under the replacement rules (module docs).
pub fn store(conn: &mut PgConnection, p: &AttestationPost) -> Result<Outcome, DbError> {
    let sigs = serde_json::to_value(&p.signatures)?;
    let atts = serde_json::to_value(&p.attestations)?;
    let checked = p.checked_at.naive_utc();
    conn.transaction::<Outcome, DbError, _>(|conn| {
        let known: Found =
            sql_query("SELECT EXISTS (SELECT 1 FROM images WHERE digest = $1) AS found")
                .bind::<Text, _>(&p.digest)
                .get_result(conn)?;
        if !known.found {
            return Ok(Outcome::UnknownDigest);
        }
        let existing: Option<Existing> = sql_query(EXISTING_SQL)
            .bind::<Text, _>(&p.digest)
            .bind::<Text, _>(&p.repository)
            .bind::<Text, _>(&p.verdict)
            .bind::<Nullable<Text>, _>(&p.reason)
            .bind::<Nullable<Text>, _>(&p.trust_root)
            .bind::<Nullable<Text>, _>(&p.signed_via)
            .bind::<Nullable<Text>, _>(&p.signed_digest)
            .bind::<Jsonb, _>(&sigs)
            .bind::<Jsonb, _>(&atts)
            .get_result(conn)
            .optional()?;
        if let Some(e) = existing {
            if checked < e.checked_at {
                return Ok(Outcome::Stale);
            }
            if checked == e.checked_at {
                return Ok(if e.same {
                    Outcome::Unchanged
                } else {
                    Outcome::Stale
                });
            }
        }
        sql_query(UPSERT_SQL)
            .bind::<Text, _>(&p.digest)
            .bind::<Text, _>(&p.repository)
            .bind::<Text, _>(&p.verdict)
            .bind::<Nullable<Text>, _>(&p.reason)
            .bind::<Nullable<Text>, _>(&p.trust_root)
            .bind::<Nullable<Text>, _>(&p.signed_via)
            .bind::<Nullable<Text>, _>(&p.signed_digest)
            .bind::<Jsonb, _>(&sigs)
            .bind::<Jsonb, _>(&atts)
            .bind::<Timestamp, _>(checked)
            .execute(conn)?;
        Ok(Outcome::Stored)
    })
}

/// Reads the body under the deadline and the size cap.
async fn read_body(payload: web::Payload) -> Result<web::Bytes, Box<HttpResponse>> {
    // Boxed: HttpResponse is large (clippy::result_large_err).
    let resp =
        match tokio::time::timeout(BODY_DEADLINE, payload.to_bytes_limited(MAX_BODY_BYTES)).await {
            Err(_) => HttpResponse::RequestTimeout().body("body not received in time"),
            Ok(Err(_)) => {
                HttpResponse::PayloadTooLarge().body(format!("body exceeds {MAX_BODY_BYTES} bytes"))
            }
            Ok(Ok(Err(e))) => HttpResponse::BadRequest().body(format!("reading body: {e}")),
            Ok(Ok(Ok(b))) => return Ok(b),
        };
    Err(Box::new(resp))
}

/// `POST /images/{digest}/attestation`, registered by [`attestation_resource`] so the
/// raw payload (not the app-wide JSON extractor) is read.
async fn post_attestation(
    req: HttpRequest,
    path: web::Path<String>,
    payload: web::Payload,
) -> HttpResponse {
    if !crate::supplychain::ingest_allowed(
        req.app_data::<web::Data<crate::auth::AuthConfig>>()
            .map(|d| d.get_ref()),
    ) {
        return HttpResponse::Forbidden().body(
            "attestation ingest requires scoped broker auth: set BROKER_TOKEN_SUPPLYCHAIN \
             (chart: broker.auth) and give the supplychain component that token",
        );
    }
    let digest = path.into_inner();
    if !is_valid_digest(&digest) {
        return HttpResponse::BadRequest()
            .body("digest must be sha256:<64 hex> or sha512:<128 hex>");
    }
    if let Some(enc) = req.headers().get(header::CONTENT_ENCODING) {
        let enc = enc.to_str().unwrap_or("").trim().to_ascii_lowercase();
        if !enc.is_empty() && enc != "identity" {
            return HttpResponse::UnsupportedMediaType()
                .body("send plain JSON (no Content-Encoding)");
        }
    }
    if let Some(len) = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
    {
        if len > MAX_BODY_BYTES {
            return HttpResponse::PayloadTooLarge()
                .body(format!("body exceeds {MAX_BODY_BYTES} bytes"));
        }
    }
    let body = match read_body(payload).await {
        Ok(b) => b,
        Err(resp) => return *resp,
    };
    let post = match parse_post(&digest, &body, Utc::now()) {
        Ok(p) => p,
        Err(r) => return r.into_response(),
    };
    drop(body);
    let Some(pool) = req.app_data::<web::Data<DbPool>>().cloned() else {
        return HttpResponse::InternalServerError().finish();
    };
    let res = web::block(move || {
        let mut conn = pool.get()?;
        store(&mut conn, &post)
    })
    .await;
    match res {
        Ok(Ok(Outcome::Stored)) => HttpResponse::Created().finish(),
        Ok(Ok(Outcome::Unchanged)) => HttpResponse::Ok().finish(),
        Ok(Ok(Outcome::Stale)) => HttpResponse::Conflict()
            .body("an equal or newer result for this digest is already stored"),
        Ok(Ok(Outcome::UnknownDigest)) => {
            HttpResponse::NotFound().body("digest is not in the image inventory")
        }
        Ok(Err(e)) => {
            warn!(error = %e, "attestation store failed");
            HttpResponse::InternalServerError().finish()
        }
        Err(e) => {
            warn!(error = %e, "attestation store task failed");
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// The POST resource, with the authorize wrap on it like every route.
pub fn attestation_resource() -> impl actix_web::dev::HttpServiceFactory {
    web::resource("/images/{digest}/attestation")
        .wrap(actix_web::middleware::from_fn(crate::auth::authorize))
        .app_data(web::PayloadConfig::new(MAX_BODY_BYTES))
        .route(web::post().to(post_attestation))
        .route(web::get().to(get_attestation))
}

// ---------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------

/// Per stored row: two bounded jsonb lists (≤ 96 entries of ≤ ~2 KiB after
/// the caps above), charged generously.
/// A stored row is at most one accepted body; serialised it can be larger
/// (camelCase keys, escaping), so twice the body cap.
pub const ATTESTATION_ROW_COST_BYTES: u64 = 2 * MAX_BODY_BYTES as u64;
/// Per summary row on `GET /attestations`.
/// Measured against the largest possible summary row (each identity
/// string and the repository cut to [`SUMMARY_TEXT_BYTES`]);
/// `live_summary_cost_covers_the_largest_row` checks it.
pub const ATTESTATION_SUMMARY_COST_BYTES: u64 = 24 * 1024;
pub const ATTESTATIONS_DEFAULT_LIMIT: i64 = 100;
pub const ATTESTATIONS_MAX_LIMIT: i64 = 500;

#[derive(Debug, QueryableByName, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredAttestation {
    #[diesel(sql_type = Text)]
    pub digest: String,
    #[diesel(sql_type = Text)]
    pub repository: String,
    #[diesel(sql_type = Text)]
    pub verdict: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub reason: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub trust_root: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub signed_via: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub signed_digest: Option<String>,
    #[diesel(sql_type = Jsonb)]
    pub signatures: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    pub attestations: serde_json::Value,
    #[diesel(sql_type = Timestamp)]
    pub checked_at: NaiveDateTime,
    #[diesel(sql_type = Timestamp)]
    pub received_at: NaiveDateTime,
}

pub fn load_one(
    conn: &mut PgConnection,
    digest: &str,
) -> Result<Option<StoredAttestation>, DbError> {
    Ok(sql_query(
        "SELECT digest, repository, verdict, reason, trust_root, signed_via, signed_digest, \
         signatures, attestations, checked_at, received_at FROM image_attestations WHERE digest = $1",
    )
    .bind::<Text, _>(digest)
    .get_result(conn)
    .optional()?)
}

async fn get_attestation(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    path: web::Path<String>,
) -> actix_web::Result<HttpResponse> {
    let digest = path.into_inner();
    if !is_valid_digest(&digest) {
        return Ok(
            HttpResponse::BadRequest().body("digest must be sha256:<64 hex> or sha512:<128 hex>")
        );
    }
    let _permit = match budget
        .acquire(cost_kib(1, ATTESTATION_ROW_COST_BYTES))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let row = web::block(move || {
        let mut conn = pool.get()?;
        load_one(&mut conn, &digest)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(match row {
        Some(r) => HttpResponse::Ok().json(r),
        None => HttpResponse::NotFound().body("No data found"),
    })
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub verdict: Option<String>,
    pub repository: Option<String>,
    pub limit: Option<i64>,
    pub after: Option<String>,
}

#[derive(Debug, QueryableByName, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationSummary {
    #[diesel(sql_type = Text)]
    pub digest: String,
    #[diesel(sql_type = Text)]
    pub repository: String,
    #[diesel(sql_type = Text)]
    pub verdict: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub reason: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub signed_via: Option<String>,
    /// Distinct verified signers, at most 8: `{kind: "keyless", issuer,
    /// san}` or `{kind: "key", keyName, keyFingerprint}`.
    #[diesel(sql_type = Jsonb)]
    pub signers: serde_json::Value,
    /// Distinct predicate types of verified attestations, at most 16.
    #[diesel(sql_type = Jsonb)]
    pub verified_predicates: serde_json::Value,
    #[diesel(sql_type = Timestamp)]
    pub checked_at: NaiveDateTime,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SummaryPage {
    pub items: Vec<AttestationSummary>,
    pub next_after: Option<String>,
}

const LIST_SQL: &str = "SELECT a.digest, a.repository, a.verdict, a.reason, a.signed_via, \
    COALESCE((SELECT jsonb_agg(x) FROM (SELECT DISTINCT jsonb_strip_nulls(jsonb_build_object(\
            'kind', COALESCE(s->>'signerKind', 'keyless'), 'issuer', left(s->>'issuer', 256), 'san', left(s->>'san', 256), \
            'keyName', s->>'keyName', 'keyFingerprint', s->>'keyFingerprint')) AS x \
        FROM jsonb_array_elements(a.signatures) s WHERE (s->>'verified')::boolean LIMIT 8) q), '[]'::jsonb) AS signers, \
    COALESCE((SELECT jsonb_agg(x) FROM (SELECT DISTINCT left(e->>'predicateType', 256) AS x \
        FROM jsonb_array_elements(a.attestations) e WHERE (e->>'verified')::boolean LIMIT 16) q), '[]'::jsonb) AS verified_predicates, \
    a.checked_at \
    FROM image_attestations a \
    WHERE ($1::text IS NULL OR a.digest > $1) \
      AND ($2::text IS NULL OR a.verdict = $2) \
      AND ($3::text IS NULL OR a.repository = $3) \
    ORDER BY a.digest LIMIT $4";

pub fn list(
    conn: &mut PgConnection,
    after: Option<&str>,
    verdict: Option<&str>,
    repository: Option<&str>,
    limit: i64,
) -> Result<SummaryPage, DbError> {
    let mut items: Vec<AttestationSummary> = sql_query(LIST_SQL)
        .bind::<Nullable<Text>, _>(after)
        .bind::<Nullable<Text>, _>(verdict)
        .bind::<Nullable<Text>, _>(repository)
        .bind::<BigInt, _>(limit + 1)
        .load(conn)?;
    let next_after = if items.len() as i64 > limit {
        items.truncate(limit as usize);
        items.last().map(|i| i.digest.clone())
    } else {
        None
    };
    for i in &mut items {
        truncate_bytes(&mut i.repository, SUMMARY_TEXT_BYTES);
        truncate_json_strings(&mut i.signers, SUMMARY_TEXT_BYTES);
        truncate_json_strings(&mut i.verified_predicates, SUMMARY_TEXT_BYTES);
    }
    Ok(SummaryPage { items, next_after })
}

/// Bytes of a repository, issuer, SAN or predicate type shown in a
/// summary. The SQL cuts at 256 characters (which bounds what is fetched);
/// this cuts at 256 bytes, on a character boundary, which bounds what is
/// served whatever the script.
pub const SUMMARY_TEXT_BYTES: usize = 256;

/// Truncates to at most `max` bytes without splitting a UTF-8 sequence.
pub fn truncate_bytes(s: &mut String, max: usize) {
    if s.len() <= max {
        return;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
}

fn truncate_json_strings(v: &mut serde_json::Value, max: usize) {
    match v {
        serde_json::Value::String(s) => truncate_bytes(s, max),
        serde_json::Value::Array(a) => a.iter_mut().for_each(|x| truncate_json_strings(x, max)),
        serde_json::Value::Object(o) => o.values_mut().for_each(|x| truncate_json_strings(x, max)),
        _ => {}
    }
}

fn non_empty(s: Option<String>) -> Option<String> {
    s.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

#[get(
    "/attestations",
    wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"
)]
pub async fn get_attestations(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    query: web::Query<ListQuery>,
) -> actix_web::Result<impl Responder> {
    let q = query.into_inner();
    let limit = q
        .limit
        .unwrap_or(ATTESTATIONS_DEFAULT_LIMIT)
        .clamp(1, ATTESTATIONS_MAX_LIMIT);
    let after = non_empty(q.after);
    if let Some(a) = after.as_deref() {
        if !is_valid_digest(a) {
            return Ok(HttpResponse::BadRequest().body("after must be a digest (sha256:<hex>)"));
        }
    }
    let verdict = non_empty(q.verdict);
    if let Some(v) = verdict.as_deref() {
        if !VERDICTS.contains(&v) {
            return Ok(
                HttpResponse::BadRequest().body(format!("verdict must be one of {VERDICTS:?}"))
            );
        }
    }
    let repository = non_empty(q.repository);
    let _permit = match budget
        .acquire(cost_kib(limit + 1, ATTESTATION_SUMMARY_COST_BYTES))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let page = web::block(move || {
        let mut conn = pool.get()?;
        list(
            &mut conn,
            after.as_deref(),
            verdict.as_deref(),
            repository.as_deref(),
            limit,
        )
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().json(page))
}

// ---------------------------------------------------------------------
// Retention
// ---------------------------------------------------------------------

const DEFAULT_RETENTION_DAYS: u32 = 7;
const RETENTION_BATCH: i64 = 5_000;
const RETENTION_MAX_BATCHES: usize = 20;

/// Rows whose digest left the inventory, or (when `$1 > 0`) not
/// re-checked within `$1` days.
pub(crate) const PRUNE_SQL: &str = "WITH expired AS (\
     SELECT a.digest FROM image_attestations a \
     WHERE NOT EXISTS (SELECT 1 FROM images i WHERE i.digest = a.digest) \
        OR ($1 > 0 AND a.checked_at < timezone('UTC', NOW()) - make_interval(days => $1)) \
     ORDER BY a.checked_at LIMIT $2) \
     DELETE FROM image_attestations WHERE digest IN (SELECT digest FROM expired)";

fn retention_days() -> u32 {
    std::env::var("IMAGE_ATTESTATION_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(DEFAULT_RETENTION_DAYS)
}

/// One bounded prune pass; returns rows deleted.
pub fn prune(conn: &mut PgConnection, days: u32) -> Result<usize, DbError> {
    let mut total = 0;
    for _ in 0..RETENTION_MAX_BATCHES {
        let n = sql_query(PRUNE_SQL)
            .bind::<diesel::sql_types::Integer, _>(days as i32)
            .bind::<BigInt, _>(RETENTION_BATCH)
            .execute(conn)?;
        total += n;
        if (n as i64) < RETENTION_BATCH {
            break;
        }
    }
    Ok(total)
}

/// Hourly prune: results for digests no longer in the inventory, and
/// results not re-checked within `IMAGE_ATTESTATION_RETENTION_DAYS` (0
/// keeps those).
pub fn spawn_retention(pool: DbPool) {
    let days = retention_days();
    info!(
        days,
        "image attestation retention scheduled (days=0 keeps unchecked results)"
    );
    actix_web::rt::spawn(async move {
        tokio::time::sleep(Duration::from_secs(180)).await;
        loop {
            let p = pool.clone();
            match web::block(move || -> Result<usize, DbError> {
                let mut conn = p.get()?;
                prune(&mut conn, days)
            })
            .await
            {
                Ok(Ok(n)) if n > 0 => info!(rows = n, "image attestation retention pruned rows"),
                Ok(Ok(_)) => {}
                Ok(Err(e)) => warn!(error = %e, "image attestation retention failed"),
                Err(e) => warn!(error = %e, "image attestation retention task failed"),
            }
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });
}

#[cfg(test)]
#[path = "attestation_tests.rs"]
mod tests;
