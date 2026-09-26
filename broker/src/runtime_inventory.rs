//! Runtime executable and shared-library inventory: which files each
//! workload container actually executes and maps (#1533 P1-2).
//!
//! # Where the data comes from
//!
//! The controller watches execve and shared-library mmaps per container
//! and posts the DISTINCT (container, digest, kind, path) set it has seen
//! to `POST /runtime/executables`, plus a one-off `/proc` backfill for
//! processes already running when it started (`source = backfill`). The
//! broker never sees individual events, so the table grows with what a
//! workload runs, not with how often it runs it.
//!
//! # Shape and bounds
//!
//! - `runtime_executables`: one row per (cluster, namespace, kind, name,
//!   container, digest, kind, path). The workload key is the one
//!   `workload_containers` uses (the controller's owner-ref resolution;
//!   an ownerless pod is `("Pod", pod_name)`). The digest is in the key
//!   because the same path under a new image is a different file; `''`
//!   means the controller could not resolve it.
//! - Ingest is lenient per entry (a bad entry is dropped and counted,
//!   never fails the batch) and strict per batch: more than
//!   [`MAX_BATCH_ENTRIES`] entries is a 413 and nothing is written, so a
//!   controller that forgot to chunk finds out instead of silently losing
//!   the tail of every batch.
//! - Re-posts are cheap: the upsert's `WHERE` skips the write unless
//!   `last_seen` moved by at least [`REFRESH_SECS`] or the row gained
//!   something (an earlier `first_seen`, an eBPF sighting of a backfilled
//!   path, a complete path).
//! - Retention (`retention.rs`, "Runtime inventory") prunes rows not seen
//!   within `RUNTIME_INVENTORY_RETENTION_DAYS`.

use crate::image_inventory::{is_valid_digest, DEFAULT_CLUSTER_ID, REFRESH_SECS};
use crate::read_budget::{cost_kib, ReadBudget};
use actix_web::{get, web, HttpResponse, Responder};
use chrono::NaiveDateTime;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use diesel::sql_query;
use diesel::sql_types::{Array, BigInt, Bool, Double, Nullable, Text, Timestamp};
use serde::de::Visitor;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
type DbError = Box<dyn std::error::Error + Send + Sync>;

/// Entries accepted in one post, enforced WHILE parsing: the element
/// after the cap aborts the parse with a 413 before anything is built
/// from it. A byte limit alone does not bound parsed objects (#1671: a
/// 64 KB gzip body inflated to millions of tiny structs, 720 MB RSS).
pub const MAX_BATCH_ENTRIES: usize = 5_000;
/// Body limit for the ingest route, applied after any Content-Encoding
/// is decoded. A controller entry is ~350 bytes (paths up to its 1 KiB
/// kernel buffer), so a full 5 000-entry batch is ~2 MB and 8 MiB leaves
/// room for long paths. It does not fit 5 000 entries with every field
/// at its cap (~30 MB): such a batch must be chunked smaller, and the
/// 413 says so. `tests/runtime_inventory_memory.rs` measures the peak.
pub const RUNTIME_BODY_LIMIT_BYTES: usize = 8 << 20;
/// Longest path accepted: Linux `PATH_MAX`.
pub const MAX_PATH_LEN: usize = 4096;
/// Longest Kubernetes object name (DNS subdomain).
const MAX_NAME_LEN: usize = 253;
/// Longest workload kind (a Kubernetes kind is a short CamelCase word).
const MAX_KIND_LEN: usize = 63;
/// `sha512:` + 128 hex.
const MAX_DIGEST_LEN: usize = 135;
/// `kind`, `source`.
const MAX_ENUM_LEN: usize = 16;
/// An ISO 8601 timestamp with nanoseconds is 29 bytes.
const MAX_TS_LEN: usize = 64;
/// Longest object key read; longer keys are unknown fields anyway.
const MAX_KEY_LEN: usize = 32;
/// Rows per INSERT. The insert binds one array per column, so this is not
/// a bind-count limit; it keeps each statement's lock set and WAL burst
/// small on a full batch.
const UPSERT_CHUNK: usize = 1_000;

const KINDS: [&str; 2] = ["exec", "lib"];
const SOURCES: [&str; 2] = ["ebpf", "backfill"];

/// Where a file lived when it ran, least to most suspicious (controller
/// `runtime_inventory::Origin`). When sightings of one row disagree the
/// most suspicious wins and is never downgraded: a replica that ran the
/// file from its writable layer is the drift finding, whatever the others
/// did. `unknown` = not determined (a `/proc` backfill, or a controller
/// that does not send it).
pub const ORIGINS: [&str; 6] = [
    "unknown",
    "image",
    "otherFs",
    "deleted",
    "writableLayer",
    "memfd",
];

/// Origins that mean "the image did not ship this file as it ran": the
/// input P2-5 drift reads through [`workload_unshipped_executables`].
pub const UNSHIPPED_ORIGINS: [&str; 3] = ["deleted", "writableLayer", "memfd"];

/// Rank of an origin in [`ORIGINS`]; an unrecognised value ranks as
/// `unknown`.
pub fn origin_rank(o: &str) -> usize {
    ORIGINS.iter().position(|x| *x == o).unwrap_or(0)
}

/// The SQL twin of [`origin_rank`], for `ON CONFLICT` and aggregates.
/// Kept in sync with [`ORIGINS`] by a test.
const ORIGIN_ARRAY_SQL: &str =
    "ARRAY['unknown','image','otherFs','deleted','writableLayer','memfd']::text[]";

// ---------------------------------------------------------------------
// Ingest: bounded, lenient parsing
// ---------------------------------------------------------------------
//
// The body is parsed straight into bounded fields, never into
// `serde_json::Value`: a Value would build whatever the body describes
// (an object with a million keys, a deeply nested array) before
// validation could look at it. Here a string over its field's cap is
// never copied, anything that is not the expected scalar is skipped with
// `IgnoredAny` (which allocates nothing), unknown keys are skipped the
// same way, and the number of entries is capped while parsing. A
// malformed ENTRY becomes `None` and is dropped and counted; only a body
// that is not a JSON array at all fails the request.

/// One posted field. `Bad` (wrong type, or a string over its cap) is
/// kept apart from `Absent` (missing or null) so an optional field that
/// was SENT wrong drops the entry instead of reading as "not sent": an
/// over-long digest must not become "digest unknown".
#[derive(Debug, Default, Clone, PartialEq)]
pub enum Field<T> {
    #[default]
    Absent,
    Val(T),
    Bad,
}

impl<T> Field<T> {
    /// The value, or `Err` when it was sent wrong.
    fn optional(self) -> Result<Option<T>, ()> {
        match self {
            Field::Absent => Ok(None),
            Field::Val(v) => Ok(Some(v)),
            Field::Bad => Err(()),
        }
    }

    fn required(self) -> Option<T> {
        self.optional().ok().flatten()
    }
}

/// A string field capped at `N` bytes; a longer one is never copied.
struct Str<const N: usize>(Field<String>);

impl<'de, const N: usize> Deserialize<'de> for Str<N> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Str(match d.deserialize_any(ScalarVisitor::<N>)? {
            Scalar::Str(Some(s)) => Field::Val(s),
            Scalar::Null => Field::Absent,
            _ => Field::Bad,
        }))
    }
}

struct Flag(Field<bool>);

impl<'de> Deserialize<'de> for Flag {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Flag(match d.deserialize_any(ScalarVisitor::<0>)? {
            Scalar::Bool(b) => Field::Val(b),
            Scalar::Null => Field::Absent,
            _ => Field::Bad,
        }))
    }
}

enum Scalar {
    /// `None` when over the cap: the string is never copied.
    Str(Option<String>),
    Bool(bool),
    Null,
    Other,
}

/// Reads any JSON value as a [`Scalar`], copying a string only when it
/// fits in `N` bytes and draining containers without building them.
struct ScalarVisitor<const N: usize>;

impl<'de, const N: usize> Visitor<'de> for ScalarVisitor<N> {
    type Value = Scalar;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("any JSON value")
    }
    fn visit_str<E>(self, s: &str) -> Result<Scalar, E> {
        Ok(Scalar::Str((s.len() <= N).then(|| s.to_string())))
    }
    fn visit_bool<E>(self, b: bool) -> Result<Scalar, E> {
        Ok(Scalar::Bool(b))
    }
    fn visit_i64<E>(self, _: i64) -> Result<Scalar, E> {
        Ok(Scalar::Other)
    }
    fn visit_u64<E>(self, _: u64) -> Result<Scalar, E> {
        Ok(Scalar::Other)
    }
    fn visit_f64<E>(self, _: f64) -> Result<Scalar, E> {
        Ok(Scalar::Other)
    }
    fn visit_unit<E>(self) -> Result<Scalar, E> {
        Ok(Scalar::Null)
    }
    fn visit_none<E>(self) -> Result<Scalar, E> {
        Ok(Scalar::Null)
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A) -> Result<Scalar, A::Error> {
        while a.next_element::<serde::de::IgnoredAny>()?.is_some() {}
        Ok(Scalar::Other)
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut a: A) -> Result<Scalar, A::Error> {
        while a
            .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
            .is_some()
        {}
        Ok(Scalar::Other)
    }
}

/// One posted entry (controller `runtime_inventory::RuntimeExecutablePost`),
/// every field already capped. Validation is [`row_from_entry`].
#[derive(Debug, Default, Clone)]
pub struct RawEntry {
    pub pod_namespace: Field<String>,
    pub pod_name: Field<String>,
    pub workload_kind: Field<String>,
    pub workload_name: Field<String>,
    pub container_name: Field<String>,
    pub image_digest: Field<String>,
    pub kind: Field<String>,
    pub path: Field<String>,
    pub path_complete: Field<bool>,
    pub source: Field<String>,
    pub origin: Field<String>,
    pub first_seen: Field<String>,
    pub last_seen: Field<String>,
}

/// One array element: `Some` for an object, `None` for anything else.
struct Elem(Option<RawEntry>);

impl<'de> Deserialize<'de> for Elem {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Elem;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a runtime inventory entry")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut m: A) -> Result<Elem, A::Error> {
                let mut e = RawEntry::default();
                while let Some(Str(key)) = m.next_key::<Str<MAX_KEY_LEN>>()? {
                    let s = |v: Field<String>, slot: &mut Field<String>| *slot = v;
                    let key = match &key {
                        Field::Val(k) => Some(k.as_str()),
                        _ => None,
                    };
                    match key {
                        Some("pod_namespace") => {
                            s(m.next_value::<Str<MAX_NAME_LEN>>()?.0, &mut e.pod_namespace)
                        }
                        Some("pod_name") => {
                            s(m.next_value::<Str<MAX_NAME_LEN>>()?.0, &mut e.pod_name)
                        }
                        Some("workload_kind") => {
                            s(m.next_value::<Str<MAX_KIND_LEN>>()?.0, &mut e.workload_kind)
                        }
                        Some("workload_name") => {
                            s(m.next_value::<Str<MAX_NAME_LEN>>()?.0, &mut e.workload_name)
                        }
                        Some("container_name") => s(
                            m.next_value::<Str<MAX_NAME_LEN>>()?.0,
                            &mut e.container_name,
                        ),
                        Some("image_digest") => s(
                            m.next_value::<Str<MAX_DIGEST_LEN>>()?.0,
                            &mut e.image_digest,
                        ),
                        Some("kind") => s(m.next_value::<Str<MAX_ENUM_LEN>>()?.0, &mut e.kind),
                        Some("path") => s(m.next_value::<Str<MAX_PATH_LEN>>()?.0, &mut e.path),
                        Some("path_complete") => e.path_complete = m.next_value::<Flag>()?.0,
                        Some("source") => s(m.next_value::<Str<MAX_ENUM_LEN>>()?.0, &mut e.source),
                        Some("origin") => s(m.next_value::<Str<MAX_ENUM_LEN>>()?.0, &mut e.origin),
                        Some("first_seen") => {
                            s(m.next_value::<Str<MAX_TS_LEN>>()?.0, &mut e.first_seen)
                        }
                        Some("last_seen") => {
                            s(m.next_value::<Str<MAX_TS_LEN>>()?.0, &mut e.last_seen)
                        }
                        _ => {
                            m.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(Elem(Some(e)))
            }
        }
        // Anything but an object is drained by the scalar visitor and
        // becomes a dropped entry.
        struct Either;
        impl<'de> serde::de::Visitor<'de> for Either {
            type Value = Elem;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a runtime inventory entry")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, m: A) -> Result<Elem, A::Error> {
                V.visit_map(m)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, a: A) -> Result<Elem, A::Error> {
                ScalarVisitor::<0>.visit_seq(a).map(|_| Elem(None))
            }
            fn visit_str<E>(self, _: &str) -> Result<Elem, E> {
                Ok(Elem(None))
            }
            fn visit_bool<E>(self, _: bool) -> Result<Elem, E> {
                Ok(Elem(None))
            }
            fn visit_i64<E>(self, _: i64) -> Result<Elem, E> {
                Ok(Elem(None))
            }
            fn visit_u64<E>(self, _: u64) -> Result<Elem, E> {
                Ok(Elem(None))
            }
            fn visit_f64<E>(self, _: f64) -> Result<Elem, E> {
                Ok(Elem(None))
            }
            fn visit_unit<E>(self) -> Result<Elem, E> {
                Ok(Elem(None))
            }
        }
        d.deserialize_any(Either)
    }
}

/// The top-level array, capped at [`MAX_BATCH_ENTRIES`] while parsing.
struct Entries(Vec<Option<RawEntry>>);

/// Marker in the parse error for a batch over the cap; mapped to 413.
const TOO_MANY_ENTRIES: &str = "too many entries";

impl<'de> Deserialize<'de> for Entries {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Entries;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a JSON array of at most {MAX_BATCH_ENTRIES} entries")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> Result<Entries, A::Error> {
                // Never trust the size hint for the allocation.
                let mut out = Vec::with_capacity(a.size_hint().unwrap_or(0).min(1024));
                loop {
                    if out.len() == MAX_BATCH_ENTRIES {
                        // One more element of any shape is refused
                        // without being built.
                        if a.next_element::<serde::de::IgnoredAny>()?.is_some() {
                            return Err(serde::de::Error::custom(TOO_MANY_ENTRIES));
                        }
                        return Ok(Entries(out));
                    }
                    match a.next_element::<Elem>()? {
                        Some(Elem(e)) => out.push(e),
                        None => return Ok(Entries(out)),
                    }
                }
            }
        }
        d.deserialize_seq(V)
    }
}

/// Why a body was refused as a whole.
#[derive(Debug, PartialEq)]
pub enum PrepareError {
    /// More than [`MAX_BATCH_ENTRIES`] entries: 413.
    TooMany,
    /// Not a JSON array: 400.
    Malformed(String),
}

/// One validated row, ready to upsert.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeRow {
    pub namespace: String,
    pub workload_kind: String,
    pub workload_name: String,
    pub container_name: String,
    /// `""` when unknown.
    pub image_digest: String,
    pub kind: String,
    pub path: String,
    pub path_complete: bool,
    pub source: String,
    /// One of [`ORIGINS`].
    pub origin: String,
    pub last_pod_name: Option<String>,
    pub first_seen: NaiveDateTime,
    pub last_seen: NaiveDateTime,
}

type RowKey<'a> = (
    &'a str,
    &'a str,
    &'a str,
    &'a str,
    &'a str,
    &'a str,
    &'a str,
);

impl RuntimeRow {
    /// Borrowed, so deduplicating a batch copies no strings.
    fn key(&self) -> RowKey<'_> {
        (
            &self.namespace,
            &self.workload_kind,
            &self.workload_name,
            &self.container_name,
            &self.image_digest,
            &self.kind,
            &self.path,
        )
    }

    /// Fold a second sighting of the same key into this one, with the
    /// same rules as the upsert. Needed because one INSERT ... ON CONFLICT
    /// may not touch a row twice.
    fn merge(&mut self, o: RuntimeRow) {
        self.first_seen = self.first_seen.min(o.first_seen);
        if o.last_seen >= self.last_seen && o.last_pod_name.is_some() {
            self.last_pod_name = o.last_pod_name;
        }
        self.last_seen = self.last_seen.max(o.last_seen);
        if o.source == "ebpf" {
            self.source = o.source;
        }
        self.path_complete |= o.path_complete;
        if origin_rank(&o.origin) > origin_rank(&self.origin) {
            self.origin = o.origin;
        }
    }
}

/// Trimmed, non-empty, within `max`, and free of NUL (Postgres text
/// cannot hold one; a single NUL would fail the whole chunk).
fn bounded(s: &str, max: usize) -> Option<String> {
    let s = s.trim();
    (!s.is_empty() && s.len() <= max && !s.contains('\0')).then(|| s.to_string())
}

/// Validate and normalise one entry. `None` = drop it.
///
/// The path is kept byte-for-byte (not trimmed): it is a key the SBOM
/// join matches exactly, and a file name may legitimately end in a space.
pub fn row_from_entry(e: RawEntry) -> Option<RuntimeRow> {
    let namespace = bounded(&e.pod_namespace.required()?, MAX_NAME_LEN)?;
    let container_name = bounded(&e.container_name.required()?, MAX_NAME_LEN)?;
    // Optional fields: absent is fine, sent wrong drops the entry.
    let pod_name = e
        .pod_name
        .optional()
        .ok()?
        .and_then(|p| bounded(&p, MAX_NAME_LEN));
    let workload_kind = e.workload_kind.optional().ok()?;
    let workload_name = e.workload_name.optional().ok()?;
    let (workload_kind, workload_name) = match (
        workload_kind.and_then(|k| bounded(&k, MAX_KIND_LEN)),
        workload_name.and_then(|n| bounded(&n, MAX_NAME_LEN)),
    ) {
        (Some(k), Some(n)) => (k, n),
        // Same fallback as the image inventory: an ownerless pod is its
        // own workload.
        (None, None) => ("Pod".to_string(), pod_name.clone()?),
        _ => return None,
    };
    let kind = e.kind.required()?.trim().to_ascii_lowercase();
    if !KINDS.contains(&kind.as_str()) {
        return None;
    }
    let source = e.source.required()?.trim().to_ascii_lowercase();
    if !SOURCES.contains(&source.as_str()) {
        return None;
    }
    let path = e.path.required()?;
    if path.is_empty() || path.len() > MAX_PATH_LEN || path.contains('\0') {
        return None;
    }
    let image_digest = e
        .image_digest
        .optional()
        .ok()?
        .unwrap_or_default()
        .trim()
        .to_string();
    if !image_digest.is_empty() && !is_valid_digest(&image_digest) {
        return None;
    }
    let path_complete = e.path_complete.optional().ok()?.unwrap_or(true);
    // Absent (an older controller) or a value this broker does not know
    // (a newer one) is `unknown`; sent as the wrong type drops the entry.
    let origin = e
        .origin
        .optional()
        .ok()?
        .map(|o| o.trim().to_string())
        .filter(|o| ORIGINS.contains(&o.as_str()))
        .unwrap_or_else(|| "unknown".to_string());
    // chrono's serde format for NaiveDateTime, which the controller posts.
    let ts = |s: Field<String>| s.required()?.trim().parse::<NaiveDateTime>().ok();
    let (first, last) = (ts(e.first_seen)?, ts(e.last_seen)?);
    // A reversed pair is a controller bug, not a reason to lose the path.
    let (first_seen, last_seen) = if first <= last {
        (first, last)
    } else {
        (last, first)
    };
    Some(RuntimeRow {
        namespace,
        workload_kind,
        workload_name,
        container_name,
        image_digest,
        kind,
        path,
        path_complete,
        source,
        origin,
        last_pod_name: pod_name,
        first_seen,
        last_seen,
    })
}

/// A parsed batch: rows merged per key, and how many entries were dropped.
#[derive(Debug, Default, PartialEq)]
pub struct Batch {
    pub rows: Vec<RuntimeRow>,
    pub dropped: usize,
}

/// Parse, validate and deduplicate a posted body. Pure: no database, so
/// the memory test drives exactly the per-request path.
pub fn prepare(body: &[u8]) -> Result<Batch, PrepareError> {
    let mut de = serde_json::Deserializer::from_slice(body);
    let entries = match Entries::deserialize(&mut de).and_then(|e| de.end().map(|_| e)) {
        Ok(e) => e.0,
        Err(e) if e.to_string().contains(TOO_MANY_ENTRIES) => return Err(PrepareError::TooMany),
        Err(e) => return Err(PrepareError::Malformed(e.to_string())),
    };
    let total = entries.len();
    let mut rows: Vec<RuntimeRow> = entries
        .into_iter()
        .flatten()
        .filter_map(row_from_entry)
        .collect();
    let dropped = total - rows.len();
    // One INSERT ... ON CONFLICT may not touch a row twice: fold
    // duplicates (adjacent once sorted) with the upsert's own rules.
    rows.sort_by(|a, b| a.key().cmp(&b.key()));
    let mut merged: Vec<RuntimeRow> = Vec::with_capacity(rows.len());
    for r in rows {
        match merged.last_mut() {
            Some(m) if m.key() == r.key() => m.merge(r),
            _ => merged.push(r),
        }
    }
    Ok(Batch {
        rows: merged,
        dropped,
    })
}

/// Upsert a chunk of rows, one array per column.
///
/// Posted timestamps are the controller's observation times, clamped to
/// the database clock so a skewed node cannot park a row in the future
/// (where retention would never reach it). The `WHERE` skips the write
/// unless `last_seen` moved by at least [`REFRESH_SECS`] or the row
/// gains something; `last_pod_name` alone never forces a write, so
/// replicas running the same binary do not take turns rewriting it.
pub(crate) static RUNTIME_UPSERT_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| RUNTIME_UPSERT_TEMPLATE.replace("{ORIGINS}", ORIGIN_ARRAY_SQL));

const RUNTIME_UPSERT_TEMPLATE: &str = "\
INSERT INTO runtime_executables AS r (cluster_id, pod_namespace, workload_kind, workload_name, \
    container_name, image_digest, kind, path, path_complete, source, origin, last_pod_name, \
    first_seen, last_seen) \
SELECT $1, t.ns, t.wk, t.wn, t.cn, t.dg, t.k, t.p, t.pc, t.src, t.org, t.lpn, \
    LEAST(t.fs, t.ls, timezone('UTC', NOW())), LEAST(t.ls, timezone('UTC', NOW())) \
FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], \
    $8::text[], $9::bool[], $10::text[], $15::text[], $11::text[], $12::timestamp[], \
    $13::timestamp[]) \
    AS t(ns, wk, wn, cn, dg, k, p, pc, src, org, lpn, fs, ls) \
ON CONFLICT (cluster_id, pod_namespace, workload_kind, workload_name, container_name, \
    image_digest, kind, path) \
DO UPDATE SET \
    first_seen = LEAST(r.first_seen, EXCLUDED.first_seen), \
    last_seen = GREATEST(r.last_seen, EXCLUDED.last_seen), \
    source = CASE WHEN r.source = 'ebpf' OR EXCLUDED.source = 'ebpf' THEN 'ebpf' \
        ELSE r.source END, \
    path_complete = r.path_complete OR EXCLUDED.path_complete, \
    origin = CASE WHEN array_position({ORIGINS}, EXCLUDED.origin) \
        > array_position({ORIGINS}, r.origin) THEN EXCLUDED.origin ELSE r.origin END, \
    last_pod_name = CASE WHEN EXCLUDED.last_seen >= r.last_seen \
        THEN COALESCE(EXCLUDED.last_pod_name, r.last_pod_name) ELSE r.last_pod_name END \
WHERE r.last_seen <= EXCLUDED.last_seen - make_interval(secs => $14) \
   OR EXCLUDED.first_seen < r.first_seen \
   OR (r.source <> 'ebpf' AND EXCLUDED.source = 'ebpf') \
   OR (NOT r.path_complete AND EXCLUDED.path_complete) \
   OR array_position({ORIGINS}, EXCLUDED.origin) > array_position({ORIGINS}, r.origin)";

/// Write a batch, [`UPSERT_CHUNK`] rows per statement, in one
/// transaction. Returns the rows actually written; a steady-state re-post
/// writes 0.
pub fn upsert_rows(conn: &mut PgConnection, rows: &[RuntimeRow]) -> Result<usize, DbError> {
    if rows.is_empty() {
        return Ok(0);
    }
    let written = conn.transaction::<usize, diesel::result::Error, _>(|conn| {
        let mut n = 0;
        for chunk in rows.chunks(UPSERT_CHUNK) {
            let col = |f: fn(&RuntimeRow) -> &str| -> Vec<&str> { chunk.iter().map(f).collect() };
            n += sql_query(RUNTIME_UPSERT_SQL.as_str())
                .bind::<Text, _>(DEFAULT_CLUSTER_ID)
                .bind::<Array<Text>, _>(col(|r| &r.namespace))
                .bind::<Array<Text>, _>(col(|r| &r.workload_kind))
                .bind::<Array<Text>, _>(col(|r| &r.workload_name))
                .bind::<Array<Text>, _>(col(|r| &r.container_name))
                .bind::<Array<Text>, _>(col(|r| &r.image_digest))
                .bind::<Array<Text>, _>(col(|r| &r.kind))
                .bind::<Array<Text>, _>(col(|r| &r.path))
                .bind::<Array<Bool>, _>(chunk.iter().map(|r| r.path_complete).collect::<Vec<_>>())
                .bind::<Array<Text>, _>(col(|r| &r.source))
                .bind::<Array<Nullable<Text>>, _>(
                    chunk
                        .iter()
                        .map(|r| r.last_pod_name.as_deref())
                        .collect::<Vec<_>>(),
                )
                .bind::<Array<Timestamp>, _>(chunk.iter().map(|r| r.first_seen).collect::<Vec<_>>())
                .bind::<Array<Timestamp>, _>(chunk.iter().map(|r| r.last_seen).collect::<Vec<_>>())
                .bind::<Double, _>(REFRESH_SECS as f64)
                .bind::<Array<Text>, _>(col(|r| &r.origin))
                .execute(conn)?;
        }
        Ok(n)
    })?;
    debug!(rows = rows.len(), written, "runtime inventory upserted");
    Ok(written)
}

#[derive(Debug, Serialize, PartialEq)]
pub struct IngestSummary {
    /// Entries kept after validation (duplicates within the batch merged).
    pub accepted: usize,
    /// Entries dropped as malformed.
    pub dropped: usize,
    /// Rows inserted or changed.
    pub written: usize,
}

async fn post_runtime_executables(
    pool: web::Data<DbPool>,
    body: web::Bytes,
) -> actix_web::Result<HttpResponse> {
    let batch = match prepare(&body) {
        Ok(b) => b,
        Err(PrepareError::TooMany) => {
            warn!(
                max = MAX_BATCH_ENTRIES,
                "/runtime/executables batch over the cap; refused"
            );
            return Ok(HttpResponse::PayloadTooLarge().body(format!(
                "at most {MAX_BATCH_ENTRIES} entries per post; chunk the batch"
            )));
        }
        Err(PrepareError::Malformed(m)) => {
            return Ok(HttpResponse::BadRequest().body(format!("body must be a JSON array: {m}")));
        }
    };
    drop(body);
    if batch.dropped > 0 {
        warn!(
            dropped = batch.dropped,
            kept = batch.rows.len(),
            "/runtime/executables entries malformed; dropped"
        );
    }
    let accepted = batch.rows.len();
    let dropped = batch.dropped;
    let written = web::block(move || {
        let mut conn = pool.get()?;
        upsert_rows(&mut conn, &batch.rows)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().json(IngestSummary {
        accepted,
        dropped,
        written,
    }))
}

/// `POST /runtime/executables` as a resource rather than a `#[post]`
/// handler so its body limit ([`RUNTIME_BODY_LIMIT_BYTES`]) applies to
/// this path only. The body is taken as raw bytes and parsed by
/// [`prepare`], never by `web::Json` into a generic value.
pub fn runtime_executables_resource() -> impl actix_web::dev::HttpServiceFactory {
    web::resource("/runtime/executables")
        // Per-route authorisation after routing; see crate::auth.
        .wrap(::actix_web::middleware::from_fn(crate::auth::authorize))
        .app_data(web::PayloadConfig::new(RUNTIME_BODY_LIMIT_BYTES))
        .route(web::post().to(post_runtime_executables))
}

// ---------------------------------------------------------------------
// Read side
// ---------------------------------------------------------------------

/// Peak in-flight bytes charged per row. Real paths are well under
/// 256 bytes, so 2 KiB covers the row, its serialised form and the
/// doubling transient; a page of paths at the 4 KiB cap overshoots it by
/// ~2.5x, which the [`RUNTIME_MAX_LIMIT`] cap keeps bounded.
pub const RUNTIME_ROW_COST_BYTES: u64 = 2_048;
/// Page size: default and hard cap for both reads.
pub const RUNTIME_DEFAULT_LIMIT: i64 = 1_000;
pub const RUNTIME_MAX_LIMIT: i64 = 5_000;

pub(crate) fn clamp_runtime_limit(raw: Option<i64>) -> i64 {
    raw.unwrap_or(RUNTIME_DEFAULT_LIMIT)
        .clamp(1, RUNTIME_MAX_LIMIT)
}

/// `?kind=`: absent or empty = both; otherwise `exec` or `lib`.
/// `Err` = 400.
pub(crate) fn parse_kind_filter(raw: Option<&str>) -> Result<Option<String>, ()> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(k) if KINDS.contains(&k) => Ok(Some(k.to_string())),
        Some(_) => Err(()),
    }
}

/// `?origin=`: absent or empty = all; otherwise one of [`ORIGINS`], or
/// `unshipped` for any of [`UNSHIPPED_ORIGINS`]. `Err` = 400.
pub(crate) fn parse_origin_filter(raw: Option<&str>) -> Result<Vec<String>, ()> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(Vec::new()),
        Some("unshipped") => Ok(UNSHIPPED_ORIGINS.iter().map(|s| s.to_string()).collect()),
        Some(o) if ORIGINS.contains(&o) => Ok(vec![o.to_string()]),
        Some(_) => Err(()),
    }
}

#[derive(Debug, Deserialize)]
pub struct WorkloadRuntimeQuery {
    /// Only this container.
    pub container: Option<String>,
    /// `exec` or `lib`.
    pub kind: Option<String>,
    /// One origin, or `unshipped`.
    pub origin: Option<String>,
    /// Rows; default 1000, max 5000.
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, QueryableByName)]
struct WorkloadRuntimeRow {
    #[diesel(sql_type = Text)]
    container_name: String,
    #[diesel(sql_type = Text)]
    image_digest: String,
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = Text)]
    path: String,
    #[diesel(sql_type = Text)]
    source: String,
    #[diesel(sql_type = Text)]
    origin: String,
    #[diesel(sql_type = Bool)]
    path_complete: bool,
    #[diesel(sql_type = Timestamp)]
    first_seen: NaiveDateTime,
    #[diesel(sql_type = Timestamp)]
    last_seen: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeEntry {
    pub path: String,
    /// `exec` | `lib`.
    pub kind: String,
    /// `ebpf` | `backfill`.
    pub source: String,
    /// One of [`ORIGINS`].
    pub origin: String,
    pub path_complete: bool,
    pub first_seen: NaiveDateTime,
    pub last_seen: NaiveDateTime,
}

/// One (container, digest) of a workload and the files it ran.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ContainerRuntime {
    pub container_name: String,
    /// `""` when the controller could not resolve the digest.
    pub image_digest: String,
    /// Ordered by kind, then path.
    pub entries: Vec<RuntimeEntry>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadRuntime {
    pub namespace: String,
    pub kind: String,
    pub name: String,
    pub containers: Vec<ContainerRuntime>,
    /// More rows than the page limit.
    pub truncated: bool,
}

const WORKLOAD_RUNTIME_SQL: &str = "\
SELECT container_name, image_digest, kind, path, source, origin, path_complete, first_seen, \
    last_seen \
FROM runtime_executables \
WHERE pod_namespace = $1 AND workload_kind = $2 AND workload_name = $3 \
  AND ($4::text IS NULL OR container_name = $4) \
  AND ($5::text IS NULL OR kind = $5) \
  AND (cardinality($7::text[]) = 0 OR origin = ANY($7)) \
ORDER BY container_name, image_digest, kind, path \
LIMIT $6";

/// Group rows (already ordered by container, digest) per (container,
/// digest). Pure, so it is unit-tested without a database.
fn group_workload_rows(rows: Vec<WorkloadRuntimeRow>) -> Vec<ContainerRuntime> {
    let mut out: Vec<ContainerRuntime> = Vec::new();
    for r in rows {
        let same = out.last().is_some_and(|c| {
            c.container_name == r.container_name && c.image_digest == r.image_digest
        });
        if !same {
            out.push(ContainerRuntime {
                container_name: r.container_name,
                image_digest: r.image_digest,
                entries: Vec::new(),
            });
        }
        out.last_mut()
            .expect("pushed above")
            .entries
            .push(RuntimeEntry {
                path: r.path,
                kind: r.kind,
                source: r.source,
                origin: r.origin,
                path_complete: r.path_complete,
                first_seen: r.first_seen,
                last_seen: r.last_seen,
            });
    }
    out
}

/// Optional filters of [`workload_runtime`]; the default is none.
#[derive(Debug, Default, Clone)]
pub struct RuntimeFilter {
    /// Only this container.
    pub container: Option<String>,
    /// `exec` or `lib`.
    pub kind: Option<String>,
    /// Any of these origins; empty = all.
    pub origins: Vec<String>,
}

pub fn workload_runtime(
    conn: &mut PgConnection,
    ns: &str,
    kind: &str,
    name: &str,
    filter: &RuntimeFilter,
    limit: i64,
) -> Result<WorkloadRuntime, DbError> {
    let mut rows: Vec<WorkloadRuntimeRow> = sql_query(WORKLOAD_RUNTIME_SQL)
        .bind::<Text, _>(ns)
        .bind::<Text, _>(kind)
        .bind::<Text, _>(name)
        .bind::<Nullable<Text>, _>(filter.container.as_deref())
        .bind::<Nullable<Text>, _>(filter.kind.as_deref())
        .bind::<BigInt, _>(limit + 1)
        .bind::<Array<Text>, _>(&filter.origins)
        .load(conn)?;
    let truncated = rows.len() as i64 > limit;
    rows.truncate(limit as usize);
    Ok(WorkloadRuntime {
        namespace: ns.to_string(),
        kind: kind.to_string(),
        name: name.to_string(),
        containers: group_workload_rows(rows),
        truncated,
    })
}

/// An empty inventory is a 200 with no containers, not a 404: a workload
/// the controller has not reported yet, and a `?kind=` filter that
/// matches nothing, are both ordinary answers.
#[get(
    "/workloads/{namespace}/{kind}/{name}/runtime",
    wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"
)]
pub async fn get_workload_runtime(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    path: web::Path<(String, String, String)>,
    query: web::Query<WorkloadRuntimeQuery>,
) -> actix_web::Result<impl Responder> {
    let (ns, kind, name) = path.into_inner();
    if [&ns, &kind, &name]
        .iter()
        .any(|s| s.trim().is_empty() || s.len() > MAX_NAME_LEN)
    {
        return Ok(HttpResponse::BadRequest().body("namespace, kind and name are required"));
    }
    let q = query.into_inner();
    let Ok(entry_kind) = parse_kind_filter(q.kind.as_deref()) else {
        return Ok(HttpResponse::BadRequest().body("kind must be exec or lib"));
    };
    let Ok(origins) = parse_origin_filter(q.origin.as_deref()) else {
        return Ok(HttpResponse::BadRequest().body(format!(
            "origin must be one of {} or unshipped",
            ORIGINS.join(", ")
        )));
    };
    let container = q
        .container
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty());
    let limit = clamp_runtime_limit(q.limit);
    // +1: the look-ahead row that decides `truncated`.
    let _permit = match budget
        .acquire(cost_kib(limit + 1, RUNTIME_ROW_COST_BYTES))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let out = web::block(move || {
        let mut conn = pool.get()?;
        workload_runtime(
            &mut conn,
            &ns,
            &kind,
            &name,
            &RuntimeFilter {
                container,
                kind: entry_kind,
                origins,
            },
            limit,
        )
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().json(out))
}

#[derive(Debug, Deserialize)]
pub struct ImageRuntimeQuery {
    /// `exec` or `lib`.
    pub kind: Option<String>,
    /// Rows; default 1000, max 5000.
    pub limit: Option<i64>,
}

/// One path seen running from an image, aggregated across every workload
/// container that runs the digest.
#[derive(Debug, Clone, QueryableByName, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageRuntimeEntry {
    #[diesel(sql_type = Text)]
    pub path: String,
    #[diesel(sql_type = Text)]
    pub kind: String,
    /// Complete in at least one sighting.
    #[diesel(sql_type = Bool)]
    pub path_complete: bool,
    /// The most suspicious origin across the workloads (see [`ORIGINS`]).
    #[diesel(sql_type = Text)]
    pub origin: String,
    #[diesel(sql_type = Timestamp)]
    pub first_seen: NaiveDateTime,
    #[diesel(sql_type = Timestamp)]
    pub last_seen: NaiveDateTime,
    /// Distinct workloads that ran it.
    #[diesel(sql_type = BigInt)]
    pub workloads: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageRuntime {
    pub digest: String,
    /// Ordered by kind, then path.
    pub entries: Vec<ImageRuntimeEntry>,
    pub truncated: bool,
}

/// Served by `idx_runtime_executables_digest` (digest, kind, path), whose
/// order is the GROUP BY and ORDER BY here.
static IMAGE_RUNTIME_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| IMAGE_RUNTIME_TEMPLATE.replace("{ORIGINS}", ORIGIN_ARRAY_SQL));

const IMAGE_RUNTIME_TEMPLATE: &str = "\
SELECT kind, path, bool_or(path_complete) AS path_complete, \
    ({ORIGINS})[max(array_position({ORIGINS}, origin))] AS origin, \
    min(first_seen) AS first_seen, max(last_seen) AS last_seen, \
    count(DISTINCT (cluster_id, pod_namespace, workload_kind, workload_name)) AS workloads \
FROM runtime_executables \
WHERE image_digest = $1 AND ($2::text IS NULL OR kind = $2) \
GROUP BY kind, path \
ORDER BY kind, path \
LIMIT $3";

pub fn image_runtime(
    conn: &mut PgConnection,
    digest: &str,
    entry_kind: Option<&str>,
    limit: i64,
) -> Result<ImageRuntime, DbError> {
    let mut entries: Vec<ImageRuntimeEntry> = sql_query(IMAGE_RUNTIME_SQL.as_str())
        .bind::<Text, _>(digest)
        .bind::<Nullable<Text>, _>(entry_kind)
        .bind::<BigInt, _>(limit + 1)
        .load(conn)?;
    let truncated = entries.len() as i64 > limit;
    entries.truncate(limit as usize);
    Ok(ImageRuntime {
        digest: digest.to_string(),
        entries,
        truncated,
    })
}

/// 200 with no entries when nothing has been seen running from the
/// digest (see [`get_workload_runtime`]).
#[get(
    "/images/{digest}/runtime",
    wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"
)]
pub async fn get_image_runtime(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    path: web::Path<String>,
    query: web::Query<ImageRuntimeQuery>,
) -> actix_web::Result<impl Responder> {
    let digest = path.into_inner();
    if !is_valid_digest(&digest) {
        return Ok(
            HttpResponse::BadRequest().body("digest must be sha256:<64 hex> or sha512:<128 hex>")
        );
    }
    let q = query.into_inner();
    let Ok(entry_kind) = parse_kind_filter(q.kind.as_deref()) else {
        return Ok(HttpResponse::BadRequest().body("kind must be exec or lib"));
    };
    let limit = clamp_runtime_limit(q.limit);
    let _permit = match budget
        .acquire(cost_kib(limit + 1, RUNTIME_ROW_COST_BYTES))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let out = web::block(move || {
        let mut conn = pool.get()?;
        image_runtime(&mut conn, &digest, entry_kind.as_deref(), limit)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().json(out))
}

// ---------------------------------------------------------------------
// Coverage heartbeats (read by P1-5 through kg_runtime_coverage)
// ---------------------------------------------------------------------

/// Heartbeats accepted in one post.
pub const MAX_COVERAGE_ENTRIES: usize = 5_000;
/// Body limit for the coverage route. A heartbeat is ~600 bytes, so a
/// full batch is ~3 MB.
pub const COVERAGE_BODY_LIMIT_BYTES: usize = 4 << 20;
const GAP_REASONS: [&str; 2] = ["kernel_drops", "overflow"];

/// One posted heartbeat (controller `runtime_inventory::CoveragePost`).
/// Strings are bounded by the body limit; every one is length-checked
/// before use.
#[derive(Debug, Clone, Deserialize)]
pub struct CoverageEntry {
    pub pod_namespace: String,
    pub pod_name: String,
    pub workload_kind: String,
    pub workload_name: String,
    pub container_name: String,
    #[serde(default)]
    pub image_digest: String,
    pub container_id: String,
    pub node_name: String,
    pub mode: String,
    pub exec_probe: bool,
    pub lib_probe: bool,
    pub start_mode: String,
    pub tracking_since: NaiveDateTime,
    #[serde(default)]
    pub gap: Option<String>,
    #[serde(default)]
    pub ended: bool,
    pub heartbeat_at: NaiveDateTime,
    pub heartbeat_secs: u32,
}

/// Validate one heartbeat; `None` = drop it.
pub fn valid_coverage(e: CoverageEntry) -> Option<CoverageEntry> {
    let names = [
        &e.pod_namespace,
        &e.pod_name,
        &e.workload_name,
        &e.container_name,
        &e.node_name,
    ];
    if names
        .iter()
        .any(|n| bounded(n, MAX_NAME_LEN).as_deref() != Some(n.as_str()))
    {
        return None;
    }
    if bounded(&e.workload_kind, MAX_KIND_LEN).as_deref() != Some(e.workload_kind.as_str()) {
        return None;
    }
    let id_ok = !e.container_id.is_empty()
        && e.container_id.len() <= 128
        && e.container_id.bytes().all(|b| b.is_ascii_alphanumeric());
    if !id_ok {
        return None;
    }
    if !e.image_digest.is_empty() && !is_valid_digest(&e.image_digest) {
        return None;
    }
    if !["exec", "full"].contains(&e.mode.as_str())
        || !["start", "backfill"].contains(&e.start_mode.as_str())
        || !(1..=86_400).contains(&e.heartbeat_secs)
    {
        return None;
    }
    // An unknown gap reason is still a gap.
    let gap = e.gap.map(|g| {
        if GAP_REASONS.contains(&g.as_str()) {
            g
        } else {
            "other".to_string()
        }
    });
    Some(CoverageEntry { gap, ..e })
}

/// Upsert heartbeats. The run of gap-free coverage (`covered_since`)
/// restarts at this heartbeat when the controller reports a gap, when a
/// probe or the mode changed, or when the previous heartbeat is older
/// than 3 x heartbeat_secs + 60 s (the controller, the node or the
/// broker was away: nobody can say what ran meanwhile). A heartbeat
/// older than the stored one is ignored. Times are clamped to the
/// database clock.
pub(crate) const COVERAGE_UPSERT_SQL: &str = "\
INSERT INTO runtime_coverage AS r (cluster_id, container_id, pod_namespace, workload_kind, \
    workload_name, container_name, image_digest, pod_name, node_name, mode, exec_probe, \
    lib_probe, start_mode, tracking_since, covered_since, last_heartbeat, heartbeat_secs, gaps, \
    last_gap, last_gap_at, ended) \
SELECT $1, t.cid, t.ns, t.wk, t.wn, t.cn, t.dg, t.pn, t.nn, t.md, t.ep, t.lp, t.sm, \
    LEAST(t.ts, t.hb, timezone('UTC', NOW())), \
    CASE WHEN t.gap IS NULL AND t.ep AND t.lp THEN LEAST(t.ts, t.hb, timezone('UTC', NOW())) \
         ELSE LEAST(t.hb, timezone('UTC', NOW())) END, \
    LEAST(t.hb, timezone('UTC', NOW())), t.hs, \
    CASE WHEN t.gap IS NULL THEN 0 ELSE 1 END, t.gap, \
    CASE WHEN t.gap IS NULL THEN NULL ELSE LEAST(t.hb, timezone('UTC', NOW())) END, t.ended \
FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[], \
    $9::text[], $10::text[], $11::bool[], $12::bool[], $13::text[], $14::timestamp[], \
    $15::text[], $16::timestamp[], $17::int[], $18::bool[]) \
    AS t(cid, ns, wk, wn, cn, dg, pn, nn, md, ep, lp, sm, ts, gap, hb, hs, ended) \
ON CONFLICT (cluster_id, container_id) DO UPDATE SET \
    covered_since = CASE WHEN EXCLUDED.last_gap IS NOT NULL \
            OR EXCLUDED.mode <> r.mode OR EXCLUDED.exec_probe <> r.exec_probe \
            OR EXCLUDED.lib_probe <> r.lib_probe \
            OR EXCLUDED.last_heartbeat - r.last_heartbeat \
                > make_interval(secs => 3 * r.heartbeat_secs + 60) \
        THEN EXCLUDED.last_heartbeat ELSE r.covered_since END, \
    gaps = r.gaps + CASE WHEN EXCLUDED.last_gap IS NOT NULL \
            OR EXCLUDED.last_heartbeat - r.last_heartbeat \
                > make_interval(secs => 3 * r.heartbeat_secs + 60) THEN 1 ELSE 0 END, \
    last_gap = CASE WHEN EXCLUDED.last_gap IS NOT NULL THEN EXCLUDED.last_gap \
        WHEN EXCLUDED.last_heartbeat - r.last_heartbeat \
            > make_interval(secs => 3 * r.heartbeat_secs + 60) THEN 'late_heartbeat' \
        ELSE r.last_gap END, \
    last_gap_at = CASE WHEN EXCLUDED.last_gap IS NOT NULL \
            OR EXCLUDED.last_heartbeat - r.last_heartbeat \
                > make_interval(secs => 3 * r.heartbeat_secs + 60) \
        THEN EXCLUDED.last_heartbeat ELSE r.last_gap_at END, \
    pod_name = EXCLUDED.pod_name, node_name = EXCLUDED.node_name, mode = EXCLUDED.mode, \
    exec_probe = EXCLUDED.exec_probe, lib_probe = EXCLUDED.lib_probe, \
    last_heartbeat = EXCLUDED.last_heartbeat, heartbeat_secs = EXCLUDED.heartbeat_secs, \
    ended = r.ended OR EXCLUDED.ended \
WHERE EXCLUDED.last_heartbeat >= r.last_heartbeat AND NOT r.ended";

/// Write heartbeats in one transaction; returns rows written.
pub fn upsert_coverage(conn: &mut PgConnection, rows: &[CoverageEntry]) -> Result<usize, DbError> {
    if rows.is_empty() {
        return Ok(0);
    }
    // One INSERT ... ON CONFLICT may not touch a row twice: keep the
    // newest heartbeat per container id (merging a gap into it).
    let mut by_id: std::collections::BTreeMap<&str, CoverageEntry> = Default::default();
    for r in rows {
        match by_id.get_mut(r.container_id.as_str()) {
            Some(prev) if prev.heartbeat_at > r.heartbeat_at => {
                prev.gap = prev.gap.take().or_else(|| r.gap.clone());
            }
            Some(prev) => {
                let gap = r.gap.clone().or_else(|| prev.gap.take());
                *prev = CoverageEntry { gap, ..r.clone() };
            }
            None => {
                by_id.insert(&r.container_id, r.clone());
            }
        }
    }
    let rows: Vec<&CoverageEntry> = by_id.values().collect();
    let col = |f: fn(&CoverageEntry) -> &str| -> Vec<&str> { rows.iter().map(|r| f(r)).collect() };
    let written = conn.transaction::<usize, diesel::result::Error, _>(|conn| {
        sql_query(COVERAGE_UPSERT_SQL)
            .bind::<Text, _>(DEFAULT_CLUSTER_ID)
            .bind::<Array<Text>, _>(col(|r| &r.container_id))
            .bind::<Array<Text>, _>(col(|r| &r.pod_namespace))
            .bind::<Array<Text>, _>(col(|r| &r.workload_kind))
            .bind::<Array<Text>, _>(col(|r| &r.workload_name))
            .bind::<Array<Text>, _>(col(|r| &r.container_name))
            .bind::<Array<Text>, _>(col(|r| &r.image_digest))
            .bind::<Array<Text>, _>(col(|r| &r.pod_name))
            .bind::<Array<Text>, _>(col(|r| &r.node_name))
            .bind::<Array<Text>, _>(col(|r| &r.mode))
            .bind::<Array<Bool>, _>(rows.iter().map(|r| r.exec_probe).collect::<Vec<_>>())
            .bind::<Array<Bool>, _>(rows.iter().map(|r| r.lib_probe).collect::<Vec<_>>())
            .bind::<Array<Text>, _>(col(|r| &r.start_mode))
            .bind::<Array<Timestamp>, _>(rows.iter().map(|r| r.tracking_since).collect::<Vec<_>>())
            .bind::<Array<Nullable<Text>>, _>(
                rows.iter().map(|r| r.gap.as_deref()).collect::<Vec<_>>(),
            )
            .bind::<Array<Timestamp>, _>(rows.iter().map(|r| r.heartbeat_at).collect::<Vec<_>>())
            .bind::<Array<diesel::sql_types::Integer>, _>(
                rows.iter()
                    .map(|r| r.heartbeat_secs as i32)
                    .collect::<Vec<_>>(),
            )
            .bind::<Array<Bool>, _>(rows.iter().map(|r| r.ended).collect::<Vec<_>>())
            .execute(conn)
    })?;
    Ok(written)
}

async fn post_runtime_coverage(
    pool: web::Data<DbPool>,
    body: web::Bytes,
) -> actix_web::Result<HttpResponse> {
    let entries: Vec<CoverageEntry> = match serde_json::from_slice::<Vec<CoverageEntry>>(&body) {
        Ok(v) => v,
        Err(e) => {
            return Ok(HttpResponse::BadRequest().body(format!("invalid coverage batch: {e}")));
        }
    };
    drop(body);
    if entries.len() > MAX_COVERAGE_ENTRIES {
        return Ok(HttpResponse::PayloadTooLarge().body(format!(
            "at most {MAX_COVERAGE_ENTRIES} heartbeats per post; chunk the batch"
        )));
    }
    let total = entries.len();
    let rows: Vec<CoverageEntry> = entries.into_iter().filter_map(valid_coverage).collect();
    let dropped = total - rows.len();
    if dropped > 0 {
        warn!(
            dropped,
            kept = rows.len(),
            "/runtime/coverage entries malformed; dropped"
        );
    }
    let accepted = rows.len();
    let written = web::block(move || {
        let mut conn = pool.get()?;
        upsert_coverage(&mut conn, &rows)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().json(IngestSummary {
        accepted,
        dropped,
        written,
    }))
}

/// `POST /runtime/coverage` with its own body limit.
pub fn runtime_coverage_resource() -> impl actix_web::dev::HttpServiceFactory {
    web::resource("/runtime/coverage")
        .wrap(::actix_web::middleware::from_fn(crate::auth::authorize))
        .app_data(web::PayloadConfig::new(COVERAGE_BODY_LIMIT_BYTES))
        .route(web::post().to(post_runtime_coverage))
}

/// One `kg_runtime_coverage` answer.
#[derive(Debug, Clone, QueryableByName, PartialEq, Serialize)]
pub struct CoverageAnswer {
    #[diesel(sql_type = Nullable<Bool>)]
    pub covered: Option<bool>,
    #[diesel(sql_type = Nullable<Timestamp>)]
    pub observed_since: Option<NaiveDateTime>,
    #[diesel(sql_type = Nullable<Text>)]
    pub reason: Option<String>,
}

/// Call `kg_runtime_coverage` (the migration defines it; P1-5 calls it
/// from SQL). Here for the broker's own tests and callers.
pub fn runtime_coverage(
    conn: &mut PgConnection,
    key: (&str, &str, &str, &str, &str),
    image: &str,
    window_hours: i32,
) -> Result<CoverageAnswer, DbError> {
    let (ns, kind, name, container, cluster) = key;
    Ok(sql_query(
        "SELECT covered, observed_since, reason \
         FROM kg_runtime_coverage($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind::<Text, _>(cluster)
    .bind::<Text, _>(ns)
    .bind::<Text, _>(kind)
    .bind::<Text, _>(name)
    .bind::<Text, _>(container)
    .bind::<Text, _>(image)
    .bind::<diesel::sql_types::Integer, _>(window_hours)
    .get_result(conn)?)
}

// ---------------------------------------------------------------------
// For P2-5 drift
// ---------------------------------------------------------------------

/// Files a workload ran that its image did not ship as they ran
/// ([`UNSHIPPED_ORIGINS`]): written to or modified in the container's
/// writable layer, run from a memfd, or deleted while running. What the
/// profile's drift block reads; `truncated` when there were more than
/// `limit`. Not observed is not "no drift": a workload the controller
/// does not inventory (mode off, excluded, opted out) has no rows at all,
/// so a caller must treat an empty inventory as "not evaluated" unless
/// [`workload_has_inventory`] says otherwise.
pub fn workload_unshipped_executables(
    conn: &mut PgConnection,
    ns: &str,
    kind: &str,
    name: &str,
    limit: i64,
) -> Result<WorkloadRuntime, DbError> {
    let filter = RuntimeFilter {
        origins: UNSHIPPED_ORIGINS.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    };
    workload_runtime(conn, ns, kind, name, &filter, limit)
}

/// Whether the controller has reported any runtime inventory for the
/// workload (the "evaluated" half of drift).
pub fn workload_has_inventory(
    conn: &mut PgConnection,
    ns: &str,
    kind: &str,
    name: &str,
) -> Result<bool, DbError> {
    #[derive(QueryableByName)]
    struct E {
        #[diesel(sql_type = Bool)]
        e: bool,
    }
    let r: E = sql_query(
        "SELECT EXISTS (SELECT 1 FROM runtime_executables \
         WHERE pod_namespace = $1 AND workload_kind = $2 AND workload_name = $3) AS e",
    )
    .bind::<Text, _>(ns)
    .bind::<Text, _>(kind)
    .bind::<Text, _>(name)
    .get_result(conn)?;
    Ok(r.e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn batch_from_post(v: Vec<serde_json::Value>) -> Batch {
        prepare(&serde_json::to_vec(&v).unwrap()).expect("a JSON array parses")
    }

    const D: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const D2: &str = "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    fn entry(path: &str) -> serde_json::Value {
        json!({
            "pod_namespace": "prod", "pod_name": "web-7d9f-abcde",
            "workload_kind": "Deployment", "workload_name": "web",
            "container_name": "app", "image_digest": D,
            "kind": "exec", "path": path, "path_complete": true, "source": "ebpf",
            "first_seen": "2026-09-26T10:00:00", "last_seen": "2026-09-26T10:05:00.123456"
        })
    }

    fn with(mut v: serde_json::Value, k: &str, val: serde_json::Value) -> serde_json::Value {
        v[k] = val;
        v
    }

    fn ts(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S").unwrap()
    }

    #[test]
    fn a_valid_entry_normalises() {
        let b = batch_from_post(vec![with(entry("/usr/bin/nginx"), "kind", json!(" EXEC "))]);
        assert_eq!(b.dropped, 0);
        let r = &b.rows[0];
        assert_eq!(
            (
                r.namespace.as_str(),
                r.workload_kind.as_str(),
                r.workload_name.as_str()
            ),
            ("prod", "Deployment", "web")
        );
        assert_eq!(r.kind, "exec");
        assert_eq!(r.image_digest, D);
        assert_eq!(r.last_pod_name.as_deref(), Some("web-7d9f-abcde"));
        assert_eq!(r.first_seen, ts("2026-09-26T10:00:00"));
    }

    #[test]
    fn invalid_entries_are_dropped_and_counted_not_fatal() {
        let b = batch_from_post(vec![
            entry("/ok"),
            with(entry("/a"), "kind", json!("mmap")),
            with(entry("/b"), "source", json!("guess")),
            entry(""),
            entry(&format!("/{}", "x".repeat(MAX_PATH_LEN))),
            entry("/nul\0byte"),
            with(entry("/c"), "container_name", json!(" ")),
            with(entry("/d"), "pod_namespace", json!("")),
            with(entry("/e"), "image_digest", json!("sha256:XYZ")),
            with(entry("/f"), "workload_name", json!("")),
            with(entry("/g"), "first_seen", json!("yesterday")),
            json!("not an object"),
            json!({"path": "/missing-everything"}),
        ]);
        assert_eq!(b.rows.len(), 1);
        assert_eq!(b.rows[0].path, "/ok");
        assert_eq!(b.dropped, 12);
    }

    #[test]
    fn unknown_digest_is_empty_and_ownerless_pod_is_its_own_workload() {
        let mut e = with(entry("/bin/sh"), "image_digest", json!(""));
        e["workload_kind"] = serde_json::Value::Null;
        e["workload_name"] = serde_json::Value::Null;
        let mut no_digest = entry("/bin/ls");
        no_digest.as_object_mut().unwrap().remove("image_digest");
        let b = batch_from_post(vec![e, no_digest]);
        assert_eq!(b.dropped, 0);
        let sh = b.rows.iter().find(|r| r.path == "/bin/sh").unwrap();
        assert_eq!(sh.image_digest, "");
        assert_eq!(
            (sh.workload_kind.as_str(), sh.workload_name.as_str()),
            ("Pod", "web-7d9f-abcde")
        );
        assert_eq!(
            b.rows
                .iter()
                .find(|r| r.path == "/bin/ls")
                .unwrap()
                .image_digest,
            ""
        );

        // Ownerless with no pod name to fall back on: dropped.
        let mut orphan = entry("/x");
        orphan["workload_kind"] = json!("");
        orphan["workload_name"] = json!("");
        orphan["pod_name"] = serde_json::Value::Null;
        assert_eq!(batch_from_post(vec![orphan]).dropped, 1);
    }

    #[test]
    fn path_is_kept_verbatim_and_reversed_times_are_swapped() {
        let e = with(
            entry(" /opt/app/run "),
            "first_seen",
            json!("2026-09-26T11:00:00"),
        );
        let b = batch_from_post(vec![e]);
        let r = &b.rows[0];
        assert_eq!(r.path, " /opt/app/run ");
        assert!(r.first_seen <= r.last_seen);
        assert_eq!(r.last_seen, ts("2026-09-26T11:00:00"));
    }

    #[test]
    fn duplicates_in_one_batch_merge_like_the_upsert() {
        let a = with(
            with(entry("/lib/libc.so.6"), "source", json!("backfill")),
            "path_complete",
            json!(false),
        );
        let b = with(
            with(
                entry("/lib/libc.so.6"),
                "first_seen",
                json!("2026-09-26T09:00:00"),
            ),
            "last_seen",
            json!("2026-09-26T12:00:00"),
        );
        let b = with(b, "pod_name", json!("web-other"));
        let other_digest = with(entry("/lib/libc.so.6"), "image_digest", json!(D2));
        let got = batch_from_post(vec![a, b, other_digest]);
        assert_eq!(got.rows.len(), 2, "digest is part of the key");
        let r = got.rows.iter().find(|r| r.image_digest == D).unwrap();
        assert_eq!(r.source, "ebpf", "ebpf wins over backfill");
        assert!(r.path_complete);
        assert_eq!(r.first_seen, ts("2026-09-26T09:00:00"));
        assert_eq!(r.last_seen, ts("2026-09-26T12:00:00"));
        assert_eq!(r.last_pod_name.as_deref(), Some("web-other"));
    }

    #[test]
    fn origin_is_optional_forward_compatible_and_the_most_suspicious_wins() {
        // Absent (an older controller): unknown.
        let b = batch_from_post(vec![entry("/a")]);
        assert_eq!(b.rows[0].origin, "unknown");
        // A value this broker does not know (a newer controller): unknown.
        let b = batch_from_post(vec![with(entry("/a"), "origin", json!("fromTheFuture"))]);
        assert_eq!((b.rows[0].origin.as_str(), b.dropped), ("unknown", 0));
        // Sent as the wrong type: the entry is dropped.
        let b = batch_from_post(vec![with(entry("/a"), "origin", json!(7))]);
        assert_eq!(b.dropped, 1);
        // Within a batch the most suspicious sighting wins.
        let b = batch_from_post(vec![
            with(entry("/a"), "origin", json!("image")),
            with(entry("/a"), "origin", json!("writableLayer")),
            with(entry("/a"), "origin", json!("otherFs")),
        ]);
        assert_eq!(b.rows[0].origin, "writableLayer");
    }

    #[test]
    fn the_sql_origin_ranking_matches_the_rust_one() {
        let quoted: Vec<String> = ORIGINS.iter().map(|o| format!("'{o}'")).collect();
        assert_eq!(
            ORIGIN_ARRAY_SQL,
            format!("ARRAY[{}]::text[]", quoted.join(","))
        );
        assert!(!RUNTIME_UPSERT_SQL.contains("{ORIGINS}"));
        assert!(!IMAGE_RUNTIME_SQL.contains("{ORIGINS}"));
        for o in UNSHIPPED_ORIGINS {
            assert!(origin_rank(o) > origin_rank("otherFs"), "{o}");
        }
        assert_eq!(parse_origin_filter(None), Ok(vec![]));
        assert_eq!(parse_origin_filter(Some(" ")), Ok(vec![]));
        assert_eq!(
            parse_origin_filter(Some("memfd")),
            Ok(vec!["memfd".to_string()])
        );
        assert_eq!(parse_origin_filter(Some("unshipped")).unwrap().len(), 3);
        assert!(parse_origin_filter(Some("bogus")).is_err());
    }

    #[test]
    fn the_entry_cap_is_enforced_while_parsing() {
        let one = serde_json::to_string(&entry("/x")).unwrap();
        let body = |n: usize| format!("[{}]", vec![one.as_str(); n].join(","));
        let ok = prepare(body(MAX_BATCH_ENTRIES).as_bytes()).unwrap();
        // All identical: merged into one row, none dropped.
        assert_eq!((ok.rows.len(), ok.dropped), (1, 0));
        assert_eq!(
            prepare(body(MAX_BATCH_ENTRIES + 1).as_bytes()),
            Err(PrepareError::TooMany)
        );
        // The element past the cap is refused whatever its shape.
        let tiny = format!("[{}]", vec!["0"; MAX_BATCH_ENTRIES + 1].join(","));
        assert_eq!(prepare(tiny.as_bytes()), Err(PrepareError::TooMany));
    }

    #[test]
    fn only_a_non_array_body_fails_the_request() {
        for body in ["{}", "\"x\"", "", "[", "[] trailing", "null"] {
            assert!(
                matches!(prepare(body.as_bytes()), Err(PrepareError::Malformed(_))),
                "{body}"
            );
        }
        assert_eq!(prepare(b"[]").unwrap(), Batch::default());
    }

    #[test]
    fn hostile_shapes_are_dropped_without_failing_the_batch() {
        let many_keys: serde_json::Map<String, serde_json::Value> =
            (0..10_000).map(|i| (format!("k{i}"), json!(i))).collect();
        let nested = json!([[[[[[[[1]]]]]]]]);
        let b = batch_from_post(vec![
            entry("/ok"),
            json!(many_keys),
            nested.clone(),
            json!(42),
            json!(null),
            // Every field the wrong type.
            json!({"pod_namespace": ["prod"], "container_name": {"a": 1}, "kind": 1,
                   "path": null, "path_complete": "yes", "source": true}),
            // An over-cap value in a field is dropped, not truncated.
            with(
                entry("/long-ns"),
                "pod_namespace",
                json!("n".repeat(MAX_NAME_LEN + 1)),
            ),
            with(
                entry("/long-digest"),
                "image_digest",
                json!("s".repeat(MAX_DIGEST_LEN + 1)),
            ),
            // Unknown keys, including a nested one, are ignored.
            with(entry("/extra"), "future_field", nested),
            // A wrongly typed optional field drops the entry...
            with(entry("/flag"), "path_complete", json!("false")),
            with(entry("/pod"), "pod_name", json!(7)),
            // ...while null reads as absent.
            with(entry("/null-digest"), "image_digest", json!(null)),
        ]);
        let paths: Vec<_> = b.rows.iter().map(|r| r.path.as_str()).collect();
        // Sorted by key: the unknown digest ("") first.
        assert_eq!(paths, vec!["/null-digest", "/extra", "/ok"]);
        assert_eq!(b.rows[0].image_digest, "");
        assert_eq!(b.dropped, 9);
    }

    #[test]
    fn kind_filter_and_limit() {
        assert_eq!(parse_kind_filter(None), Ok(None));
        assert_eq!(parse_kind_filter(Some(" ")), Ok(None));
        assert_eq!(parse_kind_filter(Some("lib")), Ok(Some("lib".into())));
        assert_eq!(parse_kind_filter(Some("exec")), Ok(Some("exec".into())));
        assert!(parse_kind_filter(Some("EXEC!")).is_err());
        assert_eq!(clamp_runtime_limit(None), RUNTIME_DEFAULT_LIMIT);
        assert_eq!(clamp_runtime_limit(Some(0)), 1);
        assert_eq!(clamp_runtime_limit(Some(99_999)), RUNTIME_MAX_LIMIT);
        assert_eq!(clamp_runtime_limit(Some(42)), 42);
    }

    #[test]
    fn sql_is_bounded_and_upsert_never_downgrades() {
        for sql in [WORKLOAD_RUNTIME_SQL, IMAGE_RUNTIME_SQL.as_str()] {
            assert!(sql.contains("LIMIT $"), "{sql}");
            assert!(sql.contains("ORDER BY"), "{sql}");
        }
        assert!(RUNTIME_UPSERT_SQL.contains("GREATEST(r.last_seen"));
        assert!(RUNTIME_UPSERT_SQL.contains("LEAST(r.first_seen"));
        assert!(RUNTIME_UPSERT_SQL.contains("r.path_complete OR EXCLUDED.path_complete"));
    }

    fn wrow(container: &str, digest: &str, kind: &str, path: &str) -> WorkloadRuntimeRow {
        WorkloadRuntimeRow {
            container_name: container.into(),
            image_digest: digest.into(),
            kind: kind.into(),
            path: path.into(),
            source: "ebpf".into(),
            origin: "image".into(),
            path_complete: true,
            first_seen: NaiveDateTime::default(),
            last_seen: NaiveDateTime::default(),
        }
    }

    #[test]
    fn grouping_splits_per_container_and_digest() {
        let g = group_workload_rows(vec![
            wrow("app", D, "exec", "/usr/bin/a"),
            wrow("app", D, "lib", "/lib/x.so"),
            wrow("app", D2, "exec", "/usr/bin/a"),
            wrow("side", "", "exec", "/bin/sh"),
        ]);
        assert_eq!(g.len(), 3);
        assert_eq!(g[0].entries.len(), 2);
        assert_eq!(g[1].image_digest, D2);
        assert_eq!(g[2].image_digest, "");
        let v = serde_json::to_value(&g[0]).unwrap();
        assert!(v.get("containerName").is_some() && v["entries"][0].get("pathComplete").is_some());
    }

    // ---- live database ------------------------------------------------
    //
    // Same gate as the other live tests: ignored by default, run by CI's
    // `cargo test -- --ignored` step against a real Postgres with the
    // shipped migrations applied.

    const TEST_MIGRATIONS: diesel_migrations::EmbeddedMigrations =
        diesel_migrations::embed_migrations!("./db/migrations");

    fn live_conn() -> PgConnection {
        use diesel::connection::SimpleConnection;
        use diesel_migrations::MigrationHarness;
        let Ok(url) = std::env::var("KG_TEST_DATABASE_URL") else {
            panic!("set KG_TEST_DATABASE_URL to run this test");
        };
        let mut conn = PgConnection::establish(&url).expect("connect");
        conn.run_pending_migrations(TEST_MIGRATIONS)
            .expect("apply the shipped migrations");
        conn.batch_execute("TRUNCATE runtime_executables")
            .expect("reset the runtime inventory");
        conn
    }

    fn now_entry(path: &str, workload: &str, kind: &str, source: &str) -> serde_json::Value {
        let now = chrono::Utc::now().naive_utc();
        let mut e = entry(path);
        e["workload_name"] = json!(workload);
        e["kind"] = json!(kind);
        e["source"] = json!(source);
        e["first_seen"] = json!(now - chrono::Duration::seconds(60));
        e["last_seen"] = json!(now);
        e
    }

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_upsert_skips_steady_state_and_upgrades_evidence() {
        use diesel::connection::SimpleConnection;
        let mut conn = live_conn();
        let post = |conn: &mut PgConnection, v: Vec<serde_json::Value>| {
            upsert_rows(conn, &batch_from_post(v).rows).unwrap()
        };
        let backfill = with(
            now_entry("/usr/bin/nginx", "web", "exec", "backfill"),
            "path_complete",
            json!(false),
        );
        assert_eq!(
            post(
                &mut conn,
                vec![
                    backfill.clone(),
                    now_entry("/lib/libc.so.6", "web", "lib", "ebpf")
                ]
            ),
            2
        );
        // Identical re-post: nothing written.
        assert_eq!(post(&mut conn, vec![backfill.clone()]), 0);
        // An eBPF sighting upgrades the backfilled row, and completes it.
        assert_eq!(
            post(
                &mut conn,
                vec![now_entry("/usr/bin/nginx", "web", "exec", "ebpf")]
            ),
            1
        );
        // A later backfill never downgrades it.
        assert_eq!(post(&mut conn, vec![backfill]), 0);
        let w = workload_runtime(
            &mut conn,
            "prod",
            "Deployment",
            "web",
            &RuntimeFilter::default(),
            100,
        )
        .unwrap();
        assert_eq!(w.containers.len(), 1);
        let e = &w.containers[0].entries;
        assert_eq!(
            e.iter()
                .map(|e| (e.kind.as_str(), e.path.as_str()))
                .collect::<Vec<_>>(),
            vec![("exec", "/usr/bin/nginx"), ("lib", "/lib/libc.so.6")]
        );
        assert_eq!(e[0].source, "ebpf");
        assert!(e[0].path_complete);

        // A stale row is refreshed.
        conn.batch_execute(&format!(
            "UPDATE runtime_executables SET last_seen = last_seen - INTERVAL '{} seconds'",
            REFRESH_SECS * 2
        ))
        .unwrap();
        assert_eq!(
            post(
                &mut conn,
                vec![now_entry("/usr/bin/nginx", "web", "exec", "ebpf")]
            ),
            1
        );

        // A timestamp from the future is clamped to the database clock.
        let mut future = now_entry("/usr/bin/future", "web", "exec", "ebpf");
        future["last_seen"] = json!(chrono::Utc::now().naive_utc() + chrono::Duration::days(365));
        post(&mut conn, vec![future]);
        let w = workload_runtime(
            &mut conn,
            "prod",
            "Deployment",
            "web",
            &RuntimeFilter {
                kind: Some("exec".to_string()),
                ..Default::default()
            },
            100,
        )
        .unwrap();
        let f = w.containers[0]
            .entries
            .iter()
            .find(|e| e.path == "/usr/bin/future")
            .unwrap();
        assert!(f.last_seen <= chrono::Utc::now().naive_utc() + chrono::Duration::seconds(5));
        assert!(f.first_seen <= f.last_seen);

        // Origin: a more suspicious sighting is written at once (no
        // refresh wait), a less suspicious one never downgrades it, and
        // the drift read returns exactly the unshipped rows.
        let origin = |conn: &mut PgConnection, p: &str| -> String {
            let w = workload_runtime(
                conn,
                "prod",
                "Deployment",
                "web",
                &RuntimeFilter::default(),
                100,
            )
            .unwrap();
            w.containers[0]
                .entries
                .iter()
                .find(|e| e.path == p)
                .unwrap()
                .origin
                .clone()
        };
        let o = |p: &str, origin: &str| {
            with(now_entry(p, "web", "exec", "ebpf"), "origin", json!(origin))
        };
        assert_eq!(post(&mut conn, vec![o("/tmp/dropper", "image")]), 1);
        assert_eq!(post(&mut conn, vec![o("/tmp/dropper", "writableLayer")]), 1);
        assert_eq!(origin(&mut conn, "/tmp/dropper"), "writableLayer");
        assert_eq!(post(&mut conn, vec![o("/tmp/dropper", "image")]), 0);
        assert_eq!(origin(&mut conn, "/tmp/dropper"), "writableLayer");
        post(&mut conn, vec![o("/memfd:x", "memfd")]);
        let drift =
            workload_unshipped_executables(&mut conn, "prod", "Deployment", "web", 100).unwrap();
        let paths: Vec<_> = drift.containers[0]
            .entries
            .iter()
            .map(|e| (e.path.as_str(), e.origin.as_str()))
            .collect();
        assert_eq!(
            paths,
            vec![("/memfd:x", "memfd"), ("/tmp/dropper", "writableLayer")]
        );
        assert!(workload_has_inventory(&mut conn, "prod", "Deployment", "web").unwrap());
        assert!(!workload_has_inventory(&mut conn, "prod", "Deployment", "nope").unwrap());
        let img = image_runtime(&mut conn, D, Some("exec"), 100).unwrap();
        assert_eq!(
            img.entries
                .iter()
                .find(|e| e.path == "/tmp/dropper")
                .unwrap()
                .origin,
            "writableLayer"
        );
    }

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_reads_are_bounded_filtered_and_aggregated() {
        let mut conn = live_conn();
        let mut batch = Vec::new();
        for w in ["web", "api"] {
            batch.push(now_entry("/usr/bin/nginx", w, "exec", "ebpf"));
            batch.push(now_entry("/lib/libc.so.6", w, "lib", "ebpf"));
        }
        batch.push(now_entry("/usr/bin/only-web", "web", "exec", "ebpf"));
        batch.push(with(
            now_entry("/usr/bin/sidecar", "web", "exec", "ebpf"),
            "container_name",
            json!("side"),
        ));
        // More than one chunk.
        for i in 0..(UPSERT_CHUNK + 5) {
            batch.push(now_entry(
                &format!("/lib/gen{i:05}.so"),
                "bulk",
                "lib",
                "ebpf",
            ));
        }
        assert_eq!(
            upsert_rows(&mut conn, &batch_from_post(batch).rows).unwrap(),
            4 + 2 + UPSERT_CHUNK + 5
        );

        let web = workload_runtime(
            &mut conn,
            "prod",
            "Deployment",
            "web",
            &RuntimeFilter::default(),
            100,
        )
        .unwrap();
        assert_eq!(web.containers.len(), 2);
        assert!(!web.truncated);
        let app = workload_runtime(
            &mut conn,
            "prod",
            "Deployment",
            "web",
            &RuntimeFilter {
                container: Some("app".to_string()),
                kind: Some("exec".to_string()),
                ..Default::default()
            },
            100,
        )
        .unwrap();
        assert_eq!(app.containers.len(), 1);
        assert_eq!(app.containers[0].entries.len(), 2);
        let page = workload_runtime(
            &mut conn,
            "prod",
            "Deployment",
            "bulk",
            &RuntimeFilter::default(),
            10,
        )
        .unwrap();
        assert!(page.truncated);
        assert_eq!(page.containers[0].entries.len(), 10);
        assert_eq!(page.containers[0].entries[0].path, "/lib/gen00000.so");

        let img = image_runtime(&mut conn, D, Some("exec"), 100).unwrap();
        let by: BTreeMap<_, _> = img
            .entries
            .iter()
            .map(|e| (e.path.as_str(), e.workloads))
            .collect();
        assert_eq!(by["/usr/bin/nginx"], 2);
        assert_eq!(by["/usr/bin/only-web"], 1);
        assert_eq!(by["/usr/bin/sidecar"], 1);
        assert!(img.entries.iter().all(|e| e.kind == "exec"));
        let libs = image_runtime(&mut conn, D, Some("lib"), 5).unwrap();
        assert!(libs.truncated);
        assert!(image_runtime(&mut conn, D2, None, 100)
            .unwrap()
            .entries
            .is_empty());
    }

    // ---- coverage ------------------------------------------------------

    fn beat(
        cid: &str,
        pod: &str,
        name: &str,
        start_mode: &str,
        tracking_h: i64,
        beat_h: i64,
    ) -> CoverageEntry {
        let now = chrono::Utc::now().naive_utc();
        CoverageEntry {
            pod_namespace: "covns".into(),
            pod_name: pod.into(),
            workload_kind: "Deployment".into(),
            workload_name: name.into(),
            container_name: "app".into(),
            image_digest: D.into(),
            container_id: cid.into(),
            node_name: "n1".into(),
            mode: "full".into(),
            exec_probe: true,
            lib_probe: true,
            start_mode: start_mode.into(),
            tracking_since: now - chrono::Duration::hours(tracking_h),
            gap: None,
            ended: false,
            heartbeat_at: now - chrono::Duration::hours(beat_h),
            heartbeat_secs: 300,
        }
    }

    #[test]
    fn heartbeats_are_validated() {
        let ok = beat("abc123", "web-1", "web", "start", 1, 0);
        assert!(valid_coverage(ok.clone()).is_some());
        for bad in [
            CoverageEntry {
                container_id: "../x".into(),
                ..ok.clone()
            },
            CoverageEntry {
                mode: "some".into(),
                ..ok.clone()
            },
            CoverageEntry {
                start_mode: "later".into(),
                ..ok.clone()
            },
            CoverageEntry {
                image_digest: "sha256:XYZ".into(),
                ..ok.clone()
            },
            CoverageEntry {
                heartbeat_secs: 0,
                ..ok.clone()
            },
            CoverageEntry {
                pod_namespace: " ".into(),
                ..ok.clone()
            },
        ] {
            assert!(valid_coverage(bad.clone()).is_none(), "{bad:?}");
        }
        let odd = valid_coverage(CoverageEntry {
            gap: Some("cosmic_ray".into()),
            ..ok
        })
        .unwrap();
        assert_eq!(
            odd.gap.as_deref(),
            Some("other"),
            "an unknown gap is still a gap"
        );
    }

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_coverage_function_follows_the_contract() {
        use diesel::connection::SimpleConnection;
        let mut conn = live_conn();
        conn.batch_execute(
            "DELETE FROM runtime_coverage WHERE pod_namespace = 'covns'; \
             DELETE FROM pod_details WHERE pod_namespace = 'covns';",
        )
        .unwrap();
        let cov = |conn: &mut PgConnection, name: &str| {
            runtime_coverage(conn, ("covns", "Deployment", name, "app", "primary"), D, 24).unwrap()
        };
        let put =
            |conn: &mut PgConnection, b: Vec<CoverageEntry>| upsert_coverage(conn, &b).unwrap();
        let hours_ago = |t: Option<NaiveDateTime>| {
            (chrono::Utc::now().naive_utc() - t.unwrap()).num_minutes() as f64 / 60.0
        };

        // The signature P1-5 checks for with to_regprocedure.
        #[derive(QueryableByName)]
        struct E {
            #[diesel(sql_type = Bool)]
            e: bool,
        }
        let e: E = sql_query(
            "SELECT to_regprocedure('kg_runtime_coverage(text,text,text,text,text,text,integer)') \
             IS NOT NULL AS e",
        )
        .get_result(&mut conn)
        .unwrap();
        assert!(e.e);

        // Nothing reported.
        let a = cov(&mut conn, "none");
        assert_eq!(
            (a.covered, a.reason.as_deref()),
            (Some(false), Some("no_runtime_data"))
        );

        // Captured from its start 30 h ago, heartbeating: covered.
        put(
            &mut conn,
            vec![beat("c1", "p1", "fromstart", "start", 30, 0)],
        );
        let a = cov(&mut conn, "fromstart");
        assert_eq!((a.covered, a.reason.as_deref()), (Some(true), None));
        assert!((hours_ago(a.observed_since) - 30.0).abs() < 0.1);

        // From start, but only 2 h old: not yet long enough.
        put(&mut conn, vec![beat("c2", "p2", "young", "start", 2, 0)]);
        let a = cov(&mut conn, "young");
        assert_eq!(
            (a.covered, a.reason.as_deref()),
            (Some(false), Some("capture_gap"))
        );

        // Backfilled 30 h ago: covered for the window after the backfill.
        put(
            &mut conn,
            vec![beat("c3", "p3", "backfilled", "backfill", 30, 0)],
        );
        assert_eq!(cov(&mut conn, "backfilled").covered, Some(true));
        // Backfilled 3 h ago: the container ran unobserved before that.
        put(
            &mut conn,
            vec![beat("c3b", "p3b", "backfill-late", "backfill", 3, 0)],
        );
        assert_eq!(
            cov(&mut conn, "backfill-late").reason.as_deref(),
            Some("capture_gap")
        );

        // A heartbeat gap (30 h of silence) restarts coverage.
        put(&mut conn, vec![beat("c4", "p4", "silent", "start", 31, 30)]);
        put(&mut conn, vec![beat("c4", "p4", "silent", "start", 31, 0)]);
        let a = cov(&mut conn, "silent");
        assert_eq!(
            (a.covered, a.reason.as_deref()),
            (Some(false), Some("capture_gap"))
        );
        assert!(
            hours_ago(a.observed_since) < 0.1,
            "coverage restarts at the late beat"
        );
        #[derive(QueryableByName)]
        struct G {
            #[diesel(sql_type = diesel::sql_types::Integer)]
            gaps: i32,
            #[diesel(sql_type = Nullable<Text>)]
            last_gap: Option<String>,
        }
        let g: G =
            sql_query("SELECT gaps, last_gap FROM runtime_coverage WHERE container_id = 'c4'")
                .get_result(&mut conn)
                .unwrap();
        assert_eq!((g.gaps, g.last_gap.as_deref()), (1, Some("late_heartbeat")));

        // Heartbeats on time keep coverage; a reported gap restarts it.
        let mut b = beat("c5", "p5", "drops", "start", 30, 0);
        b.heartbeat_at -= chrono::Duration::minutes(10);
        put(&mut conn, vec![b.clone()]);
        b.heartbeat_at += chrono::Duration::minutes(5);
        put(&mut conn, vec![b.clone()]);
        assert_eq!(
            cov(&mut conn, "drops").covered,
            Some(true),
            "on-time beats keep it"
        );
        b.heartbeat_at += chrono::Duration::minutes(5);
        b.gap = Some("kernel_drops".into());
        put(&mut conn, vec![b.clone()]);
        assert_eq!(
            cov(&mut conn, "drops").reason.as_deref(),
            Some("capture_gap")
        );
        // An out-of-order (older) heartbeat is ignored.
        let mut old = b.clone();
        old.heartbeat_at -= chrono::Duration::hours(1);
        old.gap = None;
        assert_eq!(put(&mut conn, vec![old]), 0);

        // Exec-only capture cannot vouch for libraries.
        let mut x = beat("c6", "p6", "execonly", "start", 30, 0);
        x.mode = "exec".into();
        x.lib_probe = false;
        put(&mut conn, vec![x]);
        assert_eq!(
            cov(&mut conn, "execonly").reason.as_deref(),
            Some("probes_missing")
        );

        // Stopped heartbeating without ending: the controller is gone.
        put(&mut conn, vec![beat("c7", "p7", "stale", "start", 30, 2)]);
        assert_eq!(
            cov(&mut conn, "stale").reason.as_deref(),
            Some("capture_gap")
        );

        // A replica that ended cleanly plus its successor, both from start.
        let mut gone = beat("c8a", "p8a", "rolled", "start", 40, 10);
        gone.ended = true;
        put(&mut conn, vec![gone.clone()]);
        put(
            &mut conn,
            vec![beat("c8b", "p8b", "rolled", "start", 10, 0)],
        );
        let a = cov(&mut conn, "rolled");
        assert_eq!(a.covered, Some(true));
        assert!((hours_ago(a.observed_since) - 40.0).abs() < 0.1);
        // Ended rows are frozen.
        gone.ended = false;
        gone.heartbeat_at = chrono::Utc::now().naive_utc();
        assert_eq!(put(&mut conn, vec![gone]), 0);

        // A live pod of the workload with no heartbeat (a node with the
        // feature off) makes the whole workload uncovered.
        put(&mut conn, vec![beat("c9", "p9", "partial", "start", 30, 0)]);
        assert_eq!(cov(&mut conn, "partial").covered, Some(true));
        conn.batch_execute(
            "INSERT INTO pod_details (pod_name, pod_ip, pod_namespace, pod_obj, time_stamp, \
               node_name, is_dead, workload_kind, workload_name) VALUES \
             ('p9', '10.0.0.9', 'covns', '{\"spec\":{\"containers\":[{\"name\":\"app\"}]}}', \
               timezone('UTC', NOW()), 'n1', false, 'Deployment', 'partial'), \
             ('p9-other-node', '10.0.0.10', 'covns', \
               '{\"spec\":{\"containers\":[{\"name\":\"app\"}]}}', \
               timezone('UTC', NOW()), 'n2', false, 'Deployment', 'partial'), \
             ('p9-no-app', '10.0.0.11', 'covns', \
               '{\"spec\":{\"containers\":[{\"name\":\"sidecar\"}]}}', \
               timezone('UTC', NOW()), 'n2', false, 'Deployment', 'partial');",
        )
        .unwrap();
        assert_eq!(
            cov(&mut conn, "partial").reason.as_deref(),
            Some("capture_gap")
        );
        conn.batch_execute(
            "UPDATE pod_details SET is_dead = true WHERE pod_name = 'p9-other-node'",
        )
        .unwrap();
        assert_eq!(
            cov(&mut conn, "partial").covered,
            Some(true),
            "dead pods do not count"
        );

        // Called the way P1-5 calls it: LATERAL over varchar columns.
        #[derive(QueryableByName)]
        struct L {
            #[diesel(sql_type = Nullable<Bool>)]
            covered: Option<bool>,
        }
        let l: L = sql_query(
            "SELECT k.covered FROM (SELECT 'primary'::varchar AS c, 'covns'::varchar AS ns, \
               'Deployment'::varchar AS wk, 'fromstart'::varchar AS wn, 'app'::varchar AS cn, \
               $1::varchar AS dg) wc \
             LEFT JOIN LATERAL kg_runtime_coverage(wc.c, wc.ns, wc.wk, wc.wn, wc.cn, wc.dg, $2) k \
               ON true",
        )
        .bind::<Text, _>(D)
        .bind::<diesel::sql_types::Integer, _>(24)
        .get_result(&mut conn)
        .unwrap();
        assert_eq!(l.covered, Some(true));

        // Other images of the same container are not this image's evidence.
        assert_eq!(
            runtime_coverage(
                &mut conn,
                ("covns", "Deployment", "fromstart", "app", "primary"),
                D2,
                24
            )
            .unwrap()
            .reason
            .as_deref(),
            Some("no_runtime_data")
        );

        conn.batch_execute(
            "DELETE FROM runtime_coverage WHERE pod_namespace = 'covns'; \
             DELETE FROM pod_details WHERE pod_namespace = 'covns';",
        )
        .unwrap();
    }
}
