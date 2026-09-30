//! From a worker response to the Broker's catalog ingest: validate the
//! untrusted response, apply what the Controller knows that the worker
//! does not (drift unknown), and cut it into pages.
//!
//! The worker validates before answering, but a compromised scan child
//! can return any JSON within the size limit (PROTOCOL.md 6), so every
//! bound is applied again here.

use std::collections::BTreeSet;

use super::api::{
    Component, Page, SbomImage, SbomPage, Scanner, COMPONENTS_PER_PAGE, MAX_PAGES, MAX_PAGE_BYTES,
    MAX_PARTIAL_REASONS, MAX_PATHS_PER_COMPONENT, MAX_PATHS_PER_PAGE, SBOM_FORMAT, SBOM_SOURCE,
    SBOM_TRUST,
};
use super::worker::{Response, PROTOCOL_VERSION};

const MAX_NAME: usize = 256;
const MAX_VERSION: usize = 128;
const MAX_FIELD: usize = 2048;
const MAX_LICENSES: usize = 8;
const MAX_LICENSE: usize = 256;
const MAX_PATH: usize = 1024;
const MAX_REASON: usize = 64;
/// Components in one SBOM (the Broker's `MAX_SBOM_COMPONENTS`).
pub const MAX_COMPONENTS: usize = 50_000;
/// `stats` kept verbatim up to this size; over it only scalars survive
/// (the Broker applies the same rule at 16 KiB).
const MAX_STATS_BYTES: usize = 16 * 1024;

/// What a validated response says.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Components to post.
    Sbom(Sbom),
    /// `failed`, with the worker's reason verbatim (mapped by the caller).
    Failed { reason: String, message: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Sbom {
    pub completeness: String,
    pub partial_reasons: Vec<String>,
    pub scanner: Scanner,
    pub stats: serde_json::Value,
    pub components: Vec<Component>,
}

/// A response the Controller refuses outright (a bug or a hostile peer):
/// the claim fails with `error`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid(pub String);

fn bounded(s: Option<String>, max: usize) -> Option<String> {
    s.filter(|v| !v.is_empty() && v.len() <= max && !v.contains('\0'))
}

/// PROTOCOL.md 4.3 path rules: absolute, clean, no NUL, at most 1024
/// bytes. (UTF-8 is guaranteed by the JSON decoder.)
pub fn valid_path(p: &str) -> bool {
    if !p.starts_with('/') || p.len() > MAX_PATH || p.contains('\0') {
        return false;
    }
    p == "/"
        || p[1..]
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != "..")
}

fn clean_component(mut c: Component) -> Option<Component> {
    if c.name.is_empty() || c.name.len() > MAX_NAME || c.name.contains('\0') {
        return None;
    }
    if c.version.as_ref().is_some_and(|v| v.len() > MAX_VERSION) {
        return None;
    }
    c.version = bounded(c.version, MAX_VERSION);
    c.purl = bounded(c.purl, MAX_FIELD);
    c.comp_type = bounded(c.comp_type, MAX_REASON * 2);
    c.class = bounded(c.class, MAX_REASON);
    c.src_name = bounded(c.src_name, MAX_NAME);
    c.src_version = bounded(c.src_version, MAX_VERSION);
    c.licenses
        .retain(|l| !l.is_empty() && l.len() <= MAX_LICENSE);
    c.licenses.truncate(MAX_LICENSES);
    let before = c.file_paths.len();
    let paths: BTreeSet<String> = c.file_paths.drain(..).filter(|p| valid_path(p)).collect();
    let mut paths: Vec<String> = paths.into_iter().collect();
    if paths.len() > MAX_PATHS_PER_COMPONENT {
        paths.truncate(MAX_PATHS_PER_COMPONENT);
    }
    // Dropped or deduplicated-away paths mean the list is not the
    // package's complete one.
    if paths.len() != before {
        c.files_truncated = true;
    }
    c.file_paths = paths;
    Some(c)
}

fn push_reason(reasons: &mut Vec<String>, r: &str) {
    if !reasons.iter().any(|x| x == r) {
        reasons.push(r.to_string());
    }
}

/// `stats`, kept when small; otherwise only its scalar fields.
fn bounded_stats(v: serde_json::Value) -> serde_json::Value {
    let serde_json::Value::Object(map) = v else {
        return serde_json::json!({});
    };
    let v = serde_json::Value::Object(map);
    if serde_json::to_vec(&v)
        .map(|b| b.len())
        .unwrap_or(usize::MAX)
        <= MAX_STATS_BYTES
    {
        return v;
    }
    let serde_json::Value::Object(map) = v else {
        unreachable!()
    };
    serde_json::Value::Object(
        map.into_iter()
            .filter(|(k, v)| k.len() <= 64 && !v.is_object() && !v.is_array())
            .filter(|(_, v)| !v.as_str().is_some_and(|s| s.len() > 256))
            .collect(),
    )
}

/// Validate a response to scan `scan_id` under `epoch`.
///
/// `drift_unknown`: the Controller could not check the upperdir, so the
/// SBOM may include packages installed at runtime; it is never `full`.
pub fn validate(
    r: Response,
    scan_id: &str,
    epoch: i64,
    drift_unknown: bool,
) -> Result<Outcome, Invalid> {
    if r.protocol_version != PROTOCOL_VERSION {
        return Err(Invalid(format!(
            "worker speaks protocol {}, not {PROTOCOL_VERSION}",
            r.protocol_version
        )));
    }
    if r.scan_id != scan_id {
        return Err(Invalid("response for another scan".into()));
    }
    if r.epoch != epoch {
        return Err(Invalid(format!(
            "response epoch {} for a scan under {epoch}",
            r.epoch
        )));
    }
    match r.status.as_str() {
        "ok" => {}
        "failed" => {
            let mut message = r.message;
            message.truncate(message.floor_char_boundary(1024));
            let reason = if r.reason.is_empty() || r.reason.len() > MAX_REASON {
                "error".to_string()
            } else {
                r.reason
            };
            return Ok(Outcome::Failed { reason, message });
        }
        other => return Err(Invalid(format!("unknown status {other:?}"))),
    }
    if r.components.len() > MAX_COMPONENTS {
        return Err(Invalid(format!(
            "{} components; at most {MAX_COMPONENTS}",
            r.components.len()
        )));
    }

    let mut reasons: Vec<String> = r
        .partial_reasons
        .into_iter()
        .filter(|s| !s.is_empty() && s.len() <= MAX_REASON)
        .collect();
    // PROTOCOL.md 5: an unknown completeness is partial.
    let mut completeness = match r.completeness.as_str() {
        "full" | "partial" | "os_only" => r.completeness,
        _ => "partial".to_string(),
    };

    let total = r.components.len();
    let mut components: Vec<Component> = r
        .components
        .into_iter()
        .filter_map(clean_component)
        .collect();
    if components.len() != total {
        push_reason(&mut reasons, "components_dropped");
    }
    if components.iter().any(|c| c.files_truncated) {
        push_reason(&mut reasons, "files_truncated");
    }
    if drift_unknown {
        push_reason(&mut reasons, "drift_unknown");
    }
    // The only non-operating-system components count as packages; an
    // `ok` with none is the worker's `no_packages_found`, which it should
    // have said. Say it for it rather than store an empty SBOM.
    if !components
        .iter()
        .any(|c| c.comp_type.as_deref() != Some("operating-system"))
    {
        return Ok(Outcome::Failed {
            reason: "no_packages_found".into(),
            message: "ok response with no packages".into(),
        });
    }
    if completeness == "full" && !reasons.is_empty() {
        completeness = "partial".into();
    }
    reasons.truncate(MAX_PARTIAL_REASONS);

    let mut stats = bounded_stats(r.stats);
    if !r.retry_reason.is_empty() && r.retry_reason.len() <= MAX_REASON {
        // The Broker does not read retry_reason; keep it with the stats.
        if let serde_json::Value::Object(m) = &mut stats {
            m.insert("retry_reason".into(), r.retry_reason.into());
        }
    }
    // Deterministic order, so an unchanged image posts an unchanged set.
    components.sort_by(|a, b| {
        (&a.comp_type, &a.name, &a.version, &a.purl).cmp(&(
            &b.comp_type,
            &b.name,
            &b.version,
            &b.purl,
        ))
    });
    Ok(Outcome::Sbom(Sbom {
        completeness,
        partial_reasons: reasons,
        scanner: Scanner {
            name: Some(SBOM_FORMAT.to_string()),
            vendor: bounded(r.scanner.vendor, MAX_NAME),
            version: bounded(r.scanner.version, MAX_VERSION),
        },
        stats,
        components,
    }))
}

/// What the SBOM is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    pub digest: String,
    pub digest_kind: Option<String>,
    pub repository: Option<String>,
    pub platform: String,
    pub epoch: i64,
}

fn approx_bytes(c: &Component) -> usize {
    // A little over the encoded size: field names, quotes, commas.
    200 + c.name.len()
        + c.version.as_ref().map_or(0, String::len)
        + c.purl.as_ref().map_or(0, String::len)
        + c.licenses.iter().map(|l| l.len() + 3).sum::<usize>()
        + c.file_paths.iter().map(|p| p.len() + 3).sum::<usize>()
}

/// Cut `sbom` into pages: at most [`COMPONENTS_PER_PAGE`] components,
/// [`MAX_PATHS_PER_PAGE`] paths and about [`MAX_PAGE_BYTES`] each. Every
/// page carries the same completeness, reasons and stats (the Broker
/// keeps the completing page's). `Err` when it would take more than
/// [`MAX_PAGES`] pages.
pub fn pages(
    subject: &Subject,
    sbom: &Sbom,
    set_id: &str,
    scanned_at: &str,
) -> Result<Vec<SbomPage>, Invalid> {
    let mut groups: Vec<Vec<Component>> = vec![Vec::new()];
    let (mut bytes, mut paths) = (0usize, 0usize);
    for c in &sbom.components {
        let b = approx_bytes(c);
        let cur = groups.last().expect("never empty");
        if !cur.is_empty()
            && (cur.len() >= COMPONENTS_PER_PAGE
                || bytes + b > MAX_PAGE_BYTES
                || paths + c.file_paths.len() > MAX_PATHS_PER_PAGE)
        {
            groups.push(Vec::new());
            bytes = 0;
            paths = 0;
        }
        bytes += b;
        paths += c.file_paths.len();
        groups.last_mut().expect("never empty").push(c.clone());
    }
    if groups.len() > MAX_PAGES {
        return Err(Invalid(format!(
            "{} pages; at most {MAX_PAGES}",
            groups.len()
        )));
    }
    let total = groups.len() as i64;
    Ok(groups
        .into_iter()
        .enumerate()
        .map(|(i, components)| SbomPage {
            schema_version: 1,
            image: SbomImage {
                digest: subject.digest.clone(),
                digest_kind: subject.digest_kind.clone(),
                repository: subject.repository.clone(),
                index_digest: subject.digest.clone(),
            },
            source: SBOM_SOURCE,
            sbom_trust: SBOM_TRUST,
            scanner: sbom.scanner.clone(),
            scanned_at: scanned_at.to_string(),
            format: SBOM_FORMAT,
            page: Page {
                set_id: set_id.to_string(),
                index: i as i64,
                total,
            },
            components,
            epoch: subject.epoch,
            completeness: sbom.completeness.clone(),
            partial_reasons: sbom.partial_reasons.clone(),
            stats: sbom.stats.clone(),
            platform: subject.platform.clone(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn comp(name: &str, paths: Vec<String>) -> Component {
        Component {
            name: name.into(),
            version: Some("1.0".into()),
            comp_type: Some("apk".into()),
            file_paths: paths,
            ..Default::default()
        }
    }

    fn resp(components: Vec<Component>) -> Response {
        Response {
            protocol_version: 1,
            scan_id: "s".into(),
            epoch: 2,
            status: "ok".into(),
            reason: String::new(),
            message: String::new(),
            completeness: "full".into(),
            partial_reasons: vec![],
            retry_reason: String::new(),
            scanner: Scanner {
                name: Some("kguardian-cataloger".into()),
                vendor: Some("kguardian".into()),
                version: Some("0.1.0".into()),
            },
            os: None,
            stats: serde_json::json!({"files": 10}),
            components,
        }
    }

    fn sbom(o: Outcome) -> Sbom {
        match o {
            Outcome::Sbom(s) => s,
            other => panic!("expected an SBOM, got {other:?}"),
        }
    }

    #[test]
    fn a_clean_response_stays_full() {
        let s = sbom(
            validate(
                resp(vec![comp("busybox", vec!["/bin/busybox".into()])]),
                "s",
                2,
                false,
            )
            .unwrap(),
        );
        assert_eq!(s.completeness, "full");
        assert!(s.partial_reasons.is_empty());
        assert_eq!(s.components[0].file_paths, vec!["/bin/busybox"]);
    }

    #[test]
    fn scan_id_epoch_and_version_must_echo() {
        assert!(validate(resp(vec![]), "other", 2, false).is_err());
        assert!(validate(resp(vec![]), "s", 3, false).is_err());
        let mut r = resp(vec![]);
        r.protocol_version = 2;
        assert!(validate(r, "s", 2, false).is_err());
        let mut r = resp(vec![]);
        r.status = "weird".into();
        assert!(validate(r, "s", 2, false).is_err());
    }

    #[test]
    fn bad_paths_are_dropped_and_mark_the_package_truncated() {
        let s = sbom(
            validate(
                resp(vec![comp(
                    "p",
                    vec![
                        "/usr/bin/ok".into(),
                        "relative/x".into(),
                        "/a/../etc/shadow".into(),
                        "/a//b".into(),
                        format!("/{}", "x".repeat(2000)),
                        "/usr/bin/ok".into(),
                    ],
                )]),
                "s",
                2,
                false,
            )
            .unwrap(),
        );
        assert_eq!(s.components[0].file_paths, vec!["/usr/bin/ok"]);
        assert!(s.components[0].files_truncated);
        assert_eq!(s.completeness, "partial");
        assert!(s.partial_reasons.contains(&"files_truncated".to_string()));
    }

    #[test]
    fn over_long_names_drop_the_component_and_path_lists_are_capped() {
        let many: Vec<String> = (0..5000).map(|i| format!("/usr/lib/x{i:05}.so")).collect();
        let s = sbom(
            validate(
                resp(vec![comp(&"n".repeat(300), vec![]), comp("big", many)]),
                "s",
                2,
                false,
            )
            .unwrap(),
        );
        assert_eq!(s.components.len(), 1);
        assert_eq!(s.components[0].file_paths.len(), MAX_PATHS_PER_COMPONENT);
        assert!(s.components[0].files_truncated);
        assert!(s
            .partial_reasons
            .contains(&"components_dropped".to_string()));
    }

    #[test]
    fn too_many_components_is_refused() {
        let cs = (0..=MAX_COMPONENTS)
            .map(|i| comp(&format!("p{i}"), vec![]))
            .collect();
        assert!(validate(resp(cs), "s", 2, false).is_err());
    }

    #[test]
    fn drift_unknown_is_never_full() {
        let s = sbom(validate(resp(vec![comp("a", vec![])]), "s", 2, true).unwrap());
        assert_eq!(s.completeness, "partial");
        assert_eq!(s.partial_reasons, vec!["drift_unknown"]);
        // os_only stays os_only, with the reason added.
        let mut r = resp(vec![comp("a", vec![])]);
        r.completeness = "os_only".into();
        let s = sbom(validate(r, "s", 2, true).unwrap());
        assert_eq!(s.completeness, "os_only");
    }

    #[test]
    fn unknown_completeness_is_partial_and_failed_passes_the_reason() {
        let mut r = resp(vec![comp("a", vec![])]);
        r.completeness = "mostly".into();
        assert_eq!(
            sbom(validate(r, "s", 2, false).unwrap()).completeness,
            "partial"
        );

        let mut r = resp(vec![]);
        r.status = "failed".into();
        r.reason = "oom".into();
        r.message = "é".repeat(800);
        match validate(r, "s", 2, false).unwrap() {
            Outcome::Failed { reason, message } => {
                assert_eq!(reason, "oom");
                assert!(message.len() <= 1024);
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn an_ok_with_only_the_os_entry_is_no_packages_found() {
        let os = Component {
            name: "alpine".into(),
            version: Some("3.20.3".into()),
            comp_type: Some("operating-system".into()),
            ..Default::default()
        };
        assert!(matches!(
            validate(resp(vec![os]), "s", 2, false).unwrap(),
            Outcome::Failed { ref reason, .. } if reason == "no_packages_found"
        ));
    }

    #[test]
    fn retry_reason_and_oversized_stats_are_handled() {
        let mut r = resp(vec![comp("a", vec![])]);
        r.retry_reason = "oom".into();
        r.stats = serde_json::json!({"files": 1, "blob": "x".repeat(20_000), "nested": {"a": 1}});
        let s = sbom(validate(r, "s", 2, false).unwrap());
        assert_eq!(s.stats["files"], 1);
        assert_eq!(s.stats["retry_reason"], "oom");
        assert!(s.stats.get("blob").is_none());
        assert!(s.stats.get("nested").is_none());
    }

    /// The Broker keeps a partial reason only when it is 1..=64 bytes of
    /// `[A-Za-z0-9_.-]` (node_catalog.rs `clean_short`, no closed set).
    /// Every reason the Controller adds must pass, `drift_unknown` first.
    #[test]
    fn the_controllers_own_partial_reasons_pass_the_broker_filter() {
        let broker_keeps = |r: &str| {
            !r.is_empty()
                && r.len() <= 64
                && r.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        };
        let mut r = resp(vec![
            comp("a", vec!["relative".into()]),
            comp(&"n".repeat(300), vec![]),
        ]);
        r.completeness = "full".into();
        let s = sbom(validate(r, "s", 2, true).unwrap());
        assert_eq!(
            s.partial_reasons,
            vec!["components_dropped", "files_truncated", "drift_unknown"]
        );
        assert!(s.partial_reasons.iter().all(|r| broker_keeps(r)));
    }

    fn subject() -> Subject {
        Subject {
            digest: format!("sha256:{}", "a".repeat(64)),
            digest_kind: Some("repo".into()),
            repository: Some("docker.io/library/nginx".into()),
            platform: "linux/arm64".into(),
            epoch: 2,
        }
    }

    #[test]
    fn pages_split_by_count_and_carry_the_catalog_fields() {
        let cs: Vec<Component> = (0..4500)
            .map(|i| comp(&format!("p{i:05}"), vec![]))
            .collect();
        let s = sbom(validate(resp(cs), "s", 2, false).unwrap());
        let pages = pages(&subject(), &s, "set-1", "2026-10-03T10:00:00Z").unwrap();
        assert_eq!(pages.len(), 3);
        assert_eq!(
            pages.iter().map(|p| p.components.len()).sum::<usize>(),
            4500
        );
        for (i, p) in pages.iter().enumerate() {
            assert_eq!(p.page.index, i as i64);
            assert_eq!(p.page.total, 3);
            assert_eq!(p.page.set_id, "set-1");
            assert_eq!(p.epoch, 2);
            assert_eq!(p.completeness, "full");
            assert_eq!(p.source, "node");
            assert_eq!(p.image.index_digest, p.image.digest);
        }
        let v = serde_json::to_value(&pages[0]).unwrap();
        assert_eq!(v["sbom_trust"], "scanned");
        assert_eq!(v["format"], "kguardian-cataloger");
        assert_eq!(v["platform"], "linux/arm64");
        assert_eq!(v["components"][0]["files_truncated"], false);
        assert_eq!(v["components"][0]["interpreted_content"], false);
        assert!(v["components"][0].get("file_paths").is_none());
    }

    #[test]
    fn pages_split_by_bytes_and_paths() {
        // 60 packages x 4096 paths of ~40 bytes: ~10 MiB of paths, over
        // one page's byte ceiling, and 245 760 paths, over the path cap.
        let cs: Vec<Component> = (0..60)
            .map(|i| {
                comp(
                    &format!("p{i:02}"),
                    (0..4096)
                        .map(|j| format!("/usr/lib/python3/site/p{i:02}/{j:06}.so"))
                        .collect(),
                )
            })
            .collect();
        let s = sbom(validate(resp(cs), "s", 2, false).unwrap());
        let pages = pages(&subject(), &s, "set", "t").unwrap();
        assert!(pages.len() >= 2);
        for p in &pages {
            let bytes = serde_json::to_vec(p).unwrap().len();
            assert!(bytes <= MAX_PAGE_BYTES, "page of {bytes} bytes");
            let n: usize = p.components.iter().map(|c| c.file_paths.len()).sum();
            assert!(n <= MAX_PATHS_PER_PAGE);
        }
    }
}
