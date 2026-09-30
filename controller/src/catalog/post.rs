//! From a worker response to the Broker's catalog ingest: validate the
//! untrusted response, apply what the Controller knows that the worker
//! does not (drift unknown, language-package deletions), and cut it into
//! pages.
//!
//! The worker validates before answering, but a compromised scan child
//! can return any JSON within the size limit (PROTOCOL.md 6), so every
//! bound is applied again: most of them while parsing (see
//! `worker::WireComponent`), the rest here.
//!
//! Memory: nothing here copies components. [`validate`] moves each
//! parsed component into its posted form, and [`pages`] consumes the
//! SBOM and moves components into one page at a time, so the upload
//! holds the SBOM plus a single encoded page (at most
//! [`MAX_PAGE_BYTES`]).

use std::io::Write;

use super::api::{
    Component, Page, SbomImage, SbomPage, Scanner, COMPONENTS_PER_PAGE, MAX_PAGES, MAX_PAGE_BYTES,
    MAX_PARTIAL_REASONS, MAX_PATHS_PER_PAGE, SBOM_FORMAT, SBOM_SOURCE, SBOM_TRUST,
};
use super::worker::{Response, WireComponent, MAX_PATH_LEN, PROTOCOL_VERSION};

/// Components in one SBOM (the Broker's `MAX_SBOM_COMPONENTS`).
pub const MAX_COMPONENTS: usize = super::worker::MAX_COMPONENTS;

/// What a validated response says.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Components to post.
    Sbom(Sbom),
    /// `failed`, with the reason to map (the worker's, or
    /// `no_packages_found` / `error` decided here).
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

/// PROTOCOL.md 4.3 path rules: absolute, clean, no control characters,
/// at most 1024 bytes. (UTF-8 is guaranteed by the JSON decoder.)
pub fn valid_path(p: &str) -> bool {
    if !p.starts_with('/') || p.len() > MAX_PATH_LEN || p.chars().any(char::is_control) {
        return false;
    }
    p == "/"
        || p[1..]
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != "..")
}

/// A parsed component as posted, moved rather than copied. `None` when
/// its name is missing or over-long, or its version over-long (PROTOCOL.md
/// 4.3: such a component is dropped).
fn into_component(c: WireComponent) -> Option<Component> {
    if c.name.too_long || c.version.too_long {
        return None;
    }
    let name = c.name.take()?;
    // A path dropped while parsing (invalid, over-long, over the cap)
    // means the list is not the package's complete one.
    let files_truncated = c.files_truncated || c.file_paths.truncated;
    // An over-long optional field is left out (`take` gives None); it
    // does not drop the package.
    Some(Component {
        name,
        version: c.version.take(),
        purl: c.purl.take(),
        comp_type: c.comp_type.take(),
        class: c.class.take(),
        src_name: c.src_name.take(),
        src_version: c.src_version.take(),
        licenses: c.licenses.0,
        file_paths: c.file_paths.paths,
        files_truncated,
        interpreted_content: c.interpreted_content,
    })
}

fn push_reason(reasons: &mut Vec<String>, r: &str) {
    if !reasons.iter().any(|x| x == r) {
        reasons.push(r.to_string());
    }
}

/// Validate a response to scan `scan_id` under `epoch`.
///
/// `local_reasons`: what the Controller found that makes the SBOM not
/// `full` whatever the worker says (`drift_unknown`, `lang_whiteout`).
///
/// `no_packages_found` is terminal for the digest on the Broker, so it is
/// reported only for a clean, complete scan: completeness `full` (or none
/// on a `failed` answer), no partial reasons from the worker and none
/// from the Controller. Anything less is `error`, which backs off and is
/// retried.
pub fn validate(
    r: Response,
    scan_id: &str,
    epoch: i64,
    local_reasons: &[&str],
) -> Result<Outcome, Invalid> {
    if r.protocol_version != PROTOCOL_VERSION {
        return Err(Invalid(format!(
            "worker speaks protocol {}, not {PROTOCOL_VERSION}",
            r.protocol_version
        )));
    }
    if r.scan_id.as_str() != scan_id {
        return Err(Invalid("response for another scan".into()));
    }
    if r.epoch != epoch {
        return Err(Invalid(format!(
            "response epoch {} for a scan under {epoch}",
            r.epoch
        )));
    }
    let clean_scan = |completeness: &str, reasons: &[String]| {
        matches!(completeness, "" | "full") && reasons.is_empty() && local_reasons.is_empty()
    };
    match r.status.as_str() {
        "ok" => {}
        "failed" => {
            let message = r.message.value.unwrap_or_default();
            let mut reason = r.reason.take().unwrap_or_else(|| "error".to_string());
            if reason == "no_packages_found"
                && !clean_scan(r.completeness.as_str(), &r.partial_reasons.0)
            {
                reason = "error".into();
            }
            return Ok(Outcome::Failed { reason, message });
        }
        other => return Err(Invalid(format!("unknown status {other:?}"))),
    }
    if r.components.overflow {
        return Err(Invalid(format!("over {MAX_COMPONENTS} components")));
    }

    let mut reasons = r.partial_reasons.0;
    // PROTOCOL.md 5: an unknown completeness is partial.
    let mut completeness = match r.completeness.as_str() {
        c @ ("full" | "partial" | "os_only") => c.to_string(),
        _ => "partial".to_string(),
    };

    let total = r.components.items.len();
    let mut components: Vec<Component> = r
        .components
        .items
        .into_iter()
        .filter_map(into_component)
        .collect();
    if components.len() != total {
        push_reason(&mut reasons, "components_dropped");
    }
    if components.iter().any(|c| c.files_truncated) {
        push_reason(&mut reasons, "files_truncated");
    }
    for l in local_reasons {
        push_reason(&mut reasons, l);
    }
    if completeness == "full" && !reasons.is_empty() {
        completeness = "partial".into();
    }
    // Only non-operating-system components count as packages. An `ok`
    // with none is the worker's `no_packages_found` unsaid; terminal only
    // for a clean scan (see above).
    if !components
        .iter()
        .any(|c| c.comp_type.as_deref() != Some("operating-system"))
    {
        let reason = if completeness == "full" && reasons.is_empty() {
            "no_packages_found"
        } else {
            "error"
        };
        return Ok(Outcome::Failed {
            reason: reason.into(),
            message: format!("ok response with no packages ({completeness})"),
        });
    }
    reasons.truncate(MAX_PARTIAL_REASONS);

    let mut stats = r.stats.0;
    if let Some(rr) = r.retry_reason.take() {
        // The Broker does not read retry_reason; keep it with the stats.
        stats.insert("retry_reason".into(), rr.into());
    }
    // Deterministic order, so an unchanged image posts an unchanged set.
    components.sort_unstable_by(|a, b| {
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
            vendor: r.scanner.vendor.take(),
            version: r.scanner.version.take(),
        },
        stats: serde_json::Value::Object(stats),
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

/// Counts bytes written; nothing is kept.
struct Counter(usize);

impl Write for Counter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0 += b.len();
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The exact encoded size of `v`, every field and escape included.
pub fn json_len<T: serde::Serialize>(v: &T) -> usize {
    let mut c = Counter(0);
    serde_json::to_writer(&mut c, v).map_or(usize::MAX, |_| c.0)
}

/// The SBOM, cut into pages lazily: each [`Iterator::next`] moves the
/// next page's components out of the SBOM. Nothing is cloned.
#[derive(Debug)]
pub struct Pages {
    head: SbomPage,
    lens: std::vec::IntoIter<usize>,
    rest: std::vec::IntoIter<Component>,
    index: i64,
}

impl Pages {
    /// Pages in the set.
    pub fn total(&self) -> usize {
        self.head.page.total as usize
    }
}

impl Iterator for Pages {
    type Item = SbomPage;
    fn next(&mut self) -> Option<SbomPage> {
        let n = self.lens.next()?;
        let mut p = self.head.clone(); // header fields only: components is empty
        p.page.index = self.index;
        p.components = self.rest.by_ref().take(n).collect();
        self.index += 1;
        Some(p)
    }
}

/// Headroom for the page index and total digits on top of the measured
/// empty page.
const PAGE_SLACK: usize = 64;

/// Cut `sbom` into pages of at most [`COMPONENTS_PER_PAGE`] components,
/// [`MAX_PATHS_PER_PAGE`] paths and [`MAX_PAGE_BYTES`] encoded bytes,
/// measured exactly. Every page carries the same completeness, reasons
/// and stats (the Broker keeps the completing page's). `Err` when it
/// would take more than [`MAX_PAGES`] pages, or one component alone is
/// over the byte ceiling.
pub fn pages(
    subject: &Subject,
    sbom: Sbom,
    set_id: &str,
    scanned_at: &str,
) -> Result<Pages, Invalid> {
    let Sbom {
        completeness,
        partial_reasons,
        scanner,
        stats,
        components,
    } = sbom;
    let mut head = SbomPage {
        schema_version: 1,
        image: SbomImage {
            digest: subject.digest.clone(),
            digest_kind: subject.digest_kind.clone(),
            repository: subject.repository.clone(),
            index_digest: subject.digest.clone(),
        },
        source: SBOM_SOURCE,
        sbom_trust: SBOM_TRUST,
        scanner,
        scanned_at: scanned_at.to_string(),
        format: SBOM_FORMAT,
        page: Page {
            set_id: set_id.to_string(),
            index: 0,
            total: 0,
        },
        components: Vec::new(),
        epoch: subject.epoch,
        completeness,
        partial_reasons,
        stats,
        platform: subject.platform.clone(),
    };
    let base = json_len(&head) + PAGE_SLACK;

    let mut lens: Vec<usize> = vec![0];
    let (mut bytes, mut paths) = (base, 0usize);
    for c in &components {
        // The component plus the comma before it.
        let b = json_len(c) + 1;
        if base + b > MAX_PAGE_BYTES {
            return Err(Invalid(format!(
                "component {:?} alone encodes to {b} bytes",
                c.name
            )));
        }
        let cur = *lens.last().expect("never empty");
        if cur > 0
            && (cur >= COMPONENTS_PER_PAGE
                || bytes + b > MAX_PAGE_BYTES
                || paths + c.file_paths.len() > MAX_PATHS_PER_PAGE)
        {
            lens.push(0);
            bytes = base;
            paths = 0;
        }
        bytes += b;
        paths += c.file_paths.len();
        *lens.last_mut().expect("never empty") += 1;
    }
    if lens.len() > MAX_PAGES {
        return Err(Invalid(format!(
            "{} pages; at most {MAX_PAGES}",
            lens.len()
        )));
    }
    head.page.total = lens.len() as i64;
    Ok(Pages {
        head,
        lens: lens.into_iter(),
        rest: components.into_iter(),
        index: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::super::worker::parse_response;
    use super::*;

    fn comp_json(name: &str, paths: Vec<String>) -> serde_json::Value {
        serde_json::json!({"name": name, "version": "1.0", "type": "apk", "file_paths": paths})
    }

    fn resp_json(components: Vec<serde_json::Value>) -> serde_json::Value {
        serde_json::json!({
            "protocol_version": 1, "scan_id": "s", "epoch": 2, "status": "ok",
            "completeness": "full",
            "scanner": {"name": "kguardian-cataloger", "vendor": "kguardian", "version": "0.1.0"},
            "stats": {"files": 10},
            "components": components
        })
    }

    fn parse(v: serde_json::Value) -> Response {
        parse_response(serde_json::to_vec(&v).unwrap()).unwrap()
    }

    fn resp(components: Vec<serde_json::Value>) -> Response {
        parse(resp_json(components))
    }

    fn sbom(o: Outcome) -> Sbom {
        match o {
            Outcome::Sbom(s) => s,
            other => panic!("expected an SBOM, got {other:?}"),
        }
    }

    fn failed_reason(o: Outcome) -> String {
        match o {
            Outcome::Failed { reason, .. } => reason,
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[test]
    fn a_clean_response_stays_full() {
        let s = sbom(
            validate(
                resp(vec![comp_json("busybox", vec!["/bin/busybox".into()])]),
                "s",
                2,
                &[],
            )
            .unwrap(),
        );
        assert_eq!(s.completeness, "full");
        assert!(s.partial_reasons.is_empty());
        assert_eq!(s.components[0].file_paths, vec!["/bin/busybox"]);
    }

    #[test]
    fn scan_id_epoch_and_version_must_echo() {
        assert!(validate(resp(vec![]), "other", 2, &[]).is_err());
        assert!(validate(resp(vec![]), "s", 3, &[]).is_err());
        let mut v = resp_json(vec![]);
        v["protocol_version"] = 2.into();
        assert!(validate(parse(v), "s", 2, &[]).is_err());
        let mut v = resp_json(vec![]);
        v["status"] = "weird".into();
        assert!(validate(parse(v), "s", 2, &[]).is_err());
    }

    #[test]
    fn bad_paths_are_dropped_and_mark_the_package_truncated() {
        let s = sbom(
            validate(
                resp(vec![comp_json(
                    "p",
                    vec![
                        "/usr/bin/ok".into(),
                        "relative/x".into(),
                        "/a/../etc/shadow".into(),
                        "/a//b".into(),
                        format!("/{}", "x".repeat(2000)),
                        "/tab\there".into(),
                        "/del\u{7f}".into(),
                        "/usr/bin/ok".into(),
                    ],
                )]),
                "s",
                2,
                &[],
            )
            .unwrap(),
        );
        assert_eq!(s.components[0].file_paths, vec!["/usr/bin/ok"]);
        assert!(s.components[0].files_truncated);
        assert_eq!(s.completeness, "partial");
        assert!(s.partial_reasons.contains(&"files_truncated".to_string()));
    }

    #[test]
    fn valid_path_rejects_control_characters() {
        assert!(valid_path("/usr/bin/x"));
        assert!(valid_path("/usr/bin/naïve"));
        for p in ["/a\nb", "/a\u{0}b", "/a\u{1b}b", "/a\u{85}b"] {
            assert!(!valid_path(p), "{p:?}");
        }
    }

    #[test]
    fn over_long_names_drop_the_component_and_path_lists_are_capped() {
        let many: Vec<String> = (0..5000).map(|i| format!("/usr/lib/x{i:05}.so")).collect();
        let s = sbom(
            validate(
                resp(vec![
                    comp_json(&"n".repeat(300), vec![]),
                    comp_json("big", many),
                ]),
                "s",
                2,
                &[],
            )
            .unwrap(),
        );
        assert_eq!(s.components.len(), 1);
        assert_eq!(s.components[0].file_paths.len(), 4096);
        assert!(s.components[0].files_truncated);
        assert!(s
            .partial_reasons
            .contains(&"components_dropped".to_string()));
    }

    #[test]
    fn too_many_components_is_refused() {
        let cs = (0..=MAX_COMPONENTS)
            .map(|i| serde_json::json!({"name": format!("p{i}")}))
            .collect();
        assert!(validate(resp(cs), "s", 2, &[]).is_err());
    }

    #[test]
    fn local_reasons_are_never_full() {
        let s = sbom(
            validate(
                resp(vec![comp_json("a", vec![])]),
                "s",
                2,
                &["drift_unknown"],
            )
            .unwrap(),
        );
        assert_eq!(s.completeness, "partial");
        assert_eq!(s.partial_reasons, vec!["drift_unknown"]);
        let mut v = resp_json(vec![comp_json("a", vec![])]);
        v["completeness"] = "os_only".into();
        let s = sbom(validate(parse(v), "s", 2, &["drift_unknown", "lang_whiteout"]).unwrap());
        assert_eq!(s.completeness, "os_only");
        assert_eq!(s.partial_reasons, vec!["drift_unknown", "lang_whiteout"]);
    }

    #[test]
    fn unknown_completeness_is_partial_and_failed_passes_the_reason() {
        let mut v = resp_json(vec![comp_json("a", vec![])]);
        v["completeness"] = "mostly".into();
        assert_eq!(
            sbom(validate(parse(v), "s", 2, &[]).unwrap()).completeness,
            "partial"
        );
        let mut v = resp_json(vec![]);
        v["status"] = "failed".into();
        v["reason"] = "oom".into();
        v["message"] = "é".repeat(400).into();
        match validate(parse(v), "s", 2, &[]).unwrap() {
            Outcome::Failed { reason, message } => {
                assert_eq!(reason, "oom");
                assert!(message.len() <= 1024);
            }
            o => panic!("{o:?}"),
        }
    }

    /// M6: terminal no_packages_found only for a clean, complete scan.
    #[test]
    fn no_packages_found_is_reported_only_for_a_clean_full_scan() {
        let os =
            serde_json::json!({"name": "alpine", "version": "3.20.3", "type": "operating-system"});
        // ok, full, no reasons: terminal.
        assert_eq!(
            failed_reason(validate(resp(vec![os.clone()]), "s", 2, &[]).unwrap()),
            "no_packages_found"
        );
        // ok but partial from the worker, or drift unknown here: error.
        let mut v = resp_json(vec![os.clone()]);
        v["completeness"] = "partial".into();
        v["partial_reasons"] = serde_json::json!(["eacces"]);
        assert_eq!(
            failed_reason(validate(parse(v), "s", 2, &[]).unwrap()),
            "error"
        );
        assert_eq!(
            failed_reason(validate(resp(vec![os]), "s", 2, &["drift_unknown"]).unwrap()),
            "error"
        );
        // A failed no_packages_found: kept when clean, else error.
        let failed = |completeness: &str, reasons: serde_json::Value| {
            let mut v = resp_json(vec![]);
            v["status"] = "failed".into();
            v["reason"] = "no_packages_found".into();
            v["completeness"] = completeness.into();
            v["partial_reasons"] = reasons;
            parse(v)
        };
        assert_eq!(
            failed_reason(validate(failed("", serde_json::json!([])), "s", 2, &[]).unwrap()),
            "no_packages_found"
        );
        assert_eq!(
            failed_reason(
                validate(
                    failed("partial", serde_json::json!(["eacces"])),
                    "s",
                    2,
                    &[]
                )
                .unwrap()
            ),
            "error"
        );
        assert_eq!(
            failed_reason(
                validate(
                    failed("", serde_json::json!([])),
                    "s",
                    2,
                    &["drift_unknown"]
                )
                .unwrap()
            ),
            "error"
        );
    }

    #[test]
    fn retry_reason_and_stats_are_kept_lean() {
        let mut v = resp_json(vec![comp_json("a", vec![])]);
        v["retry_reason"] = "oom".into();
        v["stats"] =
            serde_json::json!({"files": 1, "blob": "x".repeat(20_000), "nested": {"a": 1}});
        let s = sbom(validate(parse(v), "s", 2, &[]).unwrap());
        assert_eq!(s.stats["files"], 1);
        assert_eq!(s.stats["retry_reason"], "oom");
        assert!(s.stats.get("blob").is_none());
        assert!(s.stats.get("nested").is_none());
    }

    /// The Broker keeps a partial reason only when it is 1..=64 bytes of
    /// `[A-Za-z0-9_.-]` (node_catalog.rs `clean_short`, no closed set).
    /// Every reason the Controller adds must pass.
    #[test]
    fn the_controllers_own_partial_reasons_pass_the_broker_filter() {
        let broker_keeps = |r: &str| {
            !r.is_empty()
                && r.len() <= 64
                && r.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        };
        let r = resp(vec![
            comp_json("a", vec!["relative".into()]),
            comp_json(&"n".repeat(300), vec![]),
        ]);
        let s = sbom(validate(r, "s", 2, &["drift_unknown", "lang_whiteout"]).unwrap());
        assert_eq!(
            s.partial_reasons,
            vec![
                "components_dropped",
                "files_truncated",
                "drift_unknown",
                "lang_whiteout"
            ]
        );
        assert!(s.partial_reasons.iter().all(|r| broker_keeps(r)));
    }

    fn subject() -> Subject {
        Subject {
            digest: format!("sha256:{}", "a".repeat(64)),
            digest_kind: None,
            repository: Some("docker.io/library/nginx".into()),
            platform: "linux/arm64".into(),
            epoch: 2,
        }
    }

    fn sbom_of(components: Vec<Component>) -> Sbom {
        Sbom {
            completeness: "full".into(),
            partial_reasons: vec![],
            scanner: Scanner::default(),
            stats: serde_json::json!({}),
            components,
        }
    }

    fn comp(name: &str, paths: Vec<String>) -> Component {
        Component {
            name: name.into(),
            version: Some("1.0".into()),
            comp_type: Some("apk".into()),
            file_paths: paths,
            ..Default::default()
        }
    }

    #[test]
    fn pages_split_by_count_and_carry_the_catalog_fields() {
        let cs: Vec<Component> = (0..4500)
            .map(|i| comp(&format!("p{i:05}"), vec![]))
            .collect();
        let pages: Vec<SbomPage> = pages(&subject(), sbom_of(cs), "set-1", "2026-10-03T10:00:00Z")
            .unwrap()
            .collect();
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
        }
        let v = serde_json::to_value(&pages[0]).unwrap();
        assert_eq!(v["sbom_trust"], "scanned");
        assert_eq!(v["format"], "kguardian-cataloger");
        assert_eq!(v["platform"], "linux/arm64");
        assert_eq!(v["components"][0]["files_truncated"], false);
        assert_eq!(v["components"][0]["interpreted_content"], false);
        assert!(v["components"][0].get("file_paths").is_none());
    }

    /// B2: paging moves components; the heap buffers in the pages are the
    /// very ones the SBOM held (a clone would allocate new ones).
    #[test]
    fn paging_moves_components_and_never_clones_them() {
        let cs: Vec<Component> = (0..2500)
            .map(|i| comp(&format!("p{i:05}"), vec![format!("/usr/bin/p{i:05}")]))
            .collect();
        let before: Vec<(*const u8, *const String)> = cs
            .iter()
            .map(|c| (c.name.as_ptr(), c.file_paths.as_ptr()))
            .collect();
        let after: Vec<(*const u8, *const String)> = pages(&subject(), sbom_of(cs), "s", "t")
            .unwrap()
            .flat_map(|p| p.components)
            .map(|c| (c.name.as_ptr(), c.file_paths.as_ptr()))
            .collect();
        assert_eq!(before, after);
    }

    #[test]
    fn pages_split_by_bytes_and_paths_measured_exactly() {
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
        let pages: Vec<SbomPage> = pages(&subject(), sbom_of(cs), "set", "t")
            .unwrap()
            .collect();
        assert!(pages.len() >= 2);
        for p in &pages {
            let bytes = serde_json::to_vec(p).unwrap().len();
            assert!(bytes <= MAX_PAGE_BYTES, "page of {bytes} bytes");
            let n: usize = p.components.iter().map(|c| c.file_paths.len()).sum();
            assert!(n <= MAX_PATHS_PER_PAGE);
        }
    }

    /// Escape-heavy content encodes far larger than its length (a quote
    /// or backslash doubles, a control character becomes `\u00XX`); the
    /// exact measure keeps every page under the ceiling anyway.
    #[test]
    fn escape_heavy_components_are_sized_exactly() {
        let nasty = "\"\\\u{1}".repeat(80); // 240 bytes -> 80 * 10 encoded
        let cs: Vec<Component> = (0..9000)
            .map(|i| Component {
                name: format!("{nasty}{i}"),
                version: Some(nasty.clone()),
                purl: Some(format!("pkg:x/{}", nasty.repeat(4))),
                licenses: vec![nasty.clone(); 8],
                ..Default::default()
            })
            .collect();
        let est: usize = cs.iter().map(|c| c.name.len() + 2000).sum();
        let pages: Vec<SbomPage> = pages(&subject(), sbom_of(cs), "set", "t")
            .unwrap()
            .collect();
        assert!(pages.len() > 1, "{est} bytes of raw text must span pages");
        for p in &pages {
            let bytes = serde_json::to_vec(p).unwrap().len();
            assert!(bytes <= MAX_PAGE_BYTES, "page of {bytes} bytes");
        }
        assert_eq!(
            pages.iter().map(|p| p.components.len()).sum::<usize>(),
            9000
        );
    }

    #[test]
    fn json_len_is_the_encoded_length() {
        let c = comp("a\"b", vec!["/x".into()]);
        assert_eq!(json_len(&c), serde_json::to_vec(&c).unwrap().len());
    }
}
