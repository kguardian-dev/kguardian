//! Worst-case memory of one supply-chain ingest, measured.
//!
//! The first version capped the inflated body at 32 MiB but not the
//! number of items parsed from it: 64 KB of gzip inflated to 32 MiB of
//! `{"name":"a"}` and became 2.58 M structs, 720 MB of RSS for one
//! request. Parsing now stops each list at its cap and the inflate
//! ceiling is 8 MiB. This test drives [`api::supplychain::prepare`] (inflate +
//! parse + normalise, the whole per-request body path) plus the row
//! serialisation `store` does, with the worst bodies we can build, and
//! asserts the heap peak.
//!
//! The peak is exact: a counting global allocator in this test binary
//! records the high-water mark of live heap bytes. It does not include
//! the allocator's own overhead or libpq's copy of the statement, so
//! read it as heap in use, not RSS. Run with `--nocapture` to see the
//! numbers.

use api::supplychain::{
    prepare, Kind, PrepareError, Prepared, DEFAULT_MAX_DECOMPRESSED_BYTES,
    MAX_COMPONENTS_PER_REQUEST, MAX_COMPRESSED_BYTES, MAX_VULNERABILITIES,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Counting;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            let now = CURRENT.fetch_add(l.size(), Ordering::Relaxed) + l.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        CURRENT.fetch_sub(l.size(), Ordering::Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        let q = System.realloc(p, l, new);
        if !q.is_null() {
            if new > l.size() {
                let now = CURRENT.fetch_add(new - l.size(), Ordering::Relaxed) + new - l.size();
                PEAK.fetch_max(now, Ordering::Relaxed);
            } else {
                CURRENT.fetch_sub(l.size() - new, Ordering::Relaxed);
            }
        }
        q
    }
}

#[global_allocator]
static A: Counting = Counting;

const D: &str = "sha256:00000000000000000000000000000000000000000000000000000000000000aa";
const MIB: f64 = 1024.0 * 1024.0;

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    e.write_all(bytes).unwrap();
    e.finish().unwrap()
}

fn header(kind: &str) -> String {
    format!(
        r#"{{"schema_version":1,"image":{{"digest":"{D}","digest_kind":"manifest"}},"source":"trivy-operator","scanned_at":"2026-09-20T08:00:00Z","format":"CycloneDX","{kind}":["#
    )
}

/// A body of `n` copies of `item`, as close to `target` inflated bytes
/// as the item size allows.
fn body(kind: &str, item: &str, target: usize, max_items: usize) -> Vec<u8> {
    let mut s = header(kind);
    let n = ((target - s.len() - 2) / (item.len() + 1)).min(max_items);
    for i in 0..n {
        if i > 0 {
            s.push(',');
        }
        s.push_str(item);
    }
    s.push_str("]}");
    assert!(s.len() <= target, "{} > {target}", s.len());
    s.into_bytes()
}

/// Heap peak (bytes above the starting level) of prepare + the row
/// serialisation `store` does.
fn peak_of(kind: Kind, gz: &[u8]) -> (usize, Result<usize, String>) {
    let base = CURRENT.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    let r = match prepare(
        kind,
        D,
        gz,
        true,
        DEFAULT_MAX_DECOMPRESSED_BYTES,
        chrono::Utc::now(),
    ) {
        Ok(Prepared::Vulns(p)) => {
            let n = p.rows.len();
            let json = serde_json::to_string(&p.rows).unwrap();
            drop(p);
            drop(json);
            Ok(n)
        }
        Ok(Prepared::Sbom(p)) => {
            let n = p.rows.len();
            let json = serde_json::to_string(&p.rows).unwrap();
            drop(p);
            drop(json);
            Ok(n)
        }
        Err(PrepareError::TooMany(m)) => Err(format!("413 too many: {m}")),
        Err(e) => Err(format!("{e:?}")),
    };
    (PEAK.load(Ordering::Relaxed) - base, r)
}

#[test]
fn worst_case_ingest_memory_is_bounded() {
    let ceiling = DEFAULT_MAX_DECOMPRESSED_BYTES;
    let path = "usr/lib/python3.12/site-packages/some-package/sub/module.py";
    let paths = format!("[{}]", vec![format!("\"{path}\""); 10].join(","));
    let cases: Vec<(&str, Kind, Vec<u8>, bool)> = vec![
        // The reviewer's bomb, at the new ceiling: tiny components.
        (
            "sbom: 8 MiB of {\"name\":\"a\"}",
            Kind::Sbom,
            body("components", r#"{"name":"a"}"#, ceiling, usize::MAX),
            false,
        ),
        (
            "vulns: 8 MiB of minimal findings",
            Kind::Vulnerabilities,
            body(
                "vulnerabilities",
                r#"{"id":"a","package":{"name":"p"}}"#,
                ceiling,
                usize::MAX,
            ),
            false,
        ),
        // The largest bodies that are accepted: the per-request item cap,
        // each item as large as fits in the 8 MiB ceiling.
        (
            "sbom: 10 000 components filling 8 MiB",
            Kind::Sbom,
            {
                let per = ceiling / MAX_COMPONENTS_PER_REQUEST - 2;
                let base = format!(
                    r#"{{"name":"n","version":"1.2.3","purl":"pkg:pypi/x@1","type":"python-pkg","licenses":["MIT","Apache-2.0"],"file_paths":{paths},"src_name":""#
                );
                let pad = per.saturating_sub(base.len() + 2);
                let item = format!("{base}{}\"}}", "s".repeat(pad));
                body("components", &item, ceiling, MAX_COMPONENTS_PER_REQUEST)
            },
            true,
        ),
        (
            "vulns: 20 000 findings filling 8 MiB",
            Kind::Vulnerabilities,
            {
                let per = ceiling / MAX_VULNERABILITIES - 2;
                let base = r#"{"id":"CVE-2099-12345","package":{"name":"openssl","version":"3.0.0","type":"debian","purl":"pkg:deb/debian/openssl@3.0.0"},"severity":"HIGH","fixed_version":"3.0.1","score":7.5,"cvss":{"nvd":{"v3_score":7.5,"v3_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}},"file_paths":["a","b"],"title":""#
                    .to_string();
                let pad = per.saturating_sub(base.len() + 2);
                let item = format!("{base}{}\"}}", "t".repeat(pad));
                body("vulnerabilities", &item, ceiling, MAX_VULNERABILITIES)
            },
            true,
        ),
    ];
    let mut worst = 0usize;
    for (name, kind, raw, accepted) in cases {
        let inflated = raw.len();
        let gz = gzip(&raw);
        drop(raw);
        assert!(
            gz.len() <= MAX_COMPRESSED_BYTES,
            "{name}: {} gz bytes",
            gz.len()
        );
        let (peak, r) = peak_of(kind, &gz);
        println!(
            "{name}: {:.1} KiB gzip, {:.2} MiB inflated -> {:?}; heap peak {:.1} MiB",
            gz.len() as f64 / 1024.0,
            inflated as f64 / MIB,
            r,
            peak as f64 / MIB
        );
        assert_eq!(r.is_ok(), accepted, "{name}: {r:?}");
        if accepted {
            assert!(
                inflated > ceiling - ceiling / 50,
                "{name}: body only {inflated} bytes"
            );
        }
        worst = worst.max(peak);
    }
    println!(
        "worst case per ingest: {:.1} MiB heap; {} ingests run at once",
        worst as f64 / MIB,
        api::supplychain::INGEST_CONCURRENCY
    );
    // One ingest at a time (a single worker thread); even two must fit
    // comfortably beside the broker's
    // ~350 MiB resting set in its 1 GiB limit.
    assert!(
        worst < 128 * 1024 * 1024,
        "worst-case ingest heap {:.1} MiB",
        worst as f64 / MIB
    );
}
