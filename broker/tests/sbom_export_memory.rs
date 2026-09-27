//! Byte-exact heap peak of `GET /images/{digest}/sbom/cyclonedx`, which
//! sizes [`api::EXPORT_COMPONENT_COST_BYTES`], the read-budget charge per
//! exported component.
//!
//! The charge used to be 4 KiB, reasoned from "no file paths in the
//! export". But the export loaded `file_paths` anyway (up to 16 KiB per
//! row) and built a `serde_json::Value` tree, and one 8 000-component
//! export measured +47 MiB of RSS against 32 MiB charged. It now reads
//! only the columns it emits and builds typed structs; this test measures
//! what that costs and fails if it ever exceeds the charge.
//!
//! What is measured, per component, in the order the handler does it:
//! the rows as diesel returns them, [`api::cyclonedx_document`] (which
//! moves their strings), and the compact JSON body actix builds while the
//! document is still alive. The counting allocator leaves `realloc` to the
//! trait default (new + copy + free), so a growing body is charged for both
//! buffers, as in `read_memory_profile.rs`. libpq's copy of the rows is C
//! heap and invisible here; the test adds one row's text per component for
//! it (a chunk of at most 5 000 rows is resident while diesel converts it).

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use api::{cyclonedx_document, ExportComponent, SbomReport, EXPORT_COMPONENT_COST_BYTES};

struct CountingAlloc;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        System.dealloc(p, layout);
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }
    // realloc: trait default (see the module docs).
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

const N: usize = 2_000;

/// Every field at its ingest cap (supplychain.rs: name 256, version 128,
/// purl 1024, type/class 64, source name 256 / version 128, 8 licences of
/// 128, layer digest 136 bytes), made of `"` so JSON escaping doubles it.
fn worst(i: usize) -> ExportComponent {
    let q = |n: usize| "\"".repeat(n);
    ExportComponent {
        id: i as i64,
        name: q(256),
        version: Some(q(128)),
        purl: Some(q(1024)),
        comp_type: Some(q(64)),
        class: Some(q(64)),
        src_name: Some(q(256)),
        src_version: Some(q(128)),
        licenses: (0..8).map(|_| q(128)).collect(),
        layer_digest: Some(q(136)),
    }
}

/// A Debian package as registry SBOMs describe it.
fn typical(i: usize) -> ExportComponent {
    ExportComponent {
        id: i as i64,
        name: format!("libexample{i}"),
        version: Some("2.36-9+deb12u7".into()),
        purl: Some(format!(
            "pkg:deb/debian/libexample{i}@2.36-9%2Bdeb12u7?arch=amd64&distro=debian-12"
        )),
        comp_type: Some("debian".into()),
        class: Some("os-pkgs".into()),
        src_name: Some(format!("example{i}")),
        src_version: Some("2.36-9+deb12u7".into()),
        licenses: vec!["GPL-2.0-or-later".into(), "LGPL-2.1-or-later".into()],
        layer_digest: Some(format!("sha256:{:064x}", i)),
    }
}

fn text_bytes(c: &ExportComponent) -> usize {
    let o = |s: &Option<String>| s.as_ref().map_or(0, String::len);
    c.name.len()
        + o(&c.version)
        + o(&c.purl)
        + o(&c.comp_type)
        + o(&c.class)
        + o(&c.src_name)
        + o(&c.src_version)
        + c.licenses.iter().map(String::len).sum::<usize>()
        + o(&c.layer_digest)
}

fn report() -> SbomReport {
    let t = chrono::NaiveDate::from_ymd_opt(2026, 9, 27)
        .unwrap()
        .and_hms_opt(0, 0, 0)
        .unwrap();
    SbomReport {
        source: "registry".into(),
        report_digest: format!("sha256:{:064x}", 1),
        join: "digest".into(),
        digest_kind: "manifest".into(),
        scanned_at: t,
        db_updated_at: None,
        scanner_name: Some("syft".into()),
        scanner_version: Some("1.0".into()),
        os_family: None,
        os_name: None,
        os_eosl: false,
        image_ref: Some("ghcr.io/example/app:1".into()),
        item_count: N as i32,
        sbom_format: Some("CycloneDX".into()),
        received_at: t,
        sbom_sources: vec!["registry".into()],
        sbom_trust: Some("unverified".into()),
        attestation: None,
    }
}

/// Heap peak of one export of `n` components made by `make`, plus the
/// libpq row copy, in bytes per component.
fn per_component(n: usize, make: fn(usize) -> ExportComponent) -> (u64, usize) {
    let report = report();
    let digest = format!("sha256:{:064x}", 2);
    let base = LIVE.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    let mut rows = Vec::with_capacity(n);
    let mut libpq = 0;
    for i in 0..n {
        let c = make(i);
        libpq += text_bytes(&c);
        rows.push(c);
    }
    let doc = cyclonedx_document(&digest, &report, rows);
    let body = serde_json::to_string(&doc).unwrap();
    let body_len = body.len();
    drop(body);
    drop(doc);
    let peak = PEAK.load(Ordering::Relaxed) - base;
    (((peak + libpq) / n) as u64, body_len)
}

#[test]
fn export_cost_covers_the_measured_peak() {
    let (worst_b, worst_body) = per_component(N, worst);
    let (typical_b, typical_body) = per_component(N, typical);
    println!(
        "per component: worst {worst_b} B (body {} B), typical {typical_b} B (body {} B); charged {EXPORT_COMPONENT_COST_BYTES} B",
        worst_body / N,
        typical_body / N
    );
    assert!(
        worst_b <= EXPORT_COMPONENT_COST_BYTES,
        "a worst-case component costs {worst_b} B, more than the {EXPORT_COMPONENT_COST_BYTES} B charged"
    );
    assert!(typical_b < worst_b);
}
