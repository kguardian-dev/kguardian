//! Worst-case memory of one `POST /runtime/executables`, measured.
//!
//! A byte limit alone does not bound what parsing builds from the bytes:
//! #1671 measured 64 KB of gzip inflating to 2.58 M tiny structs and
//! 720 MB of RSS. The runtime ingest therefore caps the entry count while
//! parsing, caps every string field before copying it, and never builds
//! a `serde_json::Value`. This test drives [`prepare`] (parse, validate,
//! deduplicate: the whole per-request path before the database) with the
//! worst bodies that fit under the route's body limit, and asserts the
//! heap peak.
//!
//! The counting allocator lives here, not in the lib, because a global
//! allocator is per binary. Like `read_memory_profile.rs` it does NOT
//! override `realloc`, so a growing buffer is charged for both copies at
//! once: the conservative model for a fragmented heap. The peak is heap
//! in use above the level before the call; the request body itself (at
//! most `RUNTIME_BODY_LIMIT_BYTES`, held by actix while `prepare` runs)
//! is reported separately. Run with `--nocapture` for the numbers.

use api::runtime_inventory::{
    prepare, PrepareError, MAX_BATCH_ENTRIES, MAX_PATH_LEN, RUNTIME_BODY_LIMIT_BYTES,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            let now = LIVE.fetch_add(l.size(), Ordering::Relaxed) + l.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        p
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(l);
        if !p.is_null() {
            let now = LIVE.fetch_add(l.size(), Ordering::Relaxed) + l.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static A: Counting = Counting;

const MIB: f64 = 1024.0 * 1024.0;
const D: &str = "sha256:00000000000000000000000000000000000000000000000000000000000000aa";

/// One valid entry whose path is `path`; every other field realistic.
fn entry(i: usize, path: &str) -> String {
    format!(
        r#"{{"pod_namespace":"production-payments","pod_name":"checkout-api-7d9f8b6c5d-x{i:05}","workload_kind":"Deployment","workload_name":"checkout-api","container_name":"app","image_digest":"{D}","kind":"lib","path":"{path}","path_complete":true,"source":"ebpf","origin":"writableLayer","first_seen":"2026-09-26T10:00:00.123456789","last_seen":"2026-09-26T10:05:00.123456789"}}"#
    )
}

/// `[item,item,...]` of `n` items, asserting it fits the body limit.
fn array(items: impl Iterator<Item = String>) -> Vec<u8> {
    let mut s = String::from("[");
    for (i, it) in items.enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&it);
    }
    s.push(']');
    assert!(s.len() <= RUNTIME_BODY_LIMIT_BYTES, "{} bytes", s.len());
    s.into_bytes()
}

/// Heap peak of `prepare` (above the starting level) and its outcome.
fn peak_of(body: &[u8]) -> (usize, Result<(usize, usize), PrepareError>) {
    let base = LIVE.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    let r = prepare(body).map(|b| {
        let n = (b.rows.len(), b.dropped);
        drop(b);
        n
    });
    (PEAK.load(Ordering::Relaxed) - base, r)
}

#[test]
fn worst_case_ingest_memory_is_bounded() {
    let limit = RUNTIME_BODY_LIMIT_BYTES;
    // The largest accepted batch: MAX_BATCH_ENTRIES distinct entries, each
    // path as long as fits in the body limit.
    let per_entry = limit / MAX_BATCH_ENTRIES;
    let overhead = entry(0, "").len() + 1;
    let long = format!("/usr/lib/{}", "p".repeat(per_entry - overhead - 16));
    let max_path = format!("/{}", "q".repeat(MAX_PATH_LEN - 1));
    let max_path_fit = limit / (entry(0, &max_path).len() + 1);
    // A path over the cap, JSON-escaped so the parser must decode it into
    // its scratch buffer rather than borrow it.
    let escaped = "\\u0041".repeat((limit - 64) / 6);
    let many_keys = format!(
        "[{{{}}}]",
        (0..(limit / 16))
            .map(|i| format!("\"k{i:08}\":0"))
            .collect::<Vec<_>>()
            .join(",")
    );

    let cases: Vec<(&str, Vec<u8>, bool)> = vec![
        (
            "5000 distinct entries, ~1.6 KB paths (largest accepted batch)",
            array((0..MAX_BATCH_ENTRIES).map(|i| entry(i, &format!("{long}{i:06}")))),
            true,
        ),
        (
            "max-length (4096 B) paths, as many as fit",
            array((0..max_path_fit).map(|i| entry(i, &max_path))),
            true,
        ),
        (
            "8 MiB of `0` elements (count bomb)",
            array(std::iter::repeat_n("0".to_string(), limit / 2 - 1)),
            false,
        ),
        (
            "8 MiB of `{}` elements (count bomb)",
            array(std::iter::repeat_n("{}".to_string(), limit / 3 - 1)),
            false,
        ),
        (
            "one object with ~500k unknown keys",
            many_keys.into_bytes(),
            true,
        ),
        (
            "one 8 MiB escaped path (over the cap)",
            format!("[{}]", entry(0, &escaped)).into_bytes(),
            true,
        ),
    ];

    let mut worst = 0usize;
    for (name, body, accepted) in &cases {
        let (peak, r) = peak_of(body);
        println!(
            "{name}: body {:.2} MiB, peak {:.2} MiB, outcome {r:?}",
            body.len() as f64 / MIB,
            peak as f64 / MIB
        );
        match (accepted, &r) {
            (true, Ok(_)) => {}
            (false, Err(PrepareError::TooMany)) => {}
            _ => panic!("{name}: unexpected outcome {r:?}"),
        }
        worst = worst.max(peak);
    }
    println!(
        "worst prepare peak {:.2} MiB (+ body <= {:.0} MiB)",
        worst as f64 / MIB,
        limit as f64 / MIB
    );
    // Bound: 3x the body limit. What matters is that it is a small
    // multiple of the byte limit, not millions of structs.
    assert!(
        worst <= 3 * limit,
        "prepare peaked at {:.2} MiB",
        worst as f64 / MIB
    );
}
