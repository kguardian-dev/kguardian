//! Runtime "in use" for vulnerability findings (#1533 P1-5): which SBOM
//! package owns a path the kernel saw executed or mapped, and the risk
//! tier of a finding.
//!
//! # Path to package
//!
//! Runtime paths come from the kernel: absolute, inside the container,
//! symlinks resolved (`/usr/bin/python3` is reported as the file it
//! points at, `/usr/bin/python3.12`; `libz.so.1` as `libz.so.1.3`). SBOM
//! paths come from package databases and are NOT resolved: Debian
//! bookworm's dpkg records `/lib/x86_64-linux-gnu/libz.so.1.2.13` and
//! `/bin/cat` even though the image is merged-/usr and the kernel reports
//! `/usr/lib/...` and `/usr/bin/cat`; Trivy reports paths without a
//! leading slash. So a runtime path is looked up as a set of candidates,
//! strongest first ([`candidates`]):
//!
//! 1. the path itself (and its relative spellings);
//! 2. its merged-/usr twin: `/usr/lib` <-> `/lib`, `/usr/lib64` <->
//!    `/lib64`, `/usr/bin` <-> `/bin`, `/usr/sbin` <-> `/sbin`;
//! 3. for a versioned shared object, the shorter sonames in the same
//!    directory (`libz.so.1.2.13` -> `libz.so.1.2` -> `libz.so.1`), down
//!    to `lib*.so.<major>` and never to the bare `lib*.so`, which is the
//!    development symlink of a different package (`zlib1g-dev`).
//!
//! The first rank that matches wins; within a rank, a tie between
//! packages is reported as ambiguous (every owner is credited). A path no
//! package owns is "unowned": a binary built into the image outside any
//! package manager, or one written after start.
//!
//! Fixtures: `test/fixtures/in_use_paths.json`, real file lists from
//! Debian bookworm and Alpine 3.20 packages and the host's Ubuntu 24.04
//! dpkg database, with kernel-reported mappings.

use serde::{Deserialize, Serialize};

/// How a runtime path matched an SBOM path, strongest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathMatch {
    Exact,
    MergedUsrAlias,
    Soname,
}

/// Lexically normalise a path to an absolute form: strip `./`, add the
/// leading `/`, collapse `//`, resolve `.` and `..`. `None` for an empty
/// path.
pub fn normalise_path(p: &str) -> Option<String> {
    let p = p.trim();
    if p.is_empty() {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(format!("/{}", parts.join("/")))
}

const MERGED_USR: [(&str, &str); 4] = [
    ("/usr/lib/", "/lib/"),
    ("/usr/lib64/", "/lib64/"),
    ("/usr/bin/", "/bin/"),
    ("/usr/sbin/", "/sbin/"),
];

/// The merged-/usr twin of `p`, if it has one.
pub fn merged_usr_twin(p: &str) -> Option<String> {
    for (usr, root) in MERGED_USR {
        if let Some(rest) = p.strip_prefix(usr) {
            return Some(format!("{root}{rest}"));
        }
        if let Some(rest) = p.strip_prefix(root) {
            return Some(format!("{usr}{rest}"));
        }
    }
    None
}

/// Shorter sonames of a versioned shared object, longest first:
/// `/d/libz.so.1.2.13` -> `/d/libz.so.1.2`, `/d/libz.so.1`. Stops at
/// `.so.<major>`; empty for anything that is not `*.so.<n>[.<n>...]`.
pub fn shorter_sonames(p: &str) -> Vec<String> {
    let (dir, base) = match p.rsplit_once('/') {
        Some((d, b)) => (d, b),
        None => ("", p),
    };
    let Some(i) = base.find(".so.") else {
        return Vec::new();
    };
    let stem = &base[..i + 3]; // "libz.so"
    let versions: Vec<&str> = base[i + 4..].split('.').collect();
    if versions.len() < 2 || versions.iter().any(|v| v.is_empty()) {
        return Vec::new();
    }
    (1..versions.len())
        .rev()
        .map(|n| format!("{dir}/{stem}.{}", versions[..n].join(".")))
        .collect()
}

/// Every spelling of `p` an SBOM might record: absolute, relative, and
/// `./`-relative.
fn spellings(abs: &str) -> [String; 3] {
    let rel = abs.trim_start_matches('/');
    [abs.to_string(), rel.to_string(), format!("./{rel}")]
}

/// Candidate SBOM paths for a runtime path, with the rank each would
/// match at. Used both to query the database (`file_paths && $1`) and to
/// rank what comes back.
pub fn candidates(runtime_path: &str) -> Vec<(String, PathMatch)> {
    let Some(abs) = normalise_path(runtime_path) else {
        return Vec::new();
    };
    let mut out: Vec<(String, PathMatch)> = Vec::new();
    let push = |p: &str, m: PathMatch, out: &mut Vec<(String, PathMatch)>| {
        for s in spellings(p) {
            if !out.iter().any(|(q, _)| *q == s) {
                out.push((s, m));
            }
        }
    };
    push(&abs, PathMatch::Exact, &mut out);
    let twin = merged_usr_twin(&abs);
    if let Some(t) = &twin {
        push(t, PathMatch::MergedUsrAlias, &mut out);
    }
    for base in std::iter::once(abs.clone()).chain(twin) {
        for s in shorter_sonames(&base) {
            push(&s, PathMatch::Soname, &mut out);
        }
    }
    out
}

/// An SBOM component as the matcher needs it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct PackageKey {
    pub name: String,
    pub version: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Component {
    pub key: PackageKey,
    pub file_paths: Vec<String>,
}

/// Which packages own a runtime path, and how strongly.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Ownership {
    pub owners: Vec<PackageKey>,
    pub how: Option<PathMatch>,
}

impl Ownership {
    pub fn unowned(&self) -> bool {
        self.owners.is_empty()
    }
}

/// Owners of `runtime_path` among `components`: the packages matching at
/// the strongest rank that matches at all (all of them when several do).
pub fn owners_of(runtime_path: &str, components: &[Component]) -> Ownership {
    let cands = candidates(runtime_path);
    for rank in [
        PathMatch::Exact,
        PathMatch::MergedUsrAlias,
        PathMatch::Soname,
    ] {
        let at_rank: Vec<&str> = cands
            .iter()
            .filter(|(_, m)| *m == rank)
            .map(|(p, _)| p.as_str())
            .collect();
        let mut owners: Vec<PackageKey> = components
            .iter()
            .filter(|c| c.file_paths.iter().any(|f| at_rank.contains(&f.as_str())))
            .map(|c| c.key.clone())
            .collect();
        if !owners.is_empty() {
            owners.sort();
            owners.dedup();
            return Ownership {
                owners,
                how: Some(rank),
            };
        }
    }
    Ownership {
        owners: Vec::new(),
        how: None,
    }
}

// ---------------------------------------------------------------------
// In-use state and tiers
// ---------------------------------------------------------------------

/// Per finding per workload container. Ordered strongest first, and
/// `Unknown` sits above `InstalledNotObserved`: without coverage a
/// finding is treated as in use (tiers degrade upward, never downward).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InUse {
    /// A binary the package owns was executed.
    Executed,
    /// A file the package owns was mapped executable (a shared object).
    Loaded,
    /// No runtime evidence either way (see [`UnknownReason`]).
    Unknown,
    /// Covered for the whole window and never seen executed or loaded.
    InstalledNotObserved,
}

impl InUse {
    pub fn as_str(self) -> &'static str {
        match self {
            InUse::Executed => "executed",
            InUse::Loaded => "loaded",
            InUse::Unknown => "unknown",
            InUse::InstalledNotObserved => "installed_not_observed",
        }
    }

    /// Whether tiers treat it as in use (everything but
    /// installed_not_observed).
    pub fn counts_as_in_use(self) -> bool {
        self != InUse::InstalledNotObserved
    }

    /// `kg_in_use_rank` in SQL: 0 executed, 1 loaded, 2 unknown, 3
    /// installed_not_observed.
    pub fn rank(self) -> i16 {
        match self {
            InUse::Executed => 0,
            InUse::Loaded => 1,
            InUse::Unknown => 2,
            InUse::InstalledNotObserved => 3,
        }
    }

    /// Inverse of [`InUse::rank`]; anything else is unknown.
    pub fn from_rank(r: i16) -> InUse {
        match r {
            0 => InUse::Executed,
            1 => InUse::Loaded,
            3 => InUse::InstalledNotObserved,
            _ => InUse::Unknown,
        }
    }

    /// The legacy boolean: `Some(true)` executed/loaded, `Some(false)`
    /// installed_not_observed, `None` unknown.
    pub fn as_bool(self) -> Option<bool> {
        match self {
            InUse::Executed | InUse::Loaded => Some(true),
            InUse::InstalledNotObserved => Some(false),
            InUse::Unknown => None,
        }
    }
}

/// Why an in-use state is `unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownReason {
    /// No runtime capture data for this workload container at all.
    NoRuntimeData,
    /// Capture exists but does not cover the whole window (started late,
    /// probes missing on the node, drops, or not yet long enough).
    CaptureGap,
    /// Host-network pod: capture is keyed by the pod's network namespace,
    /// which is the node's.
    HostNetwork,
    /// A language package (npm, pip, jar, gem, ...): its modules are read
    /// by an interpreter, not mapped or executed, so they are not seen.
    LanguagePackage,
    /// No SBOM lists the package's files, so nothing can be matched to it.
    NoPackageFiles,
    /// The exec / shared-library probes are not loaded on a node that ran
    /// the container (kernel or BTF).
    ProbesMissing,
}

impl UnknownReason {
    pub fn as_str(self) -> &'static str {
        match self {
            UnknownReason::NoRuntimeData => "no_runtime_data",
            UnknownReason::CaptureGap => "capture_gap",
            UnknownReason::HostNetwork => "host_network",
            UnknownReason::LanguagePackage => "language_package",
            UnknownReason::NoPackageFiles => "no_package_files",
            UnknownReason::ProbesMissing => "probes_missing",
        }
    }
}

/// Package types that are modules compiled into a static binary (Trivy
/// `gobinary` / `rustbinary`, Syft `go-module` / `rust-binary` / `binary`).
/// The SBOM lists the binary itself as the module's file.
const STATIC_BINARY_TYPES: [&str; 5] = [
    "gobinary",
    "rustbinary",
    "rust-binary",
    "go-module",
    "binary",
];

/// Package types whose code runs as native executables or shared objects
/// (so exec/mmap evidence applies). Everything classed `lang-pkgs` that
/// is not a compiled binary is an interpreted module.
pub fn is_observable_type(pkg_type: Option<&str>, class: Option<&str>) -> bool {
    let t = pkg_type.unwrap_or("").to_ascii_lowercase();
    // Compiled language binaries: the package IS the executable.
    if STATIC_BINARY_TYPES.contains(&t.as_str()) {
        return true;
    }
    const INTERPRETED: [&str; 14] = [
        "npm",
        "node-pkg",
        "yarn",
        "pnpm",
        "pip",
        "python-pkg",
        "pipenv",
        "poetry",
        "jar",
        "pom",
        "gradle",
        "gemspec",
        "bundler",
        "composer",
    ];
    if INTERPRETED.contains(&t.as_str())
        || matches!(t.as_str(), "nuget" | "dotnet-core" | "conda-pkg")
    {
        return false;
    }
    class != Some("lang-pkgs")
}

/// What exec/mmap evidence can say about a package, by its type. Shown
/// next to the in-use state so a reader knows how much "executed" or
/// "not observed" is worth for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    /// OS package (deb, apk, rpm, ...): per file. A shared object it owns
    /// being mapped, or a binary it owns being executed, is seen.
    File,
    /// A module compiled into a static binary (Go, Rust): the whole binary
    /// is one file, so every module in it is credited when the binary
    /// runs. "executed" means linked into a running binary, not that the
    /// vulnerable function was reached.
    StaticBinary,
    /// Interpreted-language package (npm, pip, jar, gem, ...): its code is
    /// read by an interpreter, never mapped or executed on its own, so
    /// exec/mmap capture cannot see it. Always unknown.
    Interpreted,
}

impl Coverage {
    pub fn as_str(self) -> &'static str {
        match self {
            Coverage::File => "file",
            Coverage::StaticBinary => "static_binary",
            Coverage::Interpreted => "interpreted",
        }
    }
}

/// The [`Coverage`] of a package type (same classification as
/// [`is_observable_type`]).
pub fn coverage_of(pkg_type: Option<&str>, class: Option<&str>) -> Coverage {
    let t = pkg_type.unwrap_or("").to_ascii_lowercase();
    if STATIC_BINARY_TYPES.contains(&t.as_str()) {
        Coverage::StaticBinary
    } else if is_observable_type(pkg_type, class) {
        Coverage::File
    } else {
        Coverage::Interpreted
    }
}

/// Everything the in-use state of one finding in one container depends on.
#[derive(Debug, Clone, Default)]
pub struct Evidence {
    /// Capture covered the container for the whole window.
    pub covered: bool,
    /// Why not, when not covered.
    pub gap: Option<UnknownReason>,
    /// The package was seen executed / loaded in the window.
    pub executed: bool,
    pub loaded: bool,
    /// The package's type can be observed through exec/mmap at all.
    pub observable: bool,
    /// Some SBOM for the image lists files for the package.
    pub has_files: bool,
}

/// The in-use state and, for unknown, why. Positive evidence always wins
/// (a package seen loaded is loaded, coverage or not); a negative claim
/// needs coverage, an observable package type, and a file list.
pub fn in_use_of(e: &Evidence) -> (InUse, Option<UnknownReason>) {
    if e.executed {
        return (InUse::Executed, None);
    }
    if e.loaded {
        return (InUse::Loaded, None);
    }
    if !e.covered {
        return (
            InUse::Unknown,
            Some(e.gap.unwrap_or(UnknownReason::NoRuntimeData)),
        );
    }
    if !e.observable {
        return (InUse::Unknown, Some(UnknownReason::LanguagePackage));
    }
    if !e.has_files {
        return (InUse::Unknown, Some(UnknownReason::NoPackageFiles));
    }
    (InUse::InstalledNotObserved, None)
}

/// Risk tiers (team/04-ux.md section 3). Ordered most urgent first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Tier {
    P0,
    P1,
    P2,
    Background,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::P0 => "P0",
            Tier::P1 => "P1",
            Tier::P2 => "P2",
            Tier::Background => "Background",
        }
    }
    pub fn rank(self) -> i16 {
        match self {
            Tier::P0 => 0,
            Tier::P1 => 1,
            Tier::P2 => 2,
            Tier::Background => 3,
        }
    }
    pub fn from_rank(r: i16) -> Tier {
        match r {
            0 => Tier::P0,
            1 => Tier::P1,
            2 => Tier::P2,
            _ => Tier::Background,
        }
    }
}

/// Tier settings. Defaults are the UX report's; each is an env var so an
/// operator can move them (docs: "How tiers work").
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TierSettings {
    /// EPSS at or above this is "likely exploited" (`SUPPLYCHAIN_TIER_EPSS`,
    /// default 0.10).
    pub epss_threshold: f64,
    /// Treat unknown exposure (no observed flows) as exposed
    /// (`SUPPLYCHAIN_TIER_UNKNOWN_EXPOSURE_AS_EXPOSED`, default true):
    /// "degrade upward, not downward".
    pub unknown_exposure_as_exposed: bool,
    /// Hours of continuous coverage before "installed, not observed" may
    /// be claimed (`SUPPLYCHAIN_IN_USE_MIN_WINDOW_HOURS`, default 24).
    pub min_window_hours: i64,
}

impl Default for TierSettings {
    fn default() -> Self {
        TierSettings {
            epss_threshold: 0.10,
            unknown_exposure_as_exposed: true,
            min_window_hours: 24,
        }
    }
}

impl TierSettings {
    pub(crate) fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        let d = TierSettings::default();
        TierSettings {
            epss_threshold: get("SUPPLYCHAIN_TIER_EPSS")
                .and_then(|v| v.trim().parse::<f64>().ok())
                .filter(|v| v.is_finite())
                .map(|v| v.clamp(0.0, 1.0))
                .unwrap_or(d.epss_threshold),
            unknown_exposure_as_exposed: get("SUPPLYCHAIN_TIER_UNKNOWN_EXPOSURE_AS_EXPOSED")
                .map(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "false" | "0" | "no"))
                .unwrap_or(d.unknown_exposure_as_exposed),
            min_window_hours: get("SUPPLYCHAIN_IN_USE_MIN_WINDOW_HOURS")
                .and_then(|v| v.trim().parse::<i64>().ok())
                .map(|v| v.clamp(1, 24 * 30))
                .unwrap_or(d.min_window_hours),
        }
    }

    pub fn from_env() -> Self {
        static S: std::sync::OnceLock<TierSettings> = std::sync::OnceLock::new();
        *S.get_or_init(|| TierSettings::from_lookup(|k| std::env::var(k).ok()))
    }
}

/// The factors of one finding in one workload container.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TierInput {
    pub in_use: InUse,
    /// Severity rank: 5 CRITICAL .. 0 UNKNOWN.
    pub severity_rank: i16,
    pub kev: bool,
    pub epss: Option<f64>,
    /// Observed exposure: Some(true) exposed, Some(false) observed and
    /// internal, None unknown.
    pub exposed: Option<bool>,
    pub fixable: bool,
}

/// team/04-ux.md section 3, in order:
///
/// - **Background**: installed but not observed in a covered window.
/// - **P0**: in use AND (KEV or EPSS >= threshold) AND exposed.
/// - **P1**: in use AND (KEV or EPSS >= threshold) but not exposed ("P0
///   factors but not exposed"); or in use AND critical/high, except:
/// - **P2**: high with no fix and not exposed; or medium/low/none/unknown
///   severity.
///
/// Unknown in-use counts as in use; unknown exposure counts as exposed
/// unless the setting says otherwise.
pub fn tier(t: &TierInput, s: &TierSettings) -> Tier {
    if !t.in_use.counts_as_in_use() {
        return Tier::Background;
    }
    let exposed = t.exposed.unwrap_or(s.unknown_exposure_as_exposed);
    let hot = t.kev || t.epss.is_some_and(|e| e >= s.epss_threshold);
    if hot && exposed {
        return Tier::P0;
    }
    if hot {
        return Tier::P1;
    }
    let high = t.severity_rank == 4;
    let critical = t.severity_rank == 5;
    if high && !t.fixable && !exposed {
        return Tier::P2;
    }
    if critical || high {
        return Tier::P1;
    }
    Tier::P2
}

/// The factor chips that produced a tier (UX: "the ranking is
/// auditable"), e.g. `["in_use:loaded", "kev", "exposed"]`.
pub fn tier_factors(t: &TierInput, s: &TierSettings) -> Vec<String> {
    let mut f = vec![format!("in_use:{}", t.in_use.as_str())];
    if t.kev {
        f.push("kev".into());
    }
    if let Some(e) = t.epss {
        if e >= s.epss_threshold {
            f.push(format!("epss>={}", s.epss_threshold));
        }
    }
    f.push(format!(
        "severity:{}",
        crate::supplychain::severity_from_rank(t.severity_rank).to_ascii_lowercase()
    ));
    f.push(match t.exposed {
        Some(true) => "exposed".into(),
        Some(false) => "internal".into(),
        None => "exposure:unknown".into(),
    });
    if !t.fixable {
        f.push("no_fix".into());
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_normalise() {
        assert_eq!(
            normalise_path("./usr//lib/./x.so").as_deref(),
            Some("/usr/lib/x.so")
        );
        assert_eq!(
            normalise_path("app/node_modules/a/../b").as_deref(),
            Some("/app/node_modules/b")
        );
        assert_eq!(normalise_path(" /bin/cat ").as_deref(), Some("/bin/cat"));
        assert_eq!(normalise_path("/"), None);
        assert_eq!(normalise_path(""), None);
    }

    #[test]
    fn merged_usr_twins() {
        assert_eq!(
            merged_usr_twin("/usr/lib/x86_64-linux-gnu/libz.so.1").as_deref(),
            Some("/lib/x86_64-linux-gnu/libz.so.1")
        );
        assert_eq!(
            merged_usr_twin("/lib64/ld-linux-x86-64.so.2").as_deref(),
            Some("/usr/lib64/ld-linux-x86-64.so.2")
        );
        assert_eq!(merged_usr_twin("/bin/cat").as_deref(), Some("/usr/bin/cat"));
        assert_eq!(
            merged_usr_twin("/usr/sbin/nginx").as_deref(),
            Some("/sbin/nginx")
        );
        assert_eq!(merged_usr_twin("/usr/local/bin/app"), None);
        assert_eq!(merged_usr_twin("/opt/x"), None);
    }

    #[test]
    fn sonames_stop_at_major() {
        assert_eq!(
            shorter_sonames("/usr/lib/x86_64-linux-gnu/libz.so.1.2.13"),
            [
                "/usr/lib/x86_64-linux-gnu/libz.so.1.2",
                "/usr/lib/x86_64-linux-gnu/libz.so.1"
            ]
        );
        assert_eq!(shorter_sonames("/lib/libssl.so.3"), Vec::<String>::new());
        assert_eq!(shorter_sonames("/usr/lib/libx.so"), Vec::<String>::new());
        assert_eq!(shorter_sonames("/usr/bin/cat"), Vec::<String>::new());
        assert_eq!(
            shorter_sonames("/x/libexpat.so.1.9.1"),
            ["/x/libexpat.so.1.9", "/x/libexpat.so.1"]
        );
    }

    #[test]
    fn candidates_are_ranked_and_include_relative_spellings() {
        let c = candidates("/usr/lib/x86_64-linux-gnu/libz.so.1.3");
        assert_eq!(
            c[0],
            (
                "/usr/lib/x86_64-linux-gnu/libz.so.1.3".into(),
                PathMatch::Exact
            )
        );
        assert!(c.contains(&(
            "usr/lib/x86_64-linux-gnu/libz.so.1.3".into(),
            PathMatch::Exact
        )));
        assert!(c.contains(&(
            "/lib/x86_64-linux-gnu/libz.so.1.3".into(),
            PathMatch::MergedUsrAlias
        )));
        assert!(c.contains(&("/lib/x86_64-linux-gnu/libz.so.1".into(), PathMatch::Soname)));
        assert!(
            !c.iter().any(|(p, _)| p.ends_with("libz.so")),
            "never the -dev symlink"
        );
    }

    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!("../test/fixtures/in_use_paths.json")).unwrap()
    }

    fn components(v: &serde_json::Value) -> Vec<Component> {
        v["components"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| Component {
                key: PackageKey {
                    name: c["name"].as_str().unwrap().into(),
                    version: c["version"].as_str().map(String::from),
                },
                file_paths: c["file_paths"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| p.as_str().unwrap().to_string())
                    .collect(),
            })
            .collect()
    }

    /// Real package file lists against kernel-style runtime paths, for
    /// Debian bookworm (merged-/usr, dpkg records /lib and /bin), Alpine
    /// 3.20 (not merged-/usr; /usr/lib/libssl.so.3 is a symlink to /lib),
    /// and Ubuntu 24.04 (mappings the kernel actually reported, owners
    /// from dpkg -S).
    #[test]
    fn real_fixtures_map_runtime_paths_to_their_packages() {
        let f = fixture();
        let mut checked = 0;
        for (distro, v) in f["distros"].as_object().unwrap() {
            let comps = components(v);
            for r in v["runtime"].as_array().unwrap() {
                let path = r["path"].as_str().unwrap();
                let got = owners_of(path, &comps);
                match r["expect"].as_str() {
                    None => assert!(got.unowned(), "{distro} {path}: {got:?}"),
                    Some(want) => {
                        assert_eq!(
                            got.owners
                                .iter()
                                .map(|o| o.name.as_str())
                                .collect::<Vec<_>>(),
                            [want],
                            "{distro} {path}"
                        );
                        match r["match"].as_str().unwrap() {
                            "exact" => {
                                assert_eq!(got.how, Some(PathMatch::Exact), "{distro} {path}")
                            }
                            "merged_usr_alias" => {
                                assert_eq!(
                                    got.how,
                                    Some(PathMatch::MergedUsrAlias),
                                    "{distro} {path}"
                                )
                            }
                            _ => {}
                        }
                    }
                }
                checked += 1;
            }
        }
        assert!(checked >= 20, "{checked}");
    }

    #[test]
    fn a_soname_symlink_in_the_sbom_matches_the_real_file_at_runtime() {
        // An SBOM that records only the soname link (as some generators
        // do), while the kernel reports the real file.
        let comps = vec![
            Component {
                key: PackageKey {
                    name: "zlib1g".into(),
                    version: Some("1:1.2.13".into()),
                },
                file_paths: vec!["lib/x86_64-linux-gnu/libz.so.1".into()],
            },
            Component {
                key: PackageKey {
                    name: "zlib1g-dev".into(),
                    version: Some("1:1.2.13".into()),
                },
                file_paths: vec!["/usr/lib/x86_64-linux-gnu/libz.so".into()],
            },
        ];
        let o = owners_of("/usr/lib/x86_64-linux-gnu/libz.so.1.2.13", &comps);
        assert_eq!(o.owners[0].name, "zlib1g");
        assert_eq!(
            o.owners.len(),
            1,
            "the -dev package's bare .so never matches"
        );
        assert_eq!(o.how, Some(PathMatch::Soname));
    }

    #[test]
    fn an_exact_match_beats_an_alias_and_ties_credit_every_owner() {
        let comps = vec![
            Component {
                key: PackageKey {
                    name: "a".into(),
                    version: None,
                },
                file_paths: vec!["/lib/x".into()],
            },
            Component {
                key: PackageKey {
                    name: "b".into(),
                    version: None,
                },
                file_paths: vec!["/usr/lib/x".into()],
            },
            Component {
                key: PackageKey {
                    name: "c".into(),
                    version: None,
                },
                file_paths: vec!["usr/lib/x".into()],
            },
        ];
        let o = owners_of("/usr/lib/x", &comps);
        assert_eq!(o.how, Some(PathMatch::Exact));
        assert_eq!(
            o.owners.iter().map(|k| k.name.as_str()).collect::<Vec<_>>(),
            ["b", "c"]
        );
    }

    #[test]
    fn language_packages_are_not_observable_but_compiled_binaries_are() {
        assert!(!is_observable_type(Some("npm"), Some("lang-pkgs")));
        assert!(!is_observable_type(Some("python-pkg"), None));
        assert!(!is_observable_type(Some("jar"), Some("lang-pkgs")));
        assert!(!is_observable_type(None, Some("lang-pkgs")));
        assert!(is_observable_type(Some("gobinary"), Some("lang-pkgs")));
        assert!(is_observable_type(Some("debian"), Some("os-pkgs")));
        assert!(is_observable_type(Some("alpine"), None));
    }

    #[test]
    fn coverage_labels_by_package_type() {
        assert_eq!(
            coverage_of(Some("gobinary"), Some("lang-pkgs")),
            Coverage::StaticBinary
        );
        assert_eq!(
            coverage_of(Some("rustbinary"), Some("lang-pkgs")),
            Coverage::StaticBinary
        );
        assert_eq!(coverage_of(Some("debian"), Some("os-pkgs")), Coverage::File);
        assert_eq!(
            coverage_of(Some("npm"), Some("lang-pkgs")),
            Coverage::Interpreted
        );
        assert_eq!(coverage_of(Some("python-pkg"), None), Coverage::Interpreted);
        for r in 0..=3 {
            assert_eq!(InUse::from_rank(r).rank(), r);
        }
    }

    /// A static Go binary: Trivy lists each module with the binary as its
    /// file, so executing the binary credits every module in it.
    #[test]
    fn executing_a_static_binary_credits_every_module_in_it() {
        let comps = ["stdlib", "golang.org/x/net", "github.com/example/lib"]
            .iter()
            .map(|n| Component {
                key: PackageKey {
                    name: n.to_string(),
                    version: None,
                },
                file_paths: vec!["usr/local/bin/app".into()],
            })
            .collect::<Vec<_>>();
        let o = owners_of("/usr/local/bin/app", &comps);
        assert_eq!(o.how, Some(PathMatch::Exact));
        assert_eq!(o.owners.len(), 3);
    }

    #[test]
    fn every_unknown_case() {
        let covered = Evidence {
            covered: true,
            observable: true,
            has_files: true,
            ..Default::default()
        };
        assert_eq!(in_use_of(&covered), (InUse::InstalledNotObserved, None));
        // No runtime data at all.
        assert_eq!(
            in_use_of(&Evidence {
                covered: false,
                ..covered.clone()
            }),
            (InUse::Unknown, Some(UnknownReason::NoRuntimeData))
        );
        for gap in [UnknownReason::CaptureGap, UnknownReason::HostNetwork] {
            assert_eq!(
                in_use_of(&Evidence {
                    covered: false,
                    gap: Some(gap),
                    ..covered.clone()
                }),
                (InUse::Unknown, Some(gap))
            );
        }
        assert_eq!(
            in_use_of(&Evidence {
                observable: false,
                ..covered.clone()
            }),
            (InUse::Unknown, Some(UnknownReason::LanguagePackage))
        );
        assert_eq!(
            in_use_of(&Evidence {
                has_files: false,
                ..covered.clone()
            }),
            (InUse::Unknown, Some(UnknownReason::NoPackageFiles))
        );
        // Positive evidence wins even without coverage.
        assert_eq!(
            in_use_of(&Evidence {
                loaded: true,
                covered: false,
                ..covered.clone()
            })
            .0,
            InUse::Loaded
        );
        assert_eq!(
            in_use_of(&Evidence {
                executed: true,
                loaded: true,
                ..covered.clone()
            })
            .0,
            InUse::Executed
        );
        assert!(InUse::Unknown.counts_as_in_use());
        assert!(!InUse::InstalledNotObserved.counts_as_in_use());
        assert!(
            InUse::Unknown < InUse::InstalledNotObserved,
            "unknown ranks above not-observed"
        );
    }

    /// The tier table from team/04-ux.md section 3, one row per rule.
    #[test]
    fn tier_table() {
        let s = TierSettings::default();
        let t = |in_use, sev, kev, epss: Option<f64>, exposed, fixable| {
            tier(
                &TierInput {
                    in_use,
                    severity_rank: sev,
                    kev,
                    epss,
                    exposed,
                    fixable,
                },
                &s,
            )
        };
        use InUse::*;
        // P0: in use AND (KEV or EPSS >= 10%) AND exposed.
        assert_eq!(t(Loaded, 3, true, None, Some(true), true), Tier::P0);
        assert_eq!(
            t(Executed, 2, false, Some(0.10), Some(true), false),
            Tier::P0
        );
        assert_eq!(
            t(Unknown, 3, true, None, Some(true), true),
            Tier::P0,
            "unknown counts as in use"
        );
        assert_eq!(
            t(Loaded, 3, true, None, None, true),
            Tier::P0,
            "unknown exposure degrades upward"
        );
        // P1: P0 factors but not exposed.
        assert_eq!(t(Loaded, 2, true, None, Some(false), true), Tier::P1);
        assert_eq!(t(Loaded, 2, false, Some(0.34), Some(false), true), Tier::P1);
        // P1: in use AND critical/high.
        assert_eq!(t(Loaded, 5, false, Some(0.01), Some(false), true), Tier::P1);
        assert_eq!(t(Loaded, 4, false, None, Some(false), true), Tier::P1);
        assert_eq!(
            t(Loaded, 4, false, None, Some(true), false),
            Tier::P1,
            "high, no fix, but exposed"
        );
        assert_eq!(
            t(Loaded, 5, false, None, Some(false), false),
            Tier::P1,
            "critical stays P1 without a fix"
        );
        // P2: high with no fix and not exposed; medium/low.
        assert_eq!(t(Loaded, 4, false, None, Some(false), false), Tier::P2);
        assert_eq!(t(Loaded, 3, false, Some(0.05), Some(true), true), Tier::P2);
        assert_eq!(t(Unknown, 2, false, None, None, true), Tier::P2);
        assert_eq!(
            t(Loaded, 0, false, None, Some(true), true),
            Tier::P2,
            "unknown severity"
        );
        // Background: installed, not observed in a covered window,
        // whatever else is true.
        assert_eq!(
            t(InstalledNotObserved, 5, true, Some(0.9), Some(true), true),
            Tier::Background
        );
        // Settings move the thresholds.
        let strict = TierSettings {
            epss_threshold: 0.5,
            unknown_exposure_as_exposed: false,
            ..s
        };
        let ts = |epss, exposed| {
            tier(
                &TierInput {
                    in_use: Loaded,
                    severity_rank: 3,
                    kev: false,
                    epss: Some(epss),
                    exposed,
                    fixable: true,
                },
                &strict,
            )
        };
        assert_eq!(ts(0.34, Some(true)), Tier::P2);
        assert_eq!(ts(0.6, Some(true)), Tier::P0);
        assert_eq!(ts(0.6, None), Tier::P1, "unknown exposure as not exposed");
    }

    #[test]
    fn tier_settings_parse_and_clamp() {
        let get = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(kk, _)| *kk == k)
                    .map(|(_, v)| v.to_string())
            }
        };
        assert_eq!(TierSettings::from_lookup(|_| None), TierSettings::default());
        let s = TierSettings::from_lookup(get(&[
            ("SUPPLYCHAIN_TIER_EPSS", "2"),
            ("SUPPLYCHAIN_TIER_UNKNOWN_EXPOSURE_AS_EXPOSED", "false"),
            ("SUPPLYCHAIN_IN_USE_MIN_WINDOW_HOURS", "0"),
        ]));
        assert_eq!(
            (
                s.epss_threshold,
                s.unknown_exposure_as_exposed,
                s.min_window_hours
            ),
            (1.0, false, 1)
        );
        let s = TierSettings::from_lookup(get(&[("SUPPLYCHAIN_TIER_EPSS", "nope")]));
        assert_eq!(s.epss_threshold, 0.10);
    }

    #[test]
    fn factors_explain_the_tier() {
        let s = TierSettings::default();
        let f = tier_factors(
            &TierInput {
                in_use: InUse::Loaded,
                severity_rank: 5,
                kev: true,
                epss: Some(0.34),
                exposed: Some(true),
                fixable: false,
            },
            &s,
        );
        assert_eq!(
            f,
            [
                "in_use:loaded",
                "kev",
                "epss>=0.1",
                "severity:critical",
                "exposed",
                "no_fix"
            ]
        );
    }

    const TEST_MIGRATIONS: diesel_migrations::EmbeddedMigrations =
        diesel_migrations::embed_migrations!("./db/migrations");

    /// The SQL tier function the summaries use must agree with tier() on
    /// every input combination, under both exposure settings.
    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_sql_tier_matches_rust_on_every_input() {
        use diesel::prelude::*;
        use diesel::sql_types::{Bool, Double, Float, Nullable, SmallInt, Text};
        use diesel_migrations::MigrationHarness;
        let url = std::env::var("KG_TEST_DATABASE_URL").expect("set KG_TEST_DATABASE_URL");
        let mut conn = diesel::PgConnection::establish(&url).expect("connect");
        conn.run_pending_migrations(TEST_MIGRATIONS)
            .expect("migrations");
        #[derive(QueryableByName)]
        struct T {
            #[diesel(sql_type = SmallInt)]
            t: i16,
        }
        let mut n = 0;
        for s in [
            TierSettings::default(),
            TierSettings {
                epss_threshold: 0.5,
                unknown_exposure_as_exposed: false,
                ..Default::default()
            },
        ] {
            for in_use in [
                InUse::Executed,
                InUse::Loaded,
                InUse::Unknown,
                InUse::InstalledNotObserved,
            ] {
                for sev in 0..=5i16 {
                    for kev in [false, true] {
                        for epss in [None, Some(0.05f32), Some(0.10), Some(0.6)] {
                            for exposed in [None, Some(false), Some(true)] {
                                for fixable in [false, true] {
                                    let input = TierInput {
                                        in_use,
                                        severity_rank: sev,
                                        kev,
                                        epss: epss.map(f64::from),
                                        exposed,
                                        fixable,
                                    };
                                    let want = tier(&input, &s).rank();
                                    let got = diesel::sql_query(
                                        "SELECT kg_vuln_tier($1, $2, $3, $4, $5, $6, $7, $8) AS t",
                                    )
                                    .bind::<Text, _>(in_use.as_str())
                                    .bind::<SmallInt, _>(sev)
                                    .bind::<Bool, _>(kev)
                                    .bind::<Nullable<Float>, _>(epss)
                                    .bind::<Nullable<Bool>, _>(exposed)
                                    .bind::<Bool, _>(fixable)
                                    .bind::<Double, _>(s.epss_threshold)
                                    .bind::<Bool, _>(s.unknown_exposure_as_exposed)
                                    .get_result::<T>(&mut conn)
                                    .unwrap()
                                    .t;
                                    assert_eq!(got, want, "{input:?} {s:?}");
                                    n += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(n, 2 * 4 * 6 * 2 * 4 * 3 * 2);
    }
}
