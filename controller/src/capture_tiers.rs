//! Tiered syscall capture.
//!
//! The syscall probe filters events per tracked netns by a capture *tier*
//! carried in the `inode_num` map value (see `pod_flags` in models.rs and
//! `KG_TIER_*` in `src/bpf/helper.h`). Each non-`full` tier has its own
//! allowlist BPF map, populated once at startup from the name lists below.
//!
//! Names, never numbers. The previous allowlist hard-coded x86_64 syscall
//! numbers, which on arm64 select unrelated syscalls (`59` is `execve` on
//! x86_64 and `pipe2` on aarch64). Every list here is resolved to numbers
//! for the running architecture through libseccomp at startup; a name the
//! arch does not have (`open`, `fork`, `getdents` on aarch64) is logged at
//! warn and skipped — never a startup failure.
//!
//! Only `full` is complete enough to build a seccomp profile from; the
//! broker refuses to publish a profile whose workload runs at a lower
//! tier. The tiers exist for operators who want the security signal at a
//! fraction of the event volume.

use libseccomp::{ScmpArch, ScmpSyscall};
use std::collections::BTreeSet;
use tracing::{info, warn};

/// A capture tier. Ordered `full > high > medium > low`; `custom` is
/// operator-defined and unordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CaptureLevel {
    Full,
    High,
    Medium,
    Low,
    Custom,
}

impl CaptureLevel {
    /// Every level, in tier-index order.
    pub const ALL: [CaptureLevel; 5] = [
        CaptureLevel::Full,
        CaptureLevel::High,
        CaptureLevel::Medium,
        CaptureLevel::Low,
        CaptureLevel::Custom,
    ];

    /// Parse the canonical string form (case-insensitive, whitespace
    /// tolerant). `None` for anything else.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "full" => Some(CaptureLevel::Full),
            "high" => Some(CaptureLevel::High),
            "medium" => Some(CaptureLevel::Medium),
            "low" => Some(CaptureLevel::Low),
            "custom" => Some(CaptureLevel::Custom),
            _ => None,
        }
    }

    /// The exact string the broker, chart and frontend use.
    pub fn as_str(self) -> &'static str {
        match self {
            CaptureLevel::Full => "full",
            CaptureLevel::High => "high",
            CaptureLevel::Medium => "medium",
            CaptureLevel::Low => "low",
            CaptureLevel::Custom => "custom",
        }
    }

    /// Tier index stored in bits 1-3 of the `inode_num` map value:
    /// `0=full, 1=high, 2=medium, 3=low, 4=custom`. Must match the
    /// `KG_TIER_*` defines in `src/bpf/helper.h`.
    pub fn tier_index(self) -> u32 {
        match self {
            CaptureLevel::Full => 0,
            CaptureLevel::High => 1,
            CaptureLevel::Medium => 2,
            CaptureLevel::Low => 3,
            CaptureLevel::Custom => 4,
        }
    }

    /// Inverse of `tier_index`; `None` for the unused indices 5-7.
    pub fn from_tier_index(idx: u32) -> Option<Self> {
        CaptureLevel::ALL.get(idx as usize).copied()
    }

    /// How much is captured, higher is more. `None` for `custom`, which
    /// cannot be compared against the ordered tiers.
    fn rank(self) -> Option<u8> {
        match self {
            CaptureLevel::Full => Some(3),
            CaptureLevel::High => Some(2),
            CaptureLevel::Medium => Some(1),
            CaptureLevel::Low => Some(0),
            CaptureLevel::Custom => None,
        }
    }

    /// The effective tier when a workload asks for `requested` on top of
    /// the cluster default `cluster`. A per-workload setting can only ever
    /// RAISE capture: the operator picked the cluster default to bound
    /// event volume, but a workload that needs a seccomp profile must be
    /// able to opt into more.
    ///
    /// `custom` is unordered, so: `custom` cannot be requested per
    /// workload (the caller rejects it before getting here, and it maps
    /// to the cluster default if it does arrive); when the CLUSTER is
    /// `custom`, an explicitly requested ordered level is honoured as-is
    /// — there is no meaningful "higher than an arbitrary list", and the
    /// workload asked for something specific.
    pub fn raise(cluster: Self, requested: Self) -> Self {
        match (cluster.rank(), requested.rank()) {
            (Some(c), Some(r)) => {
                if r > c {
                    requested
                } else {
                    cluster
                }
            }
            (None, Some(_)) => requested,
            (_, None) => cluster,
        }
    }
}

impl std::fmt::Display for CaptureLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Default cluster-wide tier when `SYSCALL_CAPTURE_LEVEL` is unset.
/// `full`, because the in-kernel per-netns dedup makes complete capture
/// nearly free and only `full` can feed a published seccomp profile.
pub const DEFAULT_LEVEL: CaptureLevel = CaptureLevel::Full;

/// `low`: the security-relevant subset — exactly the allowlist the
/// controller has always shipped, now by name.
pub const LOW: &[&str] = &[
    // Process execution
    "execve",
    "execveat",
    "fork",
    "vfork",
    "clone",
    "exit_group",
    // Network operations
    "socket",
    "connect",
    "accept",
    "accept4",
    "bind",
    "listen",
    "sendmsg",
    "recvmsg",
    "sendto",
    "recvfrom",
    // File operations
    "open",
    "openat",
    "openat2",
    "creat",
    "unlink",
    "unlinkat",
    "rename",
    "renameat",
    "renameat2",
    "mkdir",
    "rmdir",
    "symlink",
    "symlinkat",
    // Privilege operations
    "setuid",
    "setgid",
    "setresuid",
    "setresgid",
    "setregid",
    "setreuid",
    "prctl",
    "ptrace",
    "pivot_root",
    "mount",
    "umount2",
    "swapon",
    "swapoff",
    // Module loading
    "init_module",
    "finit_module",
    "delete_module",
    // Capabilities
    "capset",
    // BPF
    "bpf",
    // Namespaces
    "setns",
    "unshare",
    // Time manipulation
    "clock_settime",
    "clock_adjtime",
    // Keyring
    "keyctl",
    // Security-sensitive I/O
    "getdents",
    "getdents64",
    "read",
    "write",
];

/// What `medium` adds on top of `low`: the rest of the socket family,
/// file create/delete/rename/link/permission changes, and process
/// lifecycle.
pub const MEDIUM_EXTRA: &[&str] = &[
    "socketpair",
    "shutdown",
    "getsockopt",
    "setsockopt",
    "getsockname",
    "getpeername",
    "sendmmsg",
    "recvmmsg",
    "link",
    "linkat",
    "chmod",
    "fchmod",
    "fchmodat",
    "chown",
    "fchown",
    "lchown",
    "fchownat",
    "truncate",
    "ftruncate",
    "mknod",
    "mknodat",
    "chdir",
    "fchdir",
    "chroot",
    "kill",
    "tkill",
    "tgkill",
    "wait4",
    "waitid",
    "exit",
    "clone3",
    "setsid",
    "setpgid",
    "setgroups",
    "setfsuid",
    "setfsgid",
    "seccomp",
    "memfd_create",
    "io_uring_setup",
    "process_vm_readv",
    "process_vm_writev",
    "userfaultfd",
    "add_key",
    "request_key",
    "personality",
    "acct",
    "reboot",
    "kexec_load",
    "kexec_file_load",
    "sethostname",
    "setdomainname",
];

/// What `high` drops: hot-path noise that carries no security signal
/// and dominates event volume. `high` is everything on the arch EXCEPT
/// these.
pub const HIGH_EXCLUSIONS: &[&str] = &[
    "read",
    "write",
    "pread64",
    "pwrite64",
    "readv",
    "writev",
    "futex",
    "epoll_wait",
    "epoll_pwait",
    "epoll_pwait2",
    "poll",
    "ppoll",
    "select",
    "pselect6",
    "nanosleep",
    "clock_nanosleep",
    "clock_gettime",
    "gettimeofday",
    "mmap",
    "munmap",
    "mprotect",
    "brk",
    "madvise",
    "sched_yield",
    "getpid",
    "gettid",
    "rt_sigprocmask",
    "rt_sigreturn",
    "sched_getaffinity",
];

/// `medium` = `low` ∪ `MEDIUM_EXTRA`, de-duplicated.
pub fn medium_names() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = LOW.to_vec();
    for n in MEDIUM_EXTRA {
        if !out.contains(n) {
            out.push(n);
        }
    }
    out
}

/// Parse `SYSCALL_CUSTOM_LIST`: comma-separated names, whitespace around
/// each entry ignored, empties dropped, duplicates collapsed (first
/// occurrence wins). Newlines count as whitespace so a multi-line Helm
/// value works.
pub fn parse_custom_list(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for name in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if !out.iter().any(|n| n == name) {
            out.push(name.to_string());
        }
    }
    out
}

/// The libseccomp arch token for the binary's target. `None` on an
/// architecture the controller does not support (the syscall probe still
/// runs, but nothing can be resolved by name there).
pub fn native_scmp_arch() -> Option<ScmpArch> {
    if cfg!(target_arch = "x86_64") {
        Some(ScmpArch::X8664)
    } else if cfg!(target_arch = "aarch64") {
        Some(ScmpArch::Aarch64)
    } else {
        None
    }
}

/// Upper bound of the number scan behind `all_syscalls_on_arch`. Both
/// supported arches top out well under this (x86_64 and aarch64 are in
/// the 460s as of Linux 6.x); the headroom covers a few years of new
/// syscalls without a code change.
const SYSCALL_SCAN_MAX: i32 = 600;

/// Every syscall number libseccomp knows for `arch`, found by asking it
/// to name each number in `0..=SYSCALL_SCAN_MAX`. Multiplexed
/// pseudo-syscalls (`socketcall` and friends carry negative numbers) are
/// outside the scan on purpose — the tracepoint never reports them.
pub fn all_syscalls_on_arch(arch: ScmpArch) -> BTreeSet<u32> {
    (0..=SYSCALL_SCAN_MAX)
        .filter(|&nr| ScmpSyscall::from(nr).get_name_by_arch(arch).is_ok())
        .map(|nr| nr as u32)
        .collect()
}

/// Resolve a list of names to numbers for `arch`. Unknown names are
/// returned separately so the caller can warn with context; nothing here
/// fails.
pub fn resolve_names<'a, I>(names: I, arch: ScmpArch) -> (BTreeSet<u32>, Vec<String>)
where
    I: IntoIterator<Item = &'a str>,
{
    let mut nrs = BTreeSet::new();
    let mut unknown = Vec::new();
    for name in names {
        match ScmpSyscall::from_name_by_arch(name, arch) {
            Ok(sc) => {
                let nr: i32 = sc.into();
                match u32::try_from(nr) {
                    Ok(n) => {
                        nrs.insert(n);
                    }
                    // libseccomp hands back a negative pseudo-number for a
                    // syscall that exists in its table but not on this
                    // arch (e.g. `open` on aarch64). Same treatment as an
                    // unknown name: not capturable here.
                    Err(_) => unknown.push(name.to_string()),
                }
            }
            Err(_) => unknown.push(name.to_string()),
        }
    }
    (nrs, unknown)
}

/// Resolved allowlists, one per non-`full` tier, for the running arch.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ResolvedTiers {
    pub high: BTreeSet<u32>,
    pub medium: BTreeSet<u32>,
    pub low: BTreeSet<u32>,
    pub custom: BTreeSet<u32>,
}

impl ResolvedTiers {
    /// The allowlist for `level`; `None` for `full`, which has no map.
    pub fn for_level(&self, level: CaptureLevel) -> Option<&BTreeSet<u32>> {
        match level {
            CaptureLevel::Full => None,
            CaptureLevel::High => Some(&self.high),
            CaptureLevel::Medium => Some(&self.medium),
            CaptureLevel::Low => Some(&self.low),
            CaptureLevel::Custom => Some(&self.custom),
        }
    }
}

/// Resolve every tier for `arch`, logging unknown names at warn.
/// `custom_names` is the parsed `SYSCALL_CUSTOM_LIST`.
pub fn resolve_tiers_for_arch(custom_names: &[String], arch: ScmpArch) -> ResolvedTiers {
    let warn_unknown = |tier: &str, unknown: &[String]| {
        if !unknown.is_empty() {
            warn!(
                tier,
                arch = ?arch,
                unknown = ?unknown,
                "syscall names not available on this architecture; skipped"
            );
        }
    };

    let all = all_syscalls_on_arch(arch);
    let (excluded, unknown) = resolve_names(HIGH_EXCLUSIONS.iter().copied(), arch);
    // An exclusion the arch lacks is expected (aarch64 has no `select`
    // or `poll`) and changes nothing, so it is debug, not warn.
    if !unknown.is_empty() {
        tracing::debug!(tier = "high", arch = ?arch, unknown = ?unknown,
            "high-tier exclusions not present on this architecture");
    }
    let high: BTreeSet<u32> = all.difference(&excluded).copied().collect();

    let (medium, unknown) = resolve_names(medium_names(), arch);
    warn_unknown("medium", &unknown);

    let (low, unknown) = resolve_names(LOW.iter().copied(), arch);
    warn_unknown("low", &unknown);

    let (custom, unknown) = resolve_names(custom_names.iter().map(String::as_str), arch);
    warn_unknown("custom", &unknown);

    ResolvedTiers {
        high,
        medium,
        low,
        custom,
    }
}

/// Startup configuration from `SYSCALL_CAPTURE_LEVEL` and
/// `SYSCALL_CUSTOM_LIST`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureConfig {
    /// Cluster-wide default tier.
    pub level: CaptureLevel,
    /// Names for the `custom` tier (may be empty when `level` is not
    /// `custom`, in which case the custom map is simply left empty).
    pub custom_names: Vec<String>,
}

impl CaptureConfig {
    /// Pure parser over the two raw env values. An unparseable level
    /// warns and falls back to `DEFAULT_LEVEL`; `custom` with an empty
    /// list warns loudly because it captures nothing at all.
    pub fn from_values(level: Option<&str>, custom_list: Option<&str>) -> Self {
        let level = match level.map(str::trim).filter(|s| !s.is_empty()) {
            None => DEFAULT_LEVEL,
            Some(raw) => match CaptureLevel::parse(raw) {
                Some(l) => l,
                None => {
                    warn!(
                        value = raw,
                        default = %DEFAULT_LEVEL,
                        "SYSCALL_CAPTURE_LEVEL is not one of full|high|medium|low|custom; using default"
                    );
                    DEFAULT_LEVEL
                }
            },
        };
        let custom_names = parse_custom_list(custom_list.unwrap_or_default());
        if level == CaptureLevel::Custom && custom_names.is_empty() {
            warn!(
                "SYSCALL_CAPTURE_LEVEL=custom with an empty SYSCALL_CUSTOM_LIST: \
                 no syscalls will be captured for workloads at the cluster default"
            );
        }
        Self {
            level,
            custom_names,
        }
    }

    pub fn from_env() -> Self {
        Self::from_values(
            std::env::var("SYSCALL_CAPTURE_LEVEL").ok().as_deref(),
            std::env::var("SYSCALL_CUSTOM_LIST").ok().as_deref(),
        )
    }

    /// Resolve every tier for the native arch and log the outcome at
    /// info so an operator can see exactly what each tier means on this
    /// node. On an unsupported arch every list is empty (and a warning
    /// says so); the `full` tier still works there because it has no map.
    pub fn resolve(&self) -> ResolvedTiers {
        let Some(arch) = native_scmp_arch() else {
            warn!(
                arch = std::env::consts::ARCH,
                "unsupported architecture: syscall tier allowlists cannot be resolved; \
                 only the full tier captures anything"
            );
            return ResolvedTiers::default();
        };
        let tiers = resolve_tiers_for_arch(&self.custom_names, arch);
        info!(
            level = %self.level,
            arch = ?arch,
            high = tiers.high.len(),
            medium = tiers.medium.len(),
            low = tiers.low.len(),
            custom = tiers.custom.len(),
            "syscall capture tiers resolved (allowlist sizes per tier; full is unfiltered)"
        );
        tiers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arch() -> ScmpArch {
        native_scmp_arch().expect("tests run on x86_64 or aarch64")
    }

    #[test]
    fn levels_round_trip_through_strings_and_indices() {
        for l in CaptureLevel::ALL {
            assert_eq!(CaptureLevel::parse(l.as_str()), Some(l));
            assert_eq!(CaptureLevel::parse(&l.as_str().to_uppercase()), Some(l));
            assert_eq!(CaptureLevel::parse(&format!("  {}\n", l)), Some(l));
            assert_eq!(CaptureLevel::from_tier_index(l.tier_index()), Some(l));
        }
        assert_eq!(CaptureLevel::parse("all"), None);
        assert_eq!(CaptureLevel::parse(""), None);
        assert_eq!(CaptureLevel::from_tier_index(5), None);
        assert_eq!(CaptureLevel::from_tier_index(7), None);
        // The indices are a wire contract with helper.h.
        assert_eq!(CaptureLevel::Full.tier_index(), 0);
        assert_eq!(CaptureLevel::High.tier_index(), 1);
        assert_eq!(CaptureLevel::Medium.tier_index(), 2);
        assert_eq!(CaptureLevel::Low.tier_index(), 3);
        assert_eq!(CaptureLevel::Custom.tier_index(), 4);
    }

    #[test]
    fn raise_never_lowers() {
        use CaptureLevel::*;
        assert_eq!(CaptureLevel::raise(Low, High), High);
        assert_eq!(CaptureLevel::raise(Full, Low), Full);
        assert_eq!(CaptureLevel::raise(Medium, Medium), Medium);
        assert_eq!(CaptureLevel::raise(High, Medium), High);
        assert_eq!(CaptureLevel::raise(Low, Full), Full);
        // custom is unordered: requesting it changes nothing, and an
        // explicit ordered request on a custom cluster is honoured.
        assert_eq!(CaptureLevel::raise(Low, Custom), Low);
        assert_eq!(CaptureLevel::raise(Custom, Custom), Custom);
        assert_eq!(CaptureLevel::raise(Custom, High), High);
        assert_eq!(CaptureLevel::raise(Custom, Full), Full);
    }

    #[test]
    fn low_names_are_the_original_allowlist() {
        // The old populate_syscall_allowlist carried 56 numbers (the
        // design doc rounds it to "~55"); the name list must match it
        // one for one.
        assert_eq!(LOW.len(), 56);
        let unique: BTreeSet<&str> = LOW.iter().copied().collect();
        assert_eq!(unique.len(), 56, "LOW has a duplicate");
    }

    #[test]
    fn low_is_a_subset_of_medium_by_name() {
        let medium: BTreeSet<&str> = medium_names().into_iter().collect();
        for n in LOW {
            assert!(medium.contains(n), "{n} is in low but not medium");
        }
        // And medium genuinely adds something.
        assert!(medium.len() > LOW.len());
        let unique_extra: BTreeSet<&str> = MEDIUM_EXTRA.iter().copied().collect();
        assert_eq!(
            unique_extra.len(),
            MEDIUM_EXTRA.len(),
            "MEDIUM_EXTRA has a duplicate"
        );
    }

    #[test]
    fn low_is_a_subset_of_medium_by_number() {
        let t = resolve_tiers_for_arch(&[], arch());
        assert!(t.low.is_subset(&t.medium));
        assert!(!t.low.is_empty());
    }

    #[test]
    fn high_excludes_exactly_the_exclusion_list() {
        let a = arch();
        let t = resolve_tiers_for_arch(&[], a);
        let all = all_syscalls_on_arch(a);
        let (excluded, _) = resolve_names(HIGH_EXCLUSIONS.iter().copied(), a);
        assert!(!all.is_empty());
        assert!(!excluded.is_empty());

        // Nothing excluded is allowed...
        for nr in &excluded {
            assert!(!t.high.contains(nr), "excluded syscall {nr} is in high");
        }
        // ...and everything else on the arch is.
        for nr in &all {
            if !excluded.contains(nr) {
                assert!(t.high.contains(nr), "syscall {nr} missing from high");
            }
        }
        assert_eq!(t.high.len() + excluded.len(), all.len());

        // Spot checks by name so the test reads as the contract does.
        let name = |n: &str| {
            u32::try_from(i32::from(ScmpSyscall::from_name_by_arch(n, a).unwrap())).unwrap()
        };
        for n in ["execve", "openat", "connect", "clone", "setuid"] {
            assert!(t.high.contains(&name(n)), "{n} must be in high");
        }
        for n in ["futex", "mmap", "clock_gettime", "write"] {
            assert!(!t.high.contains(&name(n)), "{n} must not be in high");
        }
    }

    #[test]
    fn tiers_nest_by_volume() {
        // low ⊂ medium; medium is mostly inside high except for the
        // deliberately-excluded read/write; high ⊂ all.
        let a = arch();
        let t = resolve_tiers_for_arch(&[], a);
        let all = all_syscalls_on_arch(a);
        assert!(t.low.is_subset(&t.medium));
        assert!(t.high.is_subset(&all));
        let (rw, _) = resolve_names(["read", "write"], a);
        let medium_minus_rw: BTreeSet<u32> = t.medium.difference(&rw).copied().collect();
        assert!(medium_minus_rw.is_subset(&t.high));
        assert!(t.low.len() < t.medium.len());
        assert!(t.medium.len() < t.high.len());
        assert!(t.high.len() < all.len());
    }

    #[test]
    fn names_resolve_per_arch_not_by_hard_coded_number() {
        // The regression this whole module exists to fix: the old
        // allowlist put 59 in the map on every arch, but 59 is execve
        // only on x86_64 (it is pipe2 on aarch64).
        let (x, _) = resolve_names(["execve"], ScmpArch::X8664);
        let (a, _) = resolve_names(["execve"], ScmpArch::Aarch64);
        assert_eq!(x, BTreeSet::from([59]));
        assert_eq!(a, BTreeSet::from([221]));
        assert_ne!(x, a);
    }

    #[test]
    fn unknown_names_are_skipped_never_panic() {
        let (nrs, unknown) = resolve_names(
            ["execve", "not_a_syscall", "", "sys.call!", "openat"],
            arch(),
        );
        assert_eq!(nrs.len(), 2);
        assert_eq!(unknown, vec!["not_a_syscall", "", "sys.call!"]);

        // Names libseccomp knows but the arch lacks come back as
        // negative pseudo-numbers and must also be skipped: `open` and
        // `fork` do not exist on aarch64.
        let (nrs, unknown) = resolve_names(["open", "fork", "openat"], ScmpArch::Aarch64);
        assert_eq!(nrs.len(), 1);
        assert_eq!(unknown, vec!["open", "fork"]);

        // A very long or NUL-bearing name is an Err from libseccomp, not
        // a panic.
        let long = "a".repeat(200);
        let (nrs, unknown) = resolve_names([long.as_str(), "x\0y"], arch());
        assert!(nrs.is_empty());
        assert_eq!(unknown.len(), 2);

        // Whole-tier resolution with garbage custom names still succeeds.
        let t = resolve_tiers_for_arch(&["nope".to_string(), "execve".to_string()], arch());
        assert_eq!(t.custom.len(), 1);
    }

    #[test]
    fn custom_list_parses_with_whitespace_tolerance() {
        assert_eq!(
            parse_custom_list(" execve, openat ,\n connect ,,bind,"),
            vec!["execve", "openat", "connect", "bind"]
        );
        assert_eq!(parse_custom_list("execve,execve"), vec!["execve"]);
        assert!(parse_custom_list("").is_empty());
        assert!(parse_custom_list(" , ,\t").is_empty());
        assert_eq!(parse_custom_list("execve"), vec!["execve"]);
    }

    #[test]
    fn config_defaults_to_full_and_tolerates_garbage() {
        let c = CaptureConfig::from_values(None, None);
        assert_eq!(c.level, CaptureLevel::Full);
        assert!(c.custom_names.is_empty());

        let c = CaptureConfig::from_values(Some(""), None);
        assert_eq!(c.level, CaptureLevel::Full);

        let c = CaptureConfig::from_values(Some("everything"), None);
        assert_eq!(c.level, CaptureLevel::Full);

        let c = CaptureConfig::from_values(Some(" LOW "), Some("execve, openat"));
        assert_eq!(c.level, CaptureLevel::Low);
        assert_eq!(c.custom_names, vec!["execve", "openat"]);

        let c = CaptureConfig::from_values(Some("custom"), Some(""));
        assert_eq!(c.level, CaptureLevel::Custom);
        assert!(c.custom_names.is_empty());
    }

    #[test]
    fn resolve_populates_every_tier_regardless_of_cluster_level() {
        // Annotations can raise any workload to any tier, so every map
        // must be populated even when the cluster default is full.
        let t = CaptureConfig::from_values(Some("full"), Some("execve,openat")).resolve();
        assert!(!t.high.is_empty());
        assert!(!t.medium.is_empty());
        assert!(!t.low.is_empty());
        assert_eq!(t.custom.len(), 2);
        assert!(t.for_level(CaptureLevel::Full).is_none());
        assert_eq!(t.for_level(CaptureLevel::Low), Some(&t.low));
    }

    #[test]
    fn all_syscalls_scan_is_plausible() {
        // x86_64 and aarch64 each define a few hundred syscalls; a scan
        // that returns a handful means libseccomp could not resolve
        // numbers at all (wrong arch token), and one that returns the
        // whole range means the "is it a syscall" test is broken.
        let all = all_syscalls_on_arch(arch());
        assert!(all.len() > 250, "only {} syscalls found", all.len());
        assert!(all.len() < SYSCALL_SCAN_MAX as usize);
    }

    #[test]
    fn aarch64_tiers_resolve_without_panicking_and_are_populated() {
        // The arm64 side of the regression: names must resolve to the
        // aarch64 table, and legacy-only names (open, fork, getdents,
        // ...) just drop out rather than aborting startup.
        let t = resolve_tiers_for_arch(
            &["execve".to_string(), "nope".to_string()],
            ScmpArch::Aarch64,
        );
        assert!(t.low.len() > 40, "low on aarch64 = {}", t.low.len());
        assert!(
            t.low.len() < LOW.len(),
            "aarch64 lacks open/fork/etc so low must shrink"
        );
        assert!(t.low.is_subset(&t.medium));
        assert!(t.high.len() > 250);
        assert_eq!(t.custom, BTreeSet::from([221]));
        // aarch64 has no open/select/poll: their absence from the
        // exclusion set must not have pulled anything else out of high.
        let all = all_syscalls_on_arch(ScmpArch::Aarch64);
        let (excluded, _) = resolve_names(HIGH_EXCLUSIONS.iter().copied(), ScmpArch::Aarch64);
        assert_eq!(t.high.len() + excluded.len(), all.len());
    }
}
