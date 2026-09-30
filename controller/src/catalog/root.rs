//! Opening a container's root filesystem, safely against pid reuse.
//!
//! ## The process handle
//!
//! The design says `pidfd_open(pid)`. That is not what this does, on
//! purpose: `pidfd_open` resolves the number in the CALLER's pid
//! namespace, and the Controller does not run with `hostPID`. The pids it
//! has (containerd's `Tasks.Get`, host `/proc`) are host pids, so
//! `pidfd_open` would name a different process or none.
//!
//! The handle used instead is a directory fd on `/proc/<pid>` of the
//! host procfs (mounted at `/proc`). procfs binds that directory's inode
//! to the `struct pid` it was opened for, the same kernel object a pidfd
//! refers to: once that process exits, every `openat` through the fd
//! fails with `ESRCH`, even if the number is reused, and nothing opened
//! through it can reach a newer process. So "open the handle, check
//! identity through it, open `root` through it, check identity again"
//! is exactly the pidfd sequence, in terms this pid namespace can use.
//!
//! ## The identity check
//!
//! [`acquire`] is written against [`ProcSource`], so the ordering and
//! every mismatch are unit-tested with a fake whose answers change
//! between reads (the PID-swap test); [`ProcDir`] is the real one.

use std::ffi::{CStr, CString};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::time::Duration;

use super::mountinfo::Upperdir;

/// Largest `/proc` file read here (mountinfo of a pod with many volumes
/// is a few KiB; this bounds a pathological one).
const MAX_PROC_READ: u64 = 1 << 20;

/// The four package databases (design 1b step 5), relative to a root.
pub const PACKAGE_DBS: [&str; 4] = [
    "lib/apk/db/installed",
    "var/lib/dpkg/status",
    "var/lib/rpm",
    "usr/lib/sysimage/rpm",
];

/// Who the process must be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected {
    pub pod_uid: String,
    pub container_id: String,
}

/// Who the process is, from `/proc/<pid>/cgroup` and `stat`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub pod_uid: String,
    pub container_id: String,
    /// `stat` field 22: start time in clock ticks since boot.
    pub start_ticks: u64,
}

/// `stat` field 22. The comm field (2) is parenthesised and may contain
/// spaces and parentheses itself, so fields are counted from the LAST
/// `)`.
pub fn start_ticks(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    // Fields after comm start at 3 (state); 22 is the 20th of them.
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// Identity from the two file bodies; `None` when either does not
/// describe a Kubernetes container.
pub fn identity(cgroup: &str, stat: &str) -> Option<Identity> {
    let (pod_uid, container_id) = crate::runtime_inventory::process_container(cgroup)?;
    Some(Identity {
        pod_uid,
        container_id,
        start_ticks: start_ticks(stat)?,
    })
}

/// Why no root was opened.
#[derive(Debug)]
pub enum AcquireError {
    /// The process is gone, or is no longer the container it was
    /// (another process holds the pid, or it moved cgroup). The broker's
    /// `pid_gone`.
    PidGone(&'static str),
    /// Anything else (an unexpected errno opening `/proc`).
    Io(io::Error),
}

impl std::fmt::Display for AcquireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcquireError::PidGone(why) => write!(f, "pid gone: {why}"),
            AcquireError::Io(e) => write!(f, "{e}"),
        }
    }
}

fn gone_or_io(e: io::Error, why: &'static str) -> AcquireError {
    match e.raw_os_error() {
        Some(libc::ESRCH) | Some(libc::ENOENT) => AcquireError::PidGone(why),
        _ => AcquireError::Io(e),
    }
}

/// The process reads [`acquire`] needs, so the sequence is testable.
pub trait ProcSource {
    fn cgroup(&self) -> io::Result<String>;
    fn stat(&self) -> io::Result<String>;
    fn mountinfo(&self) -> io::Result<String>;
    fn open_root(&self) -> io::Result<OwnedFd>;
}

/// What [`acquire`] hands back.
#[derive(Debug)]
pub struct Acquired {
    /// `O_PATH|O_DIRECTORY|O_CLOEXEC` on the container root.
    pub root: OwnedFd,
    pub start_ticks: u64,
    pub mountinfo: String,
}

fn read_identity<P: ProcSource>(p: &P, stage: &'static str) -> Result<Identity, AcquireError> {
    let cg = p.cgroup().map_err(|e| gone_or_io(e, stage))?;
    let st = p.stat().map_err(|e| gone_or_io(e, stage))?;
    identity(&cg, &st).ok_or(AcquireError::PidGone("not a kubernetes container"))
}

/// Check identity, open the root, read mountinfo, check identity again.
/// Everything read between the two checks belongs to the process the
/// first check vouched for: the handle is pid-reuse safe, and the second
/// check proves it did not change cgroup or exec a new start in between.
pub fn acquire<P: ProcSource>(p: &P, want: &Expected) -> Result<Acquired, AcquireError> {
    let before = read_identity(p, "before")?;
    if before.container_id != want.container_id {
        return Err(AcquireError::PidGone("pid is another container"));
    }
    if before.pod_uid != want.pod_uid {
        return Err(AcquireError::PidGone("pid is another pod"));
    }
    let root = p.open_root().map_err(|e| gone_or_io(e, "open root"))?;
    let mountinfo = p.mountinfo().map_err(|e| gone_or_io(e, "mountinfo"))?;
    let after = read_identity(p, "after")?;
    if after != before {
        return Err(AcquireError::PidGone(
            "identity changed while opening the root",
        ));
    }
    Ok(Acquired {
        root,
        start_ticks: before.start_ticks,
        mountinfo,
    })
}

fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

fn openat(dir: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: a valid dirfd and NUL-terminated name; the result is owned.
    let fd = unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd was just returned by the kernel and is ours.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn read_fd(fd: OwnedFd) -> io::Result<String> {
    let mut f = std::fs::File::from(fd);
    let mut buf = Vec::new();
    (&mut f).take(MAX_PROC_READ).read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// A `/proc/<pid>` directory handle (see module docs).
#[derive(Debug)]
pub struct ProcDir {
    fd: OwnedFd,
    pub pid: u32,
}

impl ProcDir {
    pub fn open(host_proc: &Path, pid: u32) -> io::Result<Self> {
        let p = cstr(&format!("{}/{pid}", host_proc.display()))?;
        let fd = openat(libc::AT_FDCWD, &p, libc::O_RDONLY | libc::O_DIRECTORY)?;
        Ok(Self { fd, pid })
    }

    fn read(&self, name: &CStr) -> io::Result<String> {
        read_fd(openat(self.fd.as_raw_fd(), name, libc::O_RDONLY)?)
    }

    /// `ns/mnt`, for the read-only clone.
    pub fn mnt_ns(&self) -> io::Result<OwnedFd> {
        openat(self.fd.as_raw_fd(), c"ns/mnt", libc::O_RDONLY)
    }
}

impl ProcSource for ProcDir {
    fn cgroup(&self) -> io::Result<String> {
        self.read(c"cgroup")
    }
    fn stat(&self) -> io::Result<String> {
        self.read(c"stat")
    }
    fn mountinfo(&self) -> io::Result<String> {
        self.read(c"mountinfo")
    }
    fn open_root(&self) -> io::Result<OwnedFd> {
        openat(
            self.fd.as_raw_fd(),
            c"root",
            libc::O_PATH | libc::O_DIRECTORY,
        )
    }
}

fn clock_ns(clock: libc::clockid_t) -> i128 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid clock id and an out-pointer to a local.
    unsafe { libc::clock_gettime(clock, &mut ts) };
    i128::from(ts.tv_sec) * 1_000_000_000 + i128::from(ts.tv_nsec)
}

/// A `stat` start time as `CLOCK_REALTIME` unix nanoseconds (PROTOCOL.md
/// `container_start_unix_nanos`). The kernel reports start time on the
/// boot-time clock, so the offset is taken between that and the wall
/// clock now, which is exact to the tick without reading `btime`.
pub fn start_unix_nanos(start_ticks: u64) -> i64 {
    // SAFETY: sysconf has no preconditions.
    let hz = match unsafe { libc::sysconf(libc::_SC_CLK_TCK) } {
        n if n > 0 => n as i128,
        _ => 100,
    };
    let offset = clock_ns(libc::CLOCK_REALTIME) - clock_ns(libc::CLOCK_BOOTTIME);
    let started = offset + i128::from(start_ticks) * 1_000_000_000 / hz;
    i64::try_from(started.max(1)).unwrap_or(i64::MAX)
}

// ---- Drift ----------------------------------------------------------------

/// The drift check's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drift {
    /// No package database was written, deleted or hidden since the
    /// container started.
    Clean,
    /// Packages changed at runtime: what was found in the upperdir.
    Drifted(String),
    /// It could not be told. The scan goes ahead, and its SBOM is
    /// `partial` (final review item 2).
    Unknown(String),
}

fn openat2_in_root(root: RawFd, path: &CStr, flags: u64) -> io::Result<OwnedFd> {
    // SAFETY: open_how is plain data; zero is a valid value for each field.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = flags | libc::O_CLOEXEC as u64;
    how.resolve = libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_MAGICLINKS;
    // SAFETY: valid dirfd, NUL-terminated path, and `how` sized as passed.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root,
            path.as_ptr(),
            &how as *const libc::open_how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a new fd from the kernel.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// `fstatat(AT_SYMLINK_NOFOLLOW)` of one name; `None` when absent.
fn lstat_at(dir: RawFd, name: &CStr) -> io::Result<Option<libc::stat>> {
    // SAFETY: zeroed stat is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid dirfd, NUL-terminated name, out-pointer to a local.
    let rc = unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    if rc == 0 {
        return Ok(Some(st));
    }
    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::ENOENT) => Ok(None),
        _ => Err(e),
    }
}

/// An overlay whiteout: a character device 0:0.
fn is_whiteout(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFCHR && st.st_rdev == 0
}

/// The two xattrs overlayfs marks an opaque directory with (`trusted.*`
/// for a privileged mount, `user.*` for a userxattr one).
const OPAQUE_XATTRS: [&CStr; 2] = [c"trusted.overlay.opaque", c"user.overlay.opaque"];

/// Is the directory `fd` opaque? `y` (opaque: everything below in the
/// lower layers is hidden) and `x` (has whiteouts, kernel >= 6.7) both
/// mean lower content was removed. `ENODATA` is "not set". `ENOTSUP` is
/// too: a filesystem without that xattr namespace cannot carry the mark,
/// so overlayfs cannot have set it there. Any other error is unknown.
pub fn opaque(fd: RawFd) -> io::Result<bool> {
    for name in OPAQUE_XATTRS {
        let mut buf = [0u8; 8];
        // SAFETY: valid fd, NUL-terminated name, buffer of the size passed.
        let n = unsafe { libc::fgetxattr(fd, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        if n >= 0 {
            if matches!(&buf[..n as usize], b"y" | b"x") {
                return Ok(true);
            }
            continue;
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::ENODATA) | Some(libc::ENOTSUP) => {}
            // A value longer than 8 bytes is not y/x.
            Some(libc::ERANGE) => {}
            _ => return Err(e),
        }
    }
    Ok(false)
}

/// Walk `rel` inside the upperdir `dir`, one name at a time, never
/// following a symlink. `Some(what)` is drift:
///
/// * anything at the leaf (the database written, or deleted: a whiteout);
/// * a whiteout at a parent (`var/lib/dpkg` deleted);
/// * a non-directory at a parent (replaced by a file or symlink);
/// * an opaque parent directory (deleted and recreated, which hides the
///   lower layers' database without writing the database itself).
///
/// Parents are opened `O_RDONLY|O_DIRECTORY|O_NOFOLLOW` (an `O_PATH` fd
/// cannot read xattrs) relative to the upperdir fd, which was itself
/// resolved `RESOLVE_IN_ROOT` under the host root.
fn drift_along(dir: RawFd, rel: &str) -> io::Result<Option<String>> {
    let parts: Vec<&str> = rel.split('/').collect();
    let mut held: Option<OwnedFd> = None;
    for (i, part) in parts.iter().enumerate() {
        let at = held.as_ref().map_or(dir, |f| f.as_raw_fd());
        let name = cstr(part)?;
        let path = parts[..=i].join("/");
        let Some(st) = lstat_at(at, &name)? else {
            return Ok(None);
        };
        if i == parts.len() - 1 {
            return Ok(Some(if is_whiteout(&st) {
                format!("{path} deleted (whiteout)")
            } else {
                format!("{path} written")
            }));
        }
        if is_whiteout(&st) {
            return Ok(Some(format!("{path} deleted (whiteout)")));
        }
        if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Ok(Some(format!("{path} replaced by a non-directory")));
        }
        let fd = match openat(
            at,
            &name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        ) {
            Ok(fd) => fd,
            Err(e) => match e.raw_os_error() {
                // Swapped between the stat and the open.
                Some(libc::ENOENT) => return Ok(None),
                Some(libc::ENOTDIR) | Some(libc::ELOOP) => {
                    return Ok(Some(format!("{path} replaced by a non-directory")))
                }
                _ => return Err(e),
            },
        };
        if opaque(fd.as_raw_fd())? {
            return Ok(Some(format!("{path} opaque (deleted and recreated)")));
        }
        held = Some(fd);
    }
    Ok(None)
}

/// Open the container's upperdir under `host_root` (an fd on
/// `/proc/1/root`) with `RESOLVE_IN_ROOT`, so the host path string from
/// mountinfo can never escape the host root or follow a magic link.
fn open_upper(host_root: RawFd, path: &str) -> io::Result<OwnedFd> {
    openat2_in_root(
        host_root,
        &cstr(path)?,
        (libc::O_RDONLY | libc::O_DIRECTORY) as u64,
    )
}

/// Look for runtime changes to the package databases in the container's
/// upperdir. No walk of the upperdir: the four database paths only.
pub fn drift_check(host_root: RawFd, upper: &Upperdir) -> Drift {
    let path = match upper {
        Upperdir::Path(p) => p,
        Upperdir::Missing => return Drift::Unknown("no upperdir".into()),
        Upperdir::Unparseable => return Drift::Unknown("unparseable upperdir".into()),
    };
    let upfd = match open_upper(host_root, path) {
        Ok(fd) => fd,
        Err(e) => return Drift::Unknown(format!("open upperdir: {e}")),
    };
    drift_in(upfd.as_raw_fd())
}

fn drift_in(upfd: RawFd) -> Drift {
    for db in PACKAGE_DBS {
        match drift_along(upfd, db) {
            Ok(Some(what)) => return Drift::Drifted(what),
            Ok(None) => {}
            Err(e) => return Drift::Unknown(format!("{db}: {e}")),
        }
    }
    Drift::Clean
}

// ---- Language-package deletions ---------------------------------------------

/// Entries read from any one directory by [`lang_whiteout`].
const LANG_SCAN_ENTRIES: usize = 4096;
/// Entries read by one [`lang_whiteout`] call across all directories.
pub const LANG_SCAN_BUDGET: usize = 64 * 1024;

/// Directory entries [`lang_whiteout`] may still read.
struct Budget {
    left: usize,
}

/// Up to `cap` entry names of the directory `fd` (not `.`/`..`), with
/// their `d_type`, charged to `budget`. `.1` is true when the listing
/// stopped before the end (per-directory cap or budget).
fn list_dir(
    fd: RawFd,
    cap: usize,
    budget: &mut Budget,
) -> io::Result<(Vec<(std::ffi::CString, u8)>, bool)> {
    // SAFETY: dup of a valid fd; fdopendir takes ownership of the copy.
    let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: dup is a directory fd we own.
    let d = unsafe { libc::fdopendir(dup) };
    if d.is_null() {
        let e = io::Error::last_os_error();
        // SAFETY: fdopendir failed, so dup is still ours.
        unsafe { libc::close(dup) };
        return Err(e);
    }
    let mut out = Vec::new();
    let mut cut = false;
    loop {
        // SAFETY: d is a valid DIR*.
        let ent = unsafe { libc::readdir(d) };
        if ent.is_null() {
            break;
        }
        // SAFETY: readdir returned a valid dirent with a NUL-terminated name.
        let (name, ty) = unsafe {
            (
                CStr::from_ptr((*ent).d_name.as_ptr()).to_owned(),
                (*ent).d_type,
            )
        };
        if name.as_bytes() == b"." || name.as_bytes() == b".." {
            continue;
        }
        if out.len() >= cap || budget.left == 0 {
            cut = true;
            break;
        }
        budget.left -= 1;
        out.push((name, ty));
    }
    // SAFETY: closes the DIR* and its fd.
    unsafe { libc::closedir(d) };
    Ok((out, cut))
}

/// Open `rel` as a directory below `dir`, name by name, no symlinks.
fn open_dir_path(dir: RawFd, rel: &str) -> Option<OwnedFd> {
    let mut held: Option<OwnedFd> = None;
    for part in rel.split('/') {
        let at = held.as_ref().map_or(dir, |f| f.as_raw_fd());
        held = Some(
            openat(
                at,
                &cstr(part).ok()?,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            )
            .ok()?,
        );
    }
    held
}

/// What [`lang_whiteout`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LangCheck {
    Clean,
    /// A language package was deleted at runtime (`lang_whiteout`).
    Found(String),
    /// The directories were not read completely (a per-directory cap or
    /// the [`LANG_SCAN_BUDGET`] ran out): `lang_whiteout_unknown`.
    Unknown(String),
}

/// Did the container delete a language package at runtime? The package
/// databases do not cover Python, Node or Ruby packages, whose metadata
/// lives in their own directories; deleting one leaves a whiteout (or an
/// opaque directory) in the upperdir. This checks the well-known
/// system-wide locations only, each read at most [`LANG_SCAN_ENTRIES`]
/// entries deep and one level down, with at most [`LANG_SCAN_BUDGET`]
/// entries read in all:
///
/// * `usr/lib/python*/{site,dist}-packages`,
///   `usr/local/lib/python*/{site,dist}-packages`;
/// * `usr/lib/node_modules`, `usr/local/lib/node_modules`;
/// * `usr/local/bundle/gems`, `var/lib/gems/*/gems`,
///   `usr/local/lib/ruby/gems/*/gems`.
///
/// Application-local trees (`/app/node_modules`, a virtualenv) are not
/// looked at. A directory that cannot be opened counts as absent.
pub fn lang_whiteout(upfd: RawFd) -> LangCheck {
    lang_whiteout_within(upfd, LANG_SCAN_BUDGET)
}

/// [`lang_whiteout`] with an explicit entry budget.
pub fn lang_whiteout_within(upfd: RawFd, budget: usize) -> LangCheck {
    let mut budget = Budget { left: budget };
    let mut incomplete: Option<String> = None;
    fn note_cut(cut: bool, what: &str, inc: &mut Option<String>) {
        if cut && inc.is_none() {
            *inc = Some(format!("{what} not read completely"));
        }
    }
    let mut dirs: Vec<String> = vec![
        "usr/lib/node_modules".into(),
        "usr/local/lib/node_modules".into(),
        "usr/local/bundle/gems".into(),
    ];
    for base in ["usr/lib", "usr/local/lib"] {
        let Some(fd) = open_dir_path(upfd, base) else {
            continue;
        };
        let (names, cut) =
            list_dir(fd.as_raw_fd(), LANG_SCAN_ENTRIES, &mut budget).unwrap_or_default();
        note_cut(cut, base, &mut incomplete);
        for (name, _) in names {
            let n = name.to_string_lossy();
            if n.starts_with("python") {
                dirs.push(format!("{base}/{n}/site-packages"));
                dirs.push(format!("{base}/{n}/dist-packages"));
            }
        }
    }
    for base in ["var/lib/gems", "usr/local/lib/ruby/gems"] {
        let Some(fd) = open_dir_path(upfd, base) else {
            continue;
        };
        let (names, cut) = list_dir(fd.as_raw_fd(), 64, &mut budget).unwrap_or_default();
        note_cut(cut, base, &mut incomplete);
        for (name, _) in names {
            dirs.push(format!("{base}/{}/gems", name.to_string_lossy()));
        }
    }
    for d in dirs {
        let Some(fd) = open_dir_path(upfd, &d) else {
            continue;
        };
        if opaque(fd.as_raw_fd()).unwrap_or(false) {
            return LangCheck::Found(format!("{d} opaque"));
        }
        let (names, cut) =
            list_dir(fd.as_raw_fd(), LANG_SCAN_ENTRIES, &mut budget).unwrap_or_default();
        note_cut(cut, &d, &mut incomplete);
        for (name, ty) in names {
            if ty != libc::DT_CHR && ty != libc::DT_UNKNOWN {
                continue;
            }
            if let Ok(Some(st)) = lstat_at(fd.as_raw_fd(), &name) {
                if is_whiteout(&st) {
                    return LangCheck::Found(format!("{d}/{} deleted", name.to_string_lossy()));
                }
            }
        }
    }
    match incomplete {
        Some(why) => LangCheck::Unknown(why),
        None => LangCheck::Clean,
    }
}

/// Both upperdir checks, through one open of the upperdir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpperCheck {
    pub drift: Drift,
    /// Language-package deletions ([`lang_whiteout`]).
    pub lang: LangCheck,
}

pub fn check_upper(host_root: RawFd, upper: &Upperdir) -> UpperCheck {
    let Upperdir::Path(path) = upper else {
        return UpperCheck {
            drift: drift_check(host_root, upper),
            lang: LangCheck::Clean,
        };
    };
    match open_upper(host_root, path) {
        Ok(fd) => UpperCheck {
            drift: drift_in(fd.as_raw_fd()),
            lang: lang_whiteout(fd.as_raw_fd()),
        },
        Err(e) => UpperCheck {
            drift: Drift::Unknown(format!("open upperdir: {e}")),
            lang: LangCheck::Clean,
        },
    }
}

/// `CAP_SYS_ADMIN` (bit 21) in a `/proc/<pid>/status` body's `CapEff`.
/// Without it `trusted.*` xattrs read as absent (ENODATA), so an
/// overlay opaque mark could not be seen.
pub fn cap_sys_admin(status: &str) -> bool {
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
        .is_some_and(|caps| caps & (1 << 21) != 0)
}

// ---- Mount identity -----------------------------------------------------------

/// The mount id of the mount `fd` is on (`statx` `STATX_MNT_ID`, Linux
/// 5.8). `None` when the kernel does not report it.
pub fn mount_id(fd: RawFd) -> io::Result<Option<u64>> {
    // SAFETY: zeroed statx is a valid out-parameter.
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    // SAFETY: valid fd, empty path with AT_EMPTY_PATH, out-pointer.
    let rc = unsafe {
        libc::statx(
            fd,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            libc::STATX_MNT_ID,
            &mut stx,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((stx.stx_mask & libc::STATX_MNT_ID != 0).then_some(stx.stx_mnt_id))
}

/// Do two fds name the same filesystem object (device and inode)?
pub fn same_object(a: RawFd, b: RawFd) -> io::Result<bool> {
    let st = |fd: RawFd| -> io::Result<libc::stat> {
        // SAFETY: zeroed stat is a valid out-parameter.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: valid fd and out-pointer.
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(st)
    };
    let (x, y) = (st(a)?, st(b)?);
    Ok(x.st_dev == y.st_dev && x.st_ino == y.st_ino)
}

/// `/proc/1/root` of the host procfs, for [`drift_check`].
pub fn open_host_root(host_proc: &Path) -> io::Result<OwnedFd> {
    let p = cstr(&format!("{}/1/root", host_proc.display()))?;
    openat(libc::AT_FDCWD, &p, libc::O_PATH | libc::O_DIRECTORY)
}

// ---- Read-only clone --------------------------------------------------------

const OPEN_TREE_CLONE: libc::c_uint = 1;
const AT_EMPTY_PATH: libc::c_uint = 0x1000;
const MOUNT_ATTR_RDONLY: u64 = 0x1;
const MOUNT_ATTR_NOSUID: u64 = 0x2;
const MOUNT_ATTR_NODEV: u64 = 0x4;
const MOUNT_ATTR_NOEXEC: u64 = 0x8;
/// How long the helper may take before it is killed.
const CLONE_TIMEOUT: Duration = Duration::from_secs(5);

/// `struct mount_attr` (linux/mount.h).
#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// Why the read-only clone was not made. Every one of them falls back
/// to the plain `O_PATH` root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloneError {
    pub stage: &'static str,
    pub errno: i32,
}

impl std::fmt::Display for CloneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.errno == 0 {
            return write!(f, "{}", self.stage);
        }
        write!(
            f,
            "{}: {}",
            self.stage,
            io::Error::from_raw_os_error(self.errno)
        )
    }
}

const STAGES: [&str; 4] = ["setns", "open_tree", "mount_setattr", "sendmsg"];

/// Send `fd` (or, with `fd < 0`, just `code`) on `sock`. Raw syscalls
/// and stack buffers only: this runs in the forked child.
unsafe fn child_send(sock: RawFd, code: [i32; 2], fd: RawFd) -> isize {
    let mut payload = code;
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: std::mem::size_of_val(&payload),
    };
    let mut cbuf = [0u64; 4];
    let mut msg: libc::msghdr = std::mem::zeroed();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if fd >= 0 {
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as _;
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(c).cast::<RawFd>(), fd);
    }
    libc::sendmsg(sock, &msg, 0)
}

/// The forked child: enter the container's mount namespace, clone its
/// root mount (not recursive: no volumes, SA token or /etc/hosts), make
/// the clone read-only, nosuid, nodev, noexec, and pass it back. Never
/// returns. Everything it touches was prepared before the fork.
unsafe fn clone_child(
    ns: RawFd,
    sock: RawFd,
    slash: *const libc::c_char,
    empty: *const libc::c_char,
) -> ! {
    let fail = |stage: i32| -> ! {
        let errno = *libc::__errno_location();
        child_send(sock, [stage, errno], -1);
        libc::_exit(1)
    };
    if libc::setns(ns, libc::CLONE_NEWNS) != 0 {
        fail(0);
    }
    let fd = libc::syscall(
        libc::SYS_open_tree,
        libc::AT_FDCWD,
        slash,
        OPEN_TREE_CLONE | libc::O_CLOEXEC as libc::c_uint,
    );
    if fd < 0 {
        fail(1);
    }
    let attr = MountAttr {
        attr_set: MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    if libc::syscall(
        libc::SYS_mount_setattr,
        fd as RawFd,
        empty,
        AT_EMPTY_PATH,
        &attr as *const MountAttr,
        std::mem::size_of::<MountAttr>(),
    ) != 0
    {
        fail(2);
    }
    if child_send(sock, [-1, 0], fd as RawFd) < 0 {
        fail(3);
    }
    libc::_exit(0)
}

/// A read-only, submount-free clone of the container's root (design,
/// final review "optional hardening"), made by a forked single-threaded
/// helper because `setns(CLONE_NEWNS)` refuses a multi-threaded caller.
/// The caller falls back to the plain root on any error.
pub fn readonly_clone(proc: &ProcDir) -> Result<OwnedFd, CloneError> {
    let err = |stage, e: io::Error| CloneError {
        stage,
        errno: e.raw_os_error().unwrap_or(libc::EIO),
    };
    let ns = proc.mnt_ns().map_err(|e| err("open ns/mnt", e))?;
    let mut sv = [0 as RawFd; 2];
    // SAFETY: out-array of two fds.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    } != 0
    {
        return Err(err("socketpair", io::Error::last_os_error()));
    }
    // SAFETY: both fds were just created and are ours.
    let (ours, theirs) = unsafe { (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1])) };
    let slash = c"/";
    let empty = c"";

    // SAFETY: the child runs only `clone_child`, which uses raw syscalls
    // on values prepared above and ends in `_exit`; it never returns into
    // Rust code that could touch a lock another thread held at the fork.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(err("fork", io::Error::last_os_error()));
    }
    if pid == 0 {
        // SAFETY: see above.
        unsafe {
            clone_child(
                ns.as_raw_fd(),
                theirs.as_raw_fd(),
                slash.as_ptr(),
                empty.as_ptr(),
            )
        };
    }
    drop(theirs);
    drop(ns);

    let got = recv_clone(ours.as_raw_fd());
    if got.is_err() {
        // SAFETY: our own child.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    reap(pid);
    got
}

/// Reap our own child, retrying on `EINTR`.
fn reap(pid: libc::pid_t) {
    let mut status = 0;
    loop {
        // SAFETY: waiting on our own child.
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r >= 0 || io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return;
        }
    }
}

fn recv_clone(sock: RawFd) -> Result<OwnedFd, CloneError> {
    let mut pfd = libc::pollfd {
        fd: sock,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one pollfd.
    let n = unsafe { libc::poll(&mut pfd, 1, CLONE_TIMEOUT.as_millis() as libc::c_int) };
    if n <= 0 {
        return Err(CloneError {
            stage: "helper timeout",
            errno: libc::ETIMEDOUT,
        });
    }
    let mut code = [0i32; 2];
    let mut iov = libc::iovec {
        iov_base: code.as_mut_ptr().cast(),
        iov_len: std::mem::size_of_val(&code),
    };
    let mut cbuf = [0u64; 8];
    // SAFETY: zeroed msghdr filled with pointers to locals.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&cbuf) as _;
    // SAFETY: valid socket and msghdr.
    let r = unsafe { libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if r < 0 {
        return Err(CloneError {
            stage: "recvmsg",
            errno: io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO),
        });
    }
    let mut fd: Option<OwnedFd> = None;
    // SAFETY: walking the control buffer the kernel filled.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let raw = std::ptr::read_unaligned(libc::CMSG_DATA(c).cast::<RawFd>());
                fd = Some(OwnedFd::from_raw_fd(raw));
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        // A truncated control message may have dropped the fd (an LSM
        // refusing `fd use`); whatever did arrive is closed with `fd`.
        return Err(CloneError {
            stage: "control message truncated",
            errno: 0,
        });
    }
    if r < 8 {
        // The helper died before answering (killed, or crashed).
        return Err(CloneError {
            stage: "helper exited without an answer",
            errno: 0,
        });
    }
    match (code[0], fd) {
        (-1, Some(fd)) => Ok(fd),
        (s, _) => Err(CloneError {
            stage: usize::try_from(s)
                .ok()
                .and_then(|i| STAGES.get(i).copied())
                .unwrap_or("helper"),
            errno: code[1],
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::PermissionsExt;

    const CG_A: &str = "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod5d7c1c2e_1f2a_4b3c_9d8e_0a1b2c3d4e5f.slice/cri-containerd-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.scope\n";
    const CG_B: &str = "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod5d7c1c2e_1f2a_4b3c_9d8e_0a1b2c3d4e5f.slice/cri-containerd-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.scope\n";

    fn stat_with(start: u64) -> String {
        // pid (comm with ) and spaces) state ppid ... field 22 = start.
        let mut f: Vec<String> = (3..=52).map(|i| i.to_string()).collect();
        f[19] = start.to_string();
        format!("1234 (we) ird (name) {}", f.join(" "))
    }

    fn want() -> Expected {
        Expected {
            pod_uid: "5d7c1c2e-1f2a-4b3c-9d8e-0a1b2c3d4e5f".into(),
            container_id: "a".repeat(64),
        }
    }

    /// A process whose answers are scripted per read, to swap the pid's
    /// owner at any point in the sequence.
    struct Scripted {
        cgroups: Vec<&'static str>,
        stats: Vec<String>,
        reads: Cell<usize>,
        root_err: Option<i32>,
    }

    impl Scripted {
        fn new(cgroups: Vec<&'static str>, stats: Vec<String>) -> Self {
            Self {
                cgroups,
                stats,
                reads: Cell::new(0),
                root_err: None,
            }
        }
        fn idx(&self) -> usize {
            self.reads.get().min(self.cgroups.len() - 1)
        }
    }

    impl ProcSource for Scripted {
        fn cgroup(&self) -> io::Result<String> {
            Ok(self.cgroups[self.idx()].to_string())
        }
        fn stat(&self) -> io::Result<String> {
            let s = self.stats[self.idx().min(self.stats.len() - 1)].clone();
            self.reads.set(self.reads.get() + 1);
            Ok(s)
        }
        fn mountinfo(&self) -> io::Result<String> {
            Ok(String::new())
        }
        fn open_root(&self) -> io::Result<OwnedFd> {
            if let Some(e) = self.root_err {
                return Err(io::Error::from_raw_os_error(e));
            }
            Ok(std::fs::File::open("/").unwrap().into())
        }
    }

    #[test]
    fn start_ticks_counts_from_the_last_paren() {
        assert_eq!(start_ticks(&stat_with(987_654)), Some(987_654));
        assert_eq!(start_ticks("garbage"), None);
        assert_eq!(start_ticks("1 (x) S 1 2"), None);
    }

    #[test]
    fn the_same_container_throughout_is_acquired() {
        let p = Scripted::new(vec![CG_A], vec![stat_with(100)]);
        let got = acquire(&p, &want()).expect("same process");
        assert_eq!(got.start_ticks, 100);
    }

    #[test]
    fn a_pid_owned_by_another_container_from_the_start_is_pid_gone() {
        let p = Scripted::new(vec![CG_B], vec![stat_with(100)]);
        assert!(matches!(
            acquire(&p, &want()),
            Err(AcquireError::PidGone("pid is another container"))
        ));
    }

    /// The PID-swap test: the process passes the first check, exits,
    /// and the number is taken by another container's process before
    /// the second. Everything opened in between is discarded.
    #[test]
    fn a_pid_swapped_to_another_container_mid_open_is_pid_gone() {
        let p = Scripted::new(vec![CG_A, CG_B], vec![stat_with(100), stat_with(100)]);
        assert!(matches!(
            acquire(&p, &want()),
            Err(AcquireError::PidGone(
                "identity changed while opening the root"
            ))
        ));
    }

    /// Same container id, but a different start time: the pid was reused
    /// by a new process in the SAME cgroup (a restart of its entrypoint).
    #[test]
    fn a_new_start_time_in_the_same_cgroup_is_pid_gone() {
        let p = Scripted::new(vec![CG_A, CG_A], vec![stat_with(100), stat_with(250)]);
        assert!(matches!(
            acquire(&p, &want()),
            Err(AcquireError::PidGone(_))
        ));
    }

    #[test]
    fn a_vanished_process_is_pid_gone_not_an_error() {
        let mut p = Scripted::new(vec![CG_A], vec![stat_with(100)]);
        p.root_err = Some(libc::ESRCH);
        assert!(matches!(
            acquire(&p, &want()),
            Err(AcquireError::PidGone("open root"))
        ));
        p.root_err = Some(libc::EACCES);
        assert!(matches!(acquire(&p, &want()), Err(AcquireError::Io(_))));
    }

    #[test]
    fn a_host_process_is_not_a_container() {
        let p = Scripted::new(
            vec!["0::/system.slice/containerd.service\n"],
            vec![stat_with(1)],
        );
        assert!(matches!(
            acquire(&p, &want()),
            Err(AcquireError::PidGone("not a kubernetes container"))
        ));
    }

    /// The real handle's pid-reuse property: once the process exits, the
    /// directory fd answers ESRCH/ENOENT, whatever now holds the number.
    #[test]
    fn a_proc_dir_handle_dies_with_its_process() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let dir = ProcDir::open(Path::new("/proc"), child.id()).expect("open /proc/<pid>");
        assert!(dir.stat().is_ok());
        assert!(dir.open_root().is_ok());
        child.kill().unwrap();
        child.wait().unwrap();
        let e = dir
            .stat()
            .expect_err("a dead process's handle must not read");
        assert!(
            matches!(e.raw_os_error(), Some(libc::ESRCH) | Some(libc::ENOENT)),
            "{e}"
        );
        assert!(matches!(gone_or_io(e, "x"), AcquireError::PidGone(_)));
    }

    #[test]
    fn start_unix_nanos_is_in_the_past_and_after_boot() {
        let ticks = start_ticks(&std::fs::read_to_string("/proc/self/stat").unwrap()).unwrap();
        let ns = start_unix_nanos(ticks);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i64;
        assert!(ns <= now, "started in the future");
        assert!(
            now - ns < 3_600 * 1_000_000_000,
            "this test process started over an hour ago?"
        );
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "kg-catalog-drift-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn check(upper: &Path) -> Drift {
        let root = std::fs::File::open("/").unwrap();
        drift_check(
            root.as_raw_fd(),
            &Upperdir::Path(upper.to_string_lossy().into_owned()),
        )
    }

    #[test]
    fn an_empty_upperdir_is_clean() {
        let up = tmp("clean");
        // Runtime writes elsewhere are not drift.
        std::fs::create_dir_all(up.join("var/cache/nginx")).unwrap();
        std::fs::create_dir_all(up.join("var/lib/dpkg")).unwrap();
        assert_eq!(check(&up), Drift::Clean);
        std::fs::remove_dir_all(&up).unwrap();
    }

    fn drifted(d: Drift) -> String {
        match d {
            Drift::Drifted(w) => w,
            other => panic!("expected drift, got {other:?}"),
        }
    }

    #[test]
    fn each_package_db_in_the_upperdir_is_drift() {
        for db in PACKAGE_DBS {
            let up = tmp("db");
            let p = up.join(db);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, b"").unwrap();
            assert_eq!(drifted(check(&up)), format!("{db} written"));
            std::fs::remove_dir_all(&up).unwrap();
        }
    }

    #[test]
    fn a_symlink_replacing_a_db_directory_is_drift_and_is_not_followed() {
        let up = tmp("link");
        std::fs::create_dir_all(up.join("var/lib")).unwrap();
        std::os::unix::fs::symlink("/etc", up.join("var/lib/dpkg")).unwrap();
        assert_eq!(
            drifted(check(&up)),
            "var/lib/dpkg replaced by a non-directory"
        );
        // A symlink AT the leaf counts without being followed.
        let up2 = tmp("leaf");
        std::fs::create_dir_all(up2.join("lib/apk/db")).unwrap();
        std::os::unix::fs::symlink("/nonexistent", up2.join("lib/apk/db/installed")).unwrap();
        assert_eq!(drifted(check(&up2)), "lib/apk/db/installed written");
        std::fs::remove_dir_all(&up).unwrap();
        std::fs::remove_dir_all(&up2).unwrap();
    }

    /// B3 without privilege: `user.overlay.opaque` (a userxattr overlay's
    /// mark) on a parent of a database is drift. Skipped where the temp
    /// filesystem has no user xattrs.
    #[test]
    fn a_user_xattr_opaque_parent_is_drift() {
        let up = tmp("uopaque");
        std::fs::create_dir_all(up.join("var/lib/dpkg")).unwrap();
        let p = std::ffi::CString::new(up.join("var/lib").to_string_lossy().as_bytes()).unwrap();
        for (value, want_drift) in [(&b"y"[..], true), (b"x", true), (b"n", false)] {
            // SAFETY: valid path, name and value buffers.
            let rc = unsafe {
                libc::setxattr(
                    p.as_ptr(),
                    c"user.overlay.opaque".as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            };
            if rc != 0 {
                eprintln!("no user xattrs here: {}", io::Error::last_os_error());
                std::fs::remove_dir_all(&up).unwrap();
                return;
            }
            let d = check(&up);
            if want_drift {
                assert_eq!(drifted(d), "var/lib opaque (deleted and recreated)");
            } else {
                assert_eq!(d, Drift::Clean, "value {value:?}");
            }
        }
        std::fs::remove_dir_all(&up).unwrap();
    }

    #[test]
    fn an_unusable_upperdir_makes_drift_unknown() {
        let root = std::fs::File::open("/").unwrap();
        for u in [Upperdir::Missing, Upperdir::Unparseable] {
            assert!(matches!(
                drift_check(root.as_raw_fd(), &u),
                Drift::Unknown(_)
            ));
        }
        assert!(matches!(
            check(Path::new("/nonexistent/kguardian/upper")),
            Drift::Unknown(_)
        ));
    }

    /// The upperdir is a host path string: resolved IN the host root, a
    /// symlink in it pointing outside cannot escape, and `..` stays
    /// inside. Here the "host root" is a temp dir.
    #[test]
    fn the_upperdir_is_resolved_inside_the_host_root() {
        let host = tmp("host");
        std::fs::create_dir_all(host.join("snap/fs/lib/apk/db")).unwrap();
        std::fs::write(host.join("snap/fs/lib/apk/db/installed"), b"").unwrap();
        std::os::unix::fs::symlink("/snap", host.join("escape")).unwrap();
        let root = std::fs::File::open(&host).unwrap();
        for p in ["/escape/fs", "/../../snap/fs"] {
            assert_eq!(
                drifted(drift_check(root.as_raw_fd(), &Upperdir::Path(p.into()))),
                "lib/apk/db/installed written"
            );
        }
        std::fs::remove_dir_all(&host).unwrap();
    }

    #[test]
    fn mount_id_and_same_object_describe_the_fd() {
        let a = std::fs::File::open("/").unwrap();
        let b = std::fs::File::open("/").unwrap();
        let c = std::fs::File::open("/proc").unwrap();
        assert!(same_object(a.as_raw_fd(), b.as_raw_fd()).unwrap());
        assert!(!same_object(a.as_raw_fd(), c.as_raw_fd()).unwrap());
        let (ma, mc) = (
            mount_id(a.as_raw_fd()).unwrap(),
            mount_id(c.as_raw_fd()).unwrap(),
        );
        if let (Some(ma), Some(mc)) = (ma, mc) {
            assert_ne!(ma, mc, "/proc is its own mount");
        }
    }

    fn mount(src: &str, target: &Path, fstype: &str, data: &str) -> io::Result<()> {
        let s = std::ffi::CString::new(src).unwrap();
        let t = std::ffi::CString::new(target.to_string_lossy().as_bytes()).unwrap();
        let f = std::ffi::CString::new(fstype).unwrap();
        let d = std::ffi::CString::new(data).unwrap();
        // SAFETY: valid NUL-terminated strings.
        if unsafe { libc::mount(s.as_ptr(), t.as_ptr(), f.as_ptr(), 0, d.as_ptr().cast()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn umount(target: &Path) {
        let t = std::ffi::CString::new(target.to_string_lossy().as_bytes()).unwrap();
        // SAFETY: valid path.
        unsafe { libc::umount2(t.as_ptr(), libc::MNT_DETACH) };
    }

    /// A real overlay on a tmpfs: lower layers with the package databases
    /// and a Python package, and the upperdir the kernel writes when the
    /// container deletes things through the merged view.
    struct Overlay {
        base: std::path::PathBuf,
        merged: std::path::PathBuf,
        upper: std::path::PathBuf,
    }

    impl Overlay {
        fn new(tag: &str) -> Self {
            let base = tmp(tag);
            mount("tmpfs", &base, "tmpfs", "size=16m").expect("mount tmpfs");
            let (lower, upper, work, merged) = (
                base.join("lower"),
                base.join("upper"),
                base.join("work"),
                base.join("merged"),
            );
            for d in [&upper, &work, &merged] {
                std::fs::create_dir_all(d).unwrap();
            }
            for f in [
                "var/lib/dpkg/status",
                "lib/apk/db/installed",
                "usr/lib/python3.12/site-packages/requests-2.32.0.dist-info/METADATA",
            ] {
                let p = lower.join(f);
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                std::fs::write(p, b"x").unwrap();
            }
            mount(
                "overlay",
                &merged,
                "overlay",
                &format!(
                    "lowerdir={},upperdir={},workdir={}",
                    lower.display(),
                    upper.display(),
                    work.display()
                ),
            )
            .expect("mount overlay");
            Overlay {
                base,
                merged,
                upper,
            }
        }

        fn check(&self) -> UpperCheck {
            let root = std::fs::File::open("/").unwrap();
            check_upper(
                root.as_raw_fd(),
                &Upperdir::Path(self.upper.to_string_lossy().into_owned()),
            )
        }
    }

    impl Drop for Overlay {
        fn drop(&mut self) {
            umount(&self.merged);
            umount(&self.base);
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    /// B3 on a real overlay (needs CAP_SYS_ADMIN): every way a container
    /// can remove a package database through the merged view is drift,
    /// and a deleted Python package is `lang_whiteout`.
    #[test]
    #[ignore = "needs CAP_SYS_ADMIN (run with --ignored as root)"]
    fn real_overlay_whiteouts_and_opaque_dirs_are_drift() {
        if let Some(why) = skip_without_overlay_or_tmpfs_xattrs() {
            eprintln!("{why}; the catalog overlay drift test is skipped");
            return;
        }
        // Untouched: clean.
        let o = Overlay::new("ovl-clean");
        assert_eq!(
            o.check(),
            UpperCheck {
                drift: Drift::Clean,
                lang: LangCheck::Clean
            }
        );
        drop(o);

        // The database deleted: a whiteout at the leaf.
        let o = Overlay::new("ovl-leaf");
        std::fs::remove_file(o.merged.join("lib/apk/db/installed")).unwrap();
        assert_eq!(
            drifted(o.check().drift),
            "lib/apk/db/installed deleted (whiteout)"
        );
        drop(o);

        // A parent deleted: a whiteout at var/lib.
        let o = Overlay::new("ovl-parent");
        std::fs::remove_dir_all(o.merged.join("var/lib")).unwrap();
        assert_eq!(drifted(o.check().drift), "var/lib deleted (whiteout)");
        drop(o);

        // Deleted and recreated empty: an opaque directory, no database
        // written in the upperdir at all.
        let o = Overlay::new("ovl-opaque");
        std::fs::remove_dir_all(o.merged.join("var/lib/dpkg")).unwrap();
        std::fs::create_dir(o.merged.join("var/lib/dpkg")).unwrap();
        assert!(!o.upper.join("var/lib/dpkg/status").exists());
        assert_eq!(
            drifted(o.check().drift),
            "var/lib/dpkg opaque (deleted and recreated)"
        );
        drop(o);

        // A Python package deleted: not drift, but lang_whiteout.
        let o = Overlay::new("ovl-lang");
        std::fs::remove_dir_all(
            o.merged
                .join("usr/lib/python3.12/site-packages/requests-2.32.0.dist-info"),
        )
        .unwrap();
        let c = o.check();
        assert_eq!(c.drift, Drift::Clean);
        let LangCheck::Found(hit) = c.lang else {
            panic!("a deleted dist-info is seen: {:?}", c.lang)
        };
        assert!(hit.contains("requests-2.32.0.dist-info"), "{hit}");
        drop(o);
    }

    /// Is overlayfs registered with this kernel?
    fn overlay_registered() -> bool {
        std::fs::read_to_string("/proc/filesystems")
            .map(|s| {
                s.lines()
                    .any(|l| l.split_whitespace().last() == Some("overlay"))
            })
            .unwrap_or(false)
    }

    /// Why a tmpfs here cannot carry `trusted.*` xattrs, if it cannot
    /// (a kernel without CONFIG_TMPFS_XATTR answers EOPNOTSUPP).
    fn skip_without_tmpfs_trusted_xattrs() -> Option<String> {
        let base = tmp("xattr-probe");
        if let Err(e) = mount("tmpfs", &base, "tmpfs", "size=1m") {
            let _ = std::fs::remove_dir_all(&base);
            return Some(format!("cannot mount a tmpfs ({e})"));
        }
        let p = std::ffi::CString::new(base.to_string_lossy().as_bytes()).unwrap();
        // SAFETY: valid path, name and value buffers.
        let rc = unsafe {
            libc::setxattr(
                p.as_ptr(),
                c"trusted.kg-probe".as_ptr(),
                b"y".as_ptr().cast(),
                1,
                0,
            )
        };
        let e = io::Error::last_os_error();
        umount(&base);
        let _ = std::fs::remove_dir_all(&base);
        match (rc, e.raw_os_error()) {
            (0, _) => None,
            (_, Some(libc::EOPNOTSUPP)) => Some(format!("tmpfs has no trusted xattrs here ({e})")),
            _ => panic!("setxattr on tmpfs: {e}"),
        }
    }

    fn skip_without_overlay_or_tmpfs_xattrs() -> Option<String> {
        if !overlay_registered() {
            return Some("overlayfs not available here (not in /proc/filesystems)".into());
        }
        skip_without_tmpfs_trusted_xattrs()
    }

    #[test]
    fn cap_sys_admin_is_read_from_cap_eff() {
        let status = |eff: &str| {
            format!(
                "Name:\tx\nCapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\nCapEff:\t{eff}\n"
            )
        };
        assert!(cap_sys_admin(&status("000001ffffffffff")));
        assert!(cap_sys_admin(&status("0000000000200000")));
        assert!(
            !cap_sys_admin(&status("00000000a80425fb")),
            "docker's default set lacks it"
        );
        assert!(!cap_sys_admin(&status("0000000000000000")));
        assert!(!cap_sys_admin("garbage"));
    }

    /// N5: a site-packages directory larger than the budget makes the
    /// check unknown rather than silently clean.
    #[test]
    fn the_language_scan_budget_makes_the_check_unknown() {
        let up = tmp("lang-budget");
        let sp = up.join("usr/lib/python3.12/site-packages");
        std::fs::create_dir_all(&sp).unwrap();
        for i in 0..50 {
            std::fs::create_dir(sp.join(format!("pkg{i}.dist-info"))).unwrap();
        }
        let fd = std::fs::File::open(&up).unwrap();
        assert_eq!(
            lang_whiteout_within(fd.as_raw_fd(), 10_000),
            LangCheck::Clean
        );
        assert!(matches!(
            lang_whiteout_within(fd.as_raw_fd(), 20),
            LangCheck::Unknown(_)
        ));
        assert_eq!(lang_whiteout(fd.as_raw_fd()), LangCheck::Clean);
        std::fs::remove_dir_all(&up).unwrap();
    }

    /// `trusted.overlay.opaque=x` (kernel >= 6.7 "has whiteouts") is drift
    /// too; set by hand on a tmpfs, which takes trusted xattrs (root only).
    #[test]
    #[ignore = "needs CAP_SYS_ADMIN (run with --ignored as root)"]
    fn a_trusted_opaque_x_parent_is_drift() {
        if let Some(why) = skip_without_tmpfs_trusted_xattrs() {
            eprintln!("{why}; the catalog opaque=x test is skipped");
            return;
        }
        let base = tmp("topaque");
        mount("tmpfs", &base, "tmpfs", "size=1m").expect("mount tmpfs");
        std::fs::create_dir_all(base.join("var/lib/dpkg")).unwrap();
        let p = std::ffi::CString::new(base.join("var").to_string_lossy().as_bytes()).unwrap();
        // SAFETY: valid path, name and value buffers.
        let rc = unsafe {
            libc::setxattr(
                p.as_ptr(),
                c"trusted.overlay.opaque".as_ptr(),
                b"x".as_ptr().cast(),
                1,
                0,
            )
        };
        assert_eq!(rc, 0, "{}", io::Error::last_os_error());
        assert_eq!(drifted(check(&base)), "var opaque (deleted and recreated)");
        umount(&base);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn an_unreadable_db_directory_makes_drift_unknown_when_not_root() {
        // SAFETY: getuid has no preconditions.
        if unsafe { libc::getuid() } == 0 {
            return; // root reads through 0000 directories.
        }
        let up = tmp("perm");
        std::fs::create_dir_all(up.join("lib/apk")).unwrap();
        std::fs::set_permissions(up.join("lib"), std::fs::Permissions::from_mode(0o000)).unwrap();
        assert!(matches!(check(&up), Drift::Unknown(_)));
        std::fs::set_permissions(up.join("lib"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(&up).unwrap();
    }

    /// Needs CAP_SYS_ADMIN: clones this process's own root. Run with
    /// `cargo test -- --ignored` in a privileged container.
    #[test]
    #[ignore = "needs CAP_SYS_ADMIN (run with --ignored as root)"]
    fn readonly_clone_of_our_own_root_is_read_only_and_has_no_submounts() {
        // SAFETY: getpid has no preconditions.
        let dir = ProcDir::open(Path::new("/proc"), unsafe { libc::getpid() } as u32).unwrap();
        let fd = match readonly_clone(&dir) {
            Ok(fd) => fd,
            Err(e) if matches!(e.errno, libc::ENOSYS | libc::EOPNOTSUPP) => {
                eprintln!("open_tree/mount_setattr not available here ({e}); the catalog read-only clone test is skipped");
                return;
            }
            Err(e) => panic!("clone: {e}"),
        };
        // Writing anything through the clone is refused.
        let name = c"kguardian-ro-probe";
        // SAFETY: valid dirfd and name.
        let rc = unsafe {
            libc::openat(
                fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC,
                0o600,
            )
        };
        let e = io::Error::last_os_error();
        assert!(rc < 0 && e.raw_os_error() == Some(libc::EROFS), "{e}");
        // Not recursive: /proc in the clone is an empty directory.
        let proc = openat(fd.as_raw_fd(), c"proc", libc::O_RDONLY | libc::O_DIRECTORY).unwrap();
        let self_ = openat(proc.as_raw_fd(), c"self", libc::O_PATH);
        assert!(
            self_.is_err(),
            "the clone must not carry the /proc submount"
        );
    }

    /// Unprivileged, the clone fails at setns (EPERM) and says so; the
    /// caller falls back. As root this is covered by the ignored test.
    #[test]
    fn readonly_clone_fails_cleanly_without_privilege() {
        // SAFETY: getuid has no preconditions.
        if unsafe { libc::getuid() } == 0 {
            return;
        }
        // SAFETY: getpid has no preconditions.
        let dir = ProcDir::open(Path::new("/proc"), unsafe { libc::getpid() } as u32).unwrap();
        let e = readonly_clone(&dir).expect_err("unprivileged");
        assert_eq!(e.stage, "setns");
    }
}
