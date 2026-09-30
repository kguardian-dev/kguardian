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
    /// No package database was written since the container started.
    Clean,
    /// This package database (or a directory on its path) is in the
    /// upperdir: packages changed at runtime.
    Drifted(&'static str),
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

/// Is `rel` present under `dir`? Walked one name at a time, never
/// following a symlink: intermediate components with `O_PATH|O_NOFOLLOW|
/// O_DIRECTORY`, the last with `fstatat(AT_SYMLINK_NOFOLLOW)`. Anything at
/// the leaf counts, including an overlay whiteout (a deleted database is
/// a changed one). A non-directory where a directory should be (a symlink
/// or file replacing `var/lib/dpkg`) counts too: the path was rewritten.
fn present(dir: RawFd, rel: &str) -> io::Result<bool> {
    let parts: Vec<&str> = rel.split('/').collect();
    let (last, dirs) = parts.split_last().expect("non-empty path");
    let mut held: Option<OwnedFd> = None;
    for d in dirs {
        let at = held.as_ref().map_or(dir, |f| f.as_raw_fd());
        match openat(
            at,
            &cstr(d)?,
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        ) {
            Ok(fd) => held = Some(fd),
            Err(e) => match e.raw_os_error() {
                Some(libc::ENOENT) => return Ok(false),
                Some(libc::ENOTDIR) | Some(libc::ELOOP) => return Ok(true),
                _ => return Err(e),
            },
        }
    }
    let at = held.as_ref().map_or(dir, |f| f.as_raw_fd());
    let name = cstr(last)?;
    // SAFETY: zeroed stat is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid dirfd, NUL-terminated name, out-pointer to a local.
    let rc = unsafe { libc::fstatat(at, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    if rc == 0 {
        return Ok(true);
    }
    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::ENOENT) => Ok(false),
        _ => Err(e),
    }
}

/// Look for the package databases in the container's upperdir, resolved
/// under `host_root` (an fd on `/proc/1/root`) with `RESOLVE_IN_ROOT`,
/// so the host path string from mountinfo can never escape the host
/// root or follow a magic link. No walk of the upperdir: four lookups.
pub fn drift_check(host_root: RawFd, upper: &Upperdir) -> Drift {
    let path = match upper {
        Upperdir::Path(p) => p,
        Upperdir::Missing => return Drift::Unknown("no upperdir".into()),
        Upperdir::Unparseable => return Drift::Unknown("unparseable upperdir".into()),
    };
    let Ok(c) = cstr(path) else {
        return Drift::Unknown("upperdir with a NUL".into());
    };
    let upfd = match openat2_in_root(host_root, &c, (libc::O_PATH | libc::O_DIRECTORY) as u64) {
        Ok(fd) => fd,
        Err(e) => return Drift::Unknown(format!("open upperdir: {e}")),
    };
    for db in PACKAGE_DBS {
        match present(upfd.as_raw_fd(), db) {
            Ok(true) => return Drift::Drifted(db),
            Ok(false) => {}
            Err(e) => return Drift::Unknown(format!("{db}: {e}")),
        }
    }
    Drift::Clean
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
    let mut status = 0;
    if got.is_err() {
        // SAFETY: our own child.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    // SAFETY: reap our own child; it has exited or was just killed.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    got
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
    if r < 8 {
        return Err(CloneError {
            stage: "helper exited",
            errno: libc::EPIPE,
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

    #[test]
    fn each_package_db_in_the_upperdir_is_drift() {
        for db in PACKAGE_DBS {
            let up = tmp("db");
            let p = up.join(db);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, b"").unwrap();
            assert_eq!(check(&up), Drift::Drifted(db), "{db}");
            std::fs::remove_dir_all(&up).unwrap();
        }
    }

    #[test]
    fn a_symlink_replacing_a_db_directory_is_drift_and_is_not_followed() {
        let up = tmp("link");
        std::fs::create_dir_all(up.join("var/lib")).unwrap();
        std::os::unix::fs::symlink("/etc", up.join("var/lib/dpkg")).unwrap();
        assert_eq!(check(&up), Drift::Drifted("var/lib/dpkg/status"));
        // A symlink AT the leaf counts without being followed.
        let up2 = tmp("leaf");
        std::fs::create_dir_all(up2.join("lib/apk/db")).unwrap();
        std::os::unix::fs::symlink("/nonexistent", up2.join("lib/apk/db/installed")).unwrap();
        assert_eq!(check(&up2), Drift::Drifted("lib/apk/db/installed"));
        std::fs::remove_dir_all(&up).unwrap();
        std::fs::remove_dir_all(&up2).unwrap();
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
        // A link to the real / from inside: RESOLVE_IN_ROOT makes "/"
        // the temp dir, so this names host/snap, not the filesystem root.
        std::os::unix::fs::symlink("/snap", host.join("escape")).unwrap();
        let root = std::fs::File::open(&host).unwrap();
        assert_eq!(
            drift_check(root.as_raw_fd(), &Upperdir::Path("/escape/fs".into())),
            Drift::Drifted("lib/apk/db/installed")
        );
        assert_eq!(
            drift_check(root.as_raw_fd(), &Upperdir::Path("/../../snap/fs".into())),
            Drift::Drifted("lib/apk/db/installed")
        );
        std::fs::remove_dir_all(&host).unwrap();
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
        let fd = readonly_clone(&dir).expect("clone");
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
