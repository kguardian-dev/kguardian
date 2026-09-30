//! The Controller's half of the cataloger worker protocol
//! (`cataloger/PROTOCOL.md`, v1): connect, verify the peer, send one
//! framed request with the root fd attached, read one framed response.
//!
//! Blocking I/O on purpose: it runs on a `spawn_blocking` thread, with
//! its own deadlines (`poll` in slices, so a cancel flag is noticed
//! within a second), and never on the runtime the capture paths share.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::api::Scanner;

pub const PROTOCOL_VERSION: i64 = 1;
/// Request frames are at most 64 KiB (PROTOCOL.md 2).
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// The Controller never accepts a response over this, whatever it asked
/// for (PROTOCOL.md 2: never above 64 MiB).
pub const MAX_RESPONSE_CEILING: usize = 64 * 1024 * 1024;
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// Read deadline beyond the scan budget (PROTOCOL.md 1).
pub const READ_GRACE: Duration = Duration::from_secs(30);
/// Deadline for a `ping` answer.
pub const PING_TIMEOUT: Duration = Duration::from_secs(5);

/// Budgets sent with a scan (PROTOCOL.md 3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Budgets {
    pub max_files: u64,
    pub max_components: u64,
    pub max_depth: u64,
    pub scan_timeout_ms: u64,
    pub max_paths_per_package: u64,
    pub max_response_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Request {
    pub protocol_version: i64,
    pub op: &'static str,
    pub scan_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_start_unix_nanos: Option<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub submounts: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budgets: Option<Budgets>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
pub struct Os {
    #[serde(default)]
    pub family: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

/// A response as received; [`super::post::validate`] turns it into what
/// is posted. Unknown fields are ignored (PROTOCOL.md 4.3, 5).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Response {
    pub protocol_version: i64,
    #[serde(default)]
    pub scan_id: String,
    #[serde(default)]
    pub epoch: i64,
    pub status: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub completeness: String,
    #[serde(default)]
    pub partial_reasons: Vec<String>,
    #[serde(default)]
    pub retry_reason: String,
    #[serde(default)]
    pub scanner: Scanner,
    #[serde(default)]
    pub os: Option<Os>,
    #[serde(default)]
    pub stats: serde_json::Value,
    #[serde(default)]
    pub components: Vec<super::api::Component>,
}

/// Why a hand-off produced no response.
#[derive(Debug)]
pub enum WorkerError {
    /// No worker listening, or the connect timed out.
    Unavailable(io::Error),
    /// The peer is not the cataloger sidecar of this pod. Nothing was
    /// sent to it.
    PeerRejected(String),
    /// The peer cannot be verified on this node at all: the kernel has no
    /// `SO_PEERPIDFD` (Linux < 6.5) and the Controller does not share the
    /// worker's pid namespace. Nothing was sent. Permanent for the life of
    /// the process; the claim loop stops claiming (see `catalog::degraded`).
    PeerUnsupported(String),
    /// A framing or deadline violation by the peer, or I/O failing
    /// mid-exchange. The connection is closed (which cancels the scan).
    Protocol(String),
    /// The read deadline passed.
    Timeout,
    /// The caller cancelled (lost lease). The connection is closed.
    Cancelled,
}

impl std::fmt::Display for WorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerError::Unavailable(e) => write!(f, "worker unavailable: {e}"),
            WorkerError::PeerRejected(m) => write!(f, "worker peer rejected: {m}"),
            WorkerError::PeerUnsupported(m) => write!(f, "worker peer cannot be verified: {m}"),
            WorkerError::Protocol(m) => write!(f, "worker protocol error: {m}"),
            WorkerError::Timeout => write!(f, "worker did not answer before the deadline"),
            WorkerError::Cancelled => write!(f, "scan cancelled"),
        }
    }
}

// ---- Peer verification --------------------------------------------------

/// Why a peer was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerError {
    /// This peer is not the cataloger sidecar of this pod.
    Rejected(String),
    /// No peer can be verified on this node (see
    /// [`WorkerError::PeerUnsupported`]).
    Unsupported(String),
}

impl From<String> for PeerError {
    fn from(m: String) -> Self {
        PeerError::Rejected(m)
    }
}

impl From<&str> for PeerError {
    fn from(m: &str) -> Self {
        PeerError::Rejected(m.to_string())
    }
}

/// The minimum kernel for [`peer_pidfd`], named in logs and docs.
pub const PEERPIDFD_KERNEL: &str = "Linux 6.5";

/// With `SO_PEERPIDFD` refused by `err`: the peer pid to fall back on,
/// or why there is none. The fallback (`SO_PEERCRED`'s pid) is only
/// meaningful when the host procfs is in the Controller's own pid
/// namespace (`hostPID`); otherwise that pid is 0, or a number in a
/// namespace the procfs does not show. Fails closed either way.
pub fn without_pidfd(err: &io::Error, same_pid_ns: bool, peer_pid: i32) -> Result<i32, PeerError> {
    if same_pid_ns && peer_pid > 0 {
        return Ok(peer_pid);
    }
    match err.raw_os_error() {
        // What a kernel without the option answers at SOL_SOCKET.
        Some(libc::ENOPROTOOPT) | Some(libc::EINVAL) => Err(PeerError::Unsupported(format!(
            "the kernel has no SO_PEERPIDFD ({err}; needs {PEERPIDFD_KERNEL} or later) and the \
             Controller does not share the worker's pid namespace, so the worker's process \
             cannot be pinned for the cgroup check"
        ))),
        _ => Err(PeerError::Rejected(format!(
            "cannot pin the peer process (SO_PEERPIDFD: {err}; peer pid {peer_pid})"
        ))),
    }
}

/// `SO_PEERCRED` of a connected socket.
pub fn peer_cred(sock: RawFd) -> io::Result<libc::ucred> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: out-pointers to a local of the size passed.
    let rc = unsafe {
        libc::getsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred)
}

/// `SO_PEERPIDFD` (Linux 6.5): a pidfd for the peer.
fn peer_pidfd(sock: RawFd) -> io::Result<OwnedFd> {
    let mut fd: libc::c_int = -1;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: out-pointers to a local of the size passed.
    let rc = unsafe {
        libc::getsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            (&mut fd as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if rc != 0 || fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a new fd from the kernel.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The `Pid:` line of a pidfd's fdinfo: the pid in the pid namespace of
/// the procfs it was read through, `-1` once the process has exited.
pub fn fdinfo_pid(body: &str) -> Option<i64> {
    body.lines()
        .find_map(|l| l.strip_prefix("Pid:"))
        .and_then(|v| v.trim().parse().ok())
}

/// The `0::` (cgroup v2) path of a `/proc/<pid>/cgroup` body.
pub fn v2_path(cgroup: &str) -> Option<&str> {
    cgroup
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::trim)
}

/// A cgroup path's segments with `..` folded lexically. Paths are as
/// the READER's cgroup namespace shows them: `/` for the Controller's
/// own container under a private cgroupns, `/../<sibling>` for another
/// container of the same pod.
fn segments(p: &str) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    for s in p.split('/').filter(|s| !s.is_empty() && *s != ".") {
        if s == ".." && out.last().is_some_and(|l| *l != "..") {
            out.pop();
        } else {
            out.push(s);
        }
    }
    out
}

fn parent(mut segs: Vec<&str>) -> Vec<&str> {
    match segs.last() {
        None | Some(&"..") => segs.push(".."),
        Some(_) => {
            segs.pop();
        }
    }
    segs
}

/// Is `peer` a different container of the Controller's own pod? Both
/// paths are read by the Controller, so they are in the same cgroup
/// namespace view: the peer must be a sibling of `own` (same parent,
/// which is the pod cgroup), and not `own` itself. When the view is the
/// host's (absolute kubepods paths), the pod uids must agree too.
///
/// A pod's cgroup also holds its sandbox (pause) container; that one
/// runs no code that connects to a socket, and the uid check still
/// applies.
pub fn same_pod_sibling(own: &str, peer: &str) -> Result<(), String> {
    let o = segments(own);
    let p = segments(peer);
    if o == p {
        return Err("peer is the Controller's own container".into());
    }
    if p.last().is_none_or(|l| *l == "..") {
        return Err(format!("peer cgroup {peer:?} names no container"));
    }
    if parent(o) != parent(p) {
        return Err(format!(
            "peer cgroup {peer:?} is not in the Controller's pod (own {own:?})"
        ));
    }
    let (a, b) = (
        crate::early_capture::parse_kubepods_cgroup_path(own),
        crate::early_capture::parse_kubepods_cgroup_path(peer),
    );
    if let (Some(a), Some(b)) = (a, b) {
        if a.pod_uid != b.pod_uid {
            return Err("peer is in another pod".into());
        }
    }
    Ok(())
}

/// How to find the peer's cgroup.
pub trait PeerProc {
    /// The Controller's own cgroup body.
    fn own_cgroup(&self) -> io::Result<String>;
    /// The peer's cgroup body, pid-reuse safe, or an error when the
    /// peer's process cannot be pinned.
    fn peer_cgroup(&self, sock: RawFd, cred: &libc::ucred) -> Result<String, PeerError>;
}

/// The real lookups, through the host procfs.
pub struct HostPeerProc {
    pub host_proc: PathBuf,
}

impl HostPeerProc {
    /// Is `host_proc` a procfs of the Controller's own pid namespace?
    /// `self` there resolves to our pid in THAT procfs's namespace.
    fn same_pid_ns(&self) -> bool {
        // SAFETY: getpid has no preconditions.
        let me = unsafe { libc::getpid() };
        std::fs::read_link(self.host_proc.join("self"))
            .ok()
            .and_then(|p| p.to_str().and_then(|s| s.parse::<i32>().ok()))
            == Some(me)
    }
}

impl PeerProc for HostPeerProc {
    fn own_cgroup(&self) -> io::Result<String> {
        std::fs::read_to_string(self.host_proc.join("self/cgroup"))
    }

    fn peer_cgroup(&self, sock: RawFd, cred: &libc::ucred) -> Result<String, PeerError> {
        // The worker is in another pid namespace (its own container), so
        // SO_PEERCRED's pid is 0 here. SO_PEERPIDFD pins the peer, and
        // its fdinfo, read through the host procfs, names it in the host
        // namespace. Re-reading the pid after the cgroup proves the
        // process the cgroup belonged to was alive throughout.
        match peer_pidfd(sock) {
            Ok(pidfd) => {
                let info = self
                    .host_proc
                    .join(format!("self/fdinfo/{}", pidfd.as_raw_fd()));
                let pid = |_: ()| {
                    std::fs::read_to_string(&info)
                        .ok()
                        .and_then(|b| fdinfo_pid(&b))
                        .filter(|p| *p > 0)
                };
                let before = pid(()).ok_or("peer pidfd names no live process")?;
                let cg = std::fs::read_to_string(self.host_proc.join(format!("{before}/cgroup")))
                    .map_err(|e| format!("peer cgroup: {e}"))?;
                if pid(()) != Some(before) {
                    return Err("peer exited while being verified".into());
                }
                Ok(cg)
            }
            Err(e) => {
                // A kernel without SO_PEERPIDFD: usable only when a shared
                // pid namespace makes SO_PEERCRED's pid meaningful.
                let pid = without_pidfd(&e, self.same_pid_ns(), cred.pid)?;
                tracing::debug!(error = %e, "SO_PEERPIDFD unavailable; using SO_PEERCRED pid");
                Ok(
                    std::fs::read_to_string(self.host_proc.join(format!("{pid}/cgroup")))
                        .map_err(|e| format!("peer cgroup: {e}"))?,
                )
            }
        }
    }
}

/// `SO_PEERCRED` uid in the allowed set, and the peer a sibling
/// container of this pod. Fails closed: any lookup that does not work
/// rejects the peer.
pub fn verify_peer<P: PeerProc>(
    sock: RawFd,
    allowed_uids: &[u32],
    proc: &P,
) -> Result<(), PeerError> {
    let cred = peer_cred(sock).map_err(|e| format!("SO_PEERCRED: {e}"))?;
    if !allowed_uids.contains(&cred.uid) {
        return Err(format!("peer uid {} is not allowed", cred.uid).into());
    }
    let own = proc.own_cgroup().map_err(|e| format!("own cgroup: {e}"))?;
    let peer = proc.peer_cgroup(sock, &cred)?;
    let (Some(o), Some(p)) = (v2_path(&own), v2_path(&peer)) else {
        return Err("no cgroup v2 path to compare".into());
    };
    Ok(same_pod_sibling(o, p)?)
}

// ---- Transport ------------------------------------------------------------

fn set_timeout(fd: RawFd, opt: libc::c_int, d: Duration) -> io::Result<()> {
    let tv = libc::timeval {
        tv_sec: d.as_secs() as libc::time_t,
        tv_usec: d.subsec_micros() as libc::suseconds_t,
    };
    // SAFETY: a timeval of the size passed.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            (&tv as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Connect with a deadline. `SO_SNDTIMEO` bounds a unix-socket connect
/// that would wait on a full backlog, and every later write.
pub fn connect(path: &Path) -> io::Result<UnixStream> {
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: plain socket creation.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: just created, ours.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    set_timeout(fd, libc::SO_SNDTIMEO, CONNECT_TIMEOUT)?;
    // SAFETY: zeroed sockaddr_un is valid.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= addr.sun_path.len() {
        return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
    }
    for (d, s) in addr.sun_path.iter_mut().zip(bytes) {
        *d = *s as libc::c_char;
    }
    // SAFETY: a valid sockaddr_un of the size passed.
    let rc = unsafe {
        libc::connect(
            fd,
            (&addr as *const libc::sockaddr_un).cast(),
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    set_timeout(fd, libc::SO_SNDTIMEO, WRITE_TIMEOUT)?;
    Ok(UnixStream::from(sock))
}

/// One frame: big-endian u32 length, then the payload.
pub fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Send `frame` with `fd` attached to its first byte (one `sendmsg`;
/// PROTOCOL.md 3.1), finishing with plain writes if the kernel took less.
pub fn send_with_fd(sock: &UnixStream, frame: &[u8], fd: Option<RawFd>) -> io::Result<()> {
    let mut iov = libc::iovec {
        iov_base: frame.as_ptr() as *mut libc::c_void,
        iov_len: frame.len(),
    };
    let mut cbuf = [0u64; 4];
    // SAFETY: zeroed msghdr, filled with pointers to locals that outlive it.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if let Some(fd) = fd {
        msg.msg_control = cbuf.as_mut_ptr().cast();
        // SAFETY: CMSG_* are pure arithmetic on the buffer we own.
        unsafe {
            msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as _;
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(c).cast::<RawFd>(), fd);
        }
    }
    let n = loop {
        // SAFETY: valid socket and msghdr.
        let n = unsafe { libc::sendmsg(sock.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        break n as usize;
    };
    if n < frame.len() {
        (&*sock).write_all(&frame[n..])?;
    }
    Ok(())
}

/// Read exactly `buf.len()` bytes before `deadline`, checking `cancel`
/// at least once a second.
fn read_exact_until(
    sock: &UnixStream,
    buf: &mut [u8],
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<(), WorkerError> {
    let mut got = 0;
    while got < buf.len() {
        if cancel.load(Ordering::Relaxed) {
            return Err(WorkerError::Cancelled);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(WorkerError::Timeout);
        }
        let slice = left.min(Duration::from_secs(1));
        let mut pfd = libc::pollfd {
            fd: sock.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one pollfd.
        let n = unsafe { libc::poll(&mut pfd, 1, slice.as_millis().max(1) as libc::c_int) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(WorkerError::Protocol(format!("poll: {e}")));
        }
        if n == 0 {
            continue;
        }
        match (&*sock).read(&mut buf[got..]) {
            Ok(0) => {
                return Err(WorkerError::Protocol(format!(
                    "connection closed after {got} of {} bytes",
                    buf.len()
                )))
            }
            Ok(k) => got += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(WorkerError::Protocol(format!("read: {e}"))),
        }
    }
    Ok(())
}

/// Read one frame of at most `limit` bytes. A larger length is refused
/// without reading the payload (PROTOCOL.md 2); the caller drops the
/// connection.
pub fn read_frame(
    sock: &UnixStream,
    limit: usize,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<Vec<u8>, WorkerError> {
    let mut len = [0u8; 4];
    read_exact_until(sock, &mut len, deadline, cancel)?;
    let n = u32::from_be_bytes(len) as usize;
    if n < 2 || n > limit {
        return Err(WorkerError::Protocol(format!(
            "response frame of {n} bytes outside 2..={limit}"
        )));
    }
    let mut buf = vec![0u8; n];
    read_exact_until(sock, &mut buf, deadline, cancel)?;
    Ok(buf)
}

/// One exchange on an already-connected, not-yet-verified socket: verify
/// the peer, send, close our copy of the fd, read the answer.
#[allow(clippy::too_many_arguments)]
pub fn exchange<P: PeerProc>(
    sock: UnixStream,
    allowed_uids: &[u32],
    peer: &P,
    req: &Request,
    root: Option<OwnedFd>,
    response_limit: usize,
    read_timeout: Duration,
    cancel: &AtomicBool,
) -> Result<Response, WorkerError> {
    // The fd is not sent to a peer that fails verification; dropping
    // `root` on that path closes it.
    verify_peer(sock.as_raw_fd(), allowed_uids, peer).map_err(|e| match e {
        PeerError::Rejected(m) => WorkerError::PeerRejected(m),
        PeerError::Unsupported(m) => WorkerError::PeerUnsupported(m),
    })?;
    let payload = serde_json::to_vec(req).map_err(|e| WorkerError::Protocol(e.to_string()))?;
    if payload.len() > MAX_REQUEST_BYTES {
        return Err(WorkerError::Protocol(format!(
            "request of {} bytes over the {MAX_REQUEST_BYTES} limit",
            payload.len()
        )));
    }
    let sent = send_with_fd(
        &sock,
        &frame(&payload),
        root.as_ref().map(|f| f.as_raw_fd()),
    );
    // Closed straight after sendmsg (PROTOCOL.md 3.1): the worker holds
    // its own reference now, and the Controller has no further use.
    drop(root);
    sent.map_err(|e| WorkerError::Protocol(format!("send: {e}")))?;
    let limit = response_limit.min(MAX_RESPONSE_CEILING);
    let body = read_frame(&sock, limit, Instant::now() + read_timeout, cancel)?;
    // `sock` drops here: one request, one response, no reuse.
    serde_json::from_slice(&body).map_err(|e| WorkerError::Protocol(format!("response JSON: {e}")))
}

/// Connect and [`exchange`].
#[allow(clippy::too_many_arguments)]
pub fn call<P: PeerProc>(
    path: &Path,
    allowed_uids: &[u32],
    peer: &P,
    req: &Request,
    root: Option<OwnedFd>,
    response_limit: usize,
    read_timeout: Duration,
    cancel: &AtomicBool,
) -> Result<Response, WorkerError> {
    let sock = connect(path).map_err(WorkerError::Unavailable)?;
    exchange(
        sock,
        allowed_uids,
        peer,
        req,
        root,
        response_limit,
        read_timeout,
        cancel,
    )
}

pub fn ping_request(scan_id: String) -> Request {
    Request {
        protocol_version: PROTOCOL_VERSION,
        op: "ping",
        scan_id,
        epoch: None,
        container_start_unix_nanos: None,
        submounts: Vec::new(),
        profile: None,
        budgets: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Peer lookups answered from fixed cgroup bodies.
    struct FakePeer {
        own: &'static str,
        peer: Result<&'static str, &'static str>,
    }

    impl PeerProc for FakePeer {
        fn own_cgroup(&self) -> io::Result<String> {
            Ok(self.own.to_string())
        }
        fn peer_cgroup(&self, _: RawFd, _: &libc::ucred) -> Result<String, PeerError> {
            match self.peer {
                Ok(p) => Ok(p.to_string()),
                Err(m) if m.starts_with("unsupported") => Err(PeerError::Unsupported(m.into())),
                Err(m) => Err(PeerError::Rejected(m.into())),
            }
        }
    }

    const OWN_PRIVATE_NS: &str = "0::/\n";
    const SIBLING: &str = "0::/../cri-containerd-bbbb.scope\n";

    fn good_peer() -> FakePeer {
        FakePeer {
            own: OWN_PRIVATE_NS,
            peer: Ok(SIBLING),
        }
    }

    // SAFETY: getuid has no preconditions.
    fn me() -> u32 {
        unsafe { libc::getuid() }
    }

    #[test]
    fn siblings_in_a_private_cgroup_namespace_are_the_same_pod() {
        assert!(same_pod_sibling("/", "/../cri-containerd-bbbb.scope").is_ok());
        // Our own container, a nested child of it, another pod, the host.
        assert!(same_pod_sibling("/", "/").is_err());
        assert!(same_pod_sibling("/", "/child").is_err());
        assert!(same_pod_sibling("/", "/../../other-pod/ctr").is_err());
        assert!(same_pod_sibling("/", "/../..").is_err());
        assert!(same_pod_sibling("/", "/../../../system.slice/sshd.service").is_err());
    }

    #[test]
    fn siblings_in_the_host_cgroup_view_must_share_the_pod_uid() {
        let pod = "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod5d7c1c2e_1f2a_4b3c_9d8e_0a1b2c3d4e5f.slice";
        let own = format!("{pod}/cri-containerd-{}.scope", "a".repeat(64));
        let peer = format!("{pod}/cri-containerd-{}.scope", "b".repeat(64));
        assert!(same_pod_sibling(&own, &peer).is_ok());
        let other = format!(
            "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod11111111_1f2a_4b3c_9d8e_0a1b2c3d4e5f.slice/cri-containerd-{}.scope",
            "b".repeat(64)
        );
        assert!(same_pod_sibling(&own, &other).is_err());
        assert!(same_pod_sibling(&own, &own).is_err());
    }

    #[test]
    fn fdinfo_pid_reads_the_pid_line() {
        assert_eq!(
            fdinfo_pid("pos:\t0\nflags:\t02000002\nPid:\t4242\nNSpid:\t4242\t7\n"),
            Some(4242)
        );
        assert_eq!(fdinfo_pid("Pid:\t-1\n"), Some(-1));
        assert_eq!(fdinfo_pid("pos: 0\n"), None);
    }

    /// A fake worker on the other end of a socketpair: reads one framed
    /// request with its fd, checks it, and answers with `reply`.
    fn fake_worker(
        theirs: UnixStream,
        hold: bool,
        reply: impl FnOnce(&serde_json::Value, bool) -> Vec<u8> + Send + 'static,
    ) -> std::thread::JoinHandle<(serde_json::Value, bool, Option<UnixStream>)> {
        std::thread::spawn(move || {
            let mut len = [0u8; 4];
            let mut cbuf = [0u64; 8];
            let mut iov = libc::iovec {
                iov_base: len.as_mut_ptr().cast(),
                iov_len: 4,
            };
            // SAFETY: zeroed msghdr pointing at locals.
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cbuf.as_mut_ptr().cast();
            msg.msg_controllen = std::mem::size_of_val(&cbuf) as _;
            // SAFETY: valid socket and msghdr.
            let n = unsafe { libc::recvmsg(theirs.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
            assert_eq!(n, 4, "the fd rides the first bytes of the frame");
            let mut got_fd = false;
            // SAFETY: walking the control buffer the kernel filled.
            unsafe {
                let c = libc::CMSG_FIRSTHDR(&msg);
                if !c.is_null() && (*c).cmsg_type == libc::SCM_RIGHTS {
                    let fd = std::ptr::read_unaligned(libc::CMSG_DATA(c).cast::<RawFd>());
                    let f = OwnedFd::from_raw_fd(fd);
                    let mut st: libc::stat = std::mem::zeroed();
                    assert_eq!(libc::fstat(f.as_raw_fd(), &mut st), 0);
                    assert_eq!(st.st_mode & libc::S_IFMT, libc::S_IFDIR);
                    got_fd = true;
                }
            }
            let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
            (&theirs).read_exact(&mut body).unwrap();
            let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let out = reply(&req, got_fd);
            let _ = (&theirs).write_all(&out);
            // Held: handed back so the socket stays open until the test
            // joins. Otherwise closed now, like a worker that exits.
            (req, got_fd, hold.then_some(theirs))
        })
    }

    fn scan_request() -> Request {
        Request {
            protocol_version: 1,
            op: "scan",
            scan_id: "scan-1".into(),
            epoch: Some(3),
            container_start_unix_nanos: Some(1_790_000_000_123_456_789),
            submounts: vec!["/proc".into()],
            profile: Some("full"),
            budgets: Some(Budgets {
                max_response_bytes: 1 << 20,
                ..Default::default()
            }),
        }
    }

    fn root_fd() -> OwnedFd {
        std::fs::File::open("/").unwrap().into()
    }

    #[test]
    fn a_scan_round_trips_over_a_socketpair_with_the_fd() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let worker = fake_worker(theirs, true, |req, got_fd| {
            assert!(got_fd);
            let resp = serde_json::json!({
                "protocol_version": 1, "scan_id": req["scan_id"], "epoch": req["epoch"],
                "status": "ok", "completeness": "full",
                "scanner": {"name": "kguardian-cataloger", "version": "0.1.0"},
                "stats": {"files": 3, "future_field": true},
                "components": [{"name": "busybox", "version": "1.36.1-r29", "type": "apk",
                                "file_paths": ["/bin/busybox"], "files_truncated": false,
                                "interpreted_content": false, "extra": 1}],
                "unknown_top_level": {"ignored": true}
            });
            frame(&serde_json::to_vec(&resp).unwrap())
        });
        let cancel = AtomicBool::new(false);
        let resp = exchange(
            ours,
            &[me()],
            &good_peer(),
            &scan_request(),
            Some(root_fd()),
            1 << 20,
            Duration::from_secs(5),
            &cancel,
        )
        .expect("round trip");
        let (req, _, _) = worker.join().unwrap();
        assert_eq!(req["op"], "scan");
        assert_eq!(req["epoch"], 3);
        assert_eq!(
            req["container_start_unix_nanos"],
            1_790_000_000_123_456_789i64
        );
        assert_eq!(req["budgets"]["max_response_bytes"], 1 << 20);
        assert_eq!(resp.status, "ok");
        assert_eq!(resp.scan_id, "scan-1");
        assert_eq!(resp.components[0].file_paths, vec!["/bin/busybox"]);
    }

    #[test]
    fn a_hostile_oversized_response_is_refused_without_reading_it() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let worker = fake_worker(theirs, true, |_, _| {
            // Claims 1 GiB, then sends a few bytes and keeps the socket.
            let mut out = (1u32 << 30).to_be_bytes().to_vec();
            out.extend_from_slice(b"{\"a\":");
            out
        });
        let cancel = AtomicBool::new(false);
        let started = Instant::now();
        let e = exchange(
            ours,
            &[me()],
            &good_peer(),
            &scan_request(),
            Some(root_fd()),
            1 << 20,
            Duration::from_secs(30),
            &cancel,
        )
        .expect_err("oversized");
        assert!(
            matches!(e, WorkerError::Protocol(ref m) if m.contains("outside")),
            "{e}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "refused on the length alone"
        );
        worker.join().unwrap();
    }

    #[test]
    fn a_response_over_the_ceiling_is_refused_even_if_asked_for() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let worker = fake_worker(theirs, true, |_, _| {
            ((MAX_RESPONSE_CEILING + 1) as u32).to_be_bytes().to_vec()
        });
        let e = exchange(
            ours,
            &[me()],
            &good_peer(),
            &scan_request(),
            None,
            usize::MAX,
            Duration::from_secs(5),
            &AtomicBool::new(false),
        )
        .expect_err("over the ceiling");
        assert!(matches!(e, WorkerError::Protocol(_)), "{e}");
        worker.join().unwrap();
    }

    #[test]
    fn a_peer_with_the_wrong_uid_gets_nothing() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let cancel = AtomicBool::new(false);
        let e = exchange(
            ours,
            &[me().wrapping_add(1)],
            &good_peer(),
            &scan_request(),
            Some(root_fd()),
            1 << 20,
            Duration::from_secs(5),
            &cancel,
        )
        .expect_err("uid mismatch");
        assert!(
            matches!(e, WorkerError::PeerRejected(ref m) if m.contains("uid")),
            "{e}"
        );
        // Nothing reached the peer: the socket is closed with no bytes.
        let mut buf = [0u8; 1];
        assert_eq!((&theirs).read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn a_peer_in_another_cgroup_gets_nothing() {
        for peer in [
            FakePeer {
                own: OWN_PRIVATE_NS,
                peer: Ok("0::/../../other-pod/ctr\n"),
            },
            FakePeer {
                own: OWN_PRIVATE_NS,
                peer: Err("cannot pin the peer"),
            },
            // cgroup v1 only: nothing to compare, fail closed.
            FakePeer {
                own: "4:memory:/x\n",
                peer: Ok("4:memory:/y\n"),
            },
        ] {
            let (ours, theirs) = UnixStream::pair().unwrap();
            let e = exchange(
                ours,
                &[me()],
                &peer,
                &scan_request(),
                Some(root_fd()),
                1 << 20,
                Duration::from_secs(5),
                &AtomicBool::new(false),
            )
            .expect_err("cgroup mismatch");
            assert!(matches!(e, WorkerError::PeerRejected(_)), "{e}");
            let mut buf = [0u8; 1];
            assert_eq!((&theirs).read(&mut buf).unwrap(), 0);
        }
    }

    #[test]
    fn a_silent_worker_hits_the_read_deadline_and_cancel_is_prompt() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let worker = fake_worker(theirs, true, |_, _| Vec::new());
        let e = exchange(
            ours,
            &[me()],
            &good_peer(),
            &ping_request("p".into()),
            None,
            1 << 20,
            Duration::from_millis(300),
            &AtomicBool::new(false),
        )
        .expect_err("silent");
        assert!(matches!(e, WorkerError::Timeout), "{e}");
        let (req, got_fd, _) = worker.join().unwrap();
        assert_eq!(req["op"], "ping");
        assert!(!got_fd, "a ping carries no fd");

        let (ours, theirs) = UnixStream::pair().unwrap();
        let _keep = theirs;
        let cancel = Arc::new(AtomicBool::new(false));
        let c2 = Arc::clone(&cancel);
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            c2.store(true, Ordering::Relaxed);
        });
        let started = Instant::now();
        let e = read_frame(
            &ours,
            1024,
            Instant::now() + Duration::from_secs(60),
            &cancel,
        )
        .expect_err("cancelled");
        assert!(matches!(e, WorkerError::Cancelled));
        assert!(started.elapsed() < Duration::from_secs(3));
        t.join().unwrap();
    }

    #[test]
    fn a_truncated_or_malformed_response_is_a_protocol_error() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let worker = fake_worker(theirs, false, |_, _| {
            let mut f = frame(b"{\"protocol_version\":1,\"status\":\"ok\"}");
            f.truncate(10);
            f
        });
        let e = exchange(
            ours,
            &[me()],
            &good_peer(),
            &scan_request(),
            None,
            1 << 20,
            Duration::from_secs(5),
            &AtomicBool::new(false),
        )
        .expect_err("truncated");
        assert!(matches!(e, WorkerError::Protocol(_)), "{e}");
        worker.join().unwrap();

        let (ours, theirs) = UnixStream::pair().unwrap();
        let worker = fake_worker(theirs, true, |_, _| frame(b"[not an object]"));
        let e = exchange(
            ours,
            &[me()],
            &good_peer(),
            &scan_request(),
            None,
            1 << 20,
            Duration::from_secs(5),
            &AtomicBool::new(false),
        )
        .expect_err("malformed");
        assert!(
            matches!(e, WorkerError::Protocol(ref m) if m.contains("JSON")),
            "{e}"
        );
        worker.join().unwrap();
    }

    #[test]
    fn a_missing_socket_is_unavailable() {
        let e = call(
            Path::new("/nonexistent/kguardian/worker.sock"),
            &[0],
            &good_peer(),
            &ping_request("p".into()),
            None,
            1024,
            Duration::from_secs(1),
            &AtomicBool::new(false),
        )
        .expect_err("no socket");
        assert!(matches!(e, WorkerError::Unavailable(_)));
    }

    /// Kernels before 6.5 answer SO_PEERPIDFD with ENOPROTOOPT. Without
    /// hostPID that is a typed, permanent "cannot verify", never a
    /// fallback to SO_PEERCRED's meaningless pid.
    #[test]
    fn without_pidfd_fails_closed_and_names_the_kernel() {
        let old_kernel = io::Error::from_raw_os_error(libc::ENOPROTOOPT);
        match without_pidfd(&old_kernel, false, 0) {
            Err(PeerError::Unsupported(m)) => {
                assert!(m.contains("SO_PEERPIDFD") && m.contains("6.5"), "{m}")
            }
            other => panic!("{other:?}"),
        }
        // A non-zero pid from another namespace is not trusted either.
        assert!(matches!(
            without_pidfd(&old_kernel, false, 4242),
            Err(PeerError::Unsupported(_))
        ));
        // Any other failure rejects this peer only.
        assert!(matches!(
            without_pidfd(&io::Error::from_raw_os_error(libc::EBADF), false, 0),
            Err(PeerError::Rejected(_))
        ));
        // hostPID: SO_PEERCRED's pid is a real, host-procfs pid.
        assert_eq!(without_pidfd(&old_kernel, true, 4242), Ok(4242));
        assert!(without_pidfd(&old_kernel, true, 0).is_err());
    }

    #[test]
    fn an_unverifiable_peer_is_a_typed_error_and_gets_nothing() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let e = exchange(
            ours,
            &[me()],
            &FakePeer {
                own: OWN_PRIVATE_NS,
                peer: Err("unsupported: no SO_PEERPIDFD"),
            },
            &scan_request(),
            Some(root_fd()),
            1 << 20,
            Duration::from_secs(5),
            &AtomicBool::new(false),
        )
        .expect_err("unverifiable");
        assert!(matches!(e, WorkerError::PeerUnsupported(_)), "{e}");
        let mut buf = [0u8; 1];
        assert_eq!((&theirs).read(&mut buf).unwrap(), 0);
    }

    /// The real peer lookups against a real listener in this process:
    /// the peer is ourselves, so it is rejected as the Controller's own
    /// container — which proves the lookups ran and resolved the peer.
    #[test]
    fn host_peer_proc_resolves_a_real_peer() {
        let dir = std::env::temp_dir().join(format!("kg-catalog-peer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("w.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let sock = connect(&path).unwrap();
        let (_server, _) = listener.accept().unwrap();
        let proc = HostPeerProc {
            host_proc: PathBuf::from("/proc"),
        };
        let r = verify_peer(sock.as_raw_fd(), &[me()], &proc);
        // Our own process: rejected as the Controller's own container on
        // a >= 6.5 kernel, or (same pid namespace here) via the fallback.
        match r.expect_err("our own process is not a sibling container") {
            PeerError::Rejected(m) => assert!(m.contains("own container"), "{m}"),
            PeerError::Unsupported(m) => panic!("same pid namespace must fall back: {m}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
