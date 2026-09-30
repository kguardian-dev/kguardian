//! The Controller's half of the cataloger worker protocol
//! (`cataloger/PROTOCOL.md`, v1): connect, verify the peer, send one
//! framed request with the root fd attached, read one framed response.
//!
//! Blocking I/O on purpose: it runs on a `spawn_blocking` thread, with
//! its own deadlines (`poll` in slices, so a cancel flag is noticed
//! within a second), and never on the runtime the capture paths share.
//!
//! ## Peer verification (PROTOCOL.md 1.1)
//!
//! Before every connection, the socket FILE is checked: its directory
//! and the socket are opened `O_PATH|O_NOFOLLOW` and `fstat`ed
//! (directory owned by uid 0, mode 0700; socket owned by uid 0, mode
//! 0600), and the connect goes through `/proc/self/fd/<n>` of that very
//! `O_PATH` fd, so the file checked is the file connected. Only a uid-0
//! process with the shared `emptyDir` mounted can have created it. After
//! connecting, `SO_PEERCRED` uid must be allowed (0).
//!
//! On top of that, chosen once at startup by [`probe_peer_mode`]:
//!
//! * [`PeerMode::Pidfd`] (Linux >= 6.5): `SO_PEERPIDFD` pins the worker
//!   process and its cgroup must be a sibling container of the
//!   Controller's own (same pod).
//! * [`PeerMode::PathCheck`] (older kernels): nothing more. The worker is
//!   in another pid namespace, so without a pidfd its process cannot be
//!   named; the file check above is the binding.
//!
//! ## Memory
//!
//! The response is untrusted and can be large, and an OOM kill of the
//! Controller takes capture down with it, so parsing is lean: the raw
//! frame (at most `max_response_bytes`, 16 MiB by default) is parsed
//! into bounded types ([`Capped`], [`PathList`], [`LeanStats`]) that
//! drop over-long strings without keeping them, validate paths while
//! parsing, and skip anything over their caps; the raw buffer is dropped
//! as soon as parsing ends. Worst case extra memory during a scan is the
//! raw frame plus the parsed components (about 2.5x the frame, for
//! string headers), never both after parsing: 16 MiB + 40 MiB at the
//! default, 64 MiB + 160 MiB at the hard ceiling.

use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

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
/// Components kept from one response (the Broker's `MAX_SBOM_COMPONENTS`).
pub const MAX_COMPONENTS: usize = 50_000;
/// File paths kept per component.
pub const MAX_PATHS: usize = 4096;
/// Longest file path kept (PROTOCOL.md 4.3).
pub const MAX_PATH_LEN: usize = 1024;
/// `partial_reasons` kept from a response.
pub const MAX_REASONS: usize = 16;
/// `stats` entries kept (scalars only).
pub const MAX_STATS_ENTRIES: usize = 64;

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

// ---- Lean response types ------------------------------------------------

/// A string of at most `N` bytes. A longer one is not kept (only the
/// fact that it was too long), and neither is a non-string value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Capped<const N: usize> {
    pub value: Option<String>,
    pub too_long: bool,
}

impl<const N: usize> Capped<N> {
    pub fn new(s: &str) -> Self {
        if s.len() <= N {
            Self {
                value: Some(s.to_string()),
                too_long: false,
            }
        } else {
            Self {
                value: None,
                too_long: true,
            }
        }
    }

    pub fn take(self) -> Option<String> {
        self.value.filter(|s| !s.is_empty())
    }

    pub fn as_str(&self) -> &str {
        self.value.as_deref().unwrap_or("")
    }
}

impl<'de, const N: usize> Deserialize<'de> for Capped<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<const N: usize>;
        impl<'de, const N: usize> Visitor<'de> for V<N> {
            type Value = Capped<N>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a string")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(Capped::new(v))
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(Capped::default())
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(Capped::default())
            }
        }
        d.deserialize_any(V::<N>)
    }
}

/// Up to `N` non-empty strings of at most `L` bytes; the rest skipped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CappedList<const N: usize, const L: usize>(pub Vec<String>);

impl<'de, const N: usize, const L: usize> Deserialize<'de> for CappedList<N, L> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<const N: usize, const L: usize>;
        impl<'de, const N: usize, const L: usize> Visitor<'de> for V<N, L> {
            type Value = CappedList<N, L>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a list of strings")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while let Some(s) = seq.next_element::<Capped<L>>()? {
                    if out.len() < N {
                        out.extend(s.take());
                    }
                }
                Ok(CappedList(out))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(CappedList::default())
            }
        }
        d.deserialize_any(V::<N, L>)
    }
}

/// A component's file paths, validated while parsing (PROTOCOL.md 4.3):
/// invalid or over-long paths are never kept, at most [`MAX_PATHS`] are,
/// and the result is sorted and deduplicated in place. `truncated` says
/// the list is not the package's complete one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathList {
    pub paths: Vec<String>,
    pub truncated: bool,
}

impl<'de> Deserialize<'de> for PathList {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = PathList;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a list of paths")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = PathList::default();
                while let Some(p) = seq.next_element::<Capped<MAX_PATH_LEN>>()? {
                    match p.value {
                        Some(p) if super::post::valid_path(&p) && out.paths.len() < MAX_PATHS => {
                            out.paths.push(p)
                        }
                        _ => out.truncated = true,
                    }
                }
                out.paths.sort_unstable();
                out.paths.dedup();
                Ok(out)
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(PathList::default())
            }
        }
        d.deserialize_any(V)
    }
}

/// `stats`, kept lean: at most [`MAX_STATS_ENTRIES`] scalar entries
/// (numbers, booleans, strings up to 128 bytes) with keys up to 64
/// bytes. Nested objects (`budgets`) and everything else are skipped
/// unparsed.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LeanStats(pub serde_json::Map<String, serde_json::Value>);

/// One stats value: kept when scalar, otherwise skipped.
struct StatValue(Option<serde_json::Value>);

impl<'de> Deserialize<'de> for StatValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = StatValue;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a value")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(StatValue(Some(v.into())))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(StatValue(Some(v.into())))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(StatValue(Some(v.into())))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
                Ok(StatValue(serde_json::Number::from_f64(v).map(Into::into)))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(StatValue((v.len() <= 128).then(|| v.into())))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StatValue(None))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(StatValue(None))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(StatValue(None))
            }
        }
        d.deserialize_any(V)
    }
}

impl<'de> Deserialize<'de> for LeanStats {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = LeanStats;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "an object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut out = serde_json::Map::new();
                while let Some(k) = map.next_key::<Capped<64>>()? {
                    let v = map.next_value::<StatValue>()?;
                    if let (Some(k), Some(v)) = (k.value, v.0) {
                        if out.len() < MAX_STATS_ENTRIES {
                            out.insert(k, v);
                        }
                    }
                }
                Ok(LeanStats(out))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(LeanStats::default())
            }
        }
        d.deserialize_any(V)
    }
}

/// One component as received (PROTOCOL.md 4.3), with every field bounded.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct WireComponent {
    #[serde(default)]
    pub name: Capped<256>,
    #[serde(default)]
    pub version: Capped<128>,
    #[serde(default)]
    pub purl: Capped<2048>,
    #[serde(default, rename = "type")]
    pub comp_type: Capped<128>,
    #[serde(default)]
    pub class: Capped<64>,
    #[serde(default)]
    pub src_name: Capped<256>,
    #[serde(default)]
    pub src_version: Capped<128>,
    #[serde(default)]
    pub licenses: CappedList<8, 256>,
    #[serde(default)]
    pub file_paths: PathList,
    #[serde(default)]
    pub files_truncated: bool,
    #[serde(default)]
    pub interpreted_content: bool,
}

/// The component list: at most [`MAX_COMPONENTS`] kept; `overflow` says
/// there were more (the rest are skipped unparsed).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Components {
    pub items: Vec<WireComponent>,
    pub overflow: bool,
}

impl<'de> Deserialize<'de> for Components {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Components;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a list of components")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = Components::default();
                loop {
                    if out.items.len() < MAX_COMPONENTS {
                        match seq.next_element::<WireComponent>()? {
                            Some(c) => out.items.push(c),
                            None => break,
                        }
                    } else {
                        match seq.next_element::<IgnoredAny>()? {
                            Some(_) => out.overflow = true,
                            None => break,
                        }
                    }
                }
                Ok(out)
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(Components::default())
            }
        }
        d.deserialize_any(V)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct WireScanner {
    #[serde(default)]
    pub vendor: Capped<256>,
    #[serde(default)]
    pub version: Capped<128>,
}

/// A response as received; [`super::post::validate`] turns it into what
/// is posted. Unknown fields are ignored, and skipped without being kept
/// (PROTOCOL.md 4.3, 5).
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct Response {
    pub protocol_version: i64,
    #[serde(default)]
    pub scan_id: Capped<128>,
    #[serde(default)]
    pub epoch: i64,
    #[serde(default)]
    pub status: Capped<16>,
    #[serde(default)]
    pub reason: Capped<64>,
    #[serde(default)]
    pub message: Capped<1024>,
    #[serde(default)]
    pub completeness: Capped<16>,
    #[serde(default)]
    pub partial_reasons: CappedList<MAX_REASONS, 64>,
    #[serde(default)]
    pub retry_reason: Capped<64>,
    #[serde(default)]
    pub scanner: WireScanner,
    #[serde(default)]
    pub stats: LeanStats,
    #[serde(default)]
    pub components: Components,
}

// ---- Errors ---------------------------------------------------------------

/// Why a hand-off produced no response.
#[derive(Debug)]
pub enum WorkerError {
    /// No worker listening, or the connect timed out.
    Unavailable(io::Error),
    /// The peer (or, in [`PeerMode::PathCheck`], the socket file) is not
    /// the cataloger sidecar's. Nothing was sent.
    PeerRejected(String),
    /// A framing or deadline violation by the peer, or I/O failing
    /// mid-exchange. The connection is closed (which cancels the scan).
    Protocol(String),
    /// The read deadline passed.
    Timeout,
    /// The caller cancelled (lost lease). The connection is closed.
    Cancelled,
}

impl fmt::Display for WorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WorkerError::Unavailable(e) => write!(f, "worker unavailable: {e}"),
            WorkerError::PeerRejected(m) => write!(f, "worker peer rejected: {m}"),
            WorkerError::Protocol(m) => write!(f, "worker protocol error: {m}"),
            WorkerError::Timeout => write!(f, "worker did not answer before the deadline"),
            WorkerError::Cancelled => write!(f, "scan cancelled"),
        }
    }
}

// ---- Peer verification ----------------------------------------------------

/// What is checked beyond the socket file and the uid (see module
/// docs). Decided once, at startup, by [`probe_peer_mode`]; never changed
/// at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerMode {
    Pidfd,
    PathCheck,
}

impl PeerMode {
    pub fn as_str(self) -> &'static str {
        match self {
            PeerMode::Pidfd => "pidfd",
            PeerMode::PathCheck => "path_check",
        }
    }
}

/// The mode for a `getsockopt(SO_PEERPIDFD)` probe's result. Only
/// `ENOPROTOOPT` (a kernel without the option, < 6.5) selects the path
/// check; any other error still means the kernel knows the option.
pub fn peer_mode_from(probe: Result<(), i32>) -> PeerMode {
    match probe {
        Err(e) if e == libc::ENOPROTOOPT => PeerMode::PathCheck,
        _ => PeerMode::Pidfd,
    }
}

/// Probe `SO_PEERPIDFD` on a local socketpair.
pub fn probe_peer_mode() -> PeerMode {
    let probe = UnixStream::pair()
        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
        .and_then(|(a, _b)| {
            peer_pidfd(a.as_raw_fd())
                .map(drop)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
        });
    peer_mode_from(probe)
}

/// Why a peer was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerError(pub String);

impl From<String> for PeerError {
    fn from(m: String) -> Self {
        PeerError(m)
    }
}

impl From<&str> for PeerError {
    fn from(m: &str) -> Self {
        PeerError(m.to_string())
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

/// How to find the peer's cgroup ([`PeerMode::Pidfd`]).
pub trait PeerProc {
    /// The Controller's own cgroup body.
    fn own_cgroup(&self) -> io::Result<String>;
    /// The peer's cgroup body, pid-reuse safe.
    fn peer_cgroup(&self, sock: RawFd) -> Result<String, PeerError>;
}

/// The real lookups, through the host procfs.
pub struct HostPeerProc {
    pub host_proc: PathBuf,
}

impl PeerProc for HostPeerProc {
    fn own_cgroup(&self) -> io::Result<String> {
        std::fs::read_to_string(self.host_proc.join("self/cgroup"))
    }

    fn peer_cgroup(&self, sock: RawFd) -> Result<String, PeerError> {
        // The worker is in another pid namespace (its own container), so
        // SO_PEERCRED's pid is 0 here. SO_PEERPIDFD pins the peer, and
        // its fdinfo, read through the host procfs, names it in the host
        // namespace. Re-reading the pid after the cgroup proves the
        // process the cgroup belonged to was alive throughout. Any error
        // (EINVAL, ENODATA, ...) rejects this peer only: the mode was
        // decided at startup and does not change.
        let pidfd = peer_pidfd(sock).map_err(|e| format!("SO_PEERPIDFD: {e}"))?;
        let info = self
            .host_proc
            .join(format!("self/fdinfo/{}", pidfd.as_raw_fd()));
        let pid = || {
            std::fs::read_to_string(&info)
                .ok()
                .and_then(|b| fdinfo_pid(&b))
                .filter(|p| *p > 0)
        };
        let before = pid().ok_or("peer pidfd names no live process")?;
        let cg = std::fs::read_to_string(self.host_proc.join(format!("{before}/cgroup")))
            .map_err(|e| format!("peer cgroup: {e}"))?;
        if pid() != Some(before) {
            return Err("peer exited while being verified".into());
        }
        Ok(cg)
    }
}

fn check_uid(sock: RawFd, allowed_uids: &[u32]) -> Result<(), PeerError> {
    let cred = peer_cred(sock).map_err(|e| format!("SO_PEERCRED: {e}"))?;
    if !allowed_uids.contains(&cred.uid) {
        return Err(format!("peer uid {} is not allowed", cred.uid).into());
    }
    Ok(())
}

/// [`PeerMode::Pidfd`]: `SO_PEERCRED` uid in the allowed set, and the
/// peer a sibling container of this pod. Fails closed.
pub fn verify_peer<P: PeerProc>(
    sock: RawFd,
    allowed_uids: &[u32],
    proc: &P,
) -> Result<(), PeerError> {
    check_uid(sock, allowed_uids)?;
    let own = proc.own_cgroup().map_err(|e| format!("own cgroup: {e}"))?;
    let peer = proc.peer_cgroup(sock)?;
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

fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    // SAFETY: zeroed stat is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid fd and out-pointer.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

fn open_path(dir: RawFd, name: &std::ffi::CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: valid dirfd and NUL-terminated name.
    let fd = unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            flags | libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a new fd from the kernel.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Why the socket file failed [`connect_checked`].
#[derive(Debug)]
pub enum PathCheckError {
    /// Nothing there (the worker has not created it yet).
    Missing(io::Error),
    /// There, but not the worker's.
    Bad(String),
}

/// The mode/owner rule: a `kind` (`S_IFDIR`/`S_IFSOCK`) owned by `owner`
/// with exactly `mode` permission bits (no setuid/setgid/sticky).
pub fn check_mode(
    what: &str,
    st: &libc::stat,
    kind: libc::mode_t,
    owner: u32,
    mode: libc::mode_t,
) -> Result<(), String> {
    if st.st_mode & libc::S_IFMT != kind {
        return Err(format!(
            "{what} is not a {}",
            if kind == libc::S_IFDIR {
                "directory"
            } else {
                "socket"
            }
        ));
    }
    if st.st_uid != owner {
        return Err(format!("{what} is owned by uid {}, not {owner}", st.st_uid));
    }
    if st.st_mode & 0o7777 != mode {
        return Err(format!(
            "{what} has mode {:04o}, not {mode:04o}",
            st.st_mode & 0o7777
        ));
    }
    Ok(())
}

/// PROTOCOL.md 1.1 steps 1 and 2: open the socket's directory and the socket
/// `O_PATH|O_NOFOLLOW`, check both (directory uid `owner` mode 0700,
/// socket uid `owner` mode 0600), and connect through
/// `/proc/self/fd/<socket fd>`, so the file checked is the file
/// connected: a rename or symlink swap after the check cannot redirect
/// the connect.
pub fn connect_checked(path: &Path, owner: u32) -> Result<UnixStream, PathCheckError> {
    use std::os::unix::ffi::OsStrExt;
    let bad = |m: String| PathCheckError::Bad(m);
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(bad(format!("{} names no file", path.display())));
    };
    let c = |b: &[u8]| {
        std::ffi::CString::new(b).map_err(|_| PathCheckError::Bad("path with a NUL".into()))
    };
    let dirfd = open_path(
        libc::AT_FDCWD,
        &c(dir.as_os_str().as_bytes())?,
        libc::O_DIRECTORY,
    )
    .map_err(|e| match e.raw_os_error() {
        Some(libc::ENOENT) => PathCheckError::Missing(e),
        _ => bad(format!("socket directory {}: {e}", dir.display())),
    })?;
    let st = fstat(dirfd.as_raw_fd()).map_err(|e| bad(format!("fstat directory: {e}")))?;
    check_mode("socket directory", &st, libc::S_IFDIR, owner, 0o700).map_err(bad)?;
    let sock = open_path(dirfd.as_raw_fd(), &c(name.as_bytes())?, 0).map_err(|e| {
        match e.raw_os_error() {
            Some(libc::ENOENT) => PathCheckError::Missing(e),
            _ => bad(format!("socket {}: {e}", path.display())),
        }
    })?;
    let st = fstat(sock.as_raw_fd()).map_err(|e| bad(format!("fstat socket: {e}")))?;
    check_mode("socket", &st, libc::S_IFSOCK, owner, 0o600).map_err(bad)?;
    let via = PathBuf::from(format!("/proc/self/fd/{}", sock.as_raw_fd()));
    connect(&via).map_err(|e| match e.raw_os_error() {
        Some(libc::ECONNREFUSED) | Some(libc::ENOENT) => PathCheckError::Missing(e),
        _ => bad(format!("connect: {e}")),
    })
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

/// Parse a response frame into the lean types, consuming (and so
/// freeing) the raw buffer.
pub fn parse_response(body: Vec<u8>) -> Result<Response, WorkerError> {
    let r = serde_json::from_slice(&body)
        .map_err(|e| WorkerError::Protocol(format!("response JSON: {e}")));
    drop(body);
    r
}

/// Limits for one exchange.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub response_bytes: usize,
    pub read_timeout: Duration,
}

/// One exchange on an already-connected, not-yet-verified socket: run
/// `verify`, send, close our copy of the fd, read and parse the answer.
pub fn exchange(
    sock: UnixStream,
    verify: impl FnOnce(RawFd) -> Result<(), PeerError>,
    req: &Request,
    root: Option<OwnedFd>,
    limits: Limits,
    cancel: &AtomicBool,
) -> Result<Response, WorkerError> {
    // The fd is not sent to a peer that fails verification; dropping
    // `root` on that path closes it.
    verify(sock.as_raw_fd()).map_err(|e| WorkerError::PeerRejected(e.0))?;
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
    let limit = limits.response_bytes.min(MAX_RESPONSE_CEILING);
    let body = read_frame(&sock, limit, Instant::now() + limits.read_timeout, cancel)?;
    // One request, one response, no reuse: close before parsing.
    drop(sock);
    parse_response(body)
}

/// Everything [`call`] needs to find and verify the worker.
pub struct PeerPolicy {
    pub mode: PeerMode,
    pub allowed_uids: Vec<u32>,
    /// Owner the socket file and its directory must have; 0 in
    /// production.
    pub socket_owner: u32,
    pub host_proc: PathBuf,
}

/// Check the socket file, connect through it, verify the peer (uid, and
/// the cgroup in [`PeerMode::Pidfd`]), and [`exchange`].
pub fn call(
    path: &Path,
    policy: &PeerPolicy,
    req: &Request,
    root: Option<OwnedFd>,
    limits: Limits,
    cancel: &AtomicBool,
) -> Result<Response, WorkerError> {
    let sock = connect_checked(path, policy.socket_owner).map_err(|e| match e {
        PathCheckError::Missing(e) => WorkerError::Unavailable(e),
        PathCheckError::Bad(m) => WorkerError::PeerRejected(m),
    })?;
    let proc = HostPeerProc {
        host_proc: policy.host_proc.clone(),
    };
    exchange(
        sock,
        |fd| match policy.mode {
            PeerMode::Pidfd => verify_peer(fd, &policy.allowed_uids, &proc),
            PeerMode::PathCheck => check_uid(fd, &policy.allowed_uids),
        },
        req,
        root,
        limits,
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
pub(crate) mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
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
        fn peer_cgroup(&self, _: RawFd) -> Result<String, PeerError> {
            self.peer.map(str::to_string).map_err(PeerError::from)
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
    pub(crate) fn me() -> u32 {
        unsafe { libc::getuid() }
    }

    fn limits(bytes: usize, secs: u64) -> Limits {
        Limits {
            response_bytes: bytes,
            read_timeout: Duration::from_secs(secs),
        }
    }

    fn verify_good(fd: RawFd) -> Result<(), PeerError> {
        verify_peer(fd, &[me()], &good_peer())
    }

    #[test]
    fn siblings_in_a_private_cgroup_namespace_are_the_same_pod() {
        assert!(same_pod_sibling("/", "/../cri-containerd-bbbb.scope").is_ok());
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

    /// Only ENOPROTOOPT means "no SO_PEERPIDFD"; everything else keeps the
    /// pidfd check (a runtime error then rejects one peer, never degrades).
    #[test]
    fn the_peer_mode_is_path_check_only_for_enoprotoopt() {
        assert_eq!(peer_mode_from(Ok(())), PeerMode::Pidfd);
        assert_eq!(peer_mode_from(Err(libc::ENOPROTOOPT)), PeerMode::PathCheck);
        for e in [libc::EINVAL, libc::ENODATA, libc::EBADF] {
            assert_eq!(peer_mode_from(Err(e)), PeerMode::Pidfd, "errno {e}");
        }
        // This kernel answers one way or the other without panicking.
        let _ = probe_peer_mode();
    }

    /// A fake worker on the other end of a stream: reads one framed
    /// request with its fd, checks it, and answers with `reply`.
    pub(crate) fn fake_worker(
        theirs: UnixStream,
        hold: bool,
        reply: impl FnOnce(&serde_json::Value, bool) -> Vec<u8> + Send + 'static,
    ) -> std::thread::JoinHandle<(serde_json::Value, bool, Option<UnixStream>)> {
        std::thread::spawn(move || serve_one(theirs, hold, reply))
    }

    pub(crate) fn serve_one(
        theirs: UnixStream,
        hold: bool,
        reply: impl FnOnce(&serde_json::Value, bool) -> Vec<u8>,
    ) -> (serde_json::Value, bool, Option<UnixStream>) {
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
        (req, got_fd, hold.then_some(theirs))
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
                "stats": {"files": 3, "future_field": true, "budgets": {"max_files": 1}},
                "components": [{"name": "busybox", "version": "1.36.1-r29", "type": "apk",
                                "file_paths": ["/bin/busybox"], "files_truncated": false,
                                "interpreted_content": false, "extra": 1}],
                "unknown_top_level": {"ignored": true}
            });
            frame(&serde_json::to_vec(&resp).unwrap())
        });
        let resp = exchange(
            ours,
            verify_good,
            &scan_request(),
            Some(root_fd()),
            limits(1 << 20, 5),
            &AtomicBool::new(false),
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
        assert_eq!(resp.status.as_str(), "ok");
        assert_eq!(resp.scan_id.as_str(), "scan-1");
        assert_eq!(
            resp.components.items[0].file_paths.paths,
            vec!["/bin/busybox"]
        );
        // Lean stats: scalars kept, the nested object skipped.
        assert_eq!(resp.stats.0["files"], 3);
        assert!(resp.stats.0.get("budgets").is_none());
    }

    /// The lean types never keep what they would drop: over-long strings,
    /// invalid paths, components past the cap, nested stats.
    #[test]
    fn lean_parsing_bounds_everything() {
        let long = "x".repeat(5000);
        let body = serde_json::json!({
            "protocol_version": 1, "scan_id": "s", "status": "ok",
            "message": long, "reason": long,
            "partial_reasons": (0..40).map(|i| format!("r{i}")).collect::<Vec<_>>(),
            "stats": {"a": 1, "big": long, "deep": {"x": [1, 2, 3]}},
            "components": [{
                "name": "p", "purl": long, "licenses": (0..20).map(|i| format!("L{i}")).collect::<Vec<_>>(),
                "file_paths": ["/b", "/a", "/a", "rel", "/x/../y", format!("/{long}"), "/ctl\u{1}char"]
            }]
        });
        let r = parse_response(serde_json::to_vec(&body).unwrap()).unwrap();
        assert!(r.message.too_long && r.message.value.is_none());
        assert_eq!(r.partial_reasons.0.len(), MAX_REASONS);
        assert_eq!(r.stats.0.len(), 1);
        let c = &r.components.items[0];
        assert!(c.purl.too_long);
        assert_eq!(c.licenses.0.len(), 8);
        assert_eq!(c.file_paths.paths, vec!["/a", "/b"]);
        assert!(c.file_paths.truncated);

        let many = serde_json::json!({
            "protocol_version": 1, "status": "ok",
            "components": (0..(MAX_COMPONENTS + 3)).map(|_| serde_json::json!({"name": "n"})).collect::<Vec<_>>()
        });
        let r = parse_response(serde_json::to_vec(&many).unwrap()).unwrap();
        assert_eq!(r.components.items.len(), MAX_COMPONENTS);
        assert!(r.components.overflow);
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
        let started = Instant::now();
        let e = exchange(
            ours,
            verify_good,
            &scan_request(),
            Some(root_fd()),
            limits(1 << 20, 30),
            &AtomicBool::new(false),
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
            verify_good,
            &scan_request(),
            None,
            limits(usize::MAX, 5),
            &AtomicBool::new(false),
        )
        .expect_err("over the ceiling");
        assert!(matches!(e, WorkerError::Protocol(_)), "{e}");
        worker.join().unwrap();
    }

    #[test]
    fn a_peer_with_the_wrong_uid_gets_nothing() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let e = exchange(
            ours,
            |fd| verify_peer(fd, &[me().wrapping_add(1)], &good_peer()),
            &scan_request(),
            Some(root_fd()),
            limits(1 << 20, 5),
            &AtomicBool::new(false),
        )
        .expect_err("uid mismatch");
        assert!(
            matches!(e, WorkerError::PeerRejected(ref m) if m.contains("uid")),
            "{e}"
        );
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
                peer: Err("SO_PEERPIDFD: Invalid argument"),
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
                |fd| verify_peer(fd, &[me()], &peer),
                &scan_request(),
                Some(root_fd()),
                limits(1 << 20, 5),
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
            verify_good,
            &ping_request("p".into()),
            None,
            Limits {
                response_bytes: 1 << 20,
                read_timeout: Duration::from_millis(300),
            },
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
            verify_good,
            &scan_request(),
            None,
            limits(1 << 20, 5),
            &AtomicBool::new(false),
        )
        .expect_err("truncated");
        assert!(matches!(e, WorkerError::Protocol(_)), "{e}");
        worker.join().unwrap();

        let (ours, theirs) = UnixStream::pair().unwrap();
        let worker = fake_worker(theirs, true, |_, _| frame(b"[not an object]"));
        let e = exchange(
            ours,
            verify_good,
            &scan_request(),
            None,
            limits(1 << 20, 5),
            &AtomicBool::new(false),
        )
        .expect_err("malformed");
        assert!(
            matches!(e, WorkerError::Protocol(ref m) if m.contains("JSON")),
            "{e}"
        );
        worker.join().unwrap();
    }

    fn policy(mode: PeerMode) -> PeerPolicy {
        PeerPolicy {
            mode,
            allowed_uids: vec![me()],
            socket_owner: me(),
            host_proc: PathBuf::from("/proc"),
        }
    }

    #[test]
    fn a_missing_socket_is_unavailable_in_both_modes() {
        for mode in [PeerMode::Pidfd, PeerMode::PathCheck] {
            let e = call(
                Path::new("/nonexistent/kguardian/worker.sock"),
                &policy(mode),
                &ping_request("p".into()),
                None,
                limits(1024, 1),
                &AtomicBool::new(false),
            )
            .expect_err("no socket");
            assert!(matches!(e, WorkerError::Unavailable(_)), "{mode:?}: {e}");
        }
    }

    /// The real pidfd lookups against a real listener in this process:
    /// the peer is ourselves, so it is rejected as the Controller's own
    /// container, which proves the lookups ran and resolved the peer.
    #[test]
    fn host_peer_proc_resolves_a_real_peer() {
        if probe_peer_mode() != PeerMode::Pidfd {
            return; // < 6.5: covered by the path-check tests.
        }
        let dir = tmp_dir("peer");
        let path = dir.join("w.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let sock = connect(&path).unwrap();
        let (_server, _) = listener.accept().unwrap();
        let proc = HostPeerProc {
            host_proc: PathBuf::from("/proc"),
        };
        let err = verify_peer(sock.as_raw_fd(), &[me()], &proc)
            .expect_err("our own process is not a sibling container");
        assert!(err.0.contains("own container"), "{}", err.0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    pub(crate) fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "kg-cat-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A worker socket laid out as the path check requires: directory
    /// 0700, socket 0600, both owned by us. Returns (dir, socket path,
    /// listener).
    pub(crate) fn worker_socket(tag: &str) -> (PathBuf, PathBuf, std::os::unix::net::UnixListener) {
        let dir = tmp_dir(tag).join("catalog");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("worker.sock");
        let l = std::os::unix::net::UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        (dir, path, l)
    }

    fn reply_ok(req: &serde_json::Value, _: bool) -> Vec<u8> {
        frame(
            &serde_json::to_vec(&serde_json::json!({
                "protocol_version": 1, "scan_id": req["scan_id"], "status": "ok"
            }))
            .unwrap(),
        )
    }

    /// Below 6.5: the checked socket file is the connected one, and the
    /// exchange goes through with the uid check.
    #[test]
    fn path_check_connects_through_the_checked_fd() {
        let (dir, path, l) = worker_socket("pc-ok");
        let t = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            serve_one(s, false, reply_ok)
        });
        let r = call(
            &path,
            &policy(PeerMode::PathCheck),
            &ping_request("p1".into()),
            None,
            limits(1024, 5),
            &AtomicBool::new(false),
        )
        .expect("path check");
        assert_eq!(r.scan_id.as_str(), "p1");
        t.join().unwrap();
        std::fs::remove_dir_all(dir.parent().unwrap()).unwrap();
    }

    #[test]
    fn path_check_refuses_loose_modes_symlinks_and_non_sockets() {
        let check = |p: &Path| connect_checked(p, me());
        // Directory too open.
        let (dir, path, _l) = worker_socket("pc-dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(matches!(check(&path), Err(PathCheckError::Bad(m)) if m.contains("0750")));
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Socket too open.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
        assert!(matches!(check(&path), Err(PathCheckError::Bad(m)) if m.contains("0660")));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(check(&path).is_ok());
        // A symlink in place of the socket is not followed.
        let link = dir.join("link.sock");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(matches!(check(&link), Err(PathCheckError::Bad(m)) if m.contains("not a socket")));
        // A regular file is not a socket.
        let file = dir.join("file.sock");
        std::fs::write(&file, b"").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(check(&file), Err(PathCheckError::Bad(_))));
        // A symlinked directory is not followed.
        let base = dir.parent().unwrap();
        let dlink = base.join("dirlink");
        std::os::unix::fs::symlink(&dir, &dlink).unwrap();
        assert!(matches!(
            check(&dlink.join("worker.sock")),
            Err(PathCheckError::Bad(_))
        ));
        // The wrong owner.
        assert!(matches!(
            connect_checked(&path, me().wrapping_add(1)),
            Err(PathCheckError::Bad(m)) if m.contains("owned by")
        ));
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn check_mode_rejects_special_bits() {
        // SAFETY: zeroed stat is valid.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        st.st_mode = libc::S_IFDIR | 0o1700;
        st.st_uid = 0;
        assert!(check_mode("d", &st, libc::S_IFDIR, 0, 0o700).is_err());
        st.st_mode = libc::S_IFDIR | 0o700;
        assert!(check_mode("d", &st, libc::S_IFDIR, 0, 0o700).is_ok());
    }

    #[test]
    fn path_check_still_checks_the_peer_uid() {
        let (dir, path, l) = worker_socket("pc-uid");
        let t = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let mut b = [0u8; 1];
            (&s).read(&mut b).unwrap()
        });
        let mut p = policy(PeerMode::PathCheck);
        p.allowed_uids = vec![me().wrapping_add(1)];
        let e = call(
            &path,
            &p,
            &ping_request("p".into()),
            Some(root_fd()),
            limits(1024, 5),
            &AtomicBool::new(false),
        )
        .expect_err("uid");
        assert!(
            matches!(e, WorkerError::PeerRejected(ref m) if m.contains("uid")),
            "{e}"
        );
        assert_eq!(t.join().unwrap(), 0, "nothing was sent");
        std::fs::remove_dir_all(dir.parent().unwrap()).unwrap();
    }
}
