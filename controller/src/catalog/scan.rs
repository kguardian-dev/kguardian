//! One grant's scan: pick a running container with the granted digest,
//! prove it is that container and that its root is its own snapshot,
//! check the snapshot for runtime drift, and hand the root to the worker.
//!
//! [`NodeScanner`] is written against [`Runtime`] (containerd) and a
//! procfs path, so it runs end to end in tests against a fake procfs
//! tree and a fake worker socket.

use std::os::fd::{AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tracing::{debug, error, info, warn};

use super::api::FailReason;
use super::claim::{Scan, ScanResult};
use super::feed::RunningContainer;
use super::mountinfo::{self, Upperdir};
use super::post;
use super::root::{self, AcquireError, Drift, ProcDir};
use super::worker::{self, PeerPolicy};

/// Candidates (replicas) tried for one grant before reporting drift or
/// pid_gone (the Broker caps retries per node; this bounds local work).
pub const MAX_CANDIDATES: usize = 3;

/// What containerd says about a container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The task's host pid; `None` when it has no running task.
    pub pid: Option<u32>,
    /// The `upperdir=` of its snapshot's mounts (`Snapshots.Mounts` on the
    /// container's snapshotter and key). `Ok(None)`: the snapshot has no
    /// upperdir. `Err`: containerd could not say.
    pub upperdir: Result<Option<String>, String>,
}

/// The container runtime, as the scan needs it.
pub trait Runtime: Send + Sync {
    fn resolve(&self, container_id: &str) -> impl std::future::Future<Output = Resolved> + Send;
}

/// containerd over its socket, with the existing connect and RPC bounds.
pub struct Containerd;

/// A host path compared the way the kernel stores it: trailing slashes
/// dropped (`/a/fs/` and `/a/fs` are one directory). Nothing else is
/// rewritten; any other difference is a mismatch.
pub fn normalise_upper(p: &str) -> &str {
    let t = p.trim_end_matches('/');
    if t.is_empty() {
        "/"
    } else {
        t
    }
}

/// The `upperdir=` option of a `Snapshots.Mounts` reply.
///
/// containerd v2.2's overlay snapshotter (`plugins/snapshots/overlay/
/// overlay.go`, `(*snapshotter).mounts`) answers an active snapshot with
/// one mount `{Type: "overlay", Source: "overlay", Options: [...]}`
/// whose options are `workdir=<root>/snapshots/<id>/work`,
/// `upperdir=<root>/snapshots/<id>/fs` and `lowerdir=<parents joined by
/// ':'>`, followed by the snapshotter's own options (`index=off`,
/// `userxattr`, ...); `<root>` is
/// `/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs` by
/// default and the paths come from `filepath.Join`, so they are clean.
/// The upperdir is found by prefix among any other options, so their
/// order and extra entries (idmap `uidmap=`/`gidmap=`) do not matter.
/// Two different upperdirs are ambiguous: `None`, which the caller
/// treats as a mismatch.
pub fn upperdir_option(mounts: &[containerd_client::types::Mount]) -> Option<String> {
    let mut found: Option<&str> = None;
    for o in mounts.iter().flat_map(|m| m.options.iter()) {
        if let Some(v) = o.strip_prefix("upperdir=") {
            let v = normalise_upper(v);
            match found {
                Some(f) if f != v => return None,
                _ => found = Some(v),
            }
        }
    }
    found.map(str::to_string)
}

impl Runtime for Containerd {
    async fn resolve(&self, container_id: &str) -> Resolved {
        use containerd_client::services::v1::snapshots::{
            snapshots_client::SnapshotsClient, MountsRequest,
        };
        use containerd_client::services::v1::{
            containers_client::ContainersClient, GetContainerRequest,
        };
        use containerd_client::tonic::Request;
        use containerd_client::with_namespace;

        let unknown = |m: &str| Resolved {
            pid: None,
            upperdir: Err(m.to_string()),
        };
        let Some(channel) = crate::container::connect_containerd(
            &crate::container::containerd_sock(),
            crate::container::CONNECT_TIMEOUT,
        )
        .await
        else {
            return unknown("containerd unreachable");
        };
        let pid = crate::PodInspect {
            container_id: Some(container_id.to_string()),
            ..Default::default()
        }
        .get_pid(channel.clone())
        .await
        .pid;
        if pid.is_none() {
            return Resolved {
                pid,
                upperdir: Ok(None),
            };
        }
        let timeout = crate::container::RPC_TIMEOUT;
        let req = with_namespace!(
            GetContainerRequest {
                id: container_id.to_string()
            },
            "k8s.io"
        );
        let container =
            match tokio::time::timeout(timeout, ContainersClient::new(channel.clone()).get(req))
                .await
            {
                Ok(Ok(r)) => r.into_inner().container,
                Ok(Err(e)) => {
                    return Resolved {
                        pid,
                        upperdir: Err(format!("Containers.Get: {e}")),
                    }
                }
                Err(_) => {
                    return Resolved {
                        pid,
                        upperdir: Err("Containers.Get timed out".into()),
                    }
                }
            };
        let Some(c) = container else {
            return Resolved {
                pid,
                upperdir: Err("no such container".into()),
            };
        };
        let req = with_namespace!(
            MountsRequest {
                snapshotter: c.snapshotter,
                key: c.snapshot_key,
            },
            "k8s.io"
        );
        let upperdir =
            match tokio::time::timeout(timeout, SnapshotsClient::new(channel).mounts(req)).await {
                Ok(Ok(r)) => Ok(upperdir_option(&r.into_inner().mounts)),
                Ok(Err(e)) => Err(format!("Snapshots.Mounts: {e}")),
                Err(_) => Err("Snapshots.Mounts timed out".into()),
            };
        Resolved { pid, upperdir }
    }
}

/// What a scan needs besides the candidates.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub host_proc: PathBuf,
    pub socket: PathBuf,
    pub epoch: i64,
    pub ro_clone: bool,
    pub budgets: worker::Budgets,
    pub read_timeout: std::time::Duration,
    pub platform: String,
    /// The Controller can read `trusted.*` xattrs (CAP_SYS_ADMIN in its
    /// effective set). Without it, `trusted.overlay.opaque` reads answer
    /// ENODATA silently, so an opaque directory could not be seen: drift
    /// is then unknown and every SBOM is `partial`.
    pub trusted_xattrs: bool,
}

/// One grant's scan over this node's candidates for the digest.
pub struct NodeScanner<R: Runtime> {
    pub config: ScanConfig,
    pub policy: Arc<PeerPolicy>,
    pub runtime: Arc<R>,
    pub candidates: Vec<RunningContainer>,
}

/// One candidate's result.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // one per candidate, moved once
pub enum Attempt {
    Done(ScanResult),
    Drift(String),
    PidGone(String),
}

fn failed(reason: FailReason, detail: impl Into<String>) -> Attempt {
    Attempt::Done(ScanResult::Failed {
        reason,
        detail: detail.into(),
    })
}

/// Why the root could not be tied to the container's snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotCheck {
    /// It is not the container's snapshot: report this.
    Refuse(FailReason, String),
    /// containerd could not say (unreachable, error, timeout). A fact
    /// about this node right now, not about the image: the next replica
    /// is tried, and if none works the grant ends `pid_gone`.
    Unknown(String),
}

/// Tie the root fd to the container's own snapshot (M3): the fd is on
/// the `/` mount mountinfo names, and that overlay's upperdir is the one
/// containerd has for the container's snapshot.
pub fn check_snapshot(
    root: &OwnedFd,
    info: &mountinfo::RootInfo,
    snapshot: &Result<Option<String>, String>,
) -> Result<(), SnapshotCheck> {
    let refuse = |r: FailReason, d: String| Err(SnapshotCheck::Refuse(r, d));
    match root::mount_id(root.as_raw_fd()) {
        Ok(Some(id)) if id == info.mount_id => {}
        Ok(Some(id)) => {
            return refuse(
                FailReason::UnsupportedRootfs,
                format!(
                    "root fd is on mount {id}, not the / mount {}",
                    info.mount_id
                ),
            )
        }
        Ok(None) => {
            return refuse(
                FailReason::KernelUnsupported,
                "statx gives no STATX_MNT_ID (Linux < 5.8)".into(),
            )
        }
        Err(e) => return refuse(FailReason::Error, format!("statx root: {e}")),
    }
    let Upperdir::Path(up) = &info.upperdir else {
        // Unparseable: drift unknown, the SBOM is partial (final review 2).
        return Ok(());
    };
    match snapshot {
        Ok(Some(s)) if normalise_upper(s) == normalise_upper(up) => Ok(()),
        Ok(Some(s)) => refuse(
            FailReason::UnsupportedRootfs,
            format!("root upperdir {up} is not the container snapshot's {s}"),
        ),
        Ok(None) => refuse(
            FailReason::UnsupportedRootfs,
            "the container's snapshot has no single upperdir".into(),
        ),
        Err(e) => Err(SnapshotCheck::Unknown(format!("containerd: {e}"))),
    }
}

/// Everything blocking for one candidate, on a `spawn_blocking` thread.
pub fn scan_one(
    cfg: &ScanConfig,
    policy: &PeerPolicy,
    c: &RunningContainer,
    pid: u32,
    snapshot_upperdir: &Result<Option<String>, String>,
    cancel: &AtomicBool,
) -> Attempt {
    let dir = match ProcDir::open(&cfg.host_proc, pid) {
        Ok(d) => d,
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT) | Some(libc::ESRCH)) => {
            return Attempt::PidGone(format!("pid {pid} gone"))
        }
        Err(e) => return failed(FailReason::Error, format!("open /proc/{pid}: {e}")),
    };
    let want = root::Expected {
        pod_uid: c.pod_uid.clone(),
        container_id: c.container_id.clone(),
    };
    let acq = match root::acquire(&dir, &want) {
        Ok(a) => a,
        Err(AcquireError::PidGone(why)) => return Attempt::PidGone(why.to_string()),
        Err(AcquireError::Io(e)) => return failed(FailReason::Error, format!("acquire: {e}")),
    };
    let info = match mountinfo::root_info(&mountinfo::parse(&acq.mountinfo)) {
        Ok(i) => i,
        Err(r @ mountinfo::RootRefusal::LazySnapshotter) => {
            return failed(FailReason::LazySnapshotter, r.reason())
        }
        Err(r @ mountinfo::RootRefusal::UnsupportedRootfs) => {
            return failed(FailReason::UnsupportedRootfs, r.reason())
        }
    };
    match check_snapshot(&acq.root, &info, snapshot_upperdir) {
        Ok(()) => {}
        Err(SnapshotCheck::Refuse(reason, detail)) => return failed(reason, detail),
        Err(SnapshotCheck::Unknown(why)) => {
            return Attempt::PidGone(format!("containerd could not say: {why}"))
        }
    }
    if info.submounts_dropped > 0 {
        debug!(
            dropped = info.submounts_dropped,
            "node catalog: submounts left out of the request"
        );
    }
    let upper = match root::open_host_root(&cfg.host_proc) {
        Ok(h) => root::check_upper(h.as_raw_fd(), &info.upperdir),
        Err(e) => root::UpperCheck {
            drift: Drift::Unknown(format!("open /proc/1/root: {e}")),
            lang: root::LangCheck::Clean,
        },
    };
    let mut local: Vec<&str> = Vec::new();
    let drift = match upper.drift {
        // Without CAP_SYS_ADMIN a trusted.overlay.opaque mark reads as
        // absent: "clean" is not known to be clean.
        Drift::Clean if !cfg.trusted_xattrs => {
            Drift::Unknown("trusted.overlay.* unreadable without CAP_SYS_ADMIN".into())
        }
        d => d,
    };
    match drift {
        Drift::Drifted(what) => return Attempt::Drift(what),
        Drift::Unknown(why) => {
            info!(
                container = c.container_id,
                why, "node catalog: drift unknown; SBOM will be partial"
            );
            local.push("drift_unknown");
        }
        Drift::Clean => {}
    }
    match upper.lang {
        root::LangCheck::Clean => {}
        root::LangCheck::Found(what) => {
            info!(
                container = c.container_id,
                what,
                "node catalog: a language package was deleted at runtime; SBOM will be partial"
            );
            local.push("lang_whiteout");
        }
        root::LangCheck::Unknown(why) => {
            info!(
                container = c.container_id,
                why,
                "node catalog: language package directories not fully read; SBOM will be partial"
            );
            local.push("lang_whiteout_unknown");
        }
    }
    let root_fd = if cfg.ro_clone {
        match root::readonly_clone(&dir) {
            // The clone must be the same filesystem object as the verified
            // root. Its mount id necessarily differs (a clone is a new,
            // detached mount), so device and inode are what is compared.
            Ok(clone) => match root::same_object(clone.as_raw_fd(), acq.root.as_raw_fd()) {
                Ok(true) => clone,
                other => {
                    warn!(?other, "node catalog: read-only clone is not the verified root; passing the O_PATH root");
                    acq.root
                }
            },
            Err(e) => {
                debug!(error = %e, "node catalog: read-only clone unavailable; passing the O_PATH root");
                acq.root
            }
        }
    } else {
        acq.root
    };

    let scan_id = uuid::Uuid::new_v4().to_string();
    let req = worker::Request {
        protocol_version: worker::PROTOCOL_VERSION,
        op: "scan",
        scan_id: scan_id.clone(),
        epoch: Some(cfg.epoch),
        container_start_unix_nanos: Some(root::start_unix_nanos(acq.start_ticks)),
        submounts: info.submounts,
        profile: Some("full"),
        budgets: Some(cfg.budgets),
    };
    let limits = worker::Limits {
        response_bytes: cfg.budgets.max_response_bytes as usize,
        read_timeout: cfg.read_timeout,
    };
    let resp = match worker::call(&cfg.socket, policy, &req, Some(root_fd), limits, cancel) {
        Ok(r) => r,
        Err(worker::WorkerError::Cancelled) => return Attempt::Done(ScanResult::Cancelled),
        Err(worker::WorkerError::Timeout) => {
            return failed(FailReason::Timeout, "no answer in time")
        }
        Err(e @ worker::WorkerError::Unavailable(_))
        | Err(e @ worker::WorkerError::PeerRejected(_)) => {
            error!(error = %e, "node catalog: cannot hand off to the worker");
            return failed(FailReason::WorkerUnavailable, e.to_string());
        }
        Err(e) => return failed(FailReason::Error, e.to_string()),
    };
    match post::validate(resp, &scan_id, cfg.epoch, &local) {
        Ok(post::Outcome::Sbom(sbom)) => Attempt::Done(ScanResult::Sbom {
            subject: post::Subject {
                digest: c.digest.clone(),
                // The Broker's digest_kind is index | manifest, which the
                // pod status cannot tell apart (a repo digest is either);
                // left out, it is stored as unknown.
                digest_kind: None,
                repository: c.repository.clone(),
                platform: cfg.platform.clone(),
                epoch: cfg.epoch,
            },
            sbom,
        }),
        Ok(post::Outcome::Failed { reason, .. }) if reason == "busy" => {
            Attempt::Done(ScanResult::Busy)
        }
        Ok(post::Outcome::Failed { reason, message }) => failed(
            FailReason::from_worker(&reason),
            format!("{reason}: {message}"),
        ),
        Err(post::Invalid(why)) => {
            warn!(why, "node catalog: worker response refused");
            failed(FailReason::Error, why)
        }
    }
}

impl<R: Runtime + 'static> Scan for NodeScanner<R> {
    async fn scan(&self, digest: &str, cancel: Arc<AtomicBool>) -> ScanResult {
        let mut tried = 0usize;
        let mut sandboxed = false;
        let mut drift: Option<String> = None;
        let mut pid_gone = false;
        for c in self.candidates.iter().filter(|c| c.digest == digest) {
            if cancel.load(Ordering::Relaxed) {
                return ScanResult::Cancelled;
            }
            if c.sandboxed {
                sandboxed = true;
                continue;
            }
            if tried == MAX_CANDIDATES {
                break;
            }
            tried += 1;
            let resolved = self.runtime.resolve(&c.container_id).await;
            let Some(pid) = resolved.pid else {
                // No task: exited. containerd unreachable: node-local, like
                // a pid that went away (N1).
                if resolved.upperdir.is_err() {
                    pid_gone = true;
                }
                continue;
            };
            let (cfg, policy, cand, cancel) = (
                self.config.clone(),
                Arc::clone(&self.policy),
                c.clone(),
                Arc::clone(&cancel),
            );
            let attempt = tokio::task::spawn_blocking(move || {
                scan_one(&cfg, &policy, &cand, pid, &resolved.upperdir, &cancel)
            })
            .await;
            match attempt {
                Ok(Attempt::Done(r)) => return r,
                Ok(Attempt::Drift(what)) => {
                    info!(
                        container = c.container_id,
                        what, "node catalog: container drifted; trying another"
                    );
                    drift = Some(what);
                }
                Ok(Attempt::PidGone(why)) => {
                    debug!(
                        container = c.container_id,
                        why, "node catalog: pid gone; trying another"
                    );
                    pid_gone = true;
                }
                Err(e) => {
                    return ScanResult::Failed {
                        reason: FailReason::Error,
                        detail: format!("scan thread: {e}"),
                    }
                }
            }
        }
        let (reason, detail) = if let Some(what) = drift {
            (FailReason::Drift, what)
        } else if pid_gone {
            (
                FailReason::PidGone,
                "every candidate's process changed".to_string(),
            )
        } else if sandboxed && tried == 0 {
            (
                FailReason::Sandboxed,
                "only sandboxed containers run it here".to_string(),
            )
        } else {
            (
                FailReason::ExitedBeforeCatalog,
                "no running container left".to_string(),
            )
        };
        ScanResult::Failed { reason, detail }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::worker::tests::{me, serve_one, tmp_dir, worker_socket};
    use crate::catalog::worker::PeerMode;
    use crate::image_inventory::DigestKind;
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::Mutex;

    const POD: &str = "5d7c1c2e-1f2a-4b3c-9d8e-0a1b2c3d4e5f";
    const DIGEST: &str = "sha256:aaaa";

    fn cid(n: u32) -> String {
        format!("{n:064x}")
    }

    type SnapshotAnswer = Result<Option<String>, String>;

    /// A fake runtime: container id -> (pid, upperdir), recording calls.
    struct FakeRuntime {
        map: HashMap<String, (Option<u32>, SnapshotAnswer)>,
        calls: Mutex<Vec<String>>,
    }

    impl Runtime for FakeRuntime {
        async fn resolve(&self, id: &str) -> Resolved {
            self.calls.lock().unwrap().push(id.to_string());
            let (pid, upperdir) = self.map.get(id).cloned().unwrap_or((None, Ok(None)));
            Resolved { pid, upperdir }
        }
    }

    /// A fake host procfs: per pid, cgroup/stat/mountinfo and a real root
    /// directory; `1/root` is the fake host root holding the upperdirs.
    struct FakeProc {
        base: PathBuf,
    }

    impl FakeProc {
        fn new(tag: &str) -> Self {
            let base = tmp_dir(tag);
            std::fs::create_dir_all(base.join("1/root")).unwrap();
            FakeProc { base }
        }

        /// Container `n` as pid `n`, with its upperdir at
        /// `<host root>/snap/<n>/fs`; `drifted` writes the apk database
        /// there; `cgroup_of` is the container id its cgroup names.
        fn container(&self, n: u32, cgroup_of: u32, drifted: bool) -> String {
            let d = self.base.join(n.to_string());
            std::fs::create_dir_all(d.join("root/bin")).unwrap();
            std::fs::write(
                d.join("cgroup"),
                format!(
                    "0::/kubepods.slice/kubepods-pod{}.slice/cri-containerd-{}.scope\n",
                    POD.replace('-', "_"),
                    cid(cgroup_of)
                ),
            )
            .unwrap();
            let mut f: Vec<String> = (3..=52).map(|i| i.to_string()).collect();
            f[19] = "12345".into();
            std::fs::write(d.join("stat"), format!("{n} (sh) {}", f.join(" "))).unwrap();
            let up = format!("/snap/{n}/fs");
            let host_up = self.base.join("1/root").join(&up[1..]);
            std::fs::create_dir_all(&host_up).unwrap();
            if drifted {
                std::fs::create_dir_all(host_up.join("lib/apk/db")).unwrap();
                std::fs::write(host_up.join("lib/apk/db/installed"), b"x").unwrap();
            }
            // The / entry must carry the root dir's real mount id.
            let root = std::fs::File::open(d.join("root")).unwrap();
            let mnt = root::mount_id(root.as_raw_fd()).unwrap().unwrap_or(0);
            std::fs::write(
                d.join("mountinfo"),
                format!(
                    "{mnt} 1 0:50 / / rw - overlay overlay rw,lowerdir=1/fs,upperdir={up},workdir=/snap/{n}/work\n\
                     {} {mnt} 0:51 / /proc rw - proc proc rw\n",
                    mnt + 1
                ),
            )
            .unwrap();
            up
        }
    }

    impl Drop for FakeProc {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    fn cand(n: u32) -> RunningContainer {
        RunningContainer {
            pod_uid: POD.into(),
            namespace: "prod".into(),
            pod: "web".into(),
            container: format!("c{n}"),
            container_id: cid(n),
            digest: DIGEST.into(),
            digest_kind: DigestKind::Repo,
            repository: None,
            started_unix: Some(i64::from(n)),
            sandboxed: false,
        }
    }

    fn scanner(
        proc_: &FakeProc,
        socket: &Path,
        runtime: FakeRuntime,
        candidates: Vec<RunningContainer>,
    ) -> NodeScanner<FakeRuntime> {
        NodeScanner {
            config: ScanConfig {
                host_proc: proc_.base.clone(),
                socket: socket.to_path_buf(),
                epoch: 1,
                ro_clone: false,
                budgets: worker::Budgets {
                    max_response_bytes: 1 << 20,
                    ..Default::default()
                },
                read_timeout: std::time::Duration::from_secs(10),
                platform: "linux/amd64".into(),
                trusted_xattrs: true,
            },
            policy: Arc::new(PeerPolicy {
                mode: PeerMode::PathCheck,
                allowed_uids: vec![me()],
                socket_owner: me(),
                host_proc: proc_.base.clone(),
            }),
            runtime: Arc::new(runtime),
            candidates,
        }
    }

    /// A worker that serves `n` scans with one package each.
    fn worker(
        l: std::os::unix::net::UnixListener,
        n: usize,
    ) -> std::thread::JoinHandle<Vec<serde_json::Value>> {
        std::thread::spawn(move || {
            (0..n)
                .map(|_| {
                    let (s, _) = l.accept().unwrap();
                    serve_one(s, false, |req, got_fd| {
                        assert!(got_fd, "the root fd was passed");
                        crate::catalog::worker::frame(
                            &serde_json::to_vec(&serde_json::json!({
                                "protocol_version": 1, "scan_id": req["scan_id"],
                                "epoch": req["epoch"], "status": "ok", "completeness": "full",
                                "components": [{"name": "busybox", "version": "1", "type": "apk",
                                                "file_paths": ["/bin/busybox"]}]
                            }))
                            .unwrap(),
                        )
                    })
                    .0
                })
                .collect()
        })
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_drifted_replica_is_skipped_for_the_next_one() {
        let p = FakeProc::new("scan-drift");
        let up1 = p.container(101, 101, true);
        let up2 = p.container(102, 102, false);
        let (dir, sock, l) = worker_socket("scan-drift-w");
        let w = worker(l, 1);
        let rt = FakeRuntime {
            map: HashMap::from([
                (cid(101), (Some(101), Ok(Some(up1)))),
                (cid(102), (Some(102), Ok(Some(up2)))),
            ]),
            calls: Mutex::default(),
        };
        let s = scanner(&p, &sock, rt, vec![cand(101), cand(102)]);
        match s.scan(DIGEST, Arc::default()).await {
            ScanResult::Sbom { subject, sbom } => {
                assert_eq!(subject.digest, DIGEST);
                assert_eq!(sbom.completeness, "full");
                assert_eq!(sbom.components[0].name, "busybox");
            }
            other => panic!("{other:?}"),
        }
        let reqs = w.join().unwrap();
        assert_eq!(reqs[0]["submounts"], serde_json::json!(["/proc"]));
        assert_eq!(*s.runtime.calls.lock().unwrap(), vec![cid(101), cid(102)]);
        std::fs::remove_dir_all(dir.parent().unwrap()).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_pid_now_owned_by_another_container_is_pid_gone() {
        let p = FakeProc::new("scan-pidgone");
        // pid 201's cgroup names container 999.
        let up = p.container(201, 999, false);
        let rt = FakeRuntime {
            map: HashMap::from([(cid(201), (Some(201), Ok(Some(up))))]),
            calls: Mutex::default(),
        };
        let s = scanner(&p, Path::new("/nonexistent/w.sock"), rt, vec![cand(201)]);
        assert!(matches!(
            s.scan(DIGEST, Arc::default()).await,
            ScanResult::Failed {
                reason: FailReason::PidGone,
                ..
            }
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn at_most_max_candidates_are_tried_then_drift_is_reported() {
        let p = FakeProc::new("scan-max");
        let mut map = HashMap::new();
        let mut cands = Vec::new();
        for n in 301..=305 {
            let up = p.container(n, n, true);
            map.insert(cid(n), (Some(n), Ok(Some(up))));
            cands.push(cand(n));
        }
        let rt = FakeRuntime {
            map,
            calls: Mutex::default(),
        };
        let s = scanner(&p, Path::new("/nonexistent/w.sock"), rt, cands);
        match s.scan(DIGEST, Arc::default()).await {
            ScanResult::Failed {
                reason: FailReason::Drift,
                detail,
            } => assert_eq!(detail, "lib/apk/db/installed written"),
            other => panic!("{other:?}"),
        }
        assert_eq!(s.runtime.calls.lock().unwrap().len(), MAX_CANDIDATES);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn no_task_pid_is_exited_before_catalog() {
        let p = FakeProc::new("scan-none");
        let rt = FakeRuntime {
            map: HashMap::new(),
            calls: Mutex::default(),
        };
        let s = scanner(&p, Path::new("/nonexistent/w.sock"), rt, vec![cand(401)]);
        assert!(matches!(
            s.scan(DIGEST, Arc::default()).await,
            ScanResult::Failed {
                reason: FailReason::ExitedBeforeCatalog,
                ..
            }
        ));
    }

    /// M3: a root whose overlay upperdir is not the container snapshot's
    /// (a chroot onto another tree) is refused.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_root_that_is_not_the_container_snapshot_is_refused() {
        let p = FakeProc::new("scan-snap");
        p.container(501, 501, false);
        let rt = FakeRuntime {
            map: HashMap::from([(cid(501), (Some(501), Ok(Some("/elsewhere/fs".into()))))]),
            calls: Mutex::default(),
        };
        let s = scanner(&p, Path::new("/nonexistent/w.sock"), rt, vec![cand(501)]);
        match s.scan(DIGEST, Arc::default()).await {
            ScanResult::Failed {
                reason: FailReason::UnsupportedRootfs,
                detail,
            } => assert!(detail.contains("not the container snapshot"), "{detail}"),
            other => panic!("{other:?}"),
        }
    }

    fn mount(options: &[&str]) -> containerd_client::types::Mount {
        containerd_client::types::Mount {
            r#type: "overlay".into(),
            source: "overlay".into(),
            target: String::new(),
            options: options.iter().map(|o| o.to_string()).collect(),
        }
    }

    #[test]
    fn upperdir_option_reads_the_snapshot_mounts() {
        let m = mount(&[
            "index=off",
            "workdir=/s/2/work",
            "upperdir=/s/2/fs",
            "lowerdir=/s/1/fs",
        ]);
        assert_eq!(upperdir_option(&[m]).as_deref(), Some("/s/2/fs"));
        assert_eq!(upperdir_option(&[]), None);
        // Trailing slashes are not a difference; two different upperdirs
        // are ambiguous (a mismatch); the same one twice is not.
        assert_eq!(
            upperdir_option(&[mount(&["upperdir=/s/2/fs/"])]).as_deref(),
            Some("/s/2/fs")
        );
        assert_eq!(
            upperdir_option(&[mount(&["upperdir=/s/2/fs", "upperdir=/s/3/fs"])]),
            None
        );
        assert_eq!(
            upperdir_option(&[mount(&["upperdir=/s/2/fs", "upperdir=/s/2/fs/"])]).as_deref(),
            Some("/s/2/fs")
        );
        assert_eq!(normalise_upper("/"), "/");
        assert_eq!(normalise_upper("///"), "/");
    }

    /// N4: a containerd v2.2 overlayfs `Snapshots.Mounts` reply for an
    /// active snapshot, in the option order `(*snapshotter).mounts`
    /// builds (plugins/snapshots/overlay/overlay.go: workdir, upperdir,
    /// lowerdir, then the snapshotter's options), against the Bottlerocket
    /// mountinfo line the kernel shows for the same container (with
    /// SELinux context options, `uuid=on`, and a compacted-or-not
    /// lowerdir). The upperdirs must tie; a neighbour snapshot must not;
    /// an idmapped (userns remap) reply with extra options still ties.
    #[test]
    fn a_containerd_22_mounts_reply_ties_to_the_bottlerocket_mountinfo() {
        const SNAP: &str = "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots";
        let reply = mount(&[
            &format!("workdir={SNAP}/2305/work"),
            &format!("upperdir={SNAP}/2305/fs"),
            &format!("lowerdir={SNAP}/2291/fs:{SNAP}/2290/fs"),
            "index=off",
        ]);
        let line = format!(
            "1893 1735 0:412 / / rw,relatime master:627 - overlay overlay rw,seclabel,\
             context=\"system_u:object_r:data_t:s0\",lowerdir={SNAP}/2291/fs:{SNAP}/2290/fs,\
             upperdir={SNAP}/2305/fs,workdir={SNAP}/2305/work,uuid=on"
        );
        let info = mountinfo::root_info(&mountinfo::parse(&line)).unwrap();
        let Upperdir::Path(from_kernel) = &info.upperdir else {
            panic!("{:?}", info.upperdir)
        };
        let from_containerd = upperdir_option(&[reply]).unwrap();
        assert_eq!(
            normalise_upper(from_kernel),
            normalise_upper(&from_containerd)
        );

        let neighbour = upperdir_option(&[mount(&[&format!("upperdir={SNAP}/2306/fs")])]).unwrap();
        assert_ne!(normalise_upper(from_kernel), normalise_upper(&neighbour));

        let idmapped = mount(&[
            &format!("workdir={SNAP}/2305/work"),
            &format!("upperdir={SNAP}/2305/fs/"),
            &format!("lowerdir={SNAP}/2291/fs"),
            "userxattr",
            "uidmap=0:1000000:65536",
            "gidmap=0:1000000:65536",
        ]);
        assert_eq!(
            normalise_upper(from_kernel),
            normalise_upper(&upperdir_option(&[idmapped]).unwrap())
        );
    }

    /// N1: containerd not answering for one replica is node-local: the
    /// next replica is used.
    #[tokio::test(flavor = "multi_thread")]
    async fn containerd_trouble_moves_to_the_next_replica() {
        let p = FakeProc::new("scan-ctd");
        p.container(601, 601, false);
        let up2 = p.container(602, 602, false);
        let (dir, sock, l) = worker_socket("scan-ctd-w");
        let w = worker(l, 1);
        let rt = FakeRuntime {
            map: HashMap::from([
                (
                    cid(601),
                    (Some(601), Err("Snapshots.Mounts timed out".into())),
                ),
                (cid(602), (Some(602), Ok(Some(up2)))),
            ]),
            calls: Mutex::default(),
        };
        let s = scanner(&p, &sock, rt, vec![cand(601), cand(602)]);
        assert!(matches!(
            s.scan(DIGEST, Arc::default()).await,
            ScanResult::Sbom { .. }
        ));
        w.join().unwrap();
        std::fs::remove_dir_all(dir.parent().unwrap()).unwrap();
    }

    /// N1: with no replica containerd can speak for, the grant ends
    /// `pid_gone` (released to other nodes), never a per-digest `error`.
    #[tokio::test(flavor = "multi_thread")]
    async fn containerd_trouble_everywhere_is_pid_gone() {
        let p = FakeProc::new("scan-ctd2");
        p.container(701, 701, false);
        let rt = FakeRuntime {
            map: HashMap::from([
                (
                    cid(701),
                    (Some(701), Err("Containers.Get timed out".into())),
                ),
                // Unreachable: no pid, and containerd could not say.
                (cid(702), (None, Err("containerd unreachable".into()))),
            ]),
            calls: Mutex::default(),
        };
        let s = scanner(
            &p,
            Path::new("/nonexistent/w.sock"),
            rt,
            vec![cand(701), cand(702)],
        );
        match s.scan(DIGEST, Arc::default()).await {
            ScanResult::Failed { reason, .. } => assert_eq!(reason, FailReason::PidGone),
            other => panic!("{other:?}"),
        }
    }

    /// N3: without CAP_SYS_ADMIN a clean upperdir is not known to be
    /// clean (trusted.* reads as absent): the SBOM is partial.
    #[tokio::test(flavor = "multi_thread")]
    async fn without_cap_sys_admin_drift_is_unknown() {
        let p = FakeProc::new("scan-nocap");
        let up = p.container(801, 801, false);
        let (dir, sock, l) = worker_socket("scan-nocap-w");
        let w = worker(l, 1);
        let rt = FakeRuntime {
            map: HashMap::from([(cid(801), (Some(801), Ok(Some(up))))]),
            calls: Mutex::default(),
        };
        let mut s = scanner(&p, &sock, rt, vec![cand(801)]);
        s.config.trusted_xattrs = false;
        match s.scan(DIGEST, Arc::default()).await {
            ScanResult::Sbom { sbom, .. } => {
                assert_eq!(sbom.completeness, "partial");
                assert_eq!(sbom.partial_reasons, vec!["drift_unknown"]);
            }
            other => panic!("{other:?}"),
        }
        w.join().unwrap();
        std::fs::remove_dir_all(dir.parent().unwrap()).unwrap();
    }
}
