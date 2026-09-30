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

/// The `upperdir=` option of a mount list.
pub fn upperdir_option(mounts: &[containerd_client::types::Mount]) -> Option<String> {
    mounts
        .iter()
        .flat_map(|m| m.options.iter())
        .find_map(|o| o.strip_prefix("upperdir="))
        .map(str::to_string)
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

/// Tie the root fd to the container's own snapshot (M3): the fd is on
/// the `/` mount mountinfo names, and that overlay's upperdir is the one
/// containerd has for the container's snapshot.
fn check_snapshot(
    root: &OwnedFd,
    info: &mountinfo::RootInfo,
    snapshot: &Result<Option<String>, String>,
) -> Result<(), (FailReason, String)> {
    match root::mount_id(root.as_raw_fd()) {
        Ok(Some(id)) if id == info.mount_id => {}
        Ok(Some(id)) => {
            return Err((
                FailReason::UnsupportedRootfs,
                format!(
                    "root fd is on mount {id}, not the / mount {}",
                    info.mount_id
                ),
            ))
        }
        Ok(None) => {
            return Err((
                FailReason::KernelUnsupported,
                "statx gives no STATX_MNT_ID (Linux < 5.8)".into(),
            ))
        }
        Err(e) => return Err((FailReason::Error, format!("statx root: {e}"))),
    }
    let Upperdir::Path(up) = &info.upperdir else {
        // Unparseable: drift unknown, the SBOM is partial (final review 2).
        return Ok(());
    };
    match snapshot {
        Ok(Some(s)) if s == up => Ok(()),
        Ok(Some(s)) => Err((
            FailReason::UnsupportedRootfs,
            format!("root upperdir {up} is not the container snapshot's {s}"),
        )),
        Ok(None) => Err((
            FailReason::UnsupportedRootfs,
            "the container's snapshot has no upperdir".into(),
        )),
        Err(e) => Err((FailReason::Error, format!("containerd: {e}"))),
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
    if let Err((reason, detail)) = check_snapshot(&acq.root, &info, snapshot_upperdir) {
        return failed(reason, detail);
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
            lang_whiteout: None,
        },
    };
    let mut local: Vec<&str> = Vec::new();
    match upper.drift {
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
    if let Some(what) = upper.lang_whiteout {
        info!(
            container = c.container_id,
            what, "node catalog: a language package was deleted at runtime; SBOM will be partial"
        );
        local.push("lang_whiteout");
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

    /// A fake runtime: container id -> (pid, upperdir), recording calls.
    struct FakeRuntime {
        map: HashMap<String, (Option<u32>, Option<String>)>,
        calls: Mutex<Vec<String>>,
    }

    impl Runtime for FakeRuntime {
        async fn resolve(&self, id: &str) -> Resolved {
            self.calls.lock().unwrap().push(id.to_string());
            let (pid, up) = self.map.get(id).cloned().unwrap_or((None, None));
            Resolved {
                pid,
                upperdir: Ok(up),
            }
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
                (cid(101), (Some(101), Some(up1))),
                (cid(102), (Some(102), Some(up2))),
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
            map: HashMap::from([(cid(201), (Some(201), Some(up)))]),
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
            map.insert(cid(n), (Some(n), Some(up)));
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
            map: HashMap::from([(cid(501), (Some(501), Some("/elsewhere/fs".into())))]),
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

    #[test]
    fn upperdir_option_reads_the_snapshot_mounts() {
        let m = containerd_client::types::Mount {
            r#type: "overlay".into(),
            source: "overlay".into(),
            target: String::new(),
            options: vec![
                "index=off".into(),
                "workdir=/s/2/work".into(),
                "upperdir=/s/2/fs".into(),
                "lowerdir=/s/1/fs".into(),
            ],
        };
        assert_eq!(upperdir_option(&[m]).as_deref(), Some("/s/2/fs"));
        assert_eq!(upperdir_option(&[]), None);
    }
}
