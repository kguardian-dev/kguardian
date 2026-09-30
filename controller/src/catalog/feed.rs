//! What this node could catalog: its running containers, from the pod
//! watcher, reduced to the offer the claim loop sends the Broker.
//!
//! The pod watcher is the Controller's pod inventory, and it must never
//! wait on the catalog. So it does not call into this module's state:
//! [`note_pod`] and friends turn a Pod into a small [`FeedMsg`] and
//! `try_send` it on a bounded channel. A full channel drops the message;
//! the next 60 s resync re-sends every pod, so a drop costs at most one
//! resync interval of staleness. With the catalog off the channel does
//! not exist and each hook is one failed `OnceLock` read.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use k8s_openapi::api::core::v1::{ContainerStatus, Pod};
use tokio::sync::mpsc;

use crate::image_inventory::{is_valid_digest, parse_image_id, DigestKind};

use super::api::MAX_OFFER;

/// Capacity of the pod watcher -> catalog channel.
pub const FEED_CAPACITY: usize = 1024;

/// One running container this node could catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningContainer {
    pub pod_uid: String,
    pub namespace: String,
    pub pod: String,
    pub container: String,
    /// containerd id (no `containerd://`).
    pub container_id: String,
    pub digest: String,
    pub digest_kind: DigestKind,
    pub repository: Option<String>,
    /// `status.state.running.startedAt`, unix seconds.
    pub started_unix: Option<i64>,
    /// The pod runs under a sandboxing runtime class (gVisor, Kata): the
    /// task pid is the sandbox, not the workload, and its root is not
    /// the image.
    pub sandboxed: bool,
}

/// Pod watcher -> catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedMsg {
    /// A pod's current running containers (possibly none).
    Pod {
        uid: String,
        containers: Vec<RunningContainer>,
    },
    /// The pod is finished or gone.
    Forget { uid: String },
    /// A resync LIST: every pod not in the set is gone.
    Retain { live: HashSet<String> },
}

static FEED: OnceLock<mpsc::Sender<FeedMsg>> = OnceLock::new();

/// Open the feed. Called once, by `catalog::start`, only with the
/// catalog on. A second call returns `None` (the first owner keeps it).
pub(crate) fn open() -> Option<mpsc::Receiver<FeedMsg>> {
    let (tx, rx) = mpsc::channel(FEED_CAPACITY);
    FEED.set(tx).ok()?;
    Some(rx)
}

fn send(build: impl FnOnce() -> Option<FeedMsg>) {
    // Off: nothing is built, nothing is sent.
    let Some(tx) = FEED.get() else { return };
    if let Some(msg) = build() {
        // Never waits. A dropped message is repaired by the next resync.
        let _ = tx.try_send(msg);
    }
}

/// Is the feed open (the catalog on)? For tests of the off path.
pub fn is_open() -> bool {
    FEED.get().is_some()
}

/// Runtime classes whose task pid is a sandbox. Matched as substrings of
/// the class name, which operators choose freely (`gvisor`, `runsc`,
/// `kata-qemu`, `kata-fc`, ...).
const SANDBOX_CLASSES: [&str; 3] = ["gvisor", "runsc", "kata"];

fn is_sandboxed(pod: &Pod) -> bool {
    pod.spec
        .as_ref()
        .and_then(|s| s.runtime_class_name.as_deref())
        .map(|c| {
            let c = c.to_ascii_lowercase();
            SANDBOX_CLASSES.iter().any(|s| c.contains(s))
        })
        .unwrap_or(false)
}

fn running(cs: &ContainerStatus) -> Option<Option<i64>> {
    let r = cs.state.as_ref()?.running.as_ref()?;
    Some(r.started_at.as_ref().map(|t| t.0.as_second()))
}

/// The running containers of `pod` worth offering: regular and running
/// init (sidecar) containers with a digest from `status.imageID`.
/// Ephemeral debug containers are left out, and so is a `pinned` digest
/// (never running, by definition).
pub fn running_containers(pod: &Pod) -> Vec<RunningContainer> {
    let Some(uid) = pod.metadata.uid.clone().filter(|u| !u.is_empty()) else {
        return Vec::new();
    };
    let namespace = pod.metadata.namespace.clone().unwrap_or_default();
    let pod_name = pod.metadata.name.clone().unwrap_or_default();
    let sandboxed = is_sandboxed(pod);
    let Some(status) = pod.status.as_ref() else {
        return Vec::new();
    };
    let lists = [
        status.container_statuses.as_deref(),
        status.init_container_statuses.as_deref(),
    ];
    let mut out = Vec::new();
    for cs in lists.into_iter().flatten().flatten() {
        let Some(started_unix) = running(cs) else {
            continue;
        };
        let Some(container_id) = cs
            .container_id
            .as_deref()
            .and_then(crate::container::parse_container_id)
        else {
            continue;
        };
        let Some(parsed) = parse_image_id(&cs.image_id) else {
            continue;
        };
        if !matches!(parsed.kind, DigestKind::Repo | DigestKind::Config) {
            continue;
        }
        out.push(RunningContainer {
            pod_uid: uid.clone(),
            namespace: namespace.clone(),
            pod: pod_name.clone(),
            container: cs.name.clone(),
            container_id,
            digest: parsed.digest,
            digest_kind: parsed.kind,
            repository: parsed.repository,
            started_unix,
            sandboxed,
        });
    }
    out
}

/// Pod watcher hook: a live pod was processed.
pub fn note_pod(pod: &Pod) {
    send(|| {
        let uid = pod.metadata.uid.clone().filter(|u| !u.is_empty())?;
        Some(FeedMsg::Pod {
            uid,
            containers: running_containers(pod),
        })
    });
}

/// Pod watcher hook: a pod is terminal or deleting.
pub fn forget_pod(pod: &Pod) {
    send(|| {
        let uid = pod.metadata.uid.clone().filter(|u| !u.is_empty())?;
        Some(FeedMsg::Forget { uid })
    });
}

/// Pod watcher hook: a resync LIST's pod uids.
pub fn retain_pods(live: &HashSet<String>) {
    send(|| Some(FeedMsg::Retain { live: live.clone() }));
}

/// The catalog's view of this node, owned by the catalog task.
#[derive(Debug, Default)]
pub struct Inventory {
    pods: HashMap<String, Vec<RunningContainer>>,
}

impl Inventory {
    pub fn apply(&mut self, msg: FeedMsg) {
        match msg {
            FeedMsg::Pod { uid, containers } if containers.is_empty() => {
                self.pods.remove(&uid);
            }
            FeedMsg::Pod { uid, containers } => {
                self.pods.insert(uid, containers);
            }
            FeedMsg::Forget { uid } => {
                self.pods.remove(&uid);
            }
            FeedMsg::Retain { live } => self.pods.retain(|uid, _| live.contains(uid)),
        }
    }

    /// Every running container with `digest`, oldest first: a container
    /// that has been up longest is the least likely to be mid-rollout.
    pub fn candidates(&self, digest: &str) -> Vec<RunningContainer> {
        let mut out: Vec<RunningContainer> = self
            .pods
            .values()
            .flatten()
            .filter(|c| c.digest == digest)
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            a.started_unix
                .unwrap_or(i64::MAX)
                .cmp(&b.started_unix.unwrap_or(i64::MAX))
                .then_with(|| a.container_id.cmp(&b.container_id))
        });
        out
    }

    pub fn containers(&self) -> usize {
        self.pods.values().map(Vec::len).sum()
    }

    fn digests(&self) -> BTreeSet<&str> {
        self.pods
            .values()
            .flatten()
            .map(|c| c.digest.as_str())
            .collect()
    }
}

/// Digests this node recently finished with, kept out of offers for a
/// while so a done or refused digest is not re-offered every tick. The
/// Broker decides what is claimable; this only saves it the work.
#[derive(Debug, Default)]
pub struct Cooldown {
    until: HashMap<String, Instant>,
}

impl Cooldown {
    pub fn hold(&mut self, digest: &str, now: Instant, d: Duration) {
        self.until.insert(digest.to_string(), now + d);
    }

    pub fn holds(&self, digest: &str, now: Instant) -> bool {
        self.until.get(digest).is_some_and(|u| *u > now)
    }

    pub fn prune(&mut self, now: Instant) {
        self.until.retain(|_, u| *u > now);
    }
}

/// The offer: sorted, unique, valid digests of running containers, not
/// cooling down, at most [`MAX_OFFER`]. Sandboxed-only digests are kept:
/// another node may run them unsandboxed, and a grant here is refused
/// with `sandboxed` (a per-node skip) the Broker learns from.
pub fn offer(inv: &Inventory, cooldown: &Cooldown, now: Instant) -> Vec<String> {
    let mut out: Vec<String> = inv
        .digests()
        .into_iter()
        .filter(|d| is_valid_digest(d) && !cooldown.holds(d, now))
        .map(str::to_string)
        .collect();
    // BTreeSet order already; truncation keeps the result deterministic.
    out.truncate(MAX_OFFER);
    out
}

/// This node's platform as the Broker keys it (`os/arch`, Go's names).
/// The Controller is a native binary in a multi-arch image, so its own
/// target is the node's. `None` for an architecture with no mapping:
/// the loop then never offers (fail closed), rather than claiming under
/// a platform it cannot name.
pub fn node_platform() -> Option<String> {
    platform_for(std::env::consts::OS, std::env::consts::ARCH)
}

pub fn platform_for(os: &str, arch: &str) -> Option<String> {
    if os != "linux" {
        return None;
    }
    let goarch = match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        "arm" => "arm",
        "powerpc64" if cfg!(target_endian = "little") => "ppc64le",
        "s390x" => "s390x",
        "riscv64" => "riscv64",
        _ => return None,
    };
    Some(format!("linux/{goarch}"))
}

/// A uniform value in `[0, max)`, from the v4 UUID generator the crate
/// already carries (no `rand` dependency for one draw).
pub fn jitter(max: Duration) -> Duration {
    let ms = max.as_millis() as u64;
    if ms == 0 {
        return Duration::ZERO;
    }
    let r = (uuid::Uuid::new_v4().as_u128() & u128::from(u64::MAX)) as u64;
    Duration::from_millis(r % ms)
}

/// When to ask the Broker next. Deduplicates offers: an unchanged offer
/// that just got no grant is not re-sent until `idle` has passed, while a
/// new digest (a rollout) is offered after `min_gap`.
#[derive(Debug)]
pub struct Pacer {
    pub min_gap: Duration,
    pub idle: Duration,
    last_at: Option<Instant>,
    last_offer: Vec<String>,
    last_granted: bool,
}

impl Pacer {
    pub fn new(min_gap: Duration, idle: Duration) -> Self {
        Self {
            min_gap,
            idle,
            last_at: None,
            last_offer: Vec::new(),
            last_granted: false,
        }
    }

    /// Should `offer` be sent now?
    pub fn due(&self, offer: &[String], now: Instant) -> bool {
        if offer.is_empty() {
            return false;
        }
        let Some(at) = self.last_at else { return true };
        let since = now.saturating_duration_since(at);
        if since < self.min_gap {
            return false;
        }
        // After a grant there may be more to do; after a no-grant only a
        // changed offer is worth a request before `idle`.
        self.last_granted || offer != self.last_offer.as_slice() || since >= self.idle
    }

    pub fn sent(&mut self, offer: &[String], granted: bool, now: Instant) {
        self.last_at = Some(now);
        self.last_offer = offer.to_vec();
        self.last_granted = granted;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{
        ContainerState, ContainerStateRunning, ContainerStateTerminated, PodSpec, PodStatus,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, Time};

    fn digest(c: char) -> String {
        format!("sha256:{}", c.to_string().repeat(64))
    }

    fn status(name: &str, id: &str, image_id: &str, running: bool) -> ContainerStatus {
        let started = Time(k8s_openapi::jiff::Timestamp::from_second(1_790_000_000).unwrap());
        ContainerStatus {
            name: name.into(),
            container_id: Some(format!("containerd://{id}")),
            image_id: image_id.into(),
            state: Some(if running {
                ContainerState {
                    running: Some(ContainerStateRunning {
                        started_at: Some(started),
                    }),
                    ..Default::default()
                }
            } else {
                ContainerState {
                    terminated: Some(ContainerStateTerminated::default()),
                    ..Default::default()
                }
            }),
            ..Default::default()
        }
    }

    fn pod(uid: &str, statuses: Vec<ContainerStatus>, init: Vec<ContainerStatus>) -> Pod {
        Pod {
            metadata: ObjectMeta {
                uid: Some(uid.into()),
                name: Some(format!("pod-{uid}")),
                namespace: Some("prod".into()),
                ..Default::default()
            },
            spec: Some(PodSpec::default()),
            status: Some(PodStatus {
                container_statuses: Some(statuses),
                init_container_statuses: Some(init),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn only_running_containers_with_a_usable_digest_are_offered() {
        let a = digest('a');
        let b = digest('b');
        let p = pod(
            "u1",
            vec![
                status("web", "c1", &format!("docker.io/library/nginx@{a}"), true),
                // Config digest: still identifies the content on the node.
                status("side", "c2", &b, true),
                // Exited: not offered.
                status("done", "c3", &digest('c'), false),
                // No imageID yet.
                status("new", "c4", "", true),
            ],
            // A running sidecar init container is offered.
            vec![status("mesh", "c5", &digest('d'), true)],
        );
        let rc = running_containers(&p);
        let names: Vec<&str> = rc.iter().map(|c| c.container.as_str()).collect();
        assert_eq!(names, vec!["web", "side", "mesh"]);
        assert_eq!(rc[0].digest_kind, DigestKind::Repo);
        assert_eq!(rc[1].digest_kind, DigestKind::Config);
        assert_eq!(rc[0].started_unix, Some(1_790_000_000));
        assert_eq!(rc[0].container_id, "c1");
    }

    #[test]
    fn sandboxed_runtime_classes_are_marked() {
        let mut p = pod("u1", vec![status("w", "c1", &digest('a'), true)], vec![]);
        p.spec.as_mut().unwrap().runtime_class_name = Some("gvisor".into());
        assert!(running_containers(&p)[0].sandboxed);
        p.spec.as_mut().unwrap().runtime_class_name = Some("kata-qemu".into());
        assert!(running_containers(&p)[0].sandboxed);
        p.spec.as_mut().unwrap().runtime_class_name = Some("nvidia".into());
        assert!(!running_containers(&p)[0].sandboxed);
    }

    #[test]
    fn the_offer_is_sorted_unique_capped_and_skips_cooldown() {
        let mut inv = Inventory::default();
        let now = Instant::now();
        for (uid, d) in [("u1", 'b'), ("u2", 'a'), ("u3", 'b')] {
            inv.apply(FeedMsg::Pod {
                uid: uid.into(),
                containers: running_containers(&pod(
                    uid,
                    vec![status("w", uid, &digest(d), true)],
                    vec![],
                )),
            });
        }
        let mut cd = Cooldown::default();
        assert_eq!(offer(&inv, &cd, now), vec![digest('a'), digest('b')]);
        cd.hold(&digest('a'), now, Duration::from_secs(60));
        assert_eq!(offer(&inv, &cd, now), vec![digest('b')]);
        // The hold expires.
        assert_eq!(
            offer(&inv, &cd, now + Duration::from_secs(61)),
            vec![digest('a'), digest('b')]
        );

        // Forget and retain retire pods.
        inv.apply(FeedMsg::Forget { uid: "u2".into() });
        assert_eq!(offer(&inv, &cd, now), vec![digest('b')]);
        inv.apply(FeedMsg::Retain {
            live: HashSet::from(["u3".to_string()]),
        });
        assert_eq!(inv.containers(), 1);
        assert_eq!(inv.candidates(&digest('b'))[0].pod_uid, "u3");
    }

    #[test]
    fn the_offer_never_exceeds_the_broker_cap() {
        let mut inv = Inventory::default();
        let containers = (0..(MAX_OFFER + 40))
            .map(|i| RunningContainer {
                pod_uid: "u".into(),
                namespace: "n".into(),
                pod: "p".into(),
                container: format!("c{i}"),
                container_id: format!("id{i}"),
                digest: format!("sha256:{i:064x}"),
                digest_kind: DigestKind::Repo,
                repository: None,
                started_unix: None,
                sandboxed: false,
            })
            .collect();
        inv.apply(FeedMsg::Pod {
            uid: "u".into(),
            containers,
        });
        let o = offer(&inv, &Cooldown::default(), Instant::now());
        assert_eq!(o.len(), MAX_OFFER);
        assert!(o.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn an_empty_pod_update_removes_the_pod() {
        let mut inv = Inventory::default();
        inv.apply(FeedMsg::Pod {
            uid: "u".into(),
            containers: running_containers(&pod(
                "u",
                vec![status("w", "c", &digest('a'), true)],
                vec![],
            )),
        });
        assert_eq!(inv.containers(), 1);
        inv.apply(FeedMsg::Pod {
            uid: "u".into(),
            containers: vec![],
        });
        assert_eq!(inv.containers(), 0);
    }

    #[test]
    fn the_pacer_deduplicates_unchanged_offers() {
        let t0 = Instant::now();
        let mut p = Pacer::new(Duration::from_secs(30), Duration::from_secs(600));
        let o1 = vec![digest('a')];
        assert!(p.due(&o1, t0));
        assert!(!p.due(&[], t0), "nothing to offer, nothing to send");
        p.sent(&o1, false, t0);
        // Inside the minimum gap: never.
        assert!(!p.due(&o1, t0 + Duration::from_secs(10)));
        // Same offer, no grant last time: wait for idle.
        assert!(!p.due(&o1, t0 + Duration::from_secs(60)));
        assert!(p.due(&o1, t0 + Duration::from_secs(600)));
        // A changed offer goes after the gap.
        let o2 = vec![digest('a'), digest('b')];
        assert!(p.due(&o2, t0 + Duration::from_secs(31)));
        // After a grant, the next claim goes after the gap.
        p.sent(&o1, true, t0);
        assert!(p.due(&o1, t0 + Duration::from_secs(31)));
    }

    #[test]
    fn platforms_use_go_names_and_fail_closed() {
        assert_eq!(
            platform_for("linux", "x86_64").as_deref(),
            Some("linux/amd64")
        );
        assert_eq!(
            platform_for("linux", "aarch64").as_deref(),
            Some("linux/arm64")
        );
        assert_eq!(platform_for("linux", "mips"), None);
        assert_eq!(platform_for("macos", "aarch64"), None);
        assert!(
            node_platform().is_some(),
            "the Controller's own targets map"
        );
    }

    #[test]
    fn jitter_stays_in_range() {
        for _ in 0..200 {
            assert!(jitter(Duration::from_secs(5)) < Duration::from_secs(5));
        }
        assert_eq!(jitter(Duration::ZERO), Duration::ZERO);
    }
}
