//! Independent supervision for the Controller's long-lived subsystems.
//!
//! ## The arrangement this replaces
//!
//! `main` used to compose all nine subsystems with `tokio::try_join!`.
//! That is nine *futures* but only one *task*, and the task — not the
//! future — is what Tokio schedules. A task is polled by at most one
//! worker at a time and cannot be stolen mid-poll, so the nine shared
//! a single thread's worth of forward progress and a single fate. Two
//! consequences were measured on the 14-worker runtime this DaemonSet
//! actually runs:
//!
//! * **A blocking call anywhere froze everything.** A heartbeat placed
//!   *inside* the join stopped ticking permanently the moment any
//!   joined future blocked its worker, while a heartbeat in a
//!   separately spawned task on the same runtime kept ticking. Thirteen
//!   idle workers could not help: work stealing operates on tasks, and
//!   there was only one.
//! * **They shared one cooperative budget.** Tokio yields a task after
//!   128 ready operations. Every mpsc `recv`, every timer, every IO op
//!   across all nine subsystems decremented the same counter, so all
//!   nine were forced to yield together, constantly. That is what made
//!   the `ContainerMap` lock window in #1343 a permanent hazard rather
//!   than a rare one — the yield points were everywhere, all the time.
//!
//! One `tokio::spawn` per subsystem fixes both: nine tasks, nine
//! budgets, nine independently stealable units of work. There was no
//! `tokio::spawn` anywhere in this crate before (only the
//! `spawn_blocking` in `bpf.rs`), which is why neither property held.
//!
//! ## Why "the subsystem returned `Ok`" is a fault
//!
//! `try_join!` short-circuits on `Err` and only on `Err`. Three of the
//! event consumers return `Ok(())` when their channel closes —
//! `syscall::handle_syscall_events`, `network::handle_network_events`
//! and `network::handle_policy_drop_events`. A consumer that retires
//! *cleanly* did not resolve the join: `try_join!` went on waiting for
//! the other eight. So this is not a hazard being prevented, it is one
//! being narrowed — today's controller can already be alive, healthy
//! from the outside, and partially blind, with no non-zero exit and no
//! restart. Nothing in the old arrangement could tell "still working"
//! from "finished, quietly, hours ago".
//!
//! So supervision here is not "wait for an error". It is "these
//! subsystems are supposed to run until the process dies, and any of
//! them stopping — `Ok`, `Err` or panic — is a fault".
//!
//! That cannot be a blanket rule, and the exception is a real
//! distinction rather than a special case: a subsystem whose *feature
//! is switched off* has nothing to do and returning is correct, while
//! a *capture subsystem that stopped* is a hole in this node's
//! observations. [`Disposition`] makes each subsystem declare which it
//! is at its spawn site. Only the seccomp distributor is the first
//! kind, and it is not a corner case — `seccomp_distributor::run`
//! returns `Ok(())` immediately whenever `SECCOMP_DISTRIBUTE` is
//! unset, which is the **default** install. Alarming on that would cry
//! wolf on every cluster that has not opted in.
//!
//! ## What isolation must not quietly undo
//!
//! PR #1473 kept the eBPF handle inside `try_join!` deliberately: a
//! Controller whose eBPF loader has died is not degraded, it is blind,
//! and a blind Controller that stays up turns kguardian's core
//! guarantee (observed-absence means safe-to-deny) into a lie that
//! nothing marks. There is no readiness endpoint on this DaemonSet, so
//! a non-zero exit is the only signal that reaches an operator.
//!
//! The same argument covers a second signal that is easy to lose here.
//! `watch_service`, `watch_pods` and `reconcile_pods_task` each build a
//! kube client before their infinite loop, and each can `?` out of it
//! when the apiserver is unreachable at boot. Today that exits non-zero
//! and the kubelet backs off — and this DaemonSet has no liveness,
//! readiness or startup probe at all, so that CrashLoopBackOff is the
//! only thing an operator sees. Per-task supervision must not turn it
//! into an invisible in-process retry. That is why there is no
//! "degraded, keep running" disposition: [`Disposition::Required`]
//! preserves exactly the old fatality, the first subsystem to stop for
//! any reason ends the process non-zero. What changes is that a stall
//! no longer propagates, and that a clean stop is now caught too.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::time::Duration;

use tokio::task::{Id, JoinSet};
use tracing::{debug, error, info, warn};

use crate::error::Error;

/// How long `shutdown` waits for aborted subsystems to actually stop
/// before giving up and letting the process exit anyway.
///
/// Abort takes effect at a task's next await point, which for every
/// subsystem here is microseconds away. The bound exists for the case
/// that is not true — a task wedged inside a blocking call cannot be
/// aborted at all, and SIGTERM must not turn into "hang until the
/// kubelet sends SIGKILL" because of one of them.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// What a subsystem stopping means for the process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// The subsystem is meant to run for the life of the process. Any
    /// exit — `Ok(())` included — is a fault that ends the Controller
    /// non-zero.
    ///
    /// `Ok(())` is deliberately in that list. See the module docs: the
    /// three channel consumers return `Ok` on channel close, and under
    /// `try_join!` that produced a healthy-looking process with no
    /// ingestion.
    Required,
    /// The subsystem may legitimately return `Ok(())` and stop —
    /// its feature is switched off, or it has nothing to do on this
    /// node. `Err` and panics are still faults.
    ///
    /// Only the seccomp distributor is declared this way:
    /// `seccomp_distributor::run` returns `Ok(())` immediately unless
    /// `SECCOMP_DISTRIBUTE=true`, and has always been best-effort.
    MayRetire,
}

/// Declare the subsystem roster exactly once.
///
/// The enum, [`Subsystem::ALL`], [`Subsystem::name`] and
/// [`Subsystem::disposition`] are all generated from the single list in
/// the invocation below, because two hand-maintained lists drift. They
/// did: a variant added to the enum and declared `MayRetire` but left
/// out of a hand-written `ALL` passed clippy and all 203 tests, because
/// `only_the_seccomp_distributor_may_retire` sweeps `ALL` and cannot
/// see a variant that never reached it.
///
/// A test cannot close that, which is why this is a macro and not
/// another assertion. Any such test needs its own list of variants to
/// iterate, and that list drifts identically one level up; the
/// successor-chain and index-map shapes both let an author satisfy the
/// compiler's exhaustiveness check without ever linking the new variant
/// in. Rust has no stable way to enumerate an enum's variants, so the
/// only airtight fix is to stop having two lists.
macro_rules! subsystems {
    (
        $(
            $(#[$variant_doc:meta])*
            $variant:ident => $name:literal, $disposition:expr;
        )*
    ) => {
        /// Every supervised subsystem, and — via
        /// [`Subsystem::disposition`] — what its stopping means.
        ///
        /// A closed enum rather than a `(name, Disposition)` pair
        /// passed at each spawn site, because those literals were the
        /// part of this design with no defence at all. Mutation testing
        /// found it: flipping one word — `network-events` from
        /// `Required` to `MayRetire` — turns "this node has gone blind,
        /// exit non-zero" into "retired cleanly, the rest of the
        /// Controller continues", and the whole suite stayed green.
        ///
        /// That mutation is *reachable*, not theoretical. The eBPF
        /// loader drops the three event senders on its way out of
        /// `spawn_blocking`, so `handle_network_events` returns
        /// `Ok(())` immediately afterwards. One word would therefore
        /// have restored the exact hazard PR #1473 closed: a live,
        /// healthy-looking, permanently blind Controller.
        ///
        /// Making the disposition a property of the subsystem rather
        /// than an argument means it cannot be overridden where the
        /// future is spawned.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Subsystem {
            $(
                $(#[$variant_doc])*
                $variant,
            )*
        }

        impl Subsystem {
            /// Every subsystem, generated from the roster so it cannot
            /// drift from the enum. The disposition sweeps in the tests
            /// below are only ever as complete as this is.
            pub const ALL: &'static [Subsystem] = &[$(Subsystem::$variant),*];

            /// The name that appears in logs and in a [`Fault`].
            pub fn name(self) -> &'static str {
                match self {
                    $(Subsystem::$variant => $name,)*
                }
            }

            /// What this subsystem stopping means for the process.
            ///
            /// Generated from the roster, so adding a subsystem forces
            /// a deliberate answer to "and if this one stops?" at the
            /// point of declaration. There is nowhere for a new one to
            /// inherit a default from.
            pub fn disposition(self) -> Disposition {
                match self {
                    $(Subsystem::$variant => $disposition,)*
                }
            }
        }
    };
}

// The roster: one line per subsystem — variant, log name, and what its
// stopping means.
//
// Almost every entry is `Required`. These are capture, ingestion, and
// the correlation data that capture depends on; each runs until the
// process does, so any of them stopping is a hole in what this node
// observed, and observed-absence is what kguardian turns into "safe to
// deny".
//
// The `MayRetire` entries are the exceptions, and none of them is a
// corner case. Each is a feature an operator can switch off, and each
// returns `Ok(())` immediately when it is off — alarming on that would
// cry wolf on every cluster that has not opted in. `SeccompDistributor`
// is the clearest: `SECCOMP_DISTRIBUTE` is unset in the default install.
subsystems! {
    /// The pod watcher as `main` sees it; supervises the two below.
    PodWatcher => "pod-watcher", Disposition::Required;
    /// The streaming apiserver watch half of the pod watcher.
    PodWatchStream => "pod-watch-stream", Disposition::Required;
    /// The periodic re-list half — the safety net for the watch above.
    PodResync => "pod-resync", Disposition::Required;
    ServiceWatch => "service-watch", Disposition::Required;
    NetworkEvents => "network-events", Disposition::Required;
    SyscallEvents => "syscall-events", Disposition::Required;
    NetpolicyDropEvents => "netpolicy-drop-events", Disposition::Required;
    SyscallRecorder => "syscall-recorder", Disposition::Required;
    PodReconciler => "pod-reconciler", Disposition::Required;
    SeccompDistributor => "seccomp-distributor", Disposition::MayRetire;
    // Kernel seccomp verdicts (SECCOMP_DENIAL_CAPTURE, default on).
    // `MayRetire` because the ONLY clean exit is the operator switching
    // the feature off; a kernel that cannot carry the probe does NOT
    // retire, it keeps running and reports `capturing: false` every
    // interval so the broker can tell a blind node from a quiet one.
    SeccompDenials => "seccomp-denials", Disposition::MayRetire;
    // Compute gauges (COMPUTE_ENABLED, default on). `run` returns `Ok`
    // straight away when the feature is off; an `Err` is still fatal.
    ComputeSampler => "compute-sampler", Disposition::MayRetire;
    EbpfLoader => "ebpf-loader", Disposition::Required;
}

/// Why the supervisor is draining, which decides how loud a fault
/// recovered during the drain should be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Draining {
    /// The process is failing. Anything recovered here is part of the
    /// incident and is logged at `error` — it is frequently the root
    /// cause of whatever [`Supervisor::watch`] happened to report first.
    AfterFault,
    /// The process is stopping because it was asked to. A subsystem
    /// reporting an error while being told to stop is expected here:
    /// the eBPF poll loop returns `Err` *by design* once its shutdown
    /// flag is raised, and there is a window between raising it and
    /// aborting in which it does exactly that. Logging those at `error`
    /// would put a false `subsystem 'ebpf-loader' failed` line in an
    /// operator's logs on every single rolling restart.
    Gracefully,
}

/// Why supervision ended. Every variant is a reason to stop the
/// process; the distinction is what the operator gets told.
#[derive(Debug)]
pub enum Fault {
    /// A [`Disposition::Required`] subsystem returned `Ok(())`. The
    /// dangerous one: nothing else in the process notices, and it is
    /// how "no ingestion" used to masquerade as "healthy".
    Retired(&'static str),
    /// A subsystem returned `Err`.
    Failed(&'static str, Error),
    /// A subsystem's task ended without producing a value: it panicked,
    /// or it was aborted. Under `try_join!` a panic took the whole
    /// process down by unwinding the one shared task; spawned tasks
    /// capture the panic instead, so it has to be surfaced here or it
    /// would be swallowed.
    Crashed(&'static str, String),
    /// Every supervised subsystem has stopped. Only reachable if all of
    /// them were `MayRetire`, which is never true in `main`, but a
    /// supervisor with nothing left to supervise must not park forever.
    Exhausted,
}

impl Fault {
    /// Which subsystem this fault is about.
    pub fn subsystem(&self) -> &'static str {
        match self {
            Fault::Retired(name) | Fault::Failed(name, _) | Fault::Crashed(name, _) => name,
            Fault::Exhausted => "<all>",
        }
    }
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fault::Retired(name) => write!(
                f,
                "subsystem '{name}' returned Ok and stopped. It is required to run for the \
                 life of the process, so this node has stopped observing what it reports \
                 on; exiting rather than staying up with a silent hole in the data"
            ),
            Fault::Failed(name, e) => {
                write!(f, "subsystem '{name}' failed: {e}")
            }
            Fault::Crashed(name, detail) => {
                write!(f, "subsystem '{name}' ended without a result: {detail}")
            }
            Fault::Exhausted => write!(
                f,
                "every supervised subsystem has stopped; nothing is observing this node"
            ),
        }
    }
}

impl From<Fault> for Error {
    fn from(fault: Fault) -> Self {
        // Rendered rather than boxed: `main` returns this and the
        // `Termination` impl prints it, and that printed line plus the
        // non-zero exit code is the only channel an operator of this
        // DaemonSet has.
        Error::Custom(fault.to_string())
    }
}

/// What was spawned under a given task id.
struct Registered {
    name: &'static str,
    disposition: Disposition,
}

/// Runs each subsystem in its own task and reports the first fault.
///
/// The supervisor deliberately does **not** restart anything, and that
/// is a hard constraint of this codebase rather than a preference.
/// Three process-global pieces of state make in-process restart unsafe
/// today:
///
/// * `bpf::EBPF_SHUTDOWN` is a latch with no production reset. It is
///   tripped whenever a ring-buffer callback's `blocking_send` fails,
///   i.e. whenever any of the three event Receivers is dropped. Restart
///   a consumer task and the old receiver's drop latches it; every eBPF
///   task started afterwards then returns `Err` on its first loop
///   iteration. That is a hot restart loop, or permanent silent
///   blindness, depending on what the supervisor does next.
/// * `syscall`'s `SYSCALL_CACHE` and `LAST_SENT_CACHE` are
///   `lazy_static` and outlive task death, and
///   `send_syscall_cache_periodically` documents itself as their only
///   writer. Two instances overlapping for even one tick — easy to
///   write with a `JoinSet` that starts a replacement before the
///   predecessor has *observably* terminated — race the diff and mark
///   syscalls last-sent that were never posted, which is the shape of
///   the bug that comment records fixing.
/// * The eBPF loader is a `spawn_blocking` that owns the
///   `PodRegistration` and ignore-IP Receivers, whose senders live in
///   `watch_pods`. `JoinSet::abort` has no effect on a blocking task,
///   so those channels cannot be re-wired for a restarted watcher.
///
/// Beyond those, every subsystem owns kernel or cluster state that a
/// restart cannot rebuild in place (eBPF maps and their inode
/// registrations, the watch resource version, the syscall diff cache),
/// so "restart the subsystem" and "restart the pod" are the same
/// operation with the second one being the honest, visible version of
/// it. Reporting a fault and exiting is therefore the whole policy.
pub struct Supervisor {
    set: JoinSet<Result<(), Error>>,
    registry: HashMap<Id, Registered>,
}

impl Default for Supervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl Supervisor {
    pub fn new() -> Self {
        Self {
            set: JoinSet::new(),
            registry: HashMap::new(),
        }
    }

    /// Spawn `future` as the given subsystem's own task.
    ///
    /// Its own task is the entire point — see the module docs. Anything
    /// composed into one task with `join!`/`try_join!` shares a worker
    /// and a cooperative budget with its siblings and is not isolated
    /// from them at all.
    ///
    /// Takes a [`Subsystem`], not a name and a disposition, so the
    /// call site cannot decide that a capture subsystem is allowed to
    /// retire. See `Subsystem` for the mutation that motivated it.
    pub fn spawn<F>(&mut self, subsystem: Subsystem, future: F)
    where
        F: Future<Output = Result<(), Error>> + Send + 'static,
    {
        self.spawn_raw(subsystem.name(), subsystem.disposition(), future)
    }

    /// `spawn` with the name and disposition supplied directly.
    ///
    /// Private, and that is the whole protection: `main` and
    /// `pod_watcher` live in other modules, so the only way they can
    /// start a subsystem is `spawn` above, which carries the
    /// disposition table with it. The tests need to conjure subsystems
    /// that are not in the roster ("blocker", "heartbeat"), which is
    /// the only reason this exists.
    fn spawn_raw<F>(&mut self, name: &'static str, disposition: Disposition, future: F)
    where
        F: Future<Output = Result<(), Error>> + Send + 'static,
    {
        let handle = self.set.spawn(future);
        self.registry
            .insert(handle.id(), Registered { name, disposition });
        info!(subsystem = name, ?disposition, "subsystem started");
    }

    /// Number of subsystems still running.
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// True once nothing is left to supervise.
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Resolve with the first fault.
    ///
    /// A `MayRetire` subsystem returning `Ok(())` is logged and skipped;
    /// everything else resolves. Cancel-safe: `join_next_with_id` is,
    /// and the registry is only ever read here, so `main` can hold this
    /// in a `select!` against SIGTERM without losing a task.
    pub async fn watch(&mut self) -> Fault {
        loop {
            let Some(joined) = self.set.join_next_with_id().await else {
                return Fault::Exhausted;
            };

            match joined {
                Ok((id, Ok(()))) => {
                    let (name, disposition) = self.identify(id);
                    match disposition {
                        Disposition::MayRetire => {
                            info!(
                                subsystem = name,
                                "subsystem retired cleanly (declared optional); the rest \
                                 of the Controller continues"
                            );
                            continue;
                        }
                        // The hole `try_join!` left open. Not an error
                        // anywhere in the code, and that is exactly why
                        // it went unnoticed: the subsystem "succeeded".
                        Disposition::Required => return Fault::Retired(name),
                    }
                }
                Ok((id, Err(e))) => {
                    let (name, _) = self.identify(id);
                    return Fault::Failed(name, e);
                }
                Err(join_error) => {
                    let (name, _) = self.identify(join_error.id());
                    return Fault::Crashed(name, join_error.to_string());
                }
            }
        }
    }

    /// Abort every subsystem, wait briefly for them to stop, and
    /// return any hard faults that had already happened.
    ///
    /// The return value is not bookkeeping — it is how the root cause
    /// survives a race. When the eBPF loader dies, its `Err` and the
    /// consumers' "channel closed, so return `Ok`" become ready at
    /// almost the same instant: the loader's blocking closure drops the
    /// senders on its way out, which wakes the consumers, and only then
    /// does its `JoinHandle` resolve. Whichever [`watch`](Self::watch)
    /// happens to see first is what `main` reports, so without this the
    /// operator could get "subsystem 'network-events' returned Ok" and
    /// never see the loader's error at all. That would make an eBPF
    /// death *quieter* than it was under `try_join!`, which is the one
    /// thing this change must not do. Aborting does not discard results
    /// that are already queued, so draining recovers them.
    ///
    /// Bounded on purpose: see [`SHUTDOWN_GRACE`].
    pub async fn shutdown(&mut self, draining: Draining) -> Vec<Fault> {
        self.set.abort_all();

        // Collected rather than resolved in place: the drain holds a
        // mutable borrow of the JoinSet, and naming a subsystem needs
        // the registry.
        let mut raw: Vec<(Id, Result<Error, String>)> = Vec::new();
        let set = &mut self.set;
        let sink = &mut raw;
        let drain = async {
            while let Some(joined) = set.join_next_with_id().await {
                match joined {
                    Ok((_, Ok(()))) => {}
                    Ok((id, Err(e))) => sink.push((id, Ok(e))),
                    // A task we just aborted is not a fault; anything
                    // else that ended without a value is.
                    Err(je) if je.is_cancelled() => {}
                    Err(je) => sink.push((je.id(), Err(je.to_string()))),
                }
            }
        };

        let stopped = tokio::time::timeout(SHUTDOWN_GRACE, drain).await.is_ok();
        if stopped {
            info!("all subsystems stopped");
        } else {
            // Only reachable if a task is wedged somewhere it cannot be
            // cancelled — i.e. a blocking call on a worker thread. Say
            // so; that is a bug worth a line in the logs of a pod that
            // is on its way out anyway.
            warn!(
                grace_secs = SHUTDOWN_GRACE.as_secs(),
                still_running = self.set.len(),
                "some subsystems did not stop within the shutdown grace period; \
                 exiting anyway"
            );
        }

        raw.into_iter()
            .map(|(id, outcome)| {
                let (name, _) = self.identify(id);
                let fault = match outcome {
                    Ok(e) => Fault::Failed(name, e),
                    Err(detail) => Fault::Crashed(name, detail),
                };
                match draining {
                    Draining::AfterFault => error!("{fault}"),
                    // Expected, not alarming: see `Draining::Gracefully`.
                    Draining::Gracefully => debug!("while stopping: {fault}"),
                }
                fault
            })
            .collect()
    }

    /// Map a task id back to what was spawned under it.
    ///
    /// The registry is populated at spawn time and never pruned, so a
    /// miss is impossible; fall back to a placeholder rather than
    /// panicking inside the code path whose whole job is reporting that
    /// something went wrong.
    fn identify(&self, id: Id) -> (&'static str, Disposition) {
        match self.registry.get(&id) {
            Some(r) => (r.name, r.disposition),
            None => ("<unregistered>", Disposition::Required),
        }
    }
}

/// Stop the Controller: tell the eBPF poll loop to exit, then abort and
/// drain everything else.
///
/// The order is the entire function, which is why it is a function and
/// not two lines in `main`. The poll loop lives in a `spawn_blocking`
/// that nothing can cancel — `JoinSet::abort_all` reaches the async
/// task awaiting its `JoinHandle`, not the blocking task — and dropping
/// the runtime afterwards waits for it with no timeout (tokio 1.53.1:
/// `BlockingPool::drop` → `shutdown(None)` → `shutdown_rx.wait(None)`).
/// Raising the flag first is therefore the only thing that lets this
/// process exit at all, and doing it second would not help: by then
/// nothing is left to notice.
///
/// Before this was reachable from outside `bpf`, the flag went up only
/// when a `blocking_send` failed against a dropped receiver — which
/// needs an eBPF event to arrive. Under traffic that is instant; on an
/// idle node no event fires and SIGTERM hung until the kubelet's
/// SIGKILL.
pub async fn shut_down(supervisor: &mut Supervisor, draining: Draining) -> Vec<Fault> {
    crate::bpf::signal_ebpf_shutdown();
    supervisor.shutdown(draining).await
}

/// Log a fault at the volume it deserves and convert it into the error
/// `main` returns.
///
/// Split out from `main` so the mapping is testable: the property that
/// matters is that *every* fault, including a clean `Ok` retirement,
/// yields an `Err` — which is what makes the process exit non-zero and
/// the kubelet restart the pod.
pub fn report(fault: Fault) -> Error {
    error!("{fault}");
    Error::from(fault)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    /// How long the "blocking" subsystem hogs its worker, and how long
    /// after starting it we look at the heartbeat. The gap matters:
    /// the observation must land *while* the block is in progress,
    /// because once it ends the pending timer fires immediately and a
    /// frozen-then-thawed heartbeat looks identical to one that never
    /// froze.
    const BLOCK_FOR: Duration = Duration::from_millis(600);
    const OBSERVE_AT: Duration = Duration::from_millis(250);
    const HEARTBEAT_EVERY: Duration = Duration::from_millis(10);

    /// A subsystem that does nothing but prove it is being polled.
    async fn ticker(counter: Arc<AtomicU64>) -> Result<(), Error> {
        loop {
            tokio::time::sleep(HEARTBEAT_EVERY).await;
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A subsystem that makes the mistake this whole change exists to
    /// contain: real blocking work on a runtime worker. `container.rs`
    /// had the async equivalent — an unbounded await on a hung peer —
    /// which wedges the task just as thoroughly.
    async fn blocker(entered: Arc<AtomicBool>) -> Result<(), Error> {
        entered.store(true, Ordering::Relaxed);
        std::thread::sleep(BLOCK_FOR);
        std::future::pending::<Result<(), Error>>().await
    }

    /// The defect, pinned, in the exact shape `main` had it. Kept next
    /// to the fix so the fix cannot quietly become a tautology: if
    /// someone recomposes the subsystems into one task, this test still
    /// passes and the next one fails, which is the right way round.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn try_join_lets_one_blocking_subsystem_freeze_every_sibling() {
        let ticks = Arc::new(AtomicU64::new(0));
        let entered = Arc::new(AtomicBool::new(false));

        // ONE task holding both futures — what `try_join!` builds.
        let joined = tokio::spawn({
            let ticks = Arc::clone(&ticks);
            let entered = Arc::clone(&entered);
            async move {
                // Heartbeat first so it is polled first and has its
                // timer armed before the sibling seizes the worker.
                let _ = tokio::try_join!(ticker(ticks), blocker(entered));
            }
        });

        tokio::time::sleep(OBSERVE_AT).await;

        assert!(
            entered.load(Ordering::Relaxed),
            "the blocking subsystem must actually have started, or this test proves nothing"
        );
        assert_eq!(
            ticks.load(Ordering::Relaxed),
            0,
            "a sibling in the same task cannot be polled while another future blocks the \
             worker, no matter how many workers are idle — this is #1346"
        );

        joined.abort();
    }

    /// The fix, proven: same blocking subsystem, same runtime, same
    /// wall-clock window — and the sibling keeps running.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_blocking_subsystem_does_not_freeze_its_siblings() {
        let ticks = Arc::new(AtomicU64::new(0));
        let entered = Arc::new(AtomicBool::new(false));

        let mut sup = Supervisor::new();
        sup.spawn_raw(
            "heartbeat",
            Disposition::Required,
            ticker(Arc::clone(&ticks)),
        );
        sup.spawn_raw(
            "blocker",
            Disposition::Required,
            blocker(Arc::clone(&entered)),
        );

        tokio::time::sleep(OBSERVE_AT).await;

        assert!(
            entered.load(Ordering::Relaxed),
            "the blocking subsystem must actually have started"
        );
        let ticked = ticks.load(Ordering::Relaxed);
        assert!(
            ticked > 0,
            "a blocking subsystem must not stop its siblings once each has its own task; \
             heartbeat ticked {ticked} times in {OBSERVE_AT:?}"
        );

        sup.shutdown(Draining::AfterFault).await;
    }

    /// The other half of #1346: a required subsystem that returns
    /// `Ok(())` — the channel-close path in `handle_syscall_events`,
    /// `handle_network_events` and `handle_policy_drop_events` — must
    /// be reported. (Named, not cited by line: the line numbers in the
    /// issue had already rotted by the time this was written.)
    #[tokio::test]
    async fn a_required_subsystem_returning_ok_is_a_fault() {
        let mut sup = Supervisor::new();
        sup.spawn_raw("network-events", Disposition::Required, async {
            // Exactly what those consumers do when their channel closes.
            Ok(())
        });
        sup.spawn_raw("ebpf", Disposition::Required, async {
            std::future::pending().await
        });

        match sup.watch().await {
            Fault::Retired("network-events") => {}
            other => panic!("expected a Retired fault naming the subsystem, got {other:?}"),
        }
        sup.shutdown(Draining::AfterFault).await;
    }

    /// And the same clean `Ok` under `try_join!`: nothing happens at
    /// all. This is the pre-fix behaviour, pinned — a process that
    /// looks perfectly healthy and ingests nothing.
    #[tokio::test]
    async fn try_join_never_notices_a_subsystem_that_retires_cleanly() {
        let joined = async {
            tokio::try_join!(async { Ok::<(), Error>(()) }, async {
                std::future::pending::<Result<(), Error>>().await
            },)
        };
        let mut joined = std::pin::pin!(joined);

        assert!(
            futures::poll!(joined.as_mut()).is_pending(),
            "try_join! short-circuits only on Err: a capture subsystem that returns Ok and \
             stops leaves the join parked forever with no signal to anyone"
        );
    }

    /// A subsystem that is allowed to retire (the seccomp distributor
    /// with `SECCOMP_DISTRIBUTE` unset) must not take the process down,
    /// and must not stop the supervisor watching the others.
    #[tokio::test]
    async fn an_optional_subsystem_may_retire_without_faulting() {
        let mut sup = Supervisor::new();
        sup.spawn_raw("seccomp-distributor", Disposition::MayRetire, async {
            Ok(())
        });
        sup.spawn_raw("ebpf", Disposition::Required, async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            Err(Error::Custom("loader died".into()))
        });

        match sup.watch().await {
            Fault::Failed("ebpf", _) => {}
            other => panic!("the optional retirement should have been skipped, got {other:?}"),
        }
    }

    /// eBPF loader death stays fatal. PR #1473's guarantee, restated as
    /// a test: the loader stopping must produce an `Err` out of `main`,
    /// which is the non-zero exit and the pod restart. "Isolated" must
    /// never mean "survivable".
    #[tokio::test]
    async fn ebpf_death_still_ends_the_process() {
        for fault in [
            Fault::Failed("ebpf", Error::Custom("ring buffer poll failed".into())),
            // Even a *clean* stop: a loader that returns Ok has still
            // left this node blind.
            Fault::Retired("ebpf"),
            Fault::Crashed("ebpf", "task 7 panicked".into()),
        ] {
            let rendered = fault.to_string();
            let err = report(fault);
            assert!(
                matches!(err, Error::Custom(_)),
                "every fault must convert into an error main can return, so the process \
                 exits non-zero: there is no readiness endpoint on this DaemonSet"
            );
            assert!(
                err.to_string().contains("ebpf"),
                "the operator must be told which subsystem died: {rendered}"
            );
        }
    }

    /// A panic in a spawned task is captured by the task, not by the
    /// process. Under `try_join!` it unwound the shared task and took
    /// the process with it; isolation must not turn that into silence.
    #[tokio::test]
    async fn a_panicking_subsystem_is_reported_rather_than_swallowed() {
        let mut sup = Supervisor::new();
        sup.spawn_raw("syscall-events", Disposition::Required, async {
            panic!("inode map poisoned");
        });

        match sup.watch().await {
            Fault::Crashed("syscall-events", detail) => {
                assert!(detail.contains("panic"), "detail should say so: {detail}");
            }
            other => panic!("expected Crashed, got {other:?}"),
        }
    }

    /// SIGTERM. `main` selects between `watch()` and the signal; this
    /// pins both halves: the supervisor yields to the shutdown branch
    /// even with every subsystem running, and `shutdown()` then really
    /// stops them, promptly.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shutdown_is_prompt_and_actually_stops_the_subsystems() {
        let ticks = Arc::new(AtomicU64::new(0));
        let mut sup = Supervisor::new();
        for name in ["pod-watch", "service-watch", "network-events"] {
            sup.spawn_raw(name, Disposition::Required, ticker(Arc::clone(&ticks)));
        }

        // Let them get going, so "stopped" is a real observation.
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(ticks.load(Ordering::Relaxed) > 0, "subsystems must be live");

        // `biased` polls the supervisor first, so the shutdown branch
        // only wins if `watch()` genuinely yielded.
        let winner = tokio::select! {
            biased;
            _ = sup.watch() => "fault",
            _ = std::future::ready(()) => "sigterm",
        };
        assert_eq!(
            winner, "sigterm",
            "supervision must not starve main's shutdown branch"
        );

        let started = tokio::time::Instant::now();
        assert!(
            sup.shutdown(Draining::AfterFault).await.is_empty(),
            "cancelling a healthy subsystem is not a fault and must not be reported as one"
        );
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "SIGTERM must not wait on the grace period when nothing is wedged; took {:?}",
            started.elapsed()
        );

        let after = ticks.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(
            ticks.load(Ordering::Relaxed),
            after,
            "a shut-down subsystem must stop doing work, not merely stop being awaited"
        );
    }

    /// The race that could have made an eBPF death quieter than
    /// `try_join!` made it.
    ///
    /// The loader's `Err` and a consumer's channel-close `Ok` become
    /// ready together — the loader drops the event senders on its way
    /// out, which is exactly what closes the consumers' channels. If
    /// the consumer wins, `watch` reports "network-events returned Ok"
    /// and the loader's error would never be printed at all. The drain
    /// in `shutdown` is what makes sure it is.
    #[tokio::test]
    async fn the_ebpf_failure_is_surfaced_even_when_a_consumer_is_reported_first() {
        let mut sup = Supervisor::new();
        sup.spawn_raw("network-events", Disposition::Required, async { Ok(()) });
        sup.spawn_raw("ebpf-loader", Disposition::Required, async {
            Err(Error::Custom(
                "ring buffer poll failed 50 times consecutively".into(),
            ))
        });

        // Let both finish, so both outcomes are queued and the order
        // `watch` sees them in is genuinely arbitrary.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let reported = sup.watch().await;
        let also = sup.shutdown(Draining::AfterFault).await;

        let named: Vec<&'static str> = std::iter::once(reported.subsystem())
            .chain(also.iter().map(Fault::subsystem))
            .collect();
        assert!(
            named.contains(&"ebpf-loader"),
            "the loader's death must reach the operator whichever subsystem was reported \
             first; got {named:?}"
        );
    }

    /// `SHUTDOWN_GRACE` is a ceiling on how long SIGTERM can take, and
    /// it has to sit inside the kubelet's termination window — this
    /// DaemonSet sets no `terminationGracePeriodSeconds`, so that
    /// window is the 30s default. A grace at or past 30s is not a grace
    /// period, it is "wait for SIGKILL", which is exactly the behaviour
    /// the idle-node shutdown fix exists to remove.
    ///
    /// Guarded because the value is asserted nowhere else: mutation
    /// testing set it to an hour with the whole suite green.
    #[test]
    fn the_shutdown_grace_stays_inside_the_kubelet_termination_window() {
        assert!(
            SHUTDOWN_GRACE < Duration::from_secs(30),
            "a {SHUTDOWN_GRACE:?} grace exceeds the kubelet's default 30s window, so \
             shutdown would end in SIGKILL rather than in this code"
        );
    }

    // ---- the disposition table ----
    //
    // These exist because mutation testing found the table's spawn
    // sites completely unprotected: flipping `network-events` to
    // `MayRetire` left every other test in this crate green while
    // turning "this node is blind, exit" into "retired cleanly, carry
    // on". The disposition now lives on `Subsystem` rather than at the
    // call site, and these pin the table it reads.

    /// `SeccompDenials` is deliberately NOT in this list, and the
    /// distinction is worth stating because the name says "capture".
    ///
    /// What makes the subsystems below `Required` is that nothing can
    /// legitimately stop them: they run until the process does, so an
    /// exit is a hole in what this node observed. Denial capture has one
    /// legitimate stop — `SECCOMP_DENIAL_CAPTURE=false`, an operator
    /// switching the feature off — which is the same shape as the
    /// distributor and the compute sampler.
    ///
    /// The case that looks like it belongs here is a kernel without
    /// `audit_seccomp`, and that one is covered without `Required`:
    /// `seccomp_denial::run` does not retire there. It keeps ticking and
    /// posts `capturing: false` every interval, so the broker marks the
    /// node not-capturing and the workload reads `Unknown` rather than a
    /// false all-clear. Making this `Required` would instead exit the
    /// whole Controller on every CONFIG_AUDITSYSCALL=n node, which is
    /// the crash-loop the probe's degradation path exists to avoid.
    #[test]
    fn every_capture_subsystem_is_required() {
        for subsystem in [
            Subsystem::EbpfLoader,
            Subsystem::NetworkEvents,
            Subsystem::SyscallEvents,
            Subsystem::NetpolicyDropEvents,
            Subsystem::SyscallRecorder,
            Subsystem::PodWatcher,
            Subsystem::PodWatchStream,
            Subsystem::PodResync,
            Subsystem::ServiceWatch,
            Subsystem::PodReconciler,
        ] {
            assert_eq!(
                subsystem.disposition(),
                Disposition::Required,
                "'{}' stopping means this node stops observing something, so it must end \
                 the process. Logging 'retired cleanly' and carrying on is the hazard PR \
                 #1473 closed.",
                subsystem.name()
            );
        }
    }

    /// The non-tautological half: sweep the whole roster, so a variant
    /// flipped to `MayRetire` — or a newly added subsystem declared
    /// that way — fails here rather than shipping.
    #[test]
    fn only_switchable_features_may_retire() {
        let retiring: Vec<&'static str> = Subsystem::ALL
            .iter()
            .copied()
            .filter(|s| s.disposition() == Disposition::MayRetire)
            .map(Subsystem::name)
            .collect();
        assert_eq!(
            retiring,
            vec!["seccomp-distributor", "seccomp-denials", "compute-sampler"],
            "only subsystems that are features an operator can switch off may retire; \
             everything else is capture and must be Required"
        );
    }

    /// Names reach logs and faults, and `main`'s roster is read by
    /// humans during an incident. Two subsystems sharing one would make
    /// a fault report ambiguous about which thing actually died.
    #[test]
    fn subsystem_names_are_unique() {
        let mut names: Vec<&'static str> = Subsystem::ALL
            .iter()
            .copied()
            .map(Subsystem::name)
            .collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total, "duplicate subsystem name in the roster");
    }

    /// A supervisor with nothing left to supervise must resolve rather
    /// than park: `JoinSet::join_next` yields `None` on an empty set,
    /// and parking on that would be the same silent-healthy-process
    /// failure in a different disguise.
    #[tokio::test]
    async fn an_empty_supervisor_faults_rather_than_parking() {
        let mut sup = Supervisor::new();
        sup.spawn_raw("seccomp-distributor", Disposition::MayRetire, async {
            Ok(())
        });
        assert!(matches!(sup.watch().await, Fault::Exhausted));
    }
}
