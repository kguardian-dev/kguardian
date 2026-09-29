use super::*;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

// ---------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------

#[derive(Clone)]
struct FakeClock {
    mono: Rc<Cell<Duration>>,
    /// Wall-clock offset, to model a node whose clock is wrong.
    skew_secs: i64,
}

impl FakeClock {
    fn new() -> Self {
        Self {
            mono: Rc::new(Cell::new(Duration::from_secs(1000))),
            skew_secs: 0,
        }
    }
    fn skewed(&self, secs: i64) -> Self {
        Self {
            mono: self.mono.clone(),
            skew_secs: secs,
        }
    }
    fn advance(&self, secs: u64) {
        self.mono.set(self.mono.get() + Duration::from_secs(secs));
    }
}

impl Clock for FakeClock {
    fn mono(&self) -> Duration {
        self.mono.get()
    }
    fn wall(&self) -> DateTime<Utc> {
        DateTime::from_timestamp(
            1_790_000_000 + self.mono.get().as_secs() as i64 + self.skew_secs,
            0,
        )
        .unwrap()
    }
}

#[derive(Default)]
struct FakeState {
    lease: Option<Lease>,
    rv: u64,
    /// Errors to return from the next calls, in order, before touching state.
    fail: VecDeque<LeaseError>,
    /// Simulate a concurrent writer landing between our get and replace.
    race_next_replace: bool,
    replaces: u32,
}

/// An in-memory Lease API with real resourceVersion semantics. Cloning
/// shares the store, so two electors can contend for one lease.
#[derive(Clone, Default)]
struct FakeApi(Rc<RefCell<FakeState>>);

impl FakeApi {
    fn lease(&self) -> Option<Lease> {
        self.0.borrow().lease.clone()
    }
    fn fail_next(&self, e: LeaseError) {
        self.0.borrow_mut().fail.push_back(e);
    }
    fn take_failure(&self) -> Result<(), LeaseError> {
        match self.0.borrow_mut().fail.pop_front() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
    fn stamp(&self, mut lease: Lease) -> Lease {
        let mut s = self.0.borrow_mut();
        s.rv += 1;
        lease.metadata.resource_version = Some(s.rv.to_string());
        s.lease = Some(lease.clone());
        lease
    }
}

impl LeaseApi for FakeApi {
    async fn get(&self) -> Result<Option<Lease>, LeaseError> {
        self.take_failure()?;
        Ok(self.lease())
    }
    async fn create(&self, lease: &Lease) -> Result<Lease, LeaseError> {
        self.take_failure()?;
        if self.lease().is_some() {
            return Err(LeaseError::Conflict);
        }
        Ok(self.stamp(lease.clone()))
    }
    async fn replace(&self, lease: &Lease) -> Result<Lease, LeaseError> {
        self.take_failure()?;
        {
            let mut s = self.0.borrow_mut();
            s.replaces += 1;
            if std::mem::take(&mut s.race_next_replace) {
                s.rv += 1;
                let rv = s.rv.to_string();
                if let Some(l) = s.lease.as_mut() {
                    l.metadata.resource_version = Some(rv);
                }
            }
            let current = s.lease.as_ref().ok_or(LeaseError::Conflict)?;
            if current.metadata.resource_version != lease.metadata.resource_version {
                return Err(LeaseError::Conflict);
            }
        }
        Ok(self.stamp(lease.clone()))
    }
}

const LEASE: Duration = Duration::from_secs(15);

fn elector(api: &FakeApi, clock: &FakeClock, id: &str) -> Elector<FakeApi, FakeClock> {
    Elector::new(api.clone(), clock.clone(), id, "broker-leader", LEASE)
}

fn held_by(api: &FakeApi, holder: &str) -> Lease {
    let mut l = Lease::named("broker-leader");
    l.spec.holder_identity = Some(holder.into());
    l.spec.lease_duration_seconds = Some(15);
    l.spec.lease_transitions = Some(4);
    api.stamp(l)
}

// ---------------------------------------------------------------------
// Elector state machine
// ---------------------------------------------------------------------

#[tokio::test]
async fn acquires_by_creating_an_absent_lease() {
    let (api, clock) = (FakeApi::default(), FakeClock::new());
    let mut a = elector(&api, &clock, "broker-a");
    assert_eq!(a.try_acquire_or_renew().await, Ok(Attempt::Leading));
    let l = api.lease().unwrap();
    assert_eq!(l.holder(), Some("broker-a"));
    assert_eq!(l.spec.lease_duration_seconds, Some(15));
    assert_eq!(l.spec.lease_transitions, Some(0));
    assert!(l.spec.acquire_time.is_some() && l.spec.renew_time.is_some());
    assert_eq!(l.kind, "Lease");
    assert_eq!(l.api_version, "coordination.k8s.io/v1");
}

#[tokio::test]
async fn losing_the_create_race_is_a_conflict_not_leadership() {
    let (api, clock) = (FakeApi::default(), FakeClock::new());
    let mut a = elector(&api, &clock, "broker-a");
    let b = elector(&api, &clock, "broker-b");
    // b reads "absent" then a creates before b does.
    let get_absent = b.api.get().await.unwrap();
    assert!(get_absent.is_none());
    assert_eq!(a.try_acquire_or_renew().await, Ok(Attempt::Leading));
    let mut l = Lease::named("broker-leader");
    l.spec.holder_identity = Some("broker-b".into());
    assert_eq!(b.api.create(&l).await, Err(LeaseError::Conflict));
    assert_eq!(api.lease().unwrap().holder(), Some("broker-a"));
}

#[tokio::test]
async fn does_not_take_a_fresh_lease_held_by_another() {
    let (api, clock) = (FakeApi::default(), FakeClock::new());
    held_by(&api, "broker-a");
    let mut b = elector(&api, &clock, "broker-b");
    assert_eq!(
        b.try_acquire_or_renew().await,
        Ok(Attempt::Following {
            holder: "broker-a".into()
        })
    );
    clock.advance(14);
    assert!(matches!(
        b.try_acquire_or_renew().await,
        Ok(Attempt::Following { .. })
    ));
    assert_eq!(api.0.borrow().replaces, 0, "a follower never writes");
}

#[tokio::test]
async fn acquires_an_expired_lease_and_counts_the_transition() {
    let (api, clock) = (FakeApi::default(), FakeClock::new());
    held_by(&api, "broker-a");
    let mut b = elector(&api, &clock, "broker-b");
    assert!(matches!(
        b.try_acquire_or_renew().await,
        Ok(Attempt::Following { .. })
    ));
    // The holder died: the record stops changing for a full lease duration.
    clock.advance(15);
    assert_eq!(b.try_acquire_or_renew().await, Ok(Attempt::Leading));
    let l = api.lease().unwrap();
    assert_eq!(l.holder(), Some("broker-b"));
    assert_eq!(l.spec.lease_transitions, Some(5));
}

#[tokio::test]
async fn a_renewing_holder_keeps_the_lease_indefinitely() {
    let (api, clock) = (FakeApi::default(), FakeClock::new());
    let mut a = elector(&api, &clock, "broker-a");
    let mut b = elector(&api, &clock, "broker-b");
    assert_eq!(a.try_acquire_or_renew().await, Ok(Attempt::Leading));
    for _ in 0..30 {
        clock.advance(2);
        assert_eq!(a.try_acquire_or_renew().await, Ok(Attempt::Leading));
        assert!(matches!(
            b.try_acquire_or_renew().await,
            Ok(Attempt::Following { .. })
        ));
    }
    let l = api.lease().unwrap();
    assert_eq!(l.holder(), Some("broker-a"));
    assert_eq!(
        l.spec.lease_transitions,
        Some(0),
        "renewals are not transitions"
    );
}

#[tokio::test]
async fn renew_keeps_acquire_time_and_moves_renew_time() {
    let (api, clock) = (FakeApi::default(), FakeClock::new());
    let mut a = elector(&api, &clock, "broker-a");
    a.try_acquire_or_renew().await.unwrap();
    let first = api.lease().unwrap();
    clock.advance(2);
    a.try_acquire_or_renew().await.unwrap();
    let second = api.lease().unwrap();
    assert_eq!(first.spec.acquire_time, second.spec.acquire_time);
    assert_ne!(first.spec.renew_time, second.spec.renew_time);
    assert_ne!(
        first.metadata.resource_version,
        second.metadata.resource_version
    );
}

#[tokio::test]
async fn a_concurrent_write_makes_the_replace_conflict_never_overwrite() {
    let (api, clock) = (FakeApi::default(), FakeClock::new());
    let mut a = elector(&api, &clock, "broker-a");
    a.try_acquire_or_renew().await.unwrap();
    api.0.borrow_mut().race_next_replace = true;
    assert_eq!(a.try_acquire_or_renew().await, Err(LeaseError::Conflict));
    // Nothing was written over the concurrent version.
    assert_eq!(api.0.borrow().rv, 2);
}

#[tokio::test]
async fn a_takeover_race_has_exactly_one_winner() {
    let (api, clock) = (FakeApi::default(), FakeClock::new());
    held_by(&api, "dead");
    let mut b = elector(&api, &clock, "broker-b");
    let mut c = elector(&api, &clock, "broker-c");
    b.try_acquire_or_renew().await.unwrap();
    c.try_acquire_or_renew().await.unwrap();
    clock.advance(16);
    assert_eq!(b.try_acquire_or_renew().await, Ok(Attempt::Leading));
    // c read the same expired record b did; its replace must lose, and
    // its next read sees b's fresh write.
    let stale = {
        let mut l = api.lease().unwrap();
        l.metadata.resource_version = Some("1".into());
        l.spec.holder_identity = Some("broker-c".into());
        l
    };
    assert_eq!(c.api.replace(&stale).await, Err(LeaseError::Conflict));
    assert!(matches!(
        c.try_acquire_or_renew().await,
        Ok(Attempt::Following { holder }) if holder == "broker-b"
    ));
}

#[tokio::test]
async fn a_restarted_container_with_the_same_pod_name_resumes_at_once() {
    let (api, clock) = (FakeApi::default(), FakeClock::new());
    held_by(&api, "broker-a");
    let mut a = elector(&api, &clock, "broker-a");
    assert_eq!(a.try_acquire_or_renew().await, Ok(Attempt::Leading));
    assert_eq!(api.lease().unwrap().spec.lease_transitions, Some(4));
}

#[tokio::test]
async fn release_clears_the_holder_and_a_follower_takes_over_immediately() {
    let (api, clock) = (FakeApi::default(), FakeClock::new());
    let mut a = elector(&api, &clock, "broker-a");
    let mut b = elector(&api, &clock, "broker-b");
    a.try_acquire_or_renew().await.unwrap();
    assert!(matches!(
        b.try_acquire_or_renew().await,
        Ok(Attempt::Following { .. })
    ));
    assert_eq!(a.release().await, Ok(true));
    let l = api.lease().unwrap();
    assert_eq!(l.holder(), None);
    assert_eq!(l.spec.lease_duration_seconds, Some(1));
    assert_eq!(l.spec.lease_transitions, Some(0));
    // No lease-duration wait.
    assert_eq!(b.try_acquire_or_renew().await, Ok(Attempt::Leading));
    assert_eq!(api.lease().unwrap().spec.lease_transitions, Some(1));
    // Releasing twice is a no-op.
    assert_eq!(a.release().await, Ok(false));
}

#[tokio::test]
async fn release_never_clears_a_lease_someone_else_took() {
    let (api, clock) = (FakeApi::default(), FakeClock::new());
    let mut a = elector(&api, &clock, "broker-a");
    a.try_acquire_or_renew().await.unwrap();
    // b took it over while a was partitioned.
    let mut l = api.lease().unwrap();
    l.spec.holder_identity = Some("broker-b".into());
    api.stamp(l);
    assert_eq!(a.release().await, Err(LeaseError::Conflict));
    assert_eq!(api.lease().unwrap().holder(), Some("broker-b"));
}

#[tokio::test]
async fn a_follower_that_never_held_releases_nothing() {
    let (api, clock) = (FakeApi::default(), FakeClock::new());
    held_by(&api, "broker-a");
    let mut b = elector(&api, &clock, "broker-b");
    b.try_acquire_or_renew().await.unwrap();
    assert_eq!(b.release().await, Ok(false));
    assert_eq!(api.lease().unwrap().holder(), Some("broker-a"));
}

#[tokio::test]
async fn expiry_uses_the_local_clock_so_wall_clock_skew_cannot_steal_a_lease() {
    let (api, base) = (FakeApi::default(), FakeClock::new());
    // The holder's node clock is an hour behind: its renewTime looks
    // ancient to everyone else.
    let mut a = Elector::new(
        api.clone(),
        base.skewed(-3600),
        "broker-a",
        "broker-leader",
        LEASE,
    );
    // The follower's node clock is an hour ahead.
    let mut b = Elector::new(
        api.clone(),
        base.skewed(3600),
        "broker-b",
        "broker-leader",
        LEASE,
    );
    a.try_acquire_or_renew().await.unwrap();
    for _ in 0..10 {
        base.advance(2);
        a.try_acquire_or_renew().await.unwrap();
        assert!(matches!(
            b.try_acquire_or_renew().await,
            Ok(Attempt::Following { .. })
        ));
    }
    // And a renewTime from the future does not pin a dead holder forever.
    let mut l = api.lease().unwrap();
    l.spec.renew_time = Some("2999-01-01T00:00:00.000000Z".into());
    api.stamp(l);
    b.try_acquire_or_renew().await.unwrap();
    base.advance(15);
    assert_eq!(b.try_acquire_or_renew().await, Ok(Attempt::Leading));
}

#[tokio::test]
async fn honours_the_holders_own_lease_duration() {
    let (api, clock) = (FakeApi::default(), FakeClock::new());
    let mut l = held_by(&api, "broker-a");
    l.spec.lease_duration_seconds = Some(60);
    api.stamp(l);
    let mut b = elector(&api, &clock, "broker-b");
    b.try_acquire_or_renew().await.unwrap();
    clock.advance(30);
    assert!(matches!(
        b.try_acquire_or_renew().await,
        Ok(Attempt::Following { .. })
    ));
    clock.advance(30);
    assert_eq!(b.try_acquire_or_renew().await, Ok(Attempt::Leading));
}

#[tokio::test]
async fn api_errors_surface_and_the_next_attempt_renews() {
    let (api, clock) = (FakeApi::default(), FakeClock::new());
    let mut a = elector(&api, &clock, "broker-a");
    a.try_acquire_or_renew().await.unwrap();
    api.fail_next(LeaseError::Unavailable("timeout".into()));
    assert!(matches!(
        a.try_acquire_or_renew().await,
        Err(LeaseError::Unavailable(_))
    ));
    api.fail_next(LeaseError::Denied("HTTP 403".into()));
    assert!(matches!(
        a.try_acquire_or_renew().await,
        Err(LeaseError::Denied(_))
    ));
    clock.advance(4);
    assert_eq!(a.try_acquire_or_renew().await, Ok(Attempt::Leading));
    assert_eq!(api.lease().unwrap().spec.lease_transitions, Some(0));
}

#[tokio::test]
async fn keeps_unknown_fields_through_an_update() {
    let (api, clock) = (FakeApi::default(), FakeClock::new());
    let mut l: Lease = serde_json::from_value(serde_json::json!({
        "apiVersion": "coordination.k8s.io/v1",
        "kind": "Lease",
        "metadata": {"name": "broker-leader", "labels": {"team": "x"}},
        "spec": {"holderIdentity": "", "strategy": "OldestEmulationVersion"}
    }))
    .unwrap();
    l = api.stamp(l);
    assert_eq!(l.holder(), None, "an empty holder is a released lease");
    let mut a = elector(&api, &clock, "broker-a");
    assert_eq!(a.try_acquire_or_renew().await, Ok(Attempt::Leading));
    let v = serde_json::to_value(api.lease().unwrap()).unwrap();
    assert_eq!(v["metadata"]["labels"]["team"], "x");
    assert_eq!(v["spec"]["strategy"], "OldestEmulationVersion");
    assert_eq!(v["spec"]["holderIdentity"], "broker-a");
}

// ---------------------------------------------------------------------
// Driver + gate
// ---------------------------------------------------------------------

fn elected_gate() -> LeaderGate {
    let g = LeaderGate::new();
    g.set_mode(Mode::Elected);
    g
}

const RENEW: Duration = Duration::from_secs(10);

#[test]
fn gate_opens_on_acquire_and_closes_on_loss() {
    let g = elected_gate();
    let mut d = Driver::new(RENEW);
    let t0 = Duration::from_secs(100);
    assert!(!g.is_leader_at(t0), "elected mode starts closed");
    assert_eq!(d.on_attempt(&Ok(Attempt::Leading), t0, &g), Step::Continue);
    assert!(g.is_leader_at(t0));
    assert!(g.is_leader_at(t0 + Duration::from_secs(9)));
    let lost = Ok(Attempt::Following {
        holder: "other".into(),
    });
    d.on_attempt(&lost, t0 + Duration::from_secs(2), &g);
    assert!(!g.is_leader_at(t0 + Duration::from_secs(2)));
    assert_eq!(g.transitions.load(Ordering::Relaxed), 2);
}

#[test]
fn gate_closes_by_itself_when_renewals_stop() {
    let g = elected_gate();
    let mut d = Driver::new(RENEW);
    let t0 = Duration::from_secs(100);
    d.on_attempt(&Ok(Attempt::Leading), t0, &g);
    // No further attempt at all (a hung elector): the deadline alone closes it.
    assert!(g.is_leader_at(t0 + Duration::from_millis(9_999)));
    assert!(!g.is_leader_at(t0 + RENEW));
}

#[test]
fn failed_renewals_lose_leadership_at_the_renew_deadline_not_before() {
    let g = elected_gate();
    let mut d = Driver::new(RENEW);
    let t0 = Duration::from_secs(100);
    d.on_attempt(&Ok(Attempt::Leading), t0, &g);
    let err = Err(LeaseError::Unavailable("timeout".into()));
    d.on_attempt(&err, t0 + Duration::from_secs(4), &g);
    assert!(d.leading && g.is_leader_at(t0 + Duration::from_secs(4)));
    d.on_attempt(&err, t0 + RENEW, &g);
    assert!(!d.leading);
    assert!(!g.is_leader_at(t0 + RENEW));
    // Recovers on the next successful attempt.
    d.on_attempt(&Ok(Attempt::Leading), t0 + Duration::from_secs(12), &g);
    assert!(g.is_leader_at(t0 + Duration::from_secs(12)));
}

#[test]
fn a_renew_conflict_does_not_extend_leadership() {
    let g = elected_gate();
    let mut d = Driver::new(RENEW);
    let t0 = Duration::from_secs(100);
    d.on_attempt(&Ok(Attempt::Leading), t0, &g);
    d.on_attempt(&Err(LeaseError::Conflict), t0 + Duration::from_secs(9), &g);
    assert!(!g.is_leader_at(t0 + RENEW));
}

#[test]
fn renew_deadline_is_shorter_than_the_lease_a_successor_waits_out() {
    let t = Timings::default();
    assert!(t.renew_deadline < t.lease_duration);
    assert!(t.retry_period.mul_f64(1.2) < t.renew_deadline);
}

#[test]
fn forbidden_at_startup_falls_back_to_always_leader() {
    let g = elected_gate();
    let mut d = Driver::new(RENEW);
    let step = d.on_attempt(
        &Err(LeaseError::Denied("HTTP 403".into())),
        Duration::from_secs(1),
        &g,
    );
    assert_eq!(step, Step::Fallback(Mode::FallbackDenied));
    g.set_mode(Mode::FallbackDenied);
    assert!(g.is_leader());
    assert!(render_metrics_for(&g)
        .contains("broker_leader_election_active{mode=\"fallback_forbidden\"} 0"));
    assert!(render_metrics_for(&g).contains("broker_leader 1\n"));
}

#[test]
fn unreachable_at_startup_falls_back_only_after_the_retry_budget() {
    let g = elected_gate();
    let mut d = Driver::new(RENEW);
    let err = Err(LeaseError::Unavailable("connection refused".into()));
    for i in 1..STARTUP_ATTEMPTS {
        assert_eq!(
            d.on_attempt(&err, Duration::from_secs(u64::from(i) * 2), &g),
            Step::Continue
        );
        assert!(!g.is_leader_at(Duration::from_secs(u64::from(i) * 2)));
    }
    assert_eq!(
        d.on_attempt(&err, Duration::from_secs(100), &g),
        Step::Fallback(Mode::FallbackUnreachable)
    );
}

#[test]
fn errors_after_first_contact_never_fall_back() {
    let g = elected_gate();
    let mut d = Driver::new(RENEW);
    let following = Ok(Attempt::Following {
        holder: "other".into(),
    });
    d.on_attempt(&following, Duration::from_secs(1), &g);
    for i in 0..50 {
        let step = d.on_attempt(
            &Err(LeaseError::Denied("HTTP 403".into())),
            Duration::from_secs(2 + i),
            &g,
        );
        assert_eq!(step, Step::Continue);
    }
    assert!(!g.is_leader_at(Duration::from_secs(60)));
}

#[test]
fn disabled_gate_is_always_leader() {
    let g = LeaderGate::new();
    assert!(g.is_leader_at(Duration::ZERO));
    assert!(render_metrics_for(&g).contains("broker_leader_election_active{mode=\"disabled\"} 0"));
}

#[test]
fn metrics_show_an_elected_follower() {
    let g = elected_gate();
    let text = render_metrics_for(&g);
    assert!(text.contains("broker_leader 0\n"));
    assert!(text.contains("broker_leader_election_active{mode=\"elected\"} 1\n"));
    assert!(text.contains("broker_leader_transitions_total 0\n"));
}

// ---------------------------------------------------------------------
// Gate behaviour of the singleton loops
// ---------------------------------------------------------------------

#[tokio::test]
async fn singleton_passes_run_only_while_leader() {
    let g = elected_gate();
    let runs = Cell::new(0u32);
    let pass = || async { runs.set(runs.get() + 1) };

    assert_eq!(g.run("test", pass()).await, None);
    assert_eq!(runs.get(), 0, "a follower never polls the pass");

    g.hold_until(mono_now() + Duration::from_secs(60));
    assert_eq!(g.run("test", pass()).await, Some(()));
    assert_eq!(runs.get(), 1);

    g.clear();
    assert_eq!(g.run("test", pass()).await, None);
    assert_eq!(runs.get(), 1);

    g.set_mode(Mode::Disabled);
    assert_eq!(g.run("test", pass()).await, Some(()));
    assert_eq!(
        runs.get(),
        2,
        "disabled election runs every pass, as before"
    );
}

#[tokio::test]
async fn a_pass_stops_at_the_batch_boundary_after_losing_leadership() {
    let g = elected_gate();
    g.hold_until(mono_now() + Duration::from_secs(60));
    let mut batches = 0;
    // The shape every batched prune has: check, then one whole batch.
    for i in 0..10 {
        if !g.still_leader("test") {
            break;
        }
        batches += 1;
        if i == 2 {
            // Lost mid-batch: this batch completes, the next never starts.
            g.clear();
        }
    }
    assert_eq!(batches, 3);
}

#[test]
fn process_gate_defaults_to_always_leader() {
    // Nothing in the lib test binary starts election, so every existing
    // loop test keeps its pre-election behaviour.
    assert_eq!(gate().mode(), Mode::Disabled);
    assert!(is_leader());
}

// ---------------------------------------------------------------------
// Cadence: a new leader's first pass
// ---------------------------------------------------------------------

/// A cadence that polls fast and jitters little, so tests run in
/// milliseconds; the logic is the production one.
fn fast_cadence(interval: Duration) -> Cadence {
    Cadence {
        task: "test",
        interval,
        jitter_max: Duration::from_millis(20),
        poll: Duration::from_millis(10),
        seen_acquisitions: 0,
    }
}

/// What the elector does on acquiring: open the gate, then count it.
fn acquire(g: &LeaderGate) {
    let mut d = Driver::new(RENEW);
    d.on_attempt(&Ok(Attempt::Leading), mono_now(), g);
}

#[test]
fn the_elector_counts_acquisitions_not_renewals() {
    let g = elected_gate();
    let mut d = Driver::new(RENEW);
    d.on_attempt(&Ok(Attempt::Leading), mono_now(), &g);
    d.on_attempt(&Ok(Attempt::Leading), mono_now(), &g);
    assert_eq!(g.acquisitions(), 1);
    d.on_attempt(
        &Ok(Attempt::Following {
            holder: "other".into(),
        }),
        mono_now(),
        &g,
    );
    d.on_attempt(&Ok(Attempt::Leading), mono_now(), &g);
    assert_eq!(g.acquisitions(), 2);
}

#[tokio::test]
async fn a_new_leader_runs_an_overdue_pass_promptly() {
    let g = elected_gate();
    let mut c = fast_cadence(Duration::from_secs(3600));
    let started = Instant::now();
    let waiting = c.wait_with(&g, || async { None });
    let acquiring = async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        acquire(&g);
    };
    tokio::join!(waiting, acquiring);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "waited {:?} of an hour's interval",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_pass_another_replica_just_ran_keeps_its_schedule() {
    // Due 3 s after the last pass, which ran 2 s ago: the new leader waits
    // about 1 s, not the full 3 s interval and not zero.
    let g = elected_gate();
    let mut c = fast_cadence(Duration::from_secs(3));
    acquire(&g);
    let started = Instant::now();
    c.wait_with(&g, || async { Some(Duration::from_secs(2)) })
        .await;
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(800),
        "ran early after {waited:?}"
    );
    assert!(waited < Duration::from_millis(2500), "waited {waited:?}");
}

#[tokio::test]
async fn flapping_leadership_never_runs_passes_back_to_back() {
    let g = elected_gate();
    let mut c = fast_cadence(Duration::from_millis(600));
    // The pass just ran (age 0); leadership is lost and regained twice.
    let started = Instant::now();
    let waiting = c.wait_with(&g, || async { Some(Duration::ZERO) });
    let flapping = async {
        for _ in 0..2 {
            tokio::time::sleep(Duration::from_millis(60)).await;
            g.clear();
            acquire(&g);
        }
    };
    tokio::join!(waiting, flapping);
    assert!(
        started.elapsed() >= Duration::from_millis(550),
        "a regained lease cut the wait to {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_follower_waits_the_interval_and_an_acquisition_it_lost_is_ignored() {
    let g = elected_gate();
    let mut c = fast_cadence(Duration::from_millis(300));
    let asked = Cell::new(0u32);
    let started = Instant::now();
    // Acquired then lost before the cadence looked: nothing to run.
    acquire(&g);
    g.clear();
    c.wait_with(&g, || {
        asked.set(asked.get() + 1);
        async { None }
    })
    .await;
    assert!(started.elapsed() >= Duration::from_millis(280));
    assert_eq!(asked.get(), 0, "a follower never consults the last pass");
}

#[tokio::test]
async fn disabled_election_is_a_plain_interval() {
    let g = LeaderGate::new();
    let mut c = fast_cadence(Duration::from_millis(200));
    let started = Instant::now();
    c.wait_with(&g, || async { None }).await;
    assert!(started.elapsed() >= Duration::from_millis(190));
}

#[test]
fn takeover_jitter_is_bounded_and_scales_with_the_interval() {
    assert_eq!(
        Cadence::new("t", Duration::from_secs(3600)).jitter_max,
        MAX_TAKEOVER_JITTER
    );
    assert_eq!(
        Cadence::new("t", Duration::from_secs(60)).jitter_max,
        Duration::from_secs(6)
    );
    for _ in 0..100 {
        assert!(random_up_to(Duration::from_millis(50)) <= Duration::from_millis(50));
    }
    assert_eq!(random_up_to(Duration::ZERO), Duration::ZERO);
}

/// The cluster-wide record a new leader reads, on a real database.
#[test]
#[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
fn live_database_records_the_last_completed_pass() {
    use diesel::Connection;
    use diesel_migrations::MigrationHarness;
    const M: diesel_migrations::EmbeddedMigrations =
        diesel_migrations::embed_migrations!("./db/migrations");
    let url = std::env::var("KG_TEST_DATABASE_URL").expect("set KG_TEST_DATABASE_URL");
    let mut conn = diesel::PgConnection::establish(&url).expect("connect");
    conn.run_pending_migrations(M).expect("migrate");
    let task = format!("test-{}", uuid::Uuid::new_v4());
    assert_eq!(last_pass_age(&mut conn, &task).unwrap(), None);
    record_pass(&mut conn, &task).unwrap();
    let age = last_pass_age(&mut conn, &task).unwrap().unwrap();
    assert!(age < Duration::from_secs(5), "{age:?}");
    record_pass(&mut conn, &task).unwrap();
    use diesel::RunQueryDsl;
    diesel::sql_query("DELETE FROM leader_task_runs WHERE task = $1")
        .bind::<diesel::sql_types::Text, _>(&task)
        .execute(&mut conn)
        .unwrap();
}

// ---------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------

#[test]
fn enablement_follows_the_setting_then_the_cluster() {
    assert!(election_enabled(None, true));
    assert!(!election_enabled(None, false));
    assert!(election_enabled(Some("auto"), true));
    assert!(!election_enabled(Some("auto"), false));
    assert!(election_enabled(Some("TRUE"), false));
    assert!(!election_enabled(Some("false"), true));
    assert!(!election_enabled(Some("0"), true));
    assert!(election_enabled(Some("garbage"), true));
}

#[test]
fn timings_accept_ordered_values_and_reject_the_rest() {
    let d = Timings::default();
    assert_eq!(Timings::from_secs(None, None, None), d);
    let t = Timings::from_secs(Some(30), Some(20), Some(5));
    assert_eq!(t.lease_duration, Duration::from_secs(30));
    assert_eq!(t.renew_deadline, Duration::from_secs(20));
    assert_eq!(t.retry_period, Duration::from_secs(5));
    // Renew deadline not below the lease duration.
    assert_eq!(Timings::from_secs(Some(10), Some(10), Some(2)), d);
    // Retry period too close to the renew deadline.
    assert_eq!(Timings::from_secs(Some(15), Some(10), Some(9)), d);
    assert_eq!(Timings::from_secs(None, None, Some(0)), d);
}

#[test]
fn api_server_url_brackets_ipv6() {
    assert_eq!(
        api_server_url("10.96.0.1", Some("443")),
        "https://10.96.0.1:443"
    );
    assert_eq!(
        api_server_url("fd00::1", Some("6443")),
        "https://[fd00::1]:6443"
    );
    assert_eq!(
        api_server_url("kubernetes.default.svc", None),
        "https://kubernetes.default.svc:443"
    );
}

#[test]
fn classify_maps_statuses() {
    assert_eq!(classify(409, ""), LeaseError::Conflict);
    assert!(matches!(
        classify(403, r#"{"message":"leases is forbidden"}"#),
        LeaseError::Denied(m) if m.contains("leases is forbidden")
    ));
    assert!(matches!(classify(401, ""), LeaseError::Denied(_)));
    assert!(matches!(classify(500, "boom"), LeaseError::Unavailable(m) if m.contains("boom")));
}

#[test]
fn micro_time_is_rfc3339_with_microseconds() {
    let t = DateTime::from_timestamp(1_790_000_000, 123_456_000).unwrap();
    assert_eq!(micro_time(t), "2026-09-21T14:13:20.123456Z");
}

// ---------------------------------------------------------------------
// KubeLeaseApi against a mock API server
// ---------------------------------------------------------------------

mod http {
    use super::*;
    use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Server {
        lease: Option<serde_json::Value>,
        rv: u64,
        forbid: bool,
        auth_seen: Vec<String>,
    }

    type Shared = Arc<Mutex<Server>>;

    fn auth(req: &HttpRequest, s: &mut Server) {
        if let Some(v) = req.headers().get("authorization") {
            s.auth_seen.push(v.to_str().unwrap().to_string());
        }
    }

    fn forbidden() -> HttpResponse {
        HttpResponse::Forbidden().json(serde_json::json!({
            "kind": "Status", "message": "leases.coordination.k8s.io is forbidden", "code": 403
        }))
    }

    async fn get(req: HttpRequest, st: web::Data<Shared>) -> HttpResponse {
        let mut s = st.lock().unwrap();
        auth(&req, &mut s);
        if s.forbid {
            return forbidden();
        }
        match &s.lease {
            Some(l) => HttpResponse::Ok().json(l),
            None => HttpResponse::NotFound().json(serde_json::json!({"code": 404})),
        }
    }

    async fn create(
        req: HttpRequest,
        st: web::Data<Shared>,
        body: web::Json<serde_json::Value>,
    ) -> HttpResponse {
        let mut s = st.lock().unwrap();
        auth(&req, &mut s);
        if s.lease.is_some() {
            return HttpResponse::Conflict().json(serde_json::json!({"code": 409}));
        }
        let mut l = body.into_inner();
        s.rv += 1;
        l["metadata"]["resourceVersion"] = s.rv.to_string().into();
        s.lease = Some(l.clone());
        HttpResponse::Created().json(l)
    }

    async fn replace(
        req: HttpRequest,
        st: web::Data<Shared>,
        body: web::Json<serde_json::Value>,
    ) -> HttpResponse {
        let mut s = st.lock().unwrap();
        auth(&req, &mut s);
        let mut l = body.into_inner();
        let current = s
            .lease
            .as_ref()
            .map(|c| c["metadata"]["resourceVersion"].clone());
        if current != Some(l["metadata"]["resourceVersion"].clone()) {
            return HttpResponse::Conflict().json(serde_json::json!({"code": 409}));
        }
        s.rv += 1;
        l["metadata"]["resourceVersion"] = s.rv.to_string().into();
        s.lease = Some(l.clone());
        HttpResponse::Ok().json(l)
    }

    async fn start(state: Shared) -> String {
        let data = web::Data::new(state);
        let srv = HttpServer::new(move || {
            let base = "/apis/coordination.k8s.io/v1/namespaces/kg/leases";
            App::new()
                .app_data(data.clone())
                .route(base, web::post().to(create))
                .route(&format!("{base}/leader"), web::get().to(get))
                .route(&format!("{base}/leader"), web::put().to(replace))
        })
        .workers(1)
        .bind("127.0.0.1:0")
        .unwrap();
        let addr = srv.addrs()[0];
        actix_web::rt::spawn(srv.run());
        format!("http://{addr}")
    }

    fn api(base: &str, token: Option<PathBuf>) -> KubeLeaseApi {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        KubeLeaseApi::new(client, base, "kg", "leader", token)
    }

    #[actix_web::test]
    async fn elects_renews_and_releases_over_http() {
        let state = Shared::default();
        let base = start(state.clone()).await;
        let dir = std::env::temp_dir().join(format!("kg-leader-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let token = dir.join("token");
        std::fs::write(&token, "tok-1\n").unwrap();

        let clock = FakeClock::new();
        let mut a = Elector::new(
            api(&base, Some(token.clone())),
            clock.clone(),
            "broker-a",
            "leader",
            LEASE,
        );
        let mut b = Elector::new(api(&base, None), clock.clone(), "broker-b", "leader", LEASE);

        assert_eq!(a.try_acquire_or_renew().await, Ok(Attempt::Leading));
        assert!(
            matches!(b.try_acquire_or_renew().await, Ok(Attempt::Following { holder }) if holder == "broker-a")
        );
        // A rotated token is picked up on the next request.
        std::fs::write(&token, "tok-2").unwrap();
        clock.advance(2);
        assert_eq!(a.try_acquire_or_renew().await, Ok(Attempt::Leading));
        {
            let s = state.lock().unwrap();
            assert_eq!(s.rv, 2);
            assert_eq!(
                s.lease.as_ref().unwrap()["spec"]["holderIdentity"],
                "broker-a"
            );
            assert!(s.auth_seen.contains(&"Bearer tok-1".to_string()));
            assert!(s.auth_seen.contains(&"Bearer tok-2".to_string()));
        }
        // A stale write is refused by resourceVersion.
        let mut stale = a.held.clone().unwrap();
        stale.metadata.resource_version = Some("1".into());
        assert_eq!(a.api.replace(&stale).await, Err(LeaseError::Conflict));

        assert_eq!(a.release().await, Ok(true));
        assert!(state.lock().unwrap().lease.as_ref().unwrap()["spec"]
            .get("holderIdentity")
            .is_none());
        assert_eq!(b.try_acquire_or_renew().await, Ok(Attempt::Leading));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[actix_web::test]
    async fn forbidden_is_reported_as_denied() {
        let state = Shared::default();
        state.lock().unwrap().forbid = true;
        let base = start(state).await;
        let mut a = Elector::new(
            api(&base, None),
            FakeClock::new(),
            "broker-a",
            "leader",
            LEASE,
        );
        let r = a.try_acquire_or_renew().await;
        assert!(
            matches!(&r, Err(LeaseError::Denied(m)) if m.contains("forbidden")),
            "{r:?}"
        );
        let g = elected_gate();
        assert_eq!(
            Driver::new(RENEW).on_attempt(&r, Duration::from_secs(1), &g),
            Step::Fallback(Mode::FallbackDenied)
        );
    }

    #[actix_web::test]
    async fn unreachable_is_reported_as_unavailable() {
        // Bind then drop, so nothing listens on the port.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut a = Elector::new(
            api(&format!("http://127.0.0.1:{port}"), None),
            FakeClock::new(),
            "broker-a",
            "leader",
            LEASE,
        );
        assert!(matches!(
            a.try_acquire_or_renew().await,
            Err(LeaseError::Unavailable(_))
        ));
    }

    /// The same election against a real API server, through
    /// `kubectl proxy` (so no token or CA is involved): proves the Lease
    /// body, MicroTime format and resourceVersion conflict are what the API
    /// server accepts and enforces. Uses a throwaway Lease and deletes it.
    ///
    ///   kubectl proxy --port 8001 &
    ///   KG_TEST_KUBE_PROXY_URL=http://127.0.0.1:8001 cargo test -- --ignored live_kube
    #[actix_web::test]
    #[ignore = "requires kubectl proxy (set KG_TEST_KUBE_PROXY_URL)"]
    async fn live_kube_api_elects_through_a_real_api_server() {
        // Skipped, not failed, where only the database is provided (CI).
        let Ok(base) = std::env::var("KG_TEST_KUBE_PROXY_URL") else {
            eprintln!("KG_TEST_KUBE_PROXY_URL unset; skipping");
            return;
        };
        let ns = std::env::var("KG_TEST_KUBE_NAMESPACE").unwrap_or_else(|_| "default".into());
        let name = format!("kg-leader-test-{}", uuid::Uuid::new_v4());
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let api = || KubeLeaseApi::new(client.clone(), &base, &ns, &name, None);
        let clock = FakeClock::new();
        let mut a = Elector::new(api(), clock.clone(), "broker-a", &name, LEASE);
        let mut b = Elector::new(api(), clock.clone(), "broker-b", &name, LEASE);

        assert_eq!(a.try_acquire_or_renew().await, Ok(Attempt::Leading));
        assert!(matches!(
            b.try_acquire_or_renew().await,
            Ok(Attempt::Following { holder }) if holder == "broker-a"
        ));
        clock.advance(2);
        assert_eq!(a.try_acquire_or_renew().await, Ok(Attempt::Leading));
        let held = a.held.clone().unwrap();
        assert!(held.spec.renew_time.as_deref().unwrap().ends_with('Z'));
        // The API server rejects a write from a stale resourceVersion.
        let mut stale = held.clone();
        stale.metadata.resource_version = Some("1".into());
        assert_eq!(a.api.replace(&stale).await, Err(LeaseError::Conflict));
        // And a second create of the same name.
        assert_eq!(a.api.create(&held).await, Err(LeaseError::Conflict));

        assert_eq!(a.release().await, Ok(true));
        assert_eq!(b.try_acquire_or_renew().await, Ok(Attempt::Leading));
        let got = b.api.get().await.unwrap().unwrap();
        assert_eq!(got.holder(), Some("broker-b"));
        assert_eq!(got.spec.lease_transitions, Some(1));

        let _ = client
            .delete(format!(
                "{base}/apis/coordination.k8s.io/v1/namespaces/{ns}/leases/{name}"
            ))
            .send()
            .await;
    }
}
