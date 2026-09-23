//! A short-lived cache of the rendered `GET /seccomp/profiles` body.
//!
//! That endpoint is the broker's heaviest read and its most frequently
//! polled one. Every open UI tab asks every 15 s
//! (`frontend/src/hooks/useSeccompProfiles.ts`), and until #1632 moved it
//! to the per-workload route every controller's seccomp distributor asked
//! every 30 s per node, so a 44-node cluster produced ~90 calls a minute;
//! on one with ~2,000 observed workloads each call rebuilt the whole
//! per-workload summary from Postgres (~2.5 s), serialised a ~3.3 MB body,
//! and left ~15 MiB of RSS behind (#1514). Under that load the container
//! went from ~380 MiB to its 4 GiB limit and OOM-looped. The distributor
//! is gone from this route; the UI tabs are not, and neither is the next
//! caller that polls it without an in-flight guard.
//!
//! Every caller wants the same answer, so it is computed once per TTL. The
//! cache holds the *serialised* body as [`Bytes`], not the
//! `Vec<ProfileSummary>` it came from: a hit is a reference-count bump on a
//! buffer that already exists (no query, no serialisation, no allocation
//! proportional to the cluster) and the one retained copy is replaced, not
//! accumulated, when it expires.
//!
//! Rebuilds are single-flight. The slot is behind an async mutex that is
//! held for the whole rebuild, so a caller that finds the entry stale
//! either rebuilds it or queues behind the caller already doing so and then
//! reads what that caller stored. N concurrent misses cost one query pass,
//! even when the rebuild takes longer than the TTL: a queued caller is
//! served any body whose rebuild was still in flight when the caller
//! arrived, because that is the rebuild it was waiting for; taking it costs
//! at most one build's worth of staleness, rebuilding again costs a whole
//! build. On a shed or failed rebuild nothing is stored, so the next queued
//! caller runs its own and its wait adds to the first's rather than
//! overlapping it; once any rebuild succeeds, that same rule serves every
//! caller still queued, so the serial tail is one rebuild per consecutive
//! failure, not one per waiter.
//!
//! Staleness is bounded by the TTL alone. A `SeccompProfile` CR's
//! deployment state or drift can lag this list by up to
//! `SECCOMP_PROFILES_CACHE_TTL_SECS` after the controller reports it. The
//! write paths deliberately do not invalidate: node status arrives from
//! every node on every reconcile, so invalidating on each write would
//! rebuild about as often as not caching at all. The per-workload
//! `GET /seccomp/profiles/{namespace}/{kind}/{name}` route is uncached and
//! always current.

use actix_web::web::Bytes;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, info};

/// Default for `SECCOMP_PROFILES_CACHE_TTL_SECS`. Shorter than the fastest
/// poller (the UI's 15 s) so a tab still sees a fresh list on most polls,
/// and long enough that the 44-node cluster above would have gone from ~90
/// rebuilds a minute to at most 6.
pub const DEFAULT_PROFILES_CACHE_TTL_SECS: u64 = 10;

#[derive(Debug)]
struct Entry {
    body: Bytes,
    /// When the rebuild that produced `body` STARTED, not when it finished.
    /// The data is as old as the query that read it, so measuring the TTL
    /// from the start keeps "a hit is at most TTL old" true even when a
    /// rebuild takes seconds.
    built_at: Instant,
    /// When that rebuild finished and `body` was stored. A caller that
    /// arrived before this was queued behind the rebuild, and is served it
    /// even if the TTL has already passed (see `get_or_build`).
    finished_at: Instant,
}

/// See the module docs. Cheap to clone (all state is behind `Arc`), so it
/// lives in `web::Data`.
#[derive(Debug, Clone)]
pub struct SeccompProfilesCache {
    ttl: Duration,
    slot: Arc<Mutex<Option<Entry>>>,
    hits: Arc<AtomicU64>,
    misses: Arc<AtomicU64>,
}

impl SeccompProfilesCache {
    /// A cache serving each rebuilt body for `ttl`. A zero `ttl` disables
    /// caching entirely (see [`Self::get_or_build`]).
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            slot: Arc::new(Mutex::new(None)),
            hits: Arc::new(AtomicU64::new(0)),
            misses: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Build from `SECCOMP_PROFILES_CACHE_TTL_SECS`, default
    /// [`DEFAULT_PROFILES_CACHE_TTL_SECS`]. `0` disables caching, which
    /// restores the pre-cache behaviour for anyone who needs to rule the
    /// cache out while debugging. An unparseable value falls back to the
    /// default rather than refusing to start, like every other broker knob:
    /// a broker that crash-loops on a typo takes the telemetry pipeline
    /// down with it.
    pub fn from_env() -> Self {
        let secs = std::env::var("SECCOMP_PROFILES_CACHE_TTL_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_PROFILES_CACHE_TTL_SECS);
        if secs == 0 {
            info!("seccomp profiles cache disabled (SECCOMP_PROFILES_CACHE_TTL_SECS=0); every GET /seccomp/profiles rebuilds");
        } else {
            info!(ttl_secs = secs, "seccomp profiles cache active");
        }
        Self::new(Duration::from_secs(secs))
    }

    /// How long a rebuilt body is served before the next rebuild.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// False when the TTL is zero and every call rebuilds.
    pub fn enabled(&self) -> bool {
        !self.ttl.is_zero()
    }

    /// The cached body if it is younger than the TTL, otherwise the result
    /// of `build`, stored for the callers that follow.
    ///
    /// `build` runs at most once per expiry across all concurrent callers:
    /// the slot's lock is held while it runs, so everyone else who found the
    /// entry stale queues on the lock and, once it is released, is served
    /// what was built. "Served" means fresh by TTL *or* finished after the
    /// caller arrived, i.e. the rebuild it queued behind: without the second
    /// clause a rebuild slower than the TTL lands already stale and every
    /// queued waiter rebuilds in turn, which is single-flight collapsing
    /// into a serial rebuild per caller on exactly the cluster too big to
    /// afford it. (The rebuild's START time is not the right stamp here: a
    /// waiter queues after the winner has started, so nothing it waited for
    /// would ever qualify.) A failed build stores
    /// nothing, so the next caller retries instead of an error being served
    /// for a whole TTL. A caller that goes away mid-rebuild (client
    /// disconnect drops the handler future) takes its rebuild with it; the
    /// next caller in the queue runs its own.
    ///
    /// With the TTL at zero the lock is never taken and `build` runs for
    /// every call, concurrently, exactly as the handler did before the
    /// cache existed.
    pub async fn get_or_build<F, Fut, E>(&self, build: F) -> Result<Bytes, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Bytes, E>>,
    {
        if !self.enabled() {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return build().await;
        }

        let arrived = Instant::now();
        let mut slot = self.slot.lock().await;
        if let Some(entry) = slot.as_ref() {
            let age = entry.built_at.elapsed();
            if age < self.ttl || entry.finished_at >= arrived {
                self.hits.fetch_add(1, Ordering::Relaxed);
                debug!(
                    age_ms = age.as_millis() as u64,
                    bytes = entry.body.len(),
                    "seccomp profiles cache hit"
                );
                return Ok(entry.body.clone());
            }
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        let started = Instant::now();
        let body = build().await?;
        debug!(
            build_ms = started.elapsed().as_millis() as u64,
            bytes = body.len(),
            "seccomp profiles cache rebuilt"
        );
        *slot = Some(Entry {
            body: body.clone(),
            built_at: started,
            finished_at: Instant::now(),
        });
        Ok(body)
    }

    /// Responses served from a body another call built. Surfaced as
    /// `broker_seccomp_profiles_cache_hits_total`.
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Calls that ran (or, with the TTL at zero, would each run) a rebuild.
    /// Surfaced as `broker_seccomp_profiles_cache_misses_total`; because
    /// concurrent misses share one rebuild this is the rebuild count, and it
    /// climbing as fast as hits means the TTL is shorter than the pollers'
    /// interval.
    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::sync::atomic::AtomicUsize;

    fn body(tag: &str) -> Bytes {
        Bytes::from(format!("[\"{tag}\"]"))
    }

    /// A build that records that it ran and returns `tag`.
    fn counted(
        builds: &Arc<AtomicUsize>,
        tag: &'static str,
    ) -> impl FnOnce() -> std::future::Ready<Result<Bytes, Infallible>> {
        let builds = builds.clone();
        move || {
            builds.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(body(tag)))
        }
    }

    #[tokio::test]
    async fn hit_within_ttl_returns_the_same_buffer_without_rebuilding() {
        let cache = SeccompProfilesCache::new(Duration::from_secs(10));
        let builds = Arc::new(AtomicUsize::new(0));

        let first = cache.get_or_build(counted(&builds, "a")).await.unwrap();
        let second = cache.get_or_build(counted(&builds, "b")).await.unwrap();

        assert_eq!(
            builds.load(Ordering::SeqCst),
            1,
            "second call must not rebuild"
        );
        assert_eq!(
            second,
            body("a"),
            "a hit serves what was built, not the new closure"
        );
        // The SAME buffer, not an equal copy. A hit is a reference-count bump
        // on bytes already in the cache; that is what makes it free of any
        // allocation proportional to the cluster.
        assert_eq!(first.as_ptr(), second.as_ptr());
        assert_eq!((cache.hits(), cache.misses()), (1, 1));
    }

    #[tokio::test]
    async fn rebuilds_once_the_ttl_has_passed() {
        let cache = SeccompProfilesCache::new(Duration::from_millis(50));
        let builds = Arc::new(AtomicUsize::new(0));

        cache.get_or_build(counted(&builds, "a")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        let after = cache.get_or_build(counted(&builds, "b")).await.unwrap();

        assert_eq!(builds.load(Ordering::SeqCst), 2);
        assert_eq!(after, body("b"), "a stale entry is replaced, not served");
        assert_eq!((cache.hits(), cache.misses()), (0, 2));
    }

    #[tokio::test]
    async fn ttl_is_measured_from_when_the_rebuild_started() {
        // The data is as old as the query that read it. A rebuild that takes
        // longer than the TTL must be stale the moment it lands, or "a hit is
        // at most TTL old" is false by the build's duration.
        let cache = SeccompProfilesCache::new(Duration::from_millis(50));
        let builds = Arc::new(AtomicUsize::new(0));

        let slow = builds.clone();
        cache
            .get_or_build(|| async move {
                slow.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(80)).await;
                Ok::<_, Infallible>(body("slow"))
            })
            .await
            .unwrap();
        let next = cache.get_or_build(counted(&builds, "fresh")).await.unwrap();

        assert_eq!(builds.load(Ordering::SeqCst), 2);
        assert_eq!(next, body("fresh"));
    }

    #[tokio::test]
    async fn concurrent_misses_share_one_build() {
        // The property the OOM fix rests on: 44 controllers and a handful
        // of UI tabs arriving together must cost one query pass, not one
        // each. The build sleeps so every other task has queued on the slot
        // before it finishes; on tokio's current-thread test runtime that
        // order is deterministic.
        let cache = SeccompProfilesCache::new(Duration::from_secs(10));
        let builds = Arc::new(AtomicUsize::new(0));
        let callers = 8;

        let mut tasks = Vec::with_capacity(callers);
        for _ in 0..callers {
            let cache = cache.clone();
            let builds = builds.clone();
            tasks.push(tokio::spawn(async move {
                cache
                    .get_or_build(|| async move {
                        builds.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        Ok::<_, Infallible>(body("shared"))
                    })
                    .await
                    .unwrap()
            }));
        }
        for task in tasks {
            assert_eq!(task.await.unwrap(), body("shared"));
        }

        assert_eq!(builds.load(Ordering::SeqCst), 1, "exactly one rebuild");
        assert_eq!(cache.misses(), 1);
        assert_eq!(
            cache.hits(),
            callers as u64 - 1,
            "everyone else waited and reused it"
        );
    }

    #[tokio::test]
    async fn a_rebuild_slower_than_the_ttl_still_serves_every_waiter() {
        // The body lands already stale by TTL. Without the finished-after-
        // arrival rule each queued caller would find it stale and rebuild in
        // turn (probe: 8 callers gave 8 builds), which is the worst case of
        // the very load this cache exists to collapse.
        let cache = SeccompProfilesCache::new(Duration::from_millis(50));
        let builds = Arc::new(AtomicUsize::new(0));
        let callers = 8;

        let mut tasks = Vec::with_capacity(callers);
        for _ in 0..callers {
            let cache = cache.clone();
            let builds = builds.clone();
            tasks.push(tokio::spawn(async move {
                cache
                    .get_or_build(|| async move {
                        builds.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(120)).await;
                        Ok::<_, Infallible>(body("slow"))
                    })
                    .await
                    .unwrap()
            }));
        }
        for task in tasks {
            assert_eq!(task.await.unwrap(), body("slow"));
        }

        assert_eq!(builds.load(Ordering::SeqCst), 1, "exactly one rebuild");
        assert_eq!(cache.hits(), callers as u64 - 1);
    }

    #[tokio::test]
    async fn one_success_after_a_failure_serves_everyone_still_queued() {
        // Failures retry serially under the lock, but the serial tail is one
        // rebuild per consecutive failure, not one per waiter: the first
        // success is newer than every caller still queued, so they all take
        // it.
        let cache = SeccompProfilesCache::new(Duration::from_secs(10));
        let builds = Arc::new(AtomicUsize::new(0));
        let callers = 4;

        let mut tasks = Vec::with_capacity(callers);
        for _ in 0..callers {
            let cache = cache.clone();
            let builds = builds.clone();
            tasks.push(tokio::spawn(async move {
                cache
                    .get_or_build(|| async move {
                        // The first rebuild to run fails; every later one succeeds.
                        let nth = builds.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        if nth == 0 {
                            Err("db down")
                        } else {
                            Ok(body("ok"))
                        }
                    })
                    .await
            }));
        }
        let mut outcomes = Vec::with_capacity(callers);
        for task in tasks {
            outcomes.push(task.await.unwrap());
        }

        assert_eq!(
            outcomes[0],
            Err("db down"),
            "the failing caller gets its error"
        );
        for outcome in &outcomes[1..] {
            assert_eq!(*outcome, Ok(body("ok")));
        }
        assert_eq!(
            builds.load(Ordering::SeqCst),
            2,
            "one failure, one success, no rebuild per remaining waiter"
        );
        assert_eq!((cache.hits(), cache.misses()), (callers as u64 - 2, 2));
    }

    #[tokio::test]
    async fn ttl_zero_bypasses_the_cache() {
        let cache = SeccompProfilesCache::new(Duration::ZERO);
        assert!(!cache.enabled());
        let builds = Arc::new(AtomicUsize::new(0));

        let a = cache.get_or_build(counted(&builds, "a")).await.unwrap();
        let b = cache.get_or_build(counted(&builds, "b")).await.unwrap();

        assert_eq!(builds.load(Ordering::SeqCst), 2, "every call rebuilds");
        assert_eq!((a, b), (body("a"), body("b")));
        assert_eq!((cache.hits(), cache.misses()), (0, 2));
    }

    #[tokio::test]
    async fn a_failed_build_is_not_cached() {
        let cache = SeccompProfilesCache::new(Duration::from_secs(10));

        let failed: Result<Bytes, &str> = cache.get_or_build(|| async { Err("db down") }).await;
        assert_eq!(failed, Err("db down"), "the error reaches the caller");

        // The next caller retries rather than being served the failure, and
        // its success is what gets cached.
        let ok = cache
            .get_or_build(|| async { Ok::<_, &str>(body("a")) })
            .await
            .unwrap();
        let again = cache
            .get_or_build(|| async { Ok::<_, &str>(body("b")) })
            .await
            .unwrap();
        assert_eq!((ok, again), (body("a"), body("a")));
        assert_eq!((cache.hits(), cache.misses()), (1, 2));
    }

    // ---- env -----------------------------------------------------------

    const KEY: &str = "SECCOMP_PROFILES_CACHE_TTL_SECS";

    /// Callers hold `crate::test_support::env_lock()` for the guard's
    /// lifetime: `std::env` is process-global and parallel tests mutating
    /// even different keys race on libc's `environ`.
    struct EnvGuard(Option<String>);

    impl EnvGuard {
        fn set(value: Option<&str>) -> Self {
            let prev = std::env::var(KEY).ok();
            match value {
                Some(v) => std::env::set_var(KEY, v),
                None => std::env::remove_var(KEY),
            }
            Self(prev)
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.0.take() {
                Some(v) => std::env::set_var(KEY, v),
                None => std::env::remove_var(KEY),
            }
        }
    }

    #[test]
    fn from_env_defaults_when_unset_or_unparseable() {
        let _lock = crate::test_support::env_lock();
        let default = Duration::from_secs(DEFAULT_PROFILES_CACHE_TTL_SECS);
        {
            let _g = EnvGuard::set(None);
            assert_eq!(SeccompProfilesCache::from_env().ttl(), default);
        }
        {
            // Falls back rather than refusing to start.
            let _g = EnvGuard::set(Some("ten"));
            assert_eq!(SeccompProfilesCache::from_env().ttl(), default);
        }
    }

    #[test]
    fn from_env_parses_trims_and_treats_zero_as_disabled() {
        let _lock = crate::test_support::env_lock();
        {
            let _g = EnvGuard::set(Some(" 30\n"));
            let cache = SeccompProfilesCache::from_env();
            assert_eq!(cache.ttl(), Duration::from_secs(30));
            assert!(cache.enabled());
        }
        {
            let _g = EnvGuard::set(Some("0"));
            let cache = SeccompProfilesCache::from_env();
            assert_eq!(cache.ttl(), Duration::ZERO);
            assert!(!cache.enabled(), "0 is the documented off switch");
        }
    }
}
