//! The claim loop's two halves: talking to the Broker ([`Broker`],
//! [`HttpBroker`]), and carrying one grant from "claimed" to "stored" or
//! "failed" ([`run_grant`]), renewing the lease while the scan runs.
//!
//! Both are written against traits so the state machine — renewals,
//! a lost lease cancelling the scan, 503/429/5xx backoff, paging — is
//! tested with a scripted Broker and a scripted scan.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info, warn};

use super::api::{
    Action, ClaimRequest, ClaimResponse, ClaimUpdate, ClaimUpdateResponse, FailReason, SbomPage,
    CLAIM_HEADER,
};
use super::post::{self, Sbom, Subject};

/// Renew cadence (the lease is 15 min).
pub const RENEW_EVERY: Duration = Duration::from_secs(60);
/// Attempts per Broker write before giving up on it (the lease then
/// expires on its own and the digest is re-granted).
pub const WRITE_ATTEMPTS: u32 = 5;
/// Worker `busy` retries inside one grant, and the wait between them.
pub const BUSY_RETRIES: u32 = 5;
pub const BUSY_WAIT: Duration = Duration::from_secs(30);

/// How the Broker answered, reduced to what the loop does next.
#[derive(Debug, Clone, PartialEq)]
pub enum Answer<T> {
    Ok(T),
    /// 409: the token, lease or epoch is stale. Stop; nothing was written.
    Stale,
    /// 503: catalog off on the Broker (long wait) or its queue is full
    /// (short `Retry-After`).
    Unavailable(Duration),
    /// 404: a Broker without the catalog routes.
    Missing,
    /// 429, other 5xx, or no answer: try again after the hint.
    Retry(Option<Duration>),
    /// Any other 4xx: the request itself is wrong. Not retried.
    Refused(u16, String),
}

/// Default wait on a 503 without `Retry-After`.
pub const UNAVAILABLE_WAIT: Duration = Duration::from_secs(60);

/// Map a status (and `Retry-After`, seconds) to an [`Answer`] kind.
pub fn classify<T>(status: u16, retry_after: Option<u64>, body: String) -> Answer<T> {
    let hint = retry_after.map(|s| Duration::from_secs(s.min(3600)));
    match status {
        409 => Answer::Stale,
        503 => Answer::Unavailable(hint.unwrap_or(UNAVAILABLE_WAIT)),
        404 => Answer::Missing,
        429 | 500..=599 => Answer::Retry(hint),
        s => Answer::Refused(s, body),
    }
}

/// The three catalog writes.
pub trait Broker: Send + Sync {
    fn claim(&self, req: &ClaimRequest) -> impl Future<Output = Answer<ClaimResponse>> + Send;
    fn update(
        &self,
        digest: &str,
        token: &str,
        u: &ClaimUpdate,
    ) -> impl Future<Output = Answer<ClaimUpdateResponse>> + Send;
    fn upload(
        &self,
        digest: &str,
        token: &str,
        page: &SbomPage,
    ) -> impl Future<Output = Answer<serde_json::Value>> + Send;
}

/// The Broker over HTTP, with the catalog token as a default header.
pub struct HttpBroker {
    client: reqwest::Client,
    base: String,
}

impl HttpBroker {
    pub fn new(base: String, token: &str) -> Self {
        Self {
            client: crate::client::build_http_client(
                crate::client::REQUEST_TIMEOUT,
                crate::client::CONNECT_TIMEOUT,
                Some(token),
            ),
            base,
        }
    }

    fn url(&self, path: &str) -> String {
        crate::client::build_url(&self.base, path)
    }

    async fn send<T: serde::de::DeserializeOwned>(
        &self,
        req: reqwest::RequestBuilder,
    ) -> Answer<T> {
        let res = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                debug!(error = %e, "node catalog: broker request failed");
                return Answer::Retry(None);
            }
        };
        let status = res.status();
        let retry_after = res
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());
        if status.is_success() {
            let body = res.bytes().await.unwrap_or_default();
            return match serde_json::from_slice(&body) {
                Ok(v) => Answer::Ok(v),
                Err(e) => Answer::Refused(status.as_u16(), format!("unreadable answer: {e}")),
            };
        }
        let mut body = res.text().await.unwrap_or_default();
        body.truncate(body.floor_char_boundary(512));
        classify(status.as_u16(), retry_after, body)
    }
}

/// Path segment for a digest (`sha256:…` is URL-safe apart from `:`,
/// which is legal in a path segment; encoded anyway for proxies).
fn digest_path(d: &str) -> String {
    percent_encoding::utf8_percent_encode(d, percent_encoding::NON_ALPHANUMERIC).to_string()
}

impl Broker for HttpBroker {
    async fn claim(&self, req: &ClaimRequest) -> Answer<ClaimResponse> {
        self.send(self.client.post(self.url("catalog/claims")).json(req))
            .await
    }

    async fn update(
        &self,
        digest: &str,
        token: &str,
        u: &ClaimUpdate,
    ) -> Answer<ClaimUpdateResponse> {
        let url = self.url(&format!("catalog/claims/{}", digest_path(digest)));
        self.send(self.client.put(url).header(CLAIM_HEADER, token).json(u))
            .await
    }

    async fn upload(
        &self,
        digest: &str,
        token: &str,
        page: &SbomPage,
    ) -> Answer<serde_json::Value> {
        let url = self.url(&format!("catalog/images/{}/sbom", digest_path(digest)));
        self.send(self.client.post(url).header(CLAIM_HEADER, token).json(page))
            .await
    }
}

/// Exponential backoff with jitter, for transient Broker trouble.
#[derive(Debug, Clone)]
pub struct Backoff {
    base: Duration,
    cap: Duration,
    step: u32,
}

impl Backoff {
    pub fn new(base: Duration, cap: Duration) -> Self {
        Self { base, cap, step: 0 }
    }

    /// The next wait: base * 2^step, capped, plus up to 20 % jitter; a
    /// server hint wins when it is longer.
    pub fn next(&mut self, hint: Option<Duration>) -> Duration {
        let exp = self
            .base
            .saturating_mul(1u32 << self.step.min(16))
            .min(self.cap);
        self.step = self.step.saturating_add(1);
        let d = exp + super::feed::jitter(exp / 5);
        hint.map_or(d, |h| h.max(d))
    }

    pub fn reset(&mut self) {
        self.step = 0;
    }
}

/// What one scan produced. One value per scan, moved once: boxing the
/// large variant would buy nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum ScanResult {
    Sbom {
        subject: Subject,
        sbom: Sbom,
    },
    Failed {
        reason: FailReason,
        detail: String,
    },
    /// The worker is running another scan.
    Busy,
    /// Cancelled (the lease was lost).
    Cancelled,
}

/// Runs one scan of a granted digest. Implementations check `cancel`
/// and return [`ScanResult::Cancelled`] promptly when it is set.
pub trait Scan: Send + Sync {
    fn scan(
        &self,
        digest: &str,
        cancel: Arc<AtomicBool>,
    ) -> impl Future<Output = ScanResult> + Send;
}

/// How a grant ended.
#[derive(Debug, Clone, PartialEq)]
pub enum GrantOutcome {
    /// The SBOM was stored (or the Broker already had it).
    Stored { pages: usize, status: String },
    /// Reported to the Broker as failed/skipped with this reason.
    Reported(FailReason),
    /// The lease was lost (409): someone else owns the digest now.
    LostLease,
    /// The Broker could not be told (503/404/unreachable). The lease
    /// expires on its own and the digest is re-granted.
    Abandoned(String),
}

/// A granted digest, carried to completion.
pub struct GrantCtx<'a, B: Broker> {
    pub broker: &'a B,
    pub node: &'a str,
    pub digest: &'a str,
    pub token: &'a str,
    pub renew_every: Duration,
    pub busy_wait: Duration,
    pub retry_base: Duration,
}

impl<B: Broker> GrantCtx<'_, B> {
    fn update(&self, action: Action, reason: Option<FailReason>) -> ClaimUpdate {
        ClaimUpdate {
            action,
            node: self.node.to_string(),
            reason: reason.map(|r| r.as_str().to_string()),
        }
    }

    /// A Broker write with bounded retries on transient answers.
    async fn write<T, F, Fut>(&self, what: &str, mut f: F) -> Answer<T>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Answer<T>>,
    {
        let mut backoff = Backoff::new(self.retry_base, Duration::from_secs(60));
        let mut last = Answer::Retry(None);
        for attempt in 1..=WRITE_ATTEMPTS {
            last = f().await;
            let wait = match &last {
                Answer::Retry(hint) => backoff.next(*hint),
                // A full upload queue: short, server-chosen waits.
                Answer::Unavailable(d) if *d <= Duration::from_secs(10) => backoff.next(Some(*d)),
                _ => return last,
            };
            debug!(
                what,
                attempt,
                wait_ms = wait.as_millis() as u64,
                "node catalog: retrying"
            );
            if attempt < WRITE_ATTEMPTS {
                tokio::time::sleep(wait).await;
            }
        }
        last
    }

    async fn renew(&self) -> Answer<ClaimUpdateResponse> {
        let u = self.update(Action::Renew, None);
        self.broker.update(self.digest, self.token, &u).await
    }

    async fn report(&self, reason: FailReason) -> GrantOutcome {
        let u = self.update(reason.action(), Some(reason));
        match self
            .write("report", || self.broker.update(self.digest, self.token, &u))
            .await
        {
            Answer::Ok(_) => GrantOutcome::Reported(reason),
            Answer::Stale => GrantOutcome::LostLease,
            other => GrantOutcome::Abandoned(format!("report {}: {other:?}", reason.as_str())),
        }
    }

    /// Run `scan` while renewing the lease every `renew_every`. A 409 on
    /// renew cancels the scan; other renew trouble is tolerated (the
    /// lease has 15 minutes of slack).
    async fn scan_renewing<S: Scan>(&self, scan: &S) -> Result<ScanResult, GrantOutcome> {
        let cancel = Arc::new(AtomicBool::new(false));
        let fut = scan.scan(self.digest, Arc::clone(&cancel));
        tokio::pin!(fut);
        let mut tick = tokio::time::interval_at(
            tokio::time::Instant::now() + self.renew_every,
            self.renew_every,
        );
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut lost = false;
        loop {
            tokio::select! {
                r = &mut fut => {
                    return if lost { Err(GrantOutcome::LostLease) } else { Ok(r) };
                }
                _ = tick.tick(), if !lost => match self.renew().await {
                    Answer::Ok(_) => {}
                    Answer::Stale => {
                        warn!(digest = self.digest, "node catalog: lease lost; cancelling the scan");
                        cancel.store(true, Ordering::Relaxed);
                        lost = true;
                    }
                    other => debug!(digest = self.digest, answer = ?other, "node catalog: renew failed; will retry"),
                },
            }
        }
    }

    async fn upload(&self, subject: &Subject, sbom: &Sbom) -> GrantOutcome {
        let set_id = uuid::Uuid::new_v4().to_string();
        let scanned_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let pages = match post::pages(subject, sbom, &set_id, &scanned_at) {
            Ok(p) => p,
            Err(e) => {
                warn!(digest = self.digest, error = %e.0, "node catalog: SBOM cannot be paged");
                return self.report(FailReason::Error).await;
            }
        };
        let n = pages.len();
        let mut last_renew = tokio::time::Instant::now();
        let mut status = String::new();
        for page in &pages {
            if last_renew.elapsed() >= self.renew_every {
                if self.renew().await == Answer::Stale {
                    return GrantOutcome::LostLease;
                }
                last_renew = tokio::time::Instant::now();
            }
            match self
                .write("upload", || {
                    self.broker.upload(self.digest, self.token, page)
                })
                .await
            {
                Answer::Ok(v) => {
                    status = v
                        .get("status")
                        .and_then(|s| s.as_str())
                        .unwrap_or_default()
                        .to_string();
                }
                Answer::Stale => return GrantOutcome::LostLease,
                Answer::Refused(code, body) => {
                    warn!(
                        digest = self.digest,
                        code, body, "node catalog: Broker refused a page"
                    );
                    return self.report(FailReason::Error).await;
                }
                other => return GrantOutcome::Abandoned(format!("upload: {other:?}")),
            }
        }
        GrantOutcome::Stored { pages: n, status }
    }
}

/// Carry one grant to its end.
pub async fn run_grant<B: Broker, S: Scan>(ctx: &GrantCtx<'_, B>, scan: &S) -> GrantOutcome {
    let mut busy = 0;
    loop {
        let result = match ctx.scan_renewing(scan).await {
            Ok(r) => r,
            Err(outcome) => return outcome,
        };
        match result {
            ScanResult::Sbom { subject, sbom } => return ctx.upload(&subject, &sbom).await,
            ScanResult::Failed { reason, detail } => {
                info!(
                    digest = ctx.digest,
                    reason = reason.as_str(),
                    detail,
                    "node catalog: scan failed"
                );
                return ctx.report(reason).await;
            }
            ScanResult::Cancelled => return GrantOutcome::LostLease,
            ScanResult::Busy if busy < BUSY_RETRIES => {
                busy += 1;
                debug!(
                    digest = ctx.digest,
                    busy, "node catalog: worker busy; retrying"
                );
                tokio::time::sleep(ctx.busy_wait).await;
                if ctx.renew().await == Answer::Stale {
                    return GrantOutcome::LostLease;
                }
            }
            ScanResult::Busy => return ctx.report(FailReason::WorkerUnavailable).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::api::{Component, Scanner};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// A Broker that answers from per-route scripts and records calls.
    #[derive(Default)]
    struct MockBroker {
        updates: Mutex<VecDeque<Answer<ClaimUpdateResponse>>>,
        uploads: Mutex<VecDeque<Answer<serde_json::Value>>>,
        log: Mutex<Vec<String>>,
    }

    impl MockBroker {
        fn with(
            updates: Vec<Answer<ClaimUpdateResponse>>,
            uploads: Vec<Answer<serde_json::Value>>,
        ) -> Self {
            Self {
                updates: Mutex::new(updates.into()),
                uploads: Mutex::new(uploads.into()),
                log: Mutex::default(),
            }
        }
        fn log(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }
    }

    fn ok_update() -> Answer<ClaimUpdateResponse> {
        Answer::Ok(ClaimUpdateResponse {
            state: Some("claimed".into()),
            lease_expires_at: None,
            next_attempt_at: None,
        })
    }

    impl Broker for MockBroker {
        async fn claim(&self, _: &ClaimRequest) -> Answer<ClaimResponse> {
            unreachable!("run_grant never claims")
        }
        async fn update(
            &self,
            _: &str,
            token: &str,
            u: &ClaimUpdate,
        ) -> Answer<ClaimUpdateResponse> {
            assert_eq!(token, "tok");
            let v = serde_json::to_value(u).unwrap();
            self.log.lock().unwrap().push(format!(
                "{}{}",
                v["action"].as_str().unwrap(),
                v.get("reason")
                    .and_then(|r| r.as_str())
                    .map(|r| format!(":{r}"))
                    .unwrap_or_default()
            ));
            self.updates
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(ok_update)
        }
        async fn upload(&self, _: &str, token: &str, p: &SbomPage) -> Answer<serde_json::Value> {
            assert_eq!(token, "tok");
            self.log
                .lock()
                .unwrap()
                .push(format!("page{}/{}", p.page.index, p.page.total));
            self.uploads
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Answer::Ok(serde_json::json!({"status": "staged"})))
        }
    }

    /// A scan that takes `takes` (virtual time) and returns `result`,
    /// honouring cancel.
    struct MockScan {
        takes: Duration,
        results: Mutex<VecDeque<ScanResult>>,
        cancelled: Arc<AtomicBool>,
    }

    impl MockScan {
        fn new(takes: Duration, results: Vec<ScanResult>) -> Self {
            Self {
                takes,
                results: Mutex::new(results.into()),
                cancelled: Arc::default(),
            }
        }
    }

    impl Scan for MockScan {
        async fn scan(&self, _: &str, cancel: Arc<AtomicBool>) -> ScanResult {
            let end = tokio::time::Instant::now() + self.takes;
            while tokio::time::Instant::now() < end {
                if cancel.load(Ordering::Relaxed) {
                    self.cancelled.store(true, Ordering::Relaxed);
                    return ScanResult::Cancelled;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            self.results.lock().unwrap().pop_front().expect("scripted")
        }
    }

    fn sbom(n: usize) -> ScanResult {
        ScanResult::Sbom {
            subject: Subject {
                digest: "sha256:x".into(),
                digest_kind: None,
                repository: None,
                platform: "linux/amd64".into(),
                epoch: 1,
            },
            sbom: Sbom {
                completeness: "full".into(),
                partial_reasons: vec![],
                scanner: Scanner::default(),
                stats: serde_json::json!({}),
                components: (0..n)
                    .map(|i| Component {
                        name: format!("p{i}"),
                        ..Default::default()
                    })
                    .collect(),
            },
        }
    }

    fn ctx(b: &MockBroker) -> GrantCtx<'_, MockBroker> {
        GrantCtx {
            broker: b,
            node: "n1",
            digest: "sha256:x",
            token: "tok",
            renew_every: RENEW_EVERY,
            busy_wait: BUSY_WAIT,
            retry_base: Duration::from_secs(1),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_long_scan_renews_the_lease_every_minute_then_pages() {
        let b = MockBroker::default();
        // 150 s scan: two renewals, then 4500 components in 3 pages.
        let s = MockScan::new(Duration::from_secs(150), vec![sbom(4500)]);
        let out = run_grant(&ctx(&b), &s).await;
        assert_eq!(
            out,
            GrantOutcome::Stored {
                pages: 3,
                status: "staged".into()
            }
        );
        assert_eq!(
            b.log(),
            vec!["renew", "renew", "page0/3", "page1/3", "page2/3"]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_409_on_renew_cancels_the_scan_and_posts_nothing() {
        let b = MockBroker::with(vec![ok_update(), Answer::Stale], vec![]);
        let s = MockScan::new(Duration::from_secs(600), vec![sbom(1)]);
        let out = run_grant(&ctx(&b), &s).await;
        assert_eq!(out, GrantOutcome::LostLease);
        assert!(
            s.cancelled.load(Ordering::Relaxed),
            "the scan saw the cancel"
        );
        assert_eq!(b.log(), vec!["renew", "renew"]);
    }

    #[tokio::test(start_paused = true)]
    async fn transient_renew_failures_do_not_cancel() {
        let b = MockBroker::with(
            vec![
                Answer::Retry(None),
                Answer::Unavailable(Duration::from_secs(60)),
            ],
            vec![],
        );
        let s = MockScan::new(Duration::from_secs(150), vec![sbom(1)]);
        assert!(matches!(
            run_grant(&ctx(&b), &s).await,
            GrantOutcome::Stored { .. }
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn a_409_on_a_page_stops_the_upload() {
        let b = MockBroker::with(
            vec![],
            vec![
                Answer::Ok(serde_json::json!({"status":"staged"})),
                Answer::Stale,
            ],
        );
        let s = MockScan::new(Duration::from_secs(1), vec![sbom(4500)]);
        assert_eq!(run_grant(&ctx(&b), &s).await, GrantOutcome::LostLease);
        assert_eq!(b.log(), vec!["page0/3", "page1/3"]);
    }

    #[tokio::test(start_paused = true)]
    async fn pages_retry_429_and_5xx_with_backoff_and_a_full_queue_503() {
        let b = MockBroker::with(
            vec![],
            vec![
                Answer::Retry(Some(Duration::from_secs(2))),
                Answer::Retry(None),
                Answer::Unavailable(Duration::from_secs(5)),
                Answer::Ok(serde_json::json!({"status":"stored","claim":"done"})),
            ],
        );
        let s = MockScan::new(Duration::from_secs(1), vec![sbom(10)]);
        let started = tokio::time::Instant::now();
        let out = run_grant(&ctx(&b), &s).await;
        assert_eq!(
            out,
            GrantOutcome::Stored {
                pages: 1,
                status: "stored".into()
            }
        );
        assert_eq!(b.log().len(), 4);
        assert!(started.elapsed() >= Duration::from_secs(8), "backed off");
    }

    #[tokio::test(start_paused = true)]
    async fn a_503_catalog_off_abandons_rather_than_hammering() {
        let b = MockBroker::with(vec![], vec![Answer::Unavailable(Duration::from_secs(60))]);
        let s = MockScan::new(Duration::from_secs(1), vec![sbom(10)]);
        assert!(matches!(
            run_grant(&ctx(&b), &s).await,
            GrantOutcome::Abandoned(_)
        ));
        assert_eq!(b.log(), vec!["page0/1"]);
    }

    #[tokio::test(start_paused = true)]
    async fn failures_are_reported_with_the_right_action() {
        for (reason, want) in [
            (FailReason::LazySnapshotter, "skip:lazy_snapshotter"),
            (FailReason::Drift, "fail:drift"),
            (FailReason::Oom, "fail:oom"),
            (FailReason::NoPackagesFound, "fail:no_packages_found"),
        ] {
            let b = MockBroker::default();
            let s = MockScan::new(
                Duration::from_secs(1),
                vec![ScanResult::Failed {
                    reason,
                    detail: String::new(),
                }],
            );
            assert_eq!(
                run_grant(&ctx(&b), &s).await,
                GrantOutcome::Reported(reason)
            );
            assert_eq!(b.log(), vec![want]);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_stale_report_is_a_lost_lease_and_refusals_are_not_retried() {
        let b = MockBroker::with(vec![Answer::Stale], vec![]);
        let s = MockScan::new(
            Duration::from_secs(1),
            vec![ScanResult::Failed {
                reason: FailReason::Error,
                detail: String::new(),
            }],
        );
        assert_eq!(run_grant(&ctx(&b), &s).await, GrantOutcome::LostLease);

        let b = MockBroker::with(vec![], vec![Answer::Refused(422, "bad".into())]);
        let s = MockScan::new(Duration::from_secs(1), vec![sbom(1)]);
        assert_eq!(
            run_grant(&ctx(&b), &s).await,
            GrantOutcome::Reported(FailReason::Error)
        );
        assert_eq!(b.log(), vec!["page0/1", "fail:error"]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_busy_worker_is_retried_then_reported() {
        let b = MockBroker::default();
        let s = MockScan::new(Duration::from_secs(1), vec![ScanResult::Busy, sbom(1)]);
        assert!(matches!(
            run_grant(&ctx(&b), &s).await,
            GrantOutcome::Stored { .. }
        ));
        assert_eq!(b.log(), vec!["renew", "page0/1"]);

        let b = MockBroker::default();
        let s = MockScan::new(
            Duration::from_secs(1),
            (0..=BUSY_RETRIES).map(|_| ScanResult::Busy).collect(),
        );
        assert_eq!(
            run_grant(&ctx(&b), &s).await,
            GrantOutcome::Reported(FailReason::WorkerUnavailable)
        );
        assert_eq!(b.log().last().unwrap(), "skip:worker_unavailable");
    }

    #[test]
    fn statuses_classify() {
        assert_eq!(classify::<()>(409, None, String::new()), Answer::Stale);
        assert_eq!(
            classify::<()>(503, Some(5), String::new()),
            Answer::Unavailable(Duration::from_secs(5))
        );
        assert_eq!(
            classify::<()>(503, None, String::new()),
            Answer::Unavailable(UNAVAILABLE_WAIT)
        );
        assert_eq!(classify::<()>(404, None, String::new()), Answer::Missing);
        assert_eq!(
            classify::<()>(429, None, String::new()),
            Answer::Retry(None)
        );
        assert_eq!(
            classify::<()>(502, Some(9), String::new()),
            Answer::Retry(Some(Duration::from_secs(9)))
        );
        assert!(matches!(
            classify::<()>(422, None, "x".into()),
            Answer::Refused(422, _)
        ));
    }

    #[test]
    fn backoff_grows_caps_and_honours_hints() {
        let mut b = Backoff::new(Duration::from_secs(5), Duration::from_secs(300));
        let d0 = b.next(None);
        assert!(d0 >= Duration::from_secs(5) && d0 <= Duration::from_secs(6));
        let d1 = b.next(None);
        assert!(d1 >= Duration::from_secs(10));
        for _ in 0..20 {
            assert!(b.next(None) <= Duration::from_secs(360));
        }
        assert!(b.next(Some(Duration::from_secs(1000))) >= Duration::from_secs(1000));
        b.reset();
        assert!(b.next(None) <= Duration::from_secs(6));
    }

    /// A loopback HTTP Broker: answers each request with the next
    /// scripted `(status, extra headers, body)` and records what came in.
    fn http_broker(
        script: Vec<(u16, &'static str, &'static str)>,
    ) -> (String, std::thread::JoinHandle<Vec<String>>) {
        use std::io::{BufRead, BufReader, Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let t = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for (status, headers, body) in script {
                let (s, _) = l.accept().unwrap();
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut head = String::new();
                let mut len = 0usize;
                loop {
                    let mut line = String::new();
                    r.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap();
                    }
                    head.push_str(&line);
                }
                let mut b = vec![0; len];
                r.read_exact(&mut b).unwrap();
                seen.push(format!("{head}\r\n{}", String::from_utf8_lossy(&b)));
                let mut w = s;
                write!(
                    w,
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n{headers}content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
            seen
        });
        (base, t)
    }

    /// The real client against the route contract: paths, the bearer
    /// token, the claim header, and status mapping.
    #[tokio::test]
    async fn the_http_broker_speaks_the_catalog_routes() {
        let (base, server) = http_broker(vec![
            (
                200,
                "",
                r#"{"grantsEnabled":true,"grant":{"digest":"sha256:ab","claimToken":"t-1","leaseExpiresAt":"2026-10-03T10:15:00Z","leaseSeconds":900}}"#,
            ),
            (
                200,
                "",
                r#"{"state":"claimed","leaseExpiresAt":"2026-10-03T10:16:00Z"}"#,
            ),
            (409, "", "stale"),
            (503, "retry-after: 5\r\n", "queue full"),
            (404, "", ""),
        ]);
        let b = HttpBroker::new(base, "cat-token");
        let req = ClaimRequest {
            node: "n1".into(),
            platform: "linux/amd64".into(),
            epoch: 1,
            offer: vec!["sha256:ab".into()],
        };
        let Answer::Ok(r) = b.claim(&req).await else {
            panic!("claim")
        };
        assert_eq!(r.grant.unwrap().claim_token, "t-1");
        let renew = ClaimUpdate {
            action: Action::Renew,
            node: "n1".into(),
            reason: None,
        };
        assert!(matches!(
            b.update("sha256:ab", "t-1", &renew).await,
            Answer::Ok(_)
        ));
        assert_eq!(b.update("sha256:ab", "t-1", &renew).await, Answer::Stale);
        let page = crate::catalog::post::pages(
            &Subject {
                digest: "sha256:ab".into(),
                digest_kind: None,
                repository: None,
                platform: "linux/amd64".into(),
                epoch: 1,
            },
            &Sbom {
                completeness: "full".into(),
                partial_reasons: vec![],
                scanner: Scanner::default(),
                stats: serde_json::json!({}),
                components: vec![],
            },
            "set",
            "2026-10-03T10:00:00Z",
        )
        .unwrap()
        .remove(0);
        assert_eq!(
            b.upload("sha256:ab", "t-1", &page).await,
            Answer::Unavailable(Duration::from_secs(5))
        );
        assert_eq!(b.claim(&req).await, Answer::Missing);

        let seen = server.join().unwrap();
        let lower: Vec<String> = seen.iter().map(|s| s.to_ascii_lowercase()).collect();
        assert!(lower[0].starts_with("post /catalog/claims "));
        assert!(lower[1].starts_with("put /catalog/claims/sha256%3aab "));
        assert!(lower[3].starts_with("post /catalog/images/sha256%3aab/sbom "));
        for s in &lower {
            assert!(s.contains("authorization: bearer cat-token"), "{s}");
        }
        assert!(lower[1].contains("x-kguardian-claim: t-1"));
        assert!(lower[3].contains("x-kguardian-claim: t-1"));
        assert!(!lower[0].contains("x-kguardian-claim"));
        assert!(seen[1].ends_with(r#"{"action":"renew","node":"n1"}"#));
        assert!(seen[0].contains(r#""offer":["sha256:ab"]"#));
    }
}
