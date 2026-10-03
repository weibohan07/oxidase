//! Observable upstream timing boundaries and one logical pre-head budget.
//!
//! Request-body EOS here means local handoff to Hyper, not receipt by the peer.
//! A response may arrive before EOS; no helper waits for an upload before
//! allowing a response head to complete.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::task::AtomicWaker;
use hyper_util::client::legacy::connect::CaptureConnection;
use oxidase_runtime::{ClusterRequestPermit, PreparedEndpoint};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, watch};
use tokio::time::Instant;

use crate::metrics::Metrics;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TimeoutPhase {
    Queue,
    Connect,
    Tls,
    RequestBody,
    ResponseHeader,
    ResponseBody,
    Total,
}

impl TimeoutPhase {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Queue => "queue",
            Self::Connect => "connect",
            Self::Tls => "tls",
            Self::RequestBody => "request_body",
            Self::ResponseHeader => "response_header",
            Self::ResponseBody => "response_body",
            Self::Total => "total",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UpstreamTimeoutError {
    phase: TimeoutPhase,
    during: TimeoutPhase,
}

impl UpstreamTimeoutError {
    pub(crate) const fn phase(self) -> TimeoutPhase {
        self.phase
    }
}

impl fmt::Display for UpstreamTimeoutError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "upstream {} timeout during {}",
            self.phase.as_str(),
            self.during.as_str()
        )
    }
}

impl std::error::Error for UpstreamTimeoutError {}

/// Constructed once, never renewed by admission, attempts, or endpoint changes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PreResponseBudget {
    deadline: Instant,
}

impl PreResponseBudget {
    pub(crate) fn new(duration: Duration) -> Self {
        let now = Instant::now();
        // A nonrepresentable deadline fails closed rather than becoming infinite.
        Self {
            deadline: now.checked_add(duration).unwrap_or(now),
        }
    }

    pub(crate) const fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(crate) fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    pub(crate) async fn run<F: Future>(
        &self,
        during: TimeoutPhase,
        future: F,
    ) -> Result<F::Output, UpstreamTimeoutError> {
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(self.deadline()) => Err(UpstreamTimeoutError {
                phase: TimeoutPhase::Total,
                during,
            }),
            output = future => Ok(output),
        }
    }

    #[cfg(test)]
    async fn phase<F: Future>(
        &self,
        phase: TimeoutPhase,
        timeout: Duration,
        future: F,
    ) -> Result<F::Output, UpstreamTimeoutError> {
        let phase_deadline = Instant::now().checked_add(timeout).unwrap_or(self.deadline);
        let (deadline, reason) = if self.deadline <= phase_deadline {
            (self.deadline, TimeoutPhase::Total)
        } else {
            (phase_deadline, phase)
        };
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(deadline) => Err(UpstreamTimeoutError {
                phase: reason,
                during: phase,
            }),
            output = future => Ok(output),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LocalRequestFailure {
    Cancelled,
    IdleTimeout,
    InvalidBody,
    LimitExceeded,
}

#[derive(Default)]
struct RequestProgressState {
    eos_at: Option<Instant>,
    failure: Option<LocalRequestFailure>,
    upload_done: bool,
    response_done: bool,
    permit: Option<ClusterRequestPermit>,
    transport: Option<(CaptureConnection, bool)>,
    task_cancel: Option<Arc<UploadTaskCancellation>>,
}

#[derive(Default)]
struct RequestProgressInner {
    state: Mutex<RequestProgressState>,
    changed: Notify,
    upload_waker: AtomicWaker,
    timeout_metrics: Mutex<Option<Arc<Metrics>>>,
}

/// Shared between a body owned by Hyper and the final response lifecycle.
/// The state contains at most one permit and no request data or labels.
#[derive(Clone, Default)]
pub(crate) struct RequestProgress(Arc<RequestProgressInner>);

impl RequestProgress {
    pub(crate) fn new(initially_end_stream: bool) -> Self {
        let progress = Self::default();
        if initially_end_stream {
            progress.mark_eos();
            progress.upload_dropped();
        }
        progress
    }

    pub(crate) fn eos_at(&self) -> Option<Instant> {
        self.0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .eos_at
    }

    pub(crate) fn local_failure(&self) -> Option<LocalRequestFailure> {
        self.0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .failure
    }

    pub(crate) fn mark_eos(&self) {
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.eos_at.get_or_insert_with(Instant::now);
        drop(state);
        self.0.changed.notify_waiters();
    }

    pub(crate) fn fail(&self, failure: LocalRequestFailure) {
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let first = state.failure.is_none();
        state.failure.get_or_insert(failure);
        drop(state);
        if first
            && failure == LocalRequestFailure::IdleTimeout
            && let Some(metrics) = self
                .0
                .timeout_metrics
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
        {
            metrics.record_upstream_timeout(TimeoutPhase::RequestBody);
        }
        self.0.upload_waker.wake();
        self.0.changed.notify_waiters();
    }

    pub(crate) fn set_timeout_metrics(&self, metrics: Arc<Metrics>) {
        *self
            .0
            .timeout_metrics
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(metrics);
    }

    pub(crate) fn cancel_upload(&self) {
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cancel = if !state.upload_done {
            state.failure.get_or_insert(LocalRequestFailure::Cancelled);
            state.task_cancel.clone()
        } else {
            None
        };
        drop(state);
        if let Some(cancel) = cancel {
            cancel.cancel();
        }
        self.0.upload_waker.wake();
        self.0.changed.notify_waiters();
    }

    pub(crate) fn register_upload_waker(&self, waker: &std::task::Waker) {
        self.0.upload_waker.register(waker);
        self.register_upload_task();
    }

    /// Capture is set by Hyper before dispatch, hence before body polling.
    /// `forced_h2` includes cleartext H2 prior knowledge without an ALPN flag.
    pub(crate) fn capture_transport(&self, captured: CaptureConnection, forced_h2: bool) {
        self.0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .transport = Some((captured, forced_h2));
    }

    fn register_upload_task(&self) {
        let _ = UPSTREAM_TASK.try_with(|task| {
            if let Some(bound) = &task.bound {
                if Weak::ptr_eq(bound, &Arc::downgrade(&self.0)) {
                    self.bind_upload_task(Arc::clone(&task.cancel));
                }
                return;
            }
            let h2 = {
                let state = self
                    .0
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.transport.as_ref().and_then(|(capture, forced_h2)| {
                    if *forced_h2 {
                        Some(true)
                    } else {
                        capture
                            .connection_metadata()
                            .as_ref()
                            .map(|connected| connected.is_negotiated_h2())
                    }
                })
            };
            if h2 == Some(false) {
                // H1 has only one active request on this connection driver.
                self.bind_upload_task(Arc::clone(&task.cancel));
            } else {
                // H2 polls eagerly inside the shared dispatcher. Never bind
                // its cancellation; hand off to the subsequent Pipe spawn.
                *task
                    .pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some(Arc::downgrade(&self.0));
            }
        });
    }

    fn bind_upload_task(&self, cancel: Arc<UploadTaskCancellation>) {
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cancelled = state.failure == Some(LocalRequestFailure::Cancelled);
        state.task_cancel = Some(Arc::clone(&cancel));
        drop(state);
        if cancelled {
            cancel.cancel();
        }
    }

    pub(crate) fn upload_cancelled(&self) -> bool {
        self.local_failure() == Some(LocalRequestFailure::Cancelled)
    }

    pub(crate) fn upload_dropped(&self) {
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.upload_done = true;
        state.task_cancel.take();
        state.transport.take();
        if state.response_done {
            state.permit.take();
        }
        drop(state);
        let _ = UPSTREAM_TASK.try_with(|task| {
            let mut pending = task
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if pending
                .as_ref()
                .is_some_and(|pending| Weak::ptr_eq(pending, &Arc::downgrade(&self.0)))
            {
                pending.take();
            }
        });
        self.0.changed.notify_waiters();
    }

    pub(crate) fn attach_permit(
        &self,
        permit: ClusterRequestPermit,
    ) -> Result<AttemptLeaseGuard, ClusterRequestPermit> {
        let endpoint = Arc::clone(permit.endpoint());
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.permit.is_some() || state.response_done {
            return Err(permit);
        }
        state.permit = Some(permit);
        Ok(AttemptLeaseGuard {
            progress: self.clone(),
            endpoint,
            active: true,
        })
    }

    pub(crate) fn response_finished(&self) {
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.response_done = true;
        let cancel = if state.upload_done {
            state.permit.take();
            None
        } else {
            state.failure.get_or_insert(LocalRequestFailure::Cancelled);
            state.task_cancel.clone()
        };
        drop(state);
        if let Some(cancel) = cancel {
            cancel.cancel();
        }
        self.0.upload_waker.wake();
        self.0.changed.notify_waiters();
    }

    async fn wait_for_eos_or_terminal(&self) -> Option<Instant> {
        loop {
            let changed = self.0.changed.notified();
            {
                let state = self
                    .0
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if state.eos_at.is_some() || state.failure.is_some() || state.upload_done {
                    return state.eos_at;
                }
            }
            changed.await;
        }
    }

    async fn wait_request_closed(&self) {
        loop {
            let changed = self.0.changed.notified();
            if self
                .0
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .upload_done
            {
                return;
            }
            changed.await;
        }
    }
}

#[derive(Default)]
struct UploadTaskCancellation {
    cancelled: AtomicBool,
    changed: Notify,
}

impl UploadTaskCancellation {
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }

    async fn cancelled(&self) {
        loop {
            let changed = self.changed.notified();
            if self.cancelled.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }
}

/// Server-owned capacity for preserving a cold Hyper connecting owner after
/// logical request cancellation. This is neither a business retry nor a probe.
/// Reservations end at pool-ready; only cancellation before that boundary
/// spawns a cleanup task. Dropping the owner stops all remaining cleanup work.
pub(crate) struct DispatchRetirementBudget {
    admission: Arc<Semaphore>,
    shutdown: watch::Sender<bool>,
    workers: Arc<AtomicUsize>,
}

impl DispatchRetirementBudget {
    pub(crate) fn new(max_connecting: usize) -> Self {
        Self {
            admission: Arc::new(Semaphore::new(max_connecting.max(1))),
            shutdown: watch::channel(false).0,
            workers: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(crate) fn protect(
        &self,
        future: hyper_util::client::legacy::ResponseFuture,
        captured: CaptureConnection,
        progress: RequestProgress,
        connecting_cap: Duration,
    ) -> Result<ProtectedDispatch, ConnectingAdmissionError> {
        if *self.shutdown.borrow() {
            return Err(ConnectingAdmissionError::ShuttingDown);
        }
        let deadline = Instant::now()
            .checked_add(connecting_cap)
            .filter(|_| !connecting_cap.is_zero())
            .ok_or(ConnectingAdmissionError::InvalidDeadline)?;
        let permit = self
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| ConnectingAdmissionError::Overloaded)?;
        Ok(ProtectedDispatch {
            future: Some(future),
            captured,
            progress,
            permit: Some(permit),
            deadline,
            shutdown: self.shutdown.subscribe(),
            workers: Arc::clone(&self.workers),
            started: false,
        })
    }

    #[cfg(test)]
    fn active_workers(&self) -> usize {
        self.workers.load(Ordering::Acquire)
    }
}

impl Drop for DispatchRetirementBudget {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        self.admission.close();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConnectingAdmissionError {
    Overloaded,
    InvalidDeadline,
    ShuttingDown,
}

impl fmt::Display for ConnectingAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Overloaded => "upstream connection acquisition capacity is exhausted",
            Self::InvalidDeadline => "upstream connection acquisition deadline is invalid",
            Self::ShuttingDown => "upstream connection acquisition is shutting down",
        })
    }
}

impl std::error::Error for ConnectingAdmissionError {}

pub(crate) struct ProtectedDispatch {
    future: Option<hyper_util::client::legacy::ResponseFuture>,
    captured: CaptureConnection,
    progress: RequestProgress,
    permit: Option<OwnedSemaphorePermit>,
    deadline: Instant,
    shutdown: watch::Receiver<bool>,
    workers: Arc<AtomicUsize>,
    started: bool,
}

impl Future for ProtectedDispatch {
    type Output = Result<http::Response<hyper::body::Incoming>, hyper_util::client::legacy::Error>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.started = true;
        let output = Pin::new(
            self.future
                .as_mut()
                .expect("dispatch is polled before completion"),
        )
        .poll(context);
        if self.captured.connection_metadata().is_some() {
            self.permit.take();
        }
        if output.is_ready() {
            self.future.take();
            self.permit.take();
        }
        output
    }
}

struct RetirementWorker(Arc<AtomicUsize>);

impl Drop for RetirementWorker {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Drop for ProtectedDispatch {
    fn drop(&mut self) {
        let Some(mut future) = self.future.take() else {
            return;
        };
        if !self.started {
            return;
        }
        let Some(permit) = self.permit.take() else {
            return;
        };
        if self.captured.connection_metadata().is_some()
            || Instant::now() >= self.deadline
            || *self.shutdown.borrow()
        {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        self.progress.cancel_upload();
        let mut captured = self.captured.clone();
        let mut shutdown = self.shutdown.clone();
        let deadline = self.deadline;
        let workers = Arc::clone(&self.workers);
        workers.fetch_add(1, Ordering::AcqRel);
        runtime.spawn(async move {
            let _worker = RetirementWorker(workers);
            let _permit = permit;
            // Capture and dispatch happen in one Hyper poll. Cancellation can
            // suppress DATA, but cannot retract a head already queued to I/O.
            tokio::select! {
                biased;
                _ = shutdown.changed() => {},
                _ = tokio::time::sleep_until(deadline) => {},
                _ = captured.wait_for_connection_metadata() => {},
                _ = &mut future => {},
            }
        });
    }
}

struct UpstreamTaskScope {
    cancel: Arc<UploadTaskCancellation>,
    bound: Option<Weak<RequestProgressInner>>,
    pending: Mutex<Option<Weak<RequestProgressInner>>>,
}

tokio::task_local! {
    static UPSTREAM_TASK: UpstreamTaskScope;
}

/// Existing Hyper futures with a bounded task-local upload cancellation
/// capability. No global task registry, protocol driver, or request data.
///
/// Locked Hyper 1.11 `ClientTask::poll_pipe` synchronously invokes Executor(Pipe)
/// immediately after an eager Pending body poll. A completed eager body is
/// dropped first and clears the slot. The shared dispatcher is never bound.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct UpstreamExecutor;

impl<F> hyper::rt::Executor<F> for UpstreamExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, future: F) {
        let bound = UPSTREAM_TASK
            .try_with(|task| {
                task.pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
            })
            .ok()
            .flatten()
            .filter(|pending| {
                pending.upgrade().is_some_and(|progress| {
                    !progress
                        .state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .upload_done
                })
            });
        let cancel = Arc::new(UploadTaskCancellation::default());
        if let Some(progress) = bound.as_ref().and_then(Weak::upgrade) {
            RequestProgress(progress).bind_upload_task(Arc::clone(&cancel));
        }
        let scope = UpstreamTaskScope {
            cancel: Arc::clone(&cancel),
            bound,
            pending: Mutex::new(None),
        };
        tokio::spawn(UPSTREAM_TASK.scope(scope, async move {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {},
                _ = future => {},
            }
        }));
    }
}

/// Owns the response/pre-head leg of one attempt. Dropping an executor future
/// requests upload cancellation without releasing admission under a live H2
/// upload pipe. The second leg ends only when Hyper drops the body adapter.
pub(crate) struct AttemptLeaseGuard {
    progress: RequestProgress,
    endpoint: Arc<PreparedEndpoint>,
    active: bool,
}

impl AttemptLeaseGuard {
    pub(crate) fn endpoint(&self) -> &Arc<PreparedEndpoint> {
        &self.endpoint
    }

    pub(crate) fn progress(&self) -> RequestProgress {
        self.progress.clone()
    }

    pub(crate) async fn wait_request_closed(&self) {
        self.progress.wait_request_closed().await;
    }

    pub(crate) fn cancel_upload(&self) {
        self.progress.cancel_upload();
    }

    /// Retains the existing Cluster permit across a status retry. EOS alone is
    /// insufficient: buffered final DATA may still be waiting for send capacity.
    pub(crate) fn take_for_retry(&mut self) -> Option<ClusterRequestPermit> {
        if !self.active {
            return None;
        }
        let mut state = self
            .progress
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.upload_done {
            return None;
        }
        let permit = state.permit.take()?;
        state.response_done = true;
        self.active = false;
        Some(permit)
    }
}

impl Drop for AttemptLeaseGuard {
    fn drop(&mut self) {
        if self.active {
            self.progress.response_finished();
        }
    }
}

/// Response heads race every timer; a nonempty upload never gates an early head.
/// The header timer starts only once both pool readiness and local EOS are seen.
pub(crate) async fn await_response_head<F: Future>(
    future: F,
    mut captured: CaptureConnection,
    progress: &RequestProgress,
    response_header_timeout: Duration,
    budget: &PreResponseBudget,
) -> Result<F::Output, UpstreamTimeoutError> {
    tokio::pin!(future);
    let mut connection_ready = None;
    let mut capture_pending = true;
    let mut eos = progress.eos_at();
    let mut upload_pending = eos.is_none();
    let mut header_timer = None;
    loop {
        if header_timer.is_none()
            && let (Some(ready), Some(eos)) = (connection_ready, eos)
        {
            let started = std::cmp::max(ready, eos);
            let deadline = started
                .checked_add(response_header_timeout)
                .unwrap_or(budget.deadline);
            header_timer = Some(Box::pin(tokio::time::sleep_until(deadline)));
        }
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(budget.deadline) => return Err(UpstreamTimeoutError {
                phase: TimeoutPhase::Total,
                during: TimeoutPhase::ResponseHeader,
            }),
            output = &mut future => return Ok(output),
            connected = async { captured.wait_for_connection_metadata().await.is_some() }, if capture_pending => {
                capture_pending = false;
                if connected { connection_ready = Some(Instant::now()); }
            }
            ended = progress.wait_for_eos_or_terminal(), if upload_pending => {
                upload_pending = false;
                eos = ended;
            }
            _ = async { header_timer.as_mut().expect("enabled header timer").as_mut().await }, if header_timer.is_some() => return Err(UpstreamTimeoutError {
                phase: TimeoutPhase::ResponseHeader,
                during: TimeoutPhase::ResponseHeader,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::{
        PreResponseBudget, RequestProgress, TimeoutPhase, UpstreamExecutor, await_response_head,
    };

    #[tokio::test(start_paused = true)]
    async fn repeated_attempts_do_not_renew_the_absolute_budget() {
        let budget = PreResponseBudget::new(Duration::from_secs(10));
        for _ in 0..2 {
            budget
                .run(
                    TimeoutPhase::ResponseHeader,
                    tokio::time::sleep(Duration::from_secs(4)),
                )
                .await
                .expect("first two attempts fit");
        }
        let error = budget
            .run(
                TimeoutPhase::ResponseHeader,
                tokio::time::sleep(Duration::from_secs(4)),
            )
            .await
            .expect_err("third attempt cannot get a fresh budget");
        assert_eq!(error.phase(), TimeoutPhase::Total);
        assert!(budget.expired());
    }

    #[tokio::test(start_paused = true)]
    async fn queue_and_buffer_share_the_same_budget() {
        let budget = PreResponseBudget::new(Duration::from_secs(10));
        budget
            .run(
                TimeoutPhase::Queue,
                tokio::time::sleep(Duration::from_secs(6)),
            )
            .await
            .expect("queue is within the total");
        let error = budget
            .run(
                TimeoutPhase::RequestBody,
                tokio::time::sleep(Duration::from_secs(6)),
            )
            .await
            .expect_err("buffer does not get another ten seconds");
        assert_eq!(error.phase(), TimeoutPhase::Total);
    }

    #[tokio::test(start_paused = true)]
    async fn per_phase_and_total_expiry_are_distinct() {
        let budget = PreResponseBudget::new(Duration::from_secs(10));
        assert_eq!(
            budget
                .phase(
                    TimeoutPhase::Tls,
                    Duration::from_secs(2),
                    std::future::pending::<()>()
                )
                .await
                .expect_err("TLS phase expires first")
                .phase(),
            TimeoutPhase::Tls
        );
        assert_eq!(
            budget
                .phase(
                    TimeoutPhase::Connect,
                    Duration::from_secs(20),
                    std::future::pending::<()>()
                )
                .await
                .expect_err("remaining total expires first")
                .phase(),
            TimeoutPhase::Total
        );
    }

    #[tokio::test(start_paused = true)]
    async fn early_response_does_not_wait_for_upload_eos_or_connection_signal() {
        let mut request = http::Request::new(());
        let captured = hyper_util::client::legacy::connect::capture_connection(&mut request);
        let progress = RequestProgress::new(false);
        let budget = PreResponseBudget::new(Duration::from_secs(10));
        assert_eq!(
            await_response_head(
                async { "early response" },
                captured,
                &progress,
                Duration::from_secs(1),
                &budget
            )
            .await
            .expect("head never gates on upload"),
            "early response"
        );
        assert!(progress.eos_at().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn ongoing_upload_is_bounded_by_total_without_a_premature_header_timeout() {
        let mut request = http::Request::new(());
        let captured = hyper_util::client::legacy::connect::capture_connection(&mut request);
        let progress = RequestProgress::new(false);
        let budget = PreResponseBudget::new(Duration::from_secs(10));
        let error = await_response_head(
            std::future::pending::<()>(),
            captured,
            &progress,
            Duration::from_secs(1),
            &budget,
        )
        .await
        .expect_err("total bounds an upload without a final head");
        assert_eq!(error.phase(), TimeoutPhase::Total);
    }

    #[test]
    fn timeout_phases_are_a_closed_label_set() {
        let phases = [
            TimeoutPhase::Queue,
            TimeoutPhase::Connect,
            TimeoutPhase::Tls,
            TimeoutPhase::RequestBody,
            TimeoutPhase::ResponseHeader,
            TimeoutPhase::ResponseBody,
            TimeoutPhase::Total,
        ];
        assert_eq!(
            phases.map(TimeoutPhase::as_str),
            [
                "queue",
                "connect",
                "tls",
                "request_body",
                "response_header",
                "response_body",
                "total"
            ]
        );
    }

    #[test]
    fn request_idle_telemetry_records_only_the_first_local_fault() {
        let metrics = Arc::new(crate::metrics::Metrics::default());
        let progress = RequestProgress::new(false);
        progress.set_timeout_metrics(Arc::clone(&metrics));
        progress.fail(super::LocalRequestFailure::IdleTimeout);
        progress.fail(super::LocalRequestFailure::IdleTimeout);
        assert!(
            metrics
                .render_prometheus()
                .contains("oxidase_upstream_timeouts_total{phase=\"request_body\"} 1")
        );
        let other = RequestProgress::new(false);
        other.set_timeout_metrics(Arc::clone(&metrics));
        other.fail(super::LocalRequestFailure::InvalidBody);
        other.fail(super::LocalRequestFailure::IdleTimeout);
        assert!(
            metrics
                .render_prometheus()
                .contains("oxidase_upstream_timeouts_total{phase=\"request_body\"} 1")
        );
    }

    #[tokio::test]
    async fn completed_eager_body_cannot_bind_a_subsequent_response_task() {
        use crate::body::full_body;
        use crate::protocol::{RequestTrailerGuard, WireProtocol};
        use crate::proxy_body::ProxyRequestBody;
        use bytes::Bytes;
        use http_body_util::BodyExt as _;

        let progress = RequestProgress::new(false);
        let scope = super::UpstreamTaskScope {
            cancel: Arc::new(super::UploadTaskCancellation::default()),
            bound: None,
            pending: std::sync::Mutex::new(None),
        };
        super::UPSTREAM_TASK
            .scope(scope, async {
                let guard = RequestTrailerGuard::from_request_headers(
                    WireProtocol::Http2,
                    &http::HeaderMap::new(),
                )
                .expect("trailer guard");
                let mut body = ProxyRequestBody::streaming(
                    full_body(Bytes::from_static(b"done")),
                    guard,
                    None,
                )
                .with_progress(progress.clone(), None);
                body.frame()
                    .await
                    .expect("eager final frame")
                    .expect("DATA");
                super::UPSTREAM_TASK
                    .with(|scope| assert!(scope.pending.lock().expect("slot").is_some()));
                assert!(
                    progress
                        .0
                        .state
                        .lock()
                        .expect("progress")
                        .task_cancel
                        .is_none(),
                    "never bind shared dispatcher"
                );
                drop(body);
                super::UPSTREAM_TASK.with(|scope| {
                    assert!(
                        scope.pending.lock().expect("slot").is_none(),
                        "completed eager pipe clears handoff"
                    )
                });
                let (sent, received) = tokio::sync::oneshot::channel();
                hyper::rt::Executor::execute(&UpstreamExecutor, async move {
                    let _ = sent.send(());
                });
                progress.response_finished();
                received
                    .await
                    .expect("response child was not cancelled by completed upload");
            })
            .await;
    }

    #[tokio::test]
    async fn h2_flow_blocked_upload_is_cancelled_without_killing_sibling_streams() {
        use crate::body::full_body;
        use crate::protocol::{RequestTrailerGuard, WireProtocol};
        use crate::proxy_body::{ClusterResponseBody, ProxyRequestBody};
        use bytes::Bytes;
        use http::{Request, Response};
        use http_body_util::BodyExt as _;
        use hyper_util::client::legacy::{Client, connect::capture_connection};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("H2 fixture binds");
        let address = listener.local_addr().expect("fixture address");
        let (shutdown, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let (reset_tx, reset_rx) = tokio::sync::oneshot::channel();
        let fixture = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("one upstream connection");
            let mut connection = h2::server::Builder::new()
                .initial_window_size(0)
                .handshake::<_, Bytes>(socket)
                .await
                .expect("fixture H2 handshake");
            let mut reset_tx = Some(reset_tx);
            let mut pending = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => break,
                    request = connection.accept() => {
                        let Some(Ok((request, mut respond))) = request else { break; };
                        if request.uri().path() == "/blocked" {
                            let reset_tx = reset_tx.take().expect("one blocked upload");
                            pending.spawn(async move {
                                // Keep the request receive half alive but do
                                // not return any stream-level send capacity.
                                let _request = request;
                                let mut send = respond.send_response(Response::new(()), false).expect("early head");
                                send.send_data(Bytes::from_static(b"early"), false).expect("early DATA");
                                let reset = std::future::poll_fn(|context| send.poll_reset(context)).await;
                                let _ = reset_tx.send(reset);
                            });
                        } else {
                            assert!(matches!(request.uri().path(), "/warmup" | "/before" | "/after"));
                            let mut send = respond.send_response(Response::new(()), false).expect("sibling head");
                            send.send_data(Bytes::from_static(b"sibling"), true).expect("sibling DATA");
                        }
                    }
                }
            }
            pending.abort_all();
            while pending.join_next().await.is_some() {}
        });

        let directory = tempfile::tempdir().expect("temporary cluster fixture");
        let source = directory.path().join("oxidase.yaml");
        std::fs::write(&source, format!("api_version: oxidase.dev/v1alpha1\nkind: gateway\nresources:\n  clusters:\n    test:\n      endpoints: [http://{address}]\nlisteners:\n  - name: test\n    bind: 127.0.0.1:0\n    service:\n      type: proxy\n      cluster: test\n")).expect("fixture source");
        let snapshot = oxidase_runtime::RuntimeSnapshot::prepare(
            oxidase_config::Compiler::compile_path(&source).expect("fixture compiles"),
        )
        .expect("fixture prepares");
        let cluster = Arc::clone(
            snapshot
                .resources
                .clusters
                .values()
                .next()
                .expect("cluster"),
        );
        let permit = cluster.acquire().await.expect("request admission");
        let progress = RequestProgress::new(false);
        let lease = progress
            .attach_permit(permit)
            .unwrap_or_else(|_| panic!("fresh attempt owns admission"));
        let guard =
            RequestTrailerGuard::from_request_headers(WireProtocol::Http2, &http::HeaderMap::new())
                .expect("trailer guard");
        let body =
            ProxyRequestBody::streaming(full_body(Bytes::from(vec![b'x'; 64 * 1024])), guard, None)
                .with_progress(progress.clone(), None);
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("http://{address}/blocked"))
            .body(body)
            .expect("blocked request");
        let capture = capture_connection(&mut request);
        progress.capture_transport(capture.clone(), true);
        let client = Client::builder(UpstreamExecutor)
            .http2_only(true)
            .build_http::<ProxyRequestBody>();
        // Observe a response on the existing connection first. This guarantees
        // the client's peer SETTINGS(initial_window_size=0) has been processed;
        // merely completing the connection handshake is not that boundary.
        let warmup = tokio::time::timeout(
            Duration::from_secs(2),
            client.request(
                Request::builder()
                    .uri(format!("http://{address}/warmup"))
                    .body(ProxyRequestBody::empty())
                    .expect("warmup request"),
            ),
        )
        .await
        .expect("warmup head")
        .expect("warmup succeeds");
        assert_eq!(
            warmup
                .into_body()
                .collect()
                .await
                .expect("warmup body")
                .to_bytes(),
            Bytes::from_static(b"sibling")
        );
        let budget = PreResponseBudget::new(Duration::from_secs(3));
        let response = await_response_head(
            client.request(request),
            capture,
            &progress,
            Duration::from_secs(1),
            &budget,
        )
        .await
        .expect("head fits budget")
        .expect("early response");
        assert!(
            progress.eos_at().is_some(),
            "Hyper eagerly takes final DATA before flow capacity"
        );
        assert!(
            !progress.0.state.lock().expect("progress lock").upload_done,
            "body pipe is flow blocked"
        );
        let response = ClusterResponseBody::new_with_lease(
            response.into_body(),
            Arc::clone(&cluster),
            lease,
            false,
        );
        let sibling = tokio::time::timeout(
            Duration::from_secs(2),
            client.request(
                Request::builder()
                    .uri(format!("http://{address}/before"))
                    .body(ProxyRequestBody::empty())
                    .expect("sibling request"),
            ),
        )
        .await
        .expect("sibling head")
        .expect("sibling request succeeds");
        assert_eq!(
            sibling
                .into_body()
                .collect()
                .await
                .expect("sibling body")
                .to_bytes(),
            Bytes::from_static(b"sibling")
        );
        // Response drop must cancel the independently spawned upload pipe even
        // though it cannot poll our body while stream send capacity is zero.
        drop(response);
        tokio::time::timeout(Duration::from_secs(2), progress.wait_request_closed())
            .await
            .expect("blocked pipe is cancelled");
        assert_eq!(cluster.active_requests(), 0);
        let response = tokio::time::timeout(
            Duration::from_secs(2),
            client.request(
                Request::builder()
                    .uri(format!("http://{address}/after"))
                    .body(ProxyRequestBody::empty())
                    .expect("after request"),
            ),
        )
        .await
        .expect("same connection remains available")
        .expect("sibling after cancellation succeeds");
        assert_eq!(
            response
                .into_body()
                .collect()
                .await
                .expect("after body")
                .to_bytes(),
            Bytes::from_static(b"sibling")
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), reset_rx)
                .await
                .expect("RST observed")
                .expect("fixture reports RST")
                .expect("stream reset"),
            h2::Reason::CANCEL
        );
        assert_eq!(
            cluster.status(std::time::Instant::now()).endpoints[0]
                .runtime
                .failures,
            0
        );
        drop(client);
        shutdown.send(true).expect("fixture shutdown");
        fixture.await.expect("fixture joins");
    }

    #[tokio::test]
    async fn status_retry_without_reserved_alternative_preserves_original_stream() {
        use bytes::Bytes;
        use http::{Request, StatusCode};
        use http_body_util::{BodyExt as _, Empty};
        use hyper_util::rt::TokioIo;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let first = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("first endpoint binds");
        let first_address = first.local_addr().expect("first address");
        let second = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("second endpoint binds");
        let second_address = second.local_addr().expect("second address");
        let (finish, finished) = tokio::sync::oneshot::channel();
        let first_task = tokio::spawn(async move {
            let (mut socket, _) = first.accept().await.expect("first endpoint selected");
            let mut request = Vec::new();
            let mut chunk = [0_u8; 256];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = socket.read(&mut chunk).await.expect("request head");
                assert_ne!(read, 0);
                request.extend_from_slice(&chunk[..read]);
            }
            socket
                .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 8\r\n\r\nori")
                .await
                .expect("original head and prefix");
            finished
                .await
                .expect("test permits original stream to finish");
            socket
                .write_all(b"ginal")
                .await
                .expect("original body was not dropped by failed retry reservation");
        });
        let directory = tempfile::tempdir().expect("temporary fixture");
        let source = directory.path().join("oxidase.yaml");
        std::fs::write(&source, format!("api_version: oxidase.dev/v1alpha1\nkind: gateway\nresources:\n  clusters:\n    test:\n      endpoints:\n        - name: a\n          url: http://{first_address}\n        - name: b\n          url: http://{second_address}\n      retry:\n        max_attempts: 2\n        methods: [GET]\n        statuses: [503]\n      limits:\n        max_in_flight: 1\n        max_in_flight_per_endpoint: 1\n        queue_timeout: 0ms\n      timeouts:\n        response_header: 200ms\n        response_body_idle: 2s\n        pre_response_total: 2s\nlisteners:\n  - name: test\n    bind: 127.0.0.1:0\n    service:\n      type: proxy\n      cluster: test\n")).expect("fixture source");
        let snapshot = oxidase_runtime::RuntimeSnapshot::prepare(
            oxidase_config::Compiler::compile_path(&source).expect("fixture compiles"),
        )
        .expect("fixture prepares");
        let cluster = Arc::clone(
            snapshot
                .resources
                .clusters
                .values()
                .next()
                .expect("cluster"),
        );
        let reservation = cluster
            .reserve_retry_endpoint(&std::collections::BTreeSet::new(), "a")
            .await
            .expect("hold endpoint b without consuming a Cluster slot");
        assert_eq!(cluster.active_requests(), 0);
        let running = crate::server::GatewayServer::bind(snapshot)
            .await
            .expect("gateway binds")
            .spawn();
        let socket = tokio::net::TcpStream::connect(running.local_addresses()[0].1)
            .await
            .expect("client connects");
        let (mut client, connection) =
            hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(TokioIo::new(socket))
                .await
                .expect("client handshake");
        let driver = tokio::spawn(connection);
        let response = tokio::time::timeout(
            Duration::from_secs(2),
            client.send_request(
                Request::builder()
                    .uri("/original")
                    .header("Host", "gateway.test")
                    .body(Empty::<Bytes>::new())
                    .expect("request"),
            ),
        )
        .await
        .expect("head is not blocked by held body")
        .expect("response head");
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "original 503 is preserved, not replaced by internal error"
        );
        let mut body = response.into_body();
        assert_eq!(
            body.frame()
                .await
                .expect("body prefix")
                .expect("prefix valid")
                .into_data()
                .expect("DATA"),
            Bytes::from_static(b"ori")
        );
        assert_eq!(
            cluster.active_requests(),
            1,
            "final original stream owns Cluster admission"
        );
        finish.send(()).expect("release original body");
        assert_eq!(
            body.collect()
                .await
                .expect("original body finishes")
                .to_bytes(),
            Bytes::from_static(b"ginal")
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while cluster.active_requests() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("admission released");
        assert!(
            tokio::time::timeout(Duration::from_millis(30), second.accept())
                .await
                .is_err(),
            "no unreserved upstream request was sent"
        );
        drop(reservation);
        first_task.await.expect("first endpoint fixture joins");
        drop(client);
        driver.abort();
        let _ = driver.await;
        running.shutdown().await.expect("gateway shuts down");
    }

    #[derive(Clone)]
    struct GatedConnector {
        address: std::net::SocketAddr,
        gate: Arc<tokio::sync::Notify>,
        started: Arc<std::sync::atomic::AtomicBool>,
    }

    impl tower_service::Service<http::Uri> for GatedConnector {
        type Response = hyper_util::rt::TokioIo<tokio::net::TcpStream>;
        type Error = std::io::Error;
        type Future = std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
        >;

        fn poll_ready(
            &mut self,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, _uri: http::Uri) -> Self::Future {
            let connector = self.clone();
            Box::pin(async move {
                connector
                    .started
                    .store(true, std::sync::atomic::Ordering::Release);
                connector.gate.notified().await;
                tokio::net::TcpStream::connect(connector.address)
                    .await
                    .map(hyper_util::rt::TokioIo::new)
            })
        }
    }

    fn gated_connector(address: std::net::SocketAddr) -> GatedConnector {
        GatedConnector {
            address,
            gate: Arc::new(tokio::sync::Notify::new()),
            started: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    #[tokio::test]
    async fn cancelling_cold_h2_connecting_owner_preserves_a_valid_waiter() {
        use bytes::Bytes;
        use http::{Request, Response};
        use http_body_util::{BodyExt as _, Empty};
        use hyper_util::client::legacy::{Client, connect::capture_connection};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("H2 fixture binds");
        let address = listener.local_addr().expect("fixture address");
        let (shutdown, mut stop) = tokio::sync::watch::channel(false);
        let fixture = tokio::spawn(async move {
            let (socket, _) = listener
                .accept()
                .await
                .expect("one connection survives cancellation");
            let mut connection = h2::server::handshake(socket).await.expect("H2 handshake");
            loop {
                tokio::select! {
                    _ = stop.changed() => break,
                    incoming = connection.accept() => {
                        let Some(Ok((request, mut response))) = incoming else { break; };
                        assert!(matches!(request.uri().path(), "/owner" | "/waiter"));
                        if request.uri().path() == "/owner" {
                            // Capture and dispatch share one client poll. An
                            // already-queued owner head may race its CANCEL;
                            // replying to that reset stream is not required.
                            let _ = response.send_response(Response::new(()), true);
                            continue;
                        }
                        let mut send = response.send_response(Response::new(()), false).expect("response head");
                        send.send_data(Bytes::from_static(b"alive"), true).expect("response DATA");
                    }
                }
            }
        });
        let connector = gated_connector(address);
        let client = Client::builder(UpstreamExecutor)
            .http2_only(true)
            .retry_canceled_requests(false)
            .build::<_, Empty<Bytes>>(connector.clone());
        let retirement = super::DispatchRetirementBudget::new(1);
        let mut request = Request::builder()
            .uri(format!("http://{address}/owner"))
            .body(Empty::<Bytes>::new())
            .expect("owner request");
        let capture = capture_connection(&mut request);
        let owner = retirement
            .protect(
                client.request(request),
                capture,
                RequestProgress::new(true),
                Duration::from_secs(2),
            )
            .unwrap_or_else(|_| panic!("one acquisition is admitted"));
        let mut owner = Box::pin(owner);
        assert!(futures_util::poll!(&mut owner).is_pending());
        assert!(
            connector.started.load(std::sync::atomic::Ordering::Acquire),
            "owner holds the connecting lock"
        );
        let mut waiter = Box::pin(
            client.request(
                Request::builder()
                    .uri(format!("http://{address}/waiter"))
                    .body(Empty::<Bytes>::new())
                    .expect("waiter request"),
            ),
        );
        assert!(
            futures_util::poll!(&mut waiter).is_pending(),
            "waiter is on the same connecting lock"
        );
        drop(owner); // The short logical owner deadline/caller expires.
        assert_eq!(retirement.active_workers(), 1);
        connector.gate.notify_one();
        let response = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("valid waiter remains within its own deadline")
            .expect("owner cancellation does not cancel its pool waiter");
        assert_eq!(
            response
                .into_body()
                .collect()
                .await
                .expect("waiter body")
                .to_bytes(),
            Bytes::from_static(b"alive")
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while retirement.active_workers() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("bounded connecting cleanup finishes");
        shutdown.send(true).expect("fixture shutdown");
        fixture.await.expect("fixture joins");
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_connecting_work_is_bounded_and_cannot_renew_its_cap() {
        use bytes::Bytes;
        use http::Request;
        use http_body_util::Empty;
        use hyper_util::client::legacy::{Client, connect::capture_connection};

        let connector = gated_connector(
            "127.0.0.1:0"
                .parse()
                .expect("no socket is dialled without gate"),
        );
        let client = Client::builder(UpstreamExecutor)
            .http2_only(true)
            .build::<_, Empty<Bytes>>(connector);
        let retirement = super::DispatchRetirementBudget::new(1);
        let mut request = Request::builder()
            .uri("http://fixture.invalid/")
            .body(Empty::<Bytes>::new())
            .expect("owner request");
        let capture = capture_connection(&mut request);
        let owner = retirement
            .protect(
                client.request(request),
                capture,
                RequestProgress::new(true),
                Duration::from_secs(10),
            )
            .unwrap_or_else(|_| panic!("first acquisition"));
        let mut owner = Box::pin(owner);
        assert!(futures_util::poll!(&mut owner).is_pending());
        let mut rejected = Request::builder()
            .uri("http://fixture.invalid/other")
            .body(Empty::<Bytes>::new())
            .expect("other request");
        let capture = capture_connection(&mut rejected);
        assert!(matches!(
            retirement.protect(
                client.request(rejected),
                capture,
                RequestProgress::new(true),
                Duration::from_secs(10)
            ),
            Err(super::ConnectingAdmissionError::Overloaded)
        ));
        tokio::time::advance(Duration::from_secs(9)).await;
        drop(owner);
        assert_eq!(retirement.active_workers(), 1);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            retirement.active_workers(),
            0,
            "Drop did not grant another ten seconds"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_retirement_owner_stops_outstanding_cleanup_tasks() {
        use bytes::Bytes;
        use http::Request;
        use http_body_util::Empty;
        use hyper_util::client::legacy::{Client, connect::capture_connection};

        let connector = gated_connector(
            "127.0.0.1:0"
                .parse()
                .expect("no socket is dialled without gate"),
        );
        let client = Client::builder(UpstreamExecutor)
            .http2_only(true)
            .build::<_, Empty<Bytes>>(connector);
        let retirement = super::DispatchRetirementBudget::new(1);
        let workers = Arc::clone(&retirement.workers);
        let mut request = Request::builder()
            .uri("http://fixture.invalid/")
            .body(Empty::<Bytes>::new())
            .expect("owner request");
        let capture = capture_connection(&mut request);
        let owner = retirement
            .protect(
                client.request(request),
                capture,
                RequestProgress::new(true),
                Duration::from_secs(60),
            )
            .unwrap_or_else(|_| panic!("first acquisition"));
        let mut owner = Box::pin(owner);
        assert!(futures_util::poll!(&mut owner).is_pending());
        drop(owner);
        assert_eq!(retirement.active_workers(), 1);
        drop(retirement);
        tokio::task::yield_now().await;
        assert_eq!(workers.load(std::sync::atomic::Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn dropping_an_unpolled_dispatch_cannot_start_a_cancelled_request() {
        use bytes::Bytes;
        use http::Request;
        use http_body_util::Empty;
        use hyper_util::client::legacy::{Client, connect::capture_connection};

        let connector = gated_connector(
            "127.0.0.1:0"
                .parse()
                .expect("no socket is dialled without gate"),
        );
        let client = Client::builder(UpstreamExecutor)
            .http2_only(true)
            .build::<_, Empty<Bytes>>(connector.clone());
        let retirement = super::DispatchRetirementBudget::new(1);
        let mut request = Request::builder()
            .method("POST")
            .uri("http://fixture.invalid/")
            .body(Empty::<Bytes>::new())
            .expect("unpolled POST");
        let capture = capture_connection(&mut request);
        let dispatch = retirement
            .protect(
                client.request(request),
                capture,
                RequestProgress::new(true),
                Duration::from_secs(60),
            )
            .unwrap_or_else(|_| panic!("capacity admitted"));
        drop(dispatch);
        tokio::task::yield_now().await;
        assert_eq!(
            retirement.active_workers(),
            0,
            "no connecting lock needs preservation"
        );
        assert!(
            !connector.started.load(std::sync::atomic::Ordering::Acquire),
            "an expired budget cannot start a previously unpolled POST"
        );
    }
}
