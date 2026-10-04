use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use hyper::rt::Executor;
use tokio::sync::Notify;
use tokio::task::AbortHandle;
use tokio::time::Instant;

use crate::metrics::ListenerTransportMetrics;

tokio::task_local! {
    static H2_STREAM_DEADLINE: Arc<StreamDeadline>;
}

/// Scalar, stream-local cancellation metadata. It owns no body, snapshot,
/// connection, client, or resource. The existing Hyper stream task is the only
/// deadline runner; no disposal task or unbounded waiting queue is introduced.
#[derive(Default)]
struct StreamDeadline {
    deadline: Mutex<Option<Instant>>,
    changed: Notify,
    expired: AtomicBool,
}

impl StreamDeadline {
    fn deadline(&self) -> Option<Instant> {
        *self
            .deadline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn disarm(&self, deadline: Instant) {
        let mut current = self
            .deadline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *current == Some(deadline) {
            *current = None;
            self.changed.notify_waiters();
        }
    }

    fn expire(&self, deadline: Instant) -> bool {
        let current = self
            .deadline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *current == Some(deadline) {
            self.expired.store(true, Ordering::Release);
            true
        } else {
            false
        }
    }
}

pub(crate) struct H2DispositionDeadlineGuard {
    scope: Arc<StreamDeadline>,
    deadline: Instant,
}

impl Drop for H2DispositionDeadlineGuard {
    fn drop(&mut self) {
        self.scope.disarm(self.deadline);
    }
}

#[derive(Clone)]
pub(crate) struct H2DispositionTimeoutSignal(Arc<StreamDeadline>);

impl H2DispositionTimeoutSignal {
    pub(crate) fn is_marked(&self) -> bool {
        self.0.expired.load(Ordering::Acquire)
    }
}

pub(crate) fn arm_h2_disposition_deadline(deadline: Instant) -> Option<H2DispositionDeadlineGuard> {
    H2_STREAM_DEADLINE
        .try_with(|scope| {
            let mut current = scope
                .deadline
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            debug_assert!(current.is_none(), "one unread body per HTTP/2 stream");
            *current = Some(deadline);
            scope.changed.notify_waiters();
            H2DispositionDeadlineGuard {
                scope: Arc::clone(scope),
                deadline,
            }
        })
        .ok()
}

pub(crate) fn h2_disposition_timeout_signal() -> Option<H2DispositionTimeoutSignal> {
    H2_STREAM_DEADLINE
        .try_with(|scope| H2DispositionTimeoutSignal(Arc::clone(scope)))
        .ok()
}

async fn run_stream_with_deadline<F: Future<Output = ()>>(scope: Arc<StreamDeadline>, future: F) {
    tokio::pin!(future);
    loop {
        // Register before reading the deadline, so an arm/disarm in the Hyper
        // future cannot be lost between the read and select registration.
        let changed = scope.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if let Some(deadline) = scope.deadline() {
            tokio::select! {
                biased;
                () = tokio::time::sleep_until(deadline) => {
                    if scope.expire(deadline) {
                        tracing::debug!(
                            termination = "timeout",
                            "HTTP/2 unread request disposition hard deadline expired"
                        );
                        return;
                    }
                }
                () = &mut changed => {}
                () = &mut future => return,
            }
        } else {
            tokio::select! {
                () = &mut changed => {}
                () = &mut future => return,
            }
        }
    }
}

/// Per-HTTP/2-connection executor whose stream tasks cannot outlive a forced
/// connection abort.
#[derive(Clone)]
pub(crate) struct TrackedExecutor {
    tasks: Arc<TrackedTasks>,
    metrics: ListenerTransportMetrics,
}

impl TrackedExecutor {
    pub(crate) fn new(metrics: ListenerTransportMetrics) -> Self {
        Self {
            tasks: Arc::new(TrackedTasks::default()),
            metrics,
        }
    }
}

impl<FutureType> Executor<FutureType> for TrackedExecutor
where
    FutureType: Future<Output = ()> + Send + 'static,
{
    fn execute(&self, future: FutureType) {
        let metrics = self.metrics.clone();
        let task = tokio::spawn(async move {
            let _active_stream = metrics.h2_stream_started();
            let scope = Arc::new(StreamDeadline::default());
            H2_STREAM_DEADLINE
                .scope(Arc::clone(&scope), run_stream_with_deadline(scope, future))
                .await;
        });
        let mut tasks = self
            .tasks
            .handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tasks.retain(|task| !task.is_finished());
        tasks.push(task.abort_handle());
    }
}

#[derive(Default)]
struct TrackedTasks {
    handles: Mutex<Vec<AbortHandle>>,
}

impl Drop for TrackedTasks {
    fn drop(&mut self) {
        let handles = self
            .handles
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for handle in handles.drain(..) {
            if !handle.is_finished() {
                handle.abort();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::pending;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use hyper::rt::Executor as _;

    use super::{TrackedExecutor, arm_h2_disposition_deadline, h2_disposition_timeout_signal};
    use crate::Metrics;

    struct Dropped(Arc<AtomicBool>);

    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn armed_stream_deadline_drops_pending_future_without_body_repoll() {
        let metrics = Arc::new(Metrics::default());
        let executor = TrackedExecutor::new(metrics.listener_transport("public"));
        let dropped = Arc::new(AtomicBool::new(false));
        let retained = Dropped(Arc::clone(&dropped));
        let (ready, initialized) = tokio::sync::oneshot::channel();
        executor.execute(async move {
            let _retained = retained;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
            let _guard = arm_h2_disposition_deadline(deadline).expect("Hyper stream scope");
            assert!(
                ready
                    .send(
                        h2_disposition_timeout_signal()
                            .expect("HTTP/2 stream scope initialization")
                    )
                    .is_ok()
            );
            pending::<()>().await;
        });
        let signal = initialized
            .await
            .expect("HTTP/2 stream scope initialization");
        tokio::time::advance(Duration::from_millis(999)).await;
        assert!(!dropped.load(Ordering::Acquire));
        assert!(!signal.is_marked());
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(dropped.load(Ordering::Acquire));
        assert!(signal.is_marked());
        assert!(
            metrics
                .render_prometheus()
                .contains("oxidase_http2_active_streams{listener=\"public\"} 0")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn disarming_actual_input_eos_preserves_the_response_stream() {
        let metrics = Arc::new(Metrics::default());
        let executor = TrackedExecutor::new(metrics.listener_transport("public"));
        let dropped = Arc::new(AtomicBool::new(false));
        let retained = Dropped(Arc::clone(&dropped));
        let (ready, initialized) = tokio::sync::oneshot::channel();
        executor.execute(async move {
            let _retained = retained;
            let guard =
                arm_h2_disposition_deadline(tokio::time::Instant::now() + Duration::from_secs(1))
                    .expect("HTTP/2 stream scope initialization");
            drop(guard);
            assert!(
                ready
                    .send(
                        h2_disposition_timeout_signal()
                            .expect("HTTP/2 stream scope initialization")
                    )
                    .is_ok()
            );
            pending::<()>().await;
        });
        let signal = initialized
            .await
            .expect("HTTP/2 stream scope initialization");
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(!signal.is_marked());
        assert!(!dropped.load(Ordering::Acquire));
        drop(executor);
        tokio::task::yield_now().await;
        assert!(dropped.load(Ordering::Acquire));
        assert!(
            !signal.is_marked(),
            "connection cancellation is not a timeout"
        );
    }

    #[tokio::test]
    async fn cancellation_before_first_poll_drops_the_owned_stream_future() {
        let metrics = Arc::new(Metrics::default());
        let executor = TrackedExecutor::new(metrics.listener_transport("public"));
        let dropped = Arc::new(AtomicBool::new(false));
        let retained = Dropped(Arc::clone(&dropped));
        executor.execute(async move {
            let _retained = retained;
            panic!("future must not be polled before connection cancellation");
        });
        drop(executor);
        tokio::task::yield_now().await;
        assert!(dropped.load(Ordering::Acquire));
        assert!(
            !metrics
                .render_prometheus()
                .contains("oxidase_http2_active_streams{listener=\"public\"} 1")
        );
    }

    #[tokio::test]
    async fn dropping_the_connection_executor_aborts_detached_stream_tasks() {
        let metrics = Arc::new(Metrics::default());
        let transport = metrics.listener_transport("public");
        let executor = TrackedExecutor::new(transport);
        executor.execute(pending::<()>());
        tokio::task::yield_now().await;
        assert!(
            metrics
                .render_prometheus()
                .contains("oxidase_http2_active_streams{listener=\"public\"} 1")
        );

        drop(executor);
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if metrics
                    .render_prometheus()
                    .contains("oxidase_http2_active_streams{listener=\"public\"} 0")
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("aborted stream task releases its metrics guard");
    }
}
