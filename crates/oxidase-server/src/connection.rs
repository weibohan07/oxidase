use std::future::Future;
use std::sync::{Arc, Mutex};

use hyper::rt::Executor;
use tokio::task::AbortHandle;

use crate::metrics::ListenerTransportMetrics;

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
            future.await;
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
    use std::time::Duration;

    use hyper::rt::Executor as _;

    use super::TrackedExecutor;
    use crate::Metrics;

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
