use std::convert::Infallible;
use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use oxidase_runtime::RuntimeSnapshot;
use tokio::time::{Instant, Sleep};

use crate::metrics::{ActiveRequest, BodyTermination, Metrics};

pub type BoxError = Box<dyn Error + Send + Sync>;
pub type GatewayBody = UnsyncBoxBody<Bytes, BoxError>;

pub enum GatewayBodyPlan {
    Empty,
    Bytes(Bytes),
    Stream {
        body: GatewayBody,
        known_length: Option<u64>,
    },
    Head {
        representation_length: Option<u64>,
    },
}

impl std::fmt::Debug for GatewayBodyPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => formatter.write_str("Empty"),
            Self::Bytes(bytes) => formatter
                .debug_struct("Bytes")
                .field("length", &bytes.len())
                .finish(),
            Self::Stream { known_length, .. } => formatter
                .debug_struct("Stream")
                .field("known_length", known_length)
                .finish(),
            Self::Head {
                representation_length,
            } => formatter
                .debug_struct("Head")
                .field("representation_length", representation_length)
                .finish(),
        }
    }
}

impl GatewayBodyPlan {
    pub(crate) fn representation_length(&self) -> Option<u64> {
        match self {
            Self::Empty => Some(0),
            Self::Bytes(bytes) => Some(bytes.len() as u64),
            Self::Stream { known_length, .. } => *known_length,
            Self::Head {
                representation_length,
            } => *representation_length,
        }
    }

    pub(crate) fn into_body(self, suppress: bool) -> GatewayBody {
        if suppress {
            return empty_body();
        }
        match self {
            Self::Empty => empty_body(),
            Self::Bytes(bytes) => full_body(bytes),
            Self::Stream { body, .. } => body,
            Self::Head { .. } => empty_body(),
        }
    }
}

pub(crate) fn empty_body() -> GatewayBody {
    Empty::<Bytes>::new()
        .map_err(infallible_to_box)
        .boxed_unsync()
}

pub(crate) fn full_body(bytes: Bytes) -> GatewayBody {
    Full::new(bytes).map_err(infallible_to_box).boxed_unsync()
}

fn infallible_to_box(error: Infallible) -> BoxError {
    match error {}
}

pub(crate) fn timeout_incoming_body(body: Incoming, timeout: Duration) -> GatewayBody {
    TimeoutBody::new(body, timeout).boxed_unsync()
}

#[cfg(test)]
pub(crate) fn instrument_response_body(
    response: http::Response<GatewayBody>,
    metrics: Arc<Metrics>,
    active_request: ActiveRequest,
) -> http::Response<GatewayBody> {
    instrument_response_body_with_snapshot(response, metrics, active_request, None)
}

/// Instruments a response body while pinning the runtime snapshot that
/// produced it until the body reaches a terminal state.
///
/// The pin is released on end-of-stream, body error, or cancellation/drop. It
/// does not inspect or buffer body frames.
pub(crate) fn instrument_response_body_with_snapshot(
    response: http::Response<GatewayBody>,
    metrics: Arc<Metrics>,
    active_request: ActiveRequest,
    snapshot: Option<Arc<RuntimeSnapshot>>,
) -> http::Response<GatewayBody> {
    let (parts, body) = response.into_parts();
    let body = InstrumentedBody::new(body, metrics, active_request, snapshot).boxed_unsync();
    http::Response::from_parts(parts, body)
}

struct InstrumentedBody {
    inner: GatewayBody,
    metrics: Arc<Metrics>,
    active_request: Option<ActiveRequest>,
    started: std::time::Instant,
    bytes: u64,
    termination: Option<BodyTermination>,
    snapshot: Option<Arc<RuntimeSnapshot>>,
}

impl InstrumentedBody {
    fn new(
        inner: GatewayBody,
        metrics: Arc<Metrics>,
        active_request: ActiveRequest,
        snapshot: Option<Arc<RuntimeSnapshot>>,
    ) -> Self {
        let mut body = Self {
            inner,
            metrics,
            active_request: Some(active_request),
            started: std::time::Instant::now(),
            bytes: 0,
            termination: None,
            snapshot,
        };
        if body.inner.is_end_stream() {
            body.finish(BodyTermination::Completed);
        }
        body
    }

    fn finish(&mut self, termination: BodyTermination) {
        if self.termination.replace(termination).is_none() {
            self.metrics
                .record_response_body(self.bytes, termination, self.started.elapsed());
            self.active_request.take();
            self.snapshot.take();
        }
    }
}

impl Body for InstrumentedBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match Pin::new(&mut self.inner).poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    self.bytes = self.bytes.saturating_add(data.len() as u64);
                }
                // Hyper may stop polling after receiving the final frame and
                // drop the body immediately. Capture completion while the
                // wrapped body can still report that the stream is exhausted.
                if self.inner.is_end_stream() {
                    self.finish(BodyTermination::Completed);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                let termination = if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::TimedOut)
                {
                    BodyTermination::Timeout
                } else {
                    BodyTermination::Error
                };
                self.finish(termination);
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                self.finish(BodyTermination::Completed);
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for InstrumentedBody {
    fn drop(&mut self) {
        if self.termination.is_none() {
            self.finish(BodyTermination::Cancelled);
        }
    }
}

struct TimeoutBody<B> {
    inner: Pin<Box<B>>,
    deadline: Pin<Box<Sleep>>,
    timeout: Duration,
}

impl<B> TimeoutBody<B> {
    fn new(inner: B, timeout: Duration) -> Self {
        Self {
            inner: Box::pin(inner),
            deadline: Box::pin(tokio::time::sleep(timeout)),
            timeout,
        }
    }
}

impl<B> Body for TimeoutBody<B>
where
    B: Body<Data = Bytes>,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.inner.as_mut().poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                let timeout = self.timeout;
                self.deadline.as_mut().reset(Instant::now() + timeout);
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => match self.deadline.as_mut().poll(context) {
                Poll::Ready(()) => Poll::Ready(Some(Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "upstream response body idle timeout",
                ))))),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue, Response};
    use http_body::{Body, Frame, SizeHint};
    use http_body_util::BodyExt;

    use oxidase_config::Compiler;
    use oxidase_runtime::RuntimeSnapshot;

    use super::{
        BoxError, GatewayBody, TimeoutBody, full_body, instrument_response_body,
        instrument_response_body_with_snapshot,
    };
    use crate::metrics::Metrics;

    struct FailingBody {
        data_sent: bool,
        error_kind: std::io::ErrorKind,
    }

    struct FrameSequenceBody {
        frames: VecDeque<Result<Frame<Bytes>, BoxError>>,
    }

    impl FrameSequenceBody {
        fn new(frames: impl IntoIterator<Item = Result<Frame<Bytes>, BoxError>>) -> Self {
            Self {
                frames: frames.into_iter().collect(),
            }
        }
    }

    impl Body for FrameSequenceBody {
        type Data = Bytes;
        type Error = BoxError;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(self.frames.pop_front())
        }

        fn is_end_stream(&self) -> bool {
            self.frames.is_empty()
        }

        fn size_hint(&self) -> SizeHint {
            SizeHint::default()
        }
    }

    struct PendingBody;

    impl Body for PendingBody {
        type Data = Bytes;
        type Error = BoxError;

        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Pending
        }
    }

    impl Body for FailingBody {
        type Data = Bytes;
        type Error = BoxError;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            if !self.data_sent {
                self.data_sent = true;
                return Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"abc")))));
            }
            Poll::Ready(Some(Err(Box::new(std::io::Error::new(
                self.error_kind,
                "fixture body failure",
            )))))
        }

        fn size_hint(&self) -> SizeHint {
            SizeHint::default()
        }
    }

    fn failing_body(error_kind: std::io::ErrorKind) -> GatewayBody {
        FailingBody {
            data_sent: false,
            error_kind,
        }
        .boxed_unsync()
    }

    #[tokio::test]
    async fn records_completed_error_timeout_and_cancelled_body_lifecycles() {
        let metrics = Arc::new(Metrics::default());
        let active = metrics.request_started();
        let response = instrument_response_body(
            Response::new(full_body(Bytes::from_static(b"done"))),
            metrics.clone(),
            active,
        );
        assert_eq!(
            response
                .into_body()
                .collect()
                .await
                .expect("body completes")
                .to_bytes(),
            Bytes::from_static(b"done")
        );
        let output = metrics.render_prometheus();
        assert!(output.contains("oxidase_response_body_bytes_total 4"));
        assert!(
            output.contains("oxidase_response_body_terminations_total{reason=\"completed\"} 1")
        );
        assert!(output.contains("oxidase_active_requests 0"));

        let metrics = Arc::new(Metrics::default());
        let active = metrics.request_started();
        let response = instrument_response_body(
            Response::new(failing_body(std::io::ErrorKind::BrokenPipe)),
            metrics.clone(),
            active,
        );
        assert!(response.into_body().collect().await.is_err());
        let output = metrics.render_prometheus();
        assert!(output.contains("oxidase_response_body_bytes_total 3"));
        assert!(output.contains("oxidase_response_body_terminations_total{reason=\"error\"} 1"));
        assert!(output.contains("oxidase_active_requests 0"));

        let metrics = Arc::new(Metrics::default());
        let active = metrics.request_started();
        let response = instrument_response_body(
            Response::new(failing_body(std::io::ErrorKind::TimedOut)),
            metrics.clone(),
            active,
        );
        assert!(response.into_body().collect().await.is_err());
        let output = metrics.render_prometheus();
        assert!(output.contains("oxidase_response_body_terminations_total{reason=\"timeout\"} 1"));
        assert!(output.contains("oxidase_active_requests 0"));

        let metrics = Arc::new(Metrics::default());
        let active = metrics.request_started();
        let response = instrument_response_body(
            Response::new(full_body(Bytes::from_static(b"not-read"))),
            metrics.clone(),
            active,
        );
        drop(response);
        let output = metrics.render_prometheus();
        assert!(
            output.contains("oxidase_response_body_terminations_total{reason=\"cancelled\"} 1")
        );
        assert!(output.contains("oxidase_active_requests 0"));
    }

    #[tokio::test]
    async fn instrumentation_forwards_trailers_without_counting_them_as_data() {
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        trailers.insert("grpc-message", HeaderValue::from_static("complete"));
        let source = FrameSequenceBody::new([
            Ok(Frame::data(Bytes::from_static(b"abc"))),
            Ok(Frame::data(Bytes::from_static(b"de"))),
            Ok(Frame::trailers(trailers.clone())),
        ])
        .boxed_unsync();
        let metrics = Arc::new(Metrics::default());
        let active = metrics.request_started();

        let collected = instrument_response_body(Response::new(source), metrics.clone(), active)
            .into_body()
            .collect()
            .await
            .expect("instrumented body completes");

        assert_eq!(collected.trailers(), Some(&trailers));
        assert_eq!(collected.to_bytes(), Bytes::from_static(b"abcde"));
        let output = metrics.render_prometheus();
        assert!(output.contains("oxidase_response_body_bytes_total 5"));
        assert!(
            output.contains("oxidase_response_body_terminations_total{reason=\"completed\"} 1")
        );
        assert!(output.contains("oxidase_active_requests 0"));
    }

    #[tokio::test]
    async fn timeout_body_forwards_data_and_trailer_frames_unchanged() {
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        let source = FrameSequenceBody::new([
            Ok(Frame::data(Bytes::from_static(b"payload"))),
            Ok(Frame::trailers(trailers.clone())),
        ]);

        let collected = TimeoutBody::new(source, Duration::from_secs(1))
            .collect()
            .await
            .expect("timed body completes");

        assert_eq!(collected.trailers(), Some(&trailers));
        assert_eq!(collected.to_bytes(), Bytes::from_static(b"payload"));
    }

    #[tokio::test]
    async fn timeout_body_still_reports_idle_timeout_without_a_frame() {
        let error = TimeoutBody::new(PendingBody, Duration::from_millis(5))
            .collect()
            .await
            .expect_err("idle body must time out");
        let error = error
            .downcast_ref::<std::io::Error>()
            .expect("timeout remains an io error");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn timeout_body_forwards_inner_errors_without_reclassification() {
        let source = FrameSequenceBody::new([Err::<Frame<Bytes>, BoxError>(Box::new(
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "fixture closed"),
        ))]);

        let error = TimeoutBody::new(source, Duration::from_secs(1))
            .collect()
            .await
            .expect_err("source error must pass through");
        let error = error
            .downcast_ref::<std::io::Error>()
            .expect("source io error remains directly downcastable");
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn snapshot_pin_lives_until_body_completion_or_drop() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        std::fs::write(
            &config,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
services:
  root:
    type: respond
    body:
      text: pinned
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: root
"#,
        )
        .expect("fixture config can be written");
        let snapshot = Arc::new(
            RuntimeSnapshot::prepare(Compiler::compile_path(&config).expect("config compiles"))
                .expect("snapshot prepares"),
        );
        let weak = Arc::downgrade(&snapshot);
        let metrics = Arc::new(Metrics::default());
        let active = metrics.request_started();
        let response = instrument_response_body_with_snapshot(
            Response::new(full_body(Bytes::from_static(b"body"))),
            metrics,
            active,
            Some(snapshot.clone()),
        );
        drop(snapshot);
        assert!(weak.upgrade().is_some(), "body retains the snapshot pin");
        assert_eq!(
            response
                .into_body()
                .collect()
                .await
                .expect("body completes")
                .to_bytes(),
            Bytes::from_static(b"body")
        );
        assert!(
            weak.upgrade().is_none(),
            "end-of-stream releases the snapshot pin"
        );

        let snapshot = Arc::new(
            RuntimeSnapshot::prepare(Compiler::compile_path(&config).expect("config compiles"))
                .expect("snapshot prepares"),
        );
        let weak = Arc::downgrade(&snapshot);
        let metrics = Arc::new(Metrics::default());
        let active = metrics.request_started();
        let response = instrument_response_body_with_snapshot(
            Response::new(full_body(Bytes::from_static(b"cancel"))),
            metrics,
            active,
            Some(snapshot.clone()),
        );
        drop(snapshot);
        assert!(weak.upgrade().is_some(), "body retains the snapshot pin");
        drop(response);
        assert!(
            weak.upgrade().is_none(),
            "cancellation releases the snapshot pin"
        );

        let snapshot = Arc::new(
            RuntimeSnapshot::prepare(Compiler::compile_path(&config).expect("config compiles"))
                .expect("snapshot prepares"),
        );
        let weak = Arc::downgrade(&snapshot);
        let metrics = Arc::new(Metrics::default());
        let active = metrics.request_started();
        let response = instrument_response_body_with_snapshot(
            Response::new(failing_body(std::io::ErrorKind::BrokenPipe)),
            metrics,
            active,
            Some(snapshot.clone()),
        );
        drop(snapshot);
        assert!(weak.upgrade().is_some(), "body retains the snapshot pin");
        assert!(response.into_body().collect().await.is_err());
        assert!(
            weak.upgrade().is_none(),
            "body error releases the snapshot pin"
        );
    }
}
