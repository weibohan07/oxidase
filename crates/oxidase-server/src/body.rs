use std::convert::Infallible;
use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use oxidase_runtime::{ConcurrencyPermit, RuntimeSnapshot};
use tokio::time::{Instant, Sleep};

use crate::metrics::{ActiveRequest, BodyTermination, Metrics};
use crate::protocol::TrailerGuard;
use crate::upgrade::TunnelPlan;

pub type BoxError = Box<dyn Error + Send + Sync>;
pub type GatewayBody = UnsyncBoxBody<Bytes, BoxError>;

/// Connection-owned provenance for downstream socket write timeouts.
#[derive(Clone, Debug, Default)]
pub(crate) struct DownstreamTimeoutSignal(Arc<AtomicBool>);

impl DownstreamTimeoutSignal {
    pub(crate) fn mark(&self) {
        self.0.store(true, Ordering::Release);
    }

    fn is_marked(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Downstream request body with an allocation-free empty fast path.
///
/// Hyper reports bodyless requests as end-of-stream immediately. Dropping that
/// empty `Incoming` avoids constructing both a boxed adapter and an idle timer;
/// streaming requests retain the frame-preserving timeout wrapper.
pub(crate) enum GatewayRequestBody {
    Empty,
    Stream(GatewayBody),
}

impl From<GatewayBody> for GatewayRequestBody {
    fn from(body: GatewayBody) -> Self {
        if body.is_end_stream() {
            Self::Empty
        } else {
            Self::Stream(body)
        }
    }
}

impl Body for GatewayRequestBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match &mut *self {
            Self::Empty => Poll::Ready(None),
            Self::Stream(body) => Pin::new(body).poll_frame(context),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Empty => true,
            Self::Stream(body) => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Empty => SizeHint::with_exact(0),
            Self::Stream(body) => body.size_hint(),
        }
    }
}

pub enum GatewayBodyPlan {
    Empty,
    Bytes(Bytes),
    Stream {
        body: GatewayBody,
        known_length: Option<u64>,
        trailer_guard: Option<TrailerGuard>,
    },
    Head {
        representation_length: Option<u64>,
    },
    Guarded {
        body: Box<GatewayBodyPlan>,
        permit: ConcurrencyPermit,
    },
    TrustedUpgrade(TunnelPlan),
}

impl std::fmt::Debug for GatewayBodyPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => formatter.write_str("Empty"),
            Self::Bytes(bytes) => formatter
                .debug_struct("Bytes")
                .field("length", &bytes.len())
                .finish(),
            Self::Stream {
                known_length,
                trailer_guard,
                ..
            } => formatter
                .debug_struct("Stream")
                .field("known_length", known_length)
                .field("has_trailer_guard", &trailer_guard.is_some())
                .finish(),
            Self::Head {
                representation_length,
            } => formatter
                .debug_struct("Head")
                .field("representation_length", representation_length)
                .finish(),
            Self::Guarded { body, .. } => formatter.debug_tuple("Guarded").field(body).finish(),
            Self::TrustedUpgrade(plan) => {
                formatter.debug_tuple("TrustedUpgrade").field(plan).finish()
            }
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
            Self::Guarded { body, .. } => body.representation_length(),
            Self::TrustedUpgrade(_) => None,
        }
    }

    pub(crate) fn trailer_guard(&self) -> Option<&TrailerGuard> {
        match self {
            Self::Stream {
                trailer_guard: Some(guard),
                ..
            } => Some(guard),
            Self::Guarded { body, .. } => body.trailer_guard(),
            _ => None,
        }
    }

    pub(crate) fn can_have_trailers(&self) -> bool {
        match self {
            Self::Stream { .. } => true,
            Self::Guarded { body, .. } => body.can_have_trailers(),
            _ => false,
        }
    }

    pub(crate) fn retain_concurrency_permit(self, permit: ConcurrencyPermit) -> Self {
        match self {
            Self::TrustedUpgrade(plan) => {
                Self::TrustedUpgrade(plan.retain_concurrency_permit(permit))
            }
            body => Self::Guarded {
                body: Box::new(body),
                permit,
            },
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
            Self::Guarded { body, permit } => {
                GuardedBody::new(body.into_body(false), permit).boxed_unsync()
            }
            Self::TrustedUpgrade(_) => empty_body(),
        }
    }
}

struct GuardedBody {
    inner: GatewayBody,
    permit: Option<ConcurrencyPermit>,
}

impl GuardedBody {
    fn new(inner: GatewayBody, permit: ConcurrencyPermit) -> Self {
        Self {
            inner,
            permit: Some(permit),
        }
    }
}

impl Body for GuardedBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let frame = Pin::new(&mut self.inner).poll_frame(context);
        if matches!(frame, Poll::Ready(None) | Poll::Ready(Some(Err(_)))) {
            self.permit.take();
        }
        frame
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
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

pub(crate) fn timeout_request_body(body: Incoming, timeout: Duration) -> GatewayRequestBody {
    if body.is_end_stream() {
        GatewayRequestBody::Empty
    } else {
        GatewayRequestBody::Stream(
            TimeoutBody::new(body, timeout, BodyIdleDirection::Request).boxed_unsync(),
        )
    }
}

pub(crate) fn timeout_upstream_response_body(body: Incoming, timeout: Duration) -> GatewayBody {
    TimeoutBody::new(body, timeout, BodyIdleDirection::UpstreamResponse).boxed_unsync()
}

fn timeout_downstream_response_body(body: GatewayBody, timeout: Duration) -> GatewayBody {
    TimeoutBody::new(body, timeout, BodyIdleDirection::DownstreamResponse).boxed_unsync()
}

/// Preserves streaming body frames while enforcing the downstream trailer
/// contract selected from the response head and wire protocol.
///
/// DATA frames are returned unchanged and are never collected. An unsafe or
/// undeclared trailer terminates the body with an explicit protocol error.
pub(crate) struct ProtocolBody<B> {
    inner: Pin<Box<B>>,
    trailer_guard: TrailerGuard,
    terminated: bool,
}

impl<B> ProtocolBody<B> {
    pub(crate) fn new(inner: B, trailer_guard: TrailerGuard) -> Self {
        Self {
            inner: Box::pin(inner),
            trailer_guard,
            terminated: false,
        }
    }
}

impl<B> Body for ProtocolBody<B>
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
        if self.terminated {
            return Poll::Ready(None);
        }
        match self.inner.as_mut().poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(trailers) = frame.trailers_ref()
                    && let Err(error) = self.trailer_guard.validate(trailers)
                {
                    self.terminated = true;
                    return Poll::Ready(Some(Err(Box::new(error))));
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                self.terminated = true;
                Poll::Ready(Some(Err(error.into())))
            }
            Poll::Ready(None) => {
                self.terminated = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.terminated || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        if self.terminated {
            SizeHint::with_exact(0)
        } else {
            self.inner.size_hint()
        }
    }
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
#[cfg(test)]
pub(crate) fn instrument_response_body_with_snapshot(
    response: http::Response<GatewayBody>,
    metrics: Arc<Metrics>,
    active_request: ActiveRequest,
    snapshot: Option<Arc<RuntimeSnapshot>>,
) -> http::Response<GatewayBody> {
    instrument_response_body_with_snapshot_timeout(
        response,
        metrics,
        active_request,
        snapshot,
        None,
        None,
    )
}

pub(crate) fn instrument_response_body_with_snapshot_timeout(
    response: http::Response<GatewayBody>,
    metrics: Arc<Metrics>,
    active_request: ActiveRequest,
    snapshot: Option<Arc<RuntimeSnapshot>>,
    response_body_idle_timeout: Option<Duration>,
    downstream_timeout: Option<DownstreamTimeoutSignal>,
) -> http::Response<GatewayBody> {
    let (parts, body) = response.into_parts();
    let body = match response_body_idle_timeout {
        Some(timeout) => timeout_downstream_response_body(body, timeout),
        None => body,
    };
    let body = InstrumentedBody::new(body, metrics, active_request, snapshot, downstream_timeout)
        .boxed_unsync();
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
    downstream_timeout: Option<DownstreamTimeoutSignal>,
}

impl InstrumentedBody {
    fn new(
        inner: GatewayBody,
        metrics: Arc<Metrics>,
        active_request: ActiveRequest,
        snapshot: Option<Arc<RuntimeSnapshot>>,
        downstream_timeout: Option<DownstreamTimeoutSignal>,
    ) -> Self {
        let mut body = Self {
            inner,
            metrics,
            active_request: Some(active_request),
            started: std::time::Instant::now(),
            bytes: 0,
            termination: None,
            snapshot,
            downstream_timeout,
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
                    || error.downcast_ref::<BodyIdleTimeout>().is_some()
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
            let termination = if self
                .downstream_timeout
                .as_ref()
                .is_some_and(DownstreamTimeoutSignal::is_marked)
            {
                BodyTermination::Timeout
            } else {
                BodyTermination::Cancelled
            };
            self.finish(termination);
        }
    }
}

struct TimeoutBody<B> {
    inner: Pin<Box<B>>,
    deadline: Pin<Box<Sleep>>,
    timeout: Duration,
    direction: BodyIdleDirection,
}

impl<B> TimeoutBody<B> {
    fn new(inner: B, timeout: Duration, direction: BodyIdleDirection) -> Self {
        Self {
            inner: Box::pin(inner),
            deadline: Box::pin(tokio::time::sleep(timeout)),
            timeout,
            direction,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BodyIdleDirection {
    Request,
    UpstreamResponse,
    DownstreamResponse,
}

#[derive(Debug)]
pub(crate) struct BodyIdleTimeout {
    direction: BodyIdleDirection,
}

impl BodyIdleTimeout {
    pub(crate) const fn direction(&self) -> BodyIdleDirection {
        self.direction
    }
}

impl std::fmt::Display for BodyIdleTimeout {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self.direction {
            BodyIdleDirection::Request => "downstream request body idle timeout",
            BodyIdleDirection::UpstreamResponse => "upstream response body idle timeout",
            BodyIdleDirection::DownstreamResponse => "downstream response body idle timeout",
        })
    }
}

impl std::error::Error for BodyIdleTimeout {}

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
                Poll::Ready(()) => Poll::Ready(Some(Err(Box::new(BodyIdleTimeout {
                    direction: self.direction,
                })))),
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
    use std::collections::BTreeMap;
    use std::collections::VecDeque;
    use std::sync::{Arc, Barrier};
    use std::task::{Context, Poll};
    use std::time::Duration;

    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue, Response, header};
    use http_body::{Body, Frame, SizeHint};
    use http_body_util::BodyExt;

    use oxidase_config::Compiler;
    use oxidase_core::{ServiceGraph, ServiceId, ServiceKind, ServiceNode, SourceSpan};
    use oxidase_runtime::{ConcurrencyRejection, GovernanceRegistry, RuntimeSnapshot};

    use super::{
        BodyIdleDirection, BodyIdleTimeout, BoxError, GatewayBody, GatewayBodyPlan, ProtocolBody,
        TimeoutBody, full_body, instrument_response_body, instrument_response_body_with_snapshot,
    };
    use crate::metrics::Metrics;
    use crate::protocol::{TrailerDeclaration, TrailerGuard, TrailerValidationError, WireProtocol};

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

    #[test]
    fn concurrent_body_cancellation_releases_every_request_guard_once() {
        const WORKERS: usize = 32;

        let metrics = Arc::new(Metrics::default());
        let all_active = Arc::new(Barrier::new(WORKERS + 1));
        let release = Arc::new(Barrier::new(WORKERS + 1));
        let workers = (0..WORKERS)
            .map(|_| {
                let metrics = Arc::clone(&metrics);
                let all_active = Arc::clone(&all_active);
                let release = Arc::clone(&release);
                std::thread::spawn(move || {
                    let active = metrics.request_started();
                    let response = instrument_response_body(
                        Response::new(full_body(Bytes::from_static(b"not-polled"))),
                        Arc::clone(&metrics),
                        active,
                    );
                    all_active.wait();
                    release.wait();
                    drop(response);
                })
            })
            .collect::<Vec<_>>();

        all_active.wait();
        assert!(
            metrics
                .render_prometheus()
                .contains(&format!("oxidase_active_requests {WORKERS}"))
        );
        release.wait();
        for worker in workers {
            worker.join().expect("body worker does not panic");
        }
        let output = metrics.render_prometheus();
        assert!(output.contains("oxidase_active_requests 0"));
        assert!(output.contains(&format!(
            "oxidase_response_body_terminations_total{{reason=\"cancelled\"}} {WORKERS}"
        )));
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
    async fn guarded_response_body_holds_concurrency_until_completion() {
        let id = ServiceId::new("limit");
        let node = ServiceNode {
            id: id.clone(),
            source: SourceSpan::synthetic("limit"),
            kind: ServiceKind::ConcurrencyLimit {
                name: "body".to_owned(),
                max_in_flight: 1,
                queue_timeout: Duration::ZERO,
                reject_status: http::StatusCode::SERVICE_UNAVAILABLE,
                service: ServiceId::new("child"),
            },
        };
        let graph = ServiceGraph::new(BTreeMap::from([(id.clone(), node)]));
        let registry = GovernanceRegistry::prepare(&graph, None).0;
        let permit = registry
            .acquire_concurrency(&id, 1, Duration::ZERO)
            .await
            .expect("first request is admitted");
        let body = GatewayBodyPlan::Bytes(Bytes::from_static(b"streaming"))
            .retain_concurrency_permit(permit)
            .into_body(false);
        assert!(matches!(
            registry.acquire_concurrency(&id, 1, Duration::ZERO).await,
            Err(ConcurrencyRejection::Saturated)
        ));
        assert_eq!(
            body.collect()
                .await
                .expect("guarded response body completes")
                .to_bytes(),
            Bytes::from_static(b"streaming")
        );
        let permit = registry
            .acquire_concurrency(&id, 1, Duration::ZERO)
            .await
            .expect("body completion releases the permit");
        drop(permit);
    }

    #[tokio::test]
    async fn timeout_body_forwards_data_and_trailer_frames_unchanged() {
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        let source = FrameSequenceBody::new([
            Ok(Frame::data(Bytes::from_static(b"payload"))),
            Ok(Frame::trailers(trailers.clone())),
        ]);

        let collected = TimeoutBody::new(
            source,
            Duration::from_secs(1),
            BodyIdleDirection::UpstreamResponse,
        )
        .collect()
        .await
        .expect("timed body completes");

        assert_eq!(collected.trailers(), Some(&trailers));
        assert_eq!(collected.to_bytes(), Bytes::from_static(b"payload"));
    }

    #[tokio::test]
    async fn timeout_body_still_reports_idle_timeout_without_a_frame() {
        let error = TimeoutBody::new(
            PendingBody,
            Duration::from_millis(5),
            BodyIdleDirection::UpstreamResponse,
        )
        .collect()
        .await
        .expect_err("idle body must time out");
        let error = error
            .downcast_ref::<BodyIdleTimeout>()
            .expect("timeout retains its typed direction");
        assert_eq!(error.direction(), BodyIdleDirection::UpstreamResponse);
    }

    #[tokio::test]
    async fn timeout_body_forwards_inner_errors_without_reclassification() {
        let source = FrameSequenceBody::new([Err::<Frame<Bytes>, BoxError>(Box::new(
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "fixture closed"),
        ))]);

        let error = TimeoutBody::new(
            source,
            Duration::from_secs(1),
            BodyIdleDirection::UpstreamResponse,
        )
        .collect()
        .await
        .expect_err("source error must pass through");
        let error = error
            .downcast_ref::<std::io::Error>()
            .expect("source io error remains directly downcastable");
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn protocol_body_forwards_http2_data_and_safe_trailers() {
        let data = Bytes::from_static(b"grpc-frame");
        let data_pointer = data.as_ptr();
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        let source =
            FrameSequenceBody::new([Ok(Frame::data(data)), Ok(Frame::trailers(trailers.clone()))]);
        let mut body =
            ProtocolBody::new(source, TrailerGuard::new(WireProtocol::Http2, false, None));

        let data = body
            .frame()
            .await
            .expect("DATA frame is present")
            .expect("DATA frame is valid")
            .into_data()
            .expect("first frame is DATA");
        assert_eq!(data.as_ptr(), data_pointer, "DATA bytes are not copied");
        assert_eq!(data, Bytes::from_static(b"grpc-frame"));
        let forwarded = body
            .frame()
            .await
            .expect("trailer frame is present")
            .expect("trailer frame is valid")
            .into_trailers()
            .expect("second frame is trailers");
        assert_eq!(forwarded, trailers);
    }

    #[tokio::test]
    async fn protocol_body_rejects_unsafe_http2_trailers() {
        let mut trailers = HeaderMap::new();
        trailers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("5"));
        let source = FrameSequenceBody::new([Ok(Frame::trailers(trailers))]);
        let error = ProtocolBody::new(source, TrailerGuard::new(WireProtocol::Http2, false, None))
            .collect()
            .await
            .expect_err("framing trailer must fail the stream");
        assert!(matches!(
            error.downcast_ref::<TrailerValidationError>(),
            Some(TrailerValidationError::ForbiddenField(name))
                if name == header::CONTENT_LENGTH
        ));
    }

    #[tokio::test]
    async fn protocol_body_requires_http1_acceptance_and_complete_declaration() {
        let mut declaration_headers = HeaderMap::new();
        declaration_headers.insert(header::TRAILER, HeaderValue::from_static("grpc-status"));
        let declaration = TrailerDeclaration::parse(&declaration_headers)
            .expect("declaration is valid")
            .expect("declaration is present");
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));

        let forwarded = ProtocolBody::new(
            FrameSequenceBody::new([Ok(Frame::trailers(trailers.clone()))]),
            TrailerGuard::new(WireProtocol::Http1, true, Some(declaration.clone())),
        )
        .collect()
        .await
        .expect("accepted declared trailers are forwarded");
        assert_eq!(forwarded.trailers(), Some(&trailers));

        let error = ProtocolBody::new(
            FrameSequenceBody::new([Ok(Frame::trailers(trailers.clone()))]),
            TrailerGuard::new(WireProtocol::Http1, false, Some(declaration)),
        )
        .collect()
        .await
        .expect_err("unaccepted HTTP/1 trailers must fail the stream");
        assert_eq!(
            error.downcast_ref::<TrailerValidationError>(),
            Some(&TrailerValidationError::NotAcceptedByHttp1Client)
        );

        let error = ProtocolBody::new(
            FrameSequenceBody::new([Ok(Frame::trailers(trailers))]),
            TrailerGuard::new(WireProtocol::Http1, true, None),
        )
        .collect()
        .await
        .expect_err("undeclared HTTP/1 trailers must fail the stream");
        assert!(matches!(
            error.downcast_ref::<TrailerValidationError>(),
            Some(TrailerValidationError::UndeclaredField(name))
                if name.as_str() == "grpc-status"
        ));
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
