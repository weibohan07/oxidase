use std::convert::Infallible;
use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use oxidase_runtime::{
    ConcurrencyPermit, ResourceCensus, ResourceKind, ResourceState, ResourceToken, RuntimeSnapshot,
};
use tokio::time::{Instant, Sleep};

use crate::connection::{
    H2DispositionDeadlineGuard, H2DispositionTimeoutSignal, arm_h2_disposition_deadline,
    h2_disposition_timeout_signal,
};
use crate::metrics::{ActiveRequest, BodyTermination, Metrics};
use crate::protocol::{RequestTrailerGuard, TrailerGuard};
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

pub(crate) fn timeout_proxy_request_body(body: GatewayBody, timeout: Duration) -> GatewayBody {
    TimeoutBody::new(body, timeout, BodyIdleDirection::Request).boxed_unsync()
}

fn timeout_downstream_response_body(body: GatewayBody, timeout: Duration) -> GatewayBody {
    TimeoutBody::new(body, timeout, BodyIdleDirection::DownstreamResponse).boxed_unsync()
}

/// A one-shot ownership handoff, not an observer or replay buffer. Only a
/// payload that has never entered Proxy may return its unread HTTP/2 body here.
/// The request handler takes it immediately after Service execution; no task or
/// global registry retains this slot.
#[derive(Clone, Default)]
pub(crate) struct UnconsumedH2Body(Arc<Mutex<Option<(GatewayRequestBody, RequestTrailerGuard)>>>);

impl UnconsumedH2Body {
    pub(crate) fn recover(&self, body: GatewayRequestBody, trailers: RequestTrailerGuard) {
        let previous = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .replace((body, trailers));
        debug_assert!(previous.is_none(), "unread payload is handed off once");
    }

    fn take(&self) -> Option<(GatewayRequestBody, RequestTrailerGuard)> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

const H2_DISPOSITION_MAX_BYTES: u64 = 16 * 1024 * 1024;
const H2_DISPOSITION_MAX_DURATION: Duration = Duration::from_secs(30);
const H2_DISPOSITION_FRAMES_PER_POLL: usize = 32;

/// Early ordinary HTTP/2 responses may send their head and DATA immediately,
/// but retain stream ownership until unread input is disposed. Sending terminal
/// trailers/EOS first would make h2 reset an unfinished upload; late DATA on
/// forgotten reset streams can then exhaust its real protocol-error budget.
/// Explicit 400/413 rejection remains fail-fast, as does invalid ingress before
/// this ownership handoff is constructed. HTTP/1 and claimed Proxy bodies never
/// reach this adapter.
pub(crate) fn retain_unconsumed_h2_body(
    response: http::Response<GatewayBody>,
    slot: UnconsumedH2Body,
    request_idle_timeout: Duration,
) -> http::Response<GatewayBody> {
    let Some((request, trailers)) = slot.take() else {
        return response;
    };
    if request.is_end_stream() || matches!(response.status().as_u16(), 400 | 413) {
        return response;
    }
    let (parts, response) = response.into_parts();
    let body = H2BodyDisposition::new(
        response,
        request,
        trailers,
        H2_DISPOSITION_MAX_BYTES,
        request_idle_timeout.min(H2_DISPOSITION_MAX_DURATION),
    )
    .boxed_unsync();
    http::Response::from_parts(parts, body)
}

#[derive(Debug)]
struct H2DispositionLimit;

impl std::fmt::Display for H2DispositionLimit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("unread HTTP/2 request body disposition limit exceeded")
    }
}

impl Error for H2DispositionLimit {}

#[derive(Debug)]
struct H2DispositionDeadline;

impl std::fmt::Display for H2DispositionDeadline {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("unread HTTP/2 request body disposition deadline expired")
    }
}

impl Error for H2DispositionDeadline {}

struct H2BodyDisposition {
    response: GatewayBody,
    request: Option<GatewayRequestBody>,
    request_trailers: RequestTrailerGuard,
    deadline: Pin<Box<Sleep>>,
    stream_deadline: Option<H2DispositionDeadlineGuard>,
    max_bytes: u64,
    bytes: u64,
    response_ended: bool,
    terminal_trailers: Option<http::HeaderMap>,
    terminated: bool,
}

impl H2BodyDisposition {
    fn new(
        response: GatewayBody,
        request: GatewayRequestBody,
        request_trailers: RequestTrailerGuard,
        max_bytes: u64,
        total: Duration,
    ) -> Self {
        let now = Instant::now();
        let deadline = now.checked_add(total).unwrap_or(now);
        let response_ended = response.is_end_stream();
        Self {
            response,
            request: Some(request),
            request_trailers,
            deadline: Box::pin(tokio::time::sleep_until(deadline)),
            stream_deadline: arm_h2_disposition_deadline(deadline),
            max_bytes,
            bytes: 0,
            response_ended,
            terminal_trailers: None,
            terminated: false,
        }
    }

    fn poll_disposition(&mut self, context: &mut Context<'_>) -> Result<(), BoxError> {
        if self.request.is_none() {
            return Ok(());
        }
        if self.deadline.as_mut().poll(context).is_ready() {
            return Err(Box::new(H2DispositionDeadline));
        }
        for _ in 0..H2_DISPOSITION_FRAMES_PER_POLL {
            let request = self.request.as_mut().expect("unread request retained");
            match Pin::new(&mut *request).poll_frame(context) {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Some(bytes) = frame.data_ref() {
                        self.bytes = self
                            .bytes
                            .checked_add(bytes.len() as u64)
                            .filter(|bytes| *bytes <= self.max_bytes)
                            .ok_or_else(|| Box::new(H2DispositionLimit) as BoxError)?;
                    }
                    if let Some(trailers) = frame.trailers_ref() {
                        self.request_trailers.validate(trailers)?;
                    }
                    if request.is_end_stream() {
                        self.request.take();
                        self.stream_deadline.take();
                        return Ok(());
                    }
                }
                Poll::Ready(Some(Err(error))) => return Err(error),
                Poll::Ready(None) => {
                    self.request.take();
                    self.stream_deadline.take();
                    return Ok(());
                }
                Poll::Pending => return Ok(()),
            }
        }
        // Bound synchronous discard work. Retain the same absolute timer and
        // let other streams progress rather than monopolizing a worker.
        context.waker().wake_by_ref();
        Ok(())
    }
}

impl Body for H2BodyDisposition {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if self.terminated {
            return Poll::Ready(None);
        }
        if let Err(error) = self.poll_disposition(context) {
            self.terminated = true;
            self.request.take();
            self.stream_deadline.take();
            return Poll::Ready(Some(Err(error)));
        }
        if !self.response_ended && self.terminal_trailers.is_none() {
            match Pin::new(&mut self.response).poll_frame(context) {
                Poll::Ready(Some(Ok(frame))) => {
                    if frame.is_trailers() {
                        self.terminal_trailers =
                            Some(frame.into_trailers().expect("trailer frame"));
                        self.response_ended = true;
                    } else {
                        self.response_ended = self.response.is_end_stream();
                        return Poll::Ready(Some(Ok(frame)));
                    }
                }
                Poll::Ready(Some(Err(error))) => {
                    self.terminated = true;
                    self.request.take();
                    self.stream_deadline.take();
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(None) => self.response_ended = true,
                Poll::Pending => return Poll::Pending,
            }
        }
        if self.response_ended && self.request.is_none() {
            self.terminated = true;
            return Poll::Ready(
                self.terminal_trailers
                    .take()
                    .map(|trailers| Ok(Frame::trailers(trailers))),
            );
        }
        Poll::Pending
    }

    fn is_end_stream(&self) -> bool {
        self.terminated
            || (self.response_ended && self.request.is_none() && self.terminal_trailers.is_none())
    }

    fn size_hint(&self) -> SizeHint {
        if self.response_ended {
            SizeHint::with_exact(0)
        } else {
            // Preserve representation length, but never let it substitute for
            // the real two-sided EOS boundary above.
            self.response.size_hint()
        }
    }
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
    h2_disposition_timeout: Option<H2DispositionTimeoutSignal>,
    _resource: ResourceToken,
}

impl InstrumentedBody {
    fn new(
        inner: GatewayBody,
        metrics: Arc<Metrics>,
        active_request: ActiveRequest,
        snapshot: Option<Arc<RuntimeSnapshot>>,
        downstream_timeout: Option<DownstreamTimeoutSignal>,
    ) -> Self {
        let census = snapshot
            .as_ref()
            .map_or_else(ResourceCensus::process, |snapshot| {
                snapshot.resource_census()
            });
        let mut body = Self {
            inner,
            metrics,
            active_request: Some(active_request),
            started: std::time::Instant::now(),
            bytes: 0,
            termination: None,
            snapshot,
            downstream_timeout,
            h2_disposition_timeout: h2_disposition_timeout_signal(),
            _resource: census.token(ResourceKind::ResponseBody, ResourceState::Live),
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
                    || error.downcast_ref::<H2DispositionDeadline>().is_some()
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
                || self
                    .h2_disposition_timeout
                    .as_ref()
                    .is_some_and(H2DispositionTimeoutSignal::is_marked)
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
    deadline: Option<Pin<Box<Sleep>>>,
    timeout: Duration,
    direction: BodyIdleDirection,
    terminated: bool,
    waiting: bool,
}

impl<B> TimeoutBody<B> {
    fn new(inner: B, timeout: Duration, direction: BodyIdleDirection) -> Self {
        Self {
            inner: Box::pin(inner),
            deadline: None,
            timeout,
            direction,
            terminated: false,
            waiting: false,
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
        if self.terminated {
            return Poll::Ready(None);
        }
        match self.inner.as_mut().poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                // Returning a frame ends this demand interval. Hyper may now
                // wait for send capacity or downstream consumption without
                // polling us; that backpressure is not peer body idleness.
                self.waiting = false;
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                self.terminated = true;
                self.deadline = None;
                self.waiting = false;
                Poll::Ready(Some(Err(error.into())))
            }
            Poll::Ready(None) => {
                self.terminated = true;
                self.deadline = None;
                self.waiting = false;
                Poll::Ready(None)
            }
            Poll::Pending => {
                if !self.waiting {
                    let now = Instant::now();
                    let next = now.checked_add(self.timeout).unwrap_or(now);
                    match self.deadline.as_mut() {
                        Some(deadline) => deadline.as_mut().reset(next),
                        None => self.deadline = Some(Box::pin(tokio::time::sleep_until(next))),
                    }
                    self.waiting = true;
                }
                let deadline = self
                    .deadline
                    .as_mut()
                    .expect("pending demand arms idle timer");
                match deadline.as_mut().poll(context) {
                    Poll::Ready(()) => {
                        self.terminated = true;
                        self.deadline = None;
                        self.waiting = false;
                        Poll::Ready(Some(Err(Box::new(BodyIdleTimeout {
                            direction: self.direction,
                        }))))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
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

    struct WatchedIncoming {
        inner: hyper::body::Incoming,
        dropped: Arc<std::sync::atomic::AtomicBool>,
        polls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Body for WatchedIncoming {
        type Data = Bytes;
        type Error = BoxError;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
            self.polls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            std::pin::Pin::new(&mut self.inner)
                .poll_frame(context)
                .map(|frame| frame.map(|frame| frame.map_err(|error| Box::new(error) as BoxError)))
        }

        fn is_end_stream(&self) -> bool {
            self.inner.is_end_stream()
        }
    }

    impl Drop for WatchedIncoming {
        fn drop(&mut self) {
            self.dropped
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }

    #[derive(Clone)]
    enum DispositionTestExecutor {
        Scoped(crate::connection::TrackedExecutor),
        Cooperative(hyper_util::rt::TokioExecutor),
    }

    impl<F> hyper::rt::Executor<F> for DispositionTestExecutor
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        fn execute(&self, future: F) {
            match self {
                Self::Scoped(executor) => executor.execute(future),
                Self::Cooperative(executor) => executor.execute(future),
            }
        }
    }

    async fn zero_response_window_disposition_case(scoped: bool) {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("zero-window wire fixture");
        let address = listener.local_addr().expect("zero-window wire fixture");
        let dropped = Arc::new(AtomicBool::new(false));
        let polls = Arc::new(AtomicUsize::new(0));
        let metrics = Arc::new(Metrics::default());
        let watched_drop = Arc::clone(&dropped);
        let watched_polls = Arc::clone(&polls);
        let server_metrics = Arc::clone(&metrics);
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("zero-window wire fixture");
            let executor = if scoped {
                DispositionTestExecutor::Scoped(crate::connection::TrackedExecutor::new(
                    server_metrics.listener_transport("disposition"),
                ))
            } else {
                DispositionTestExecutor::Cooperative(hyper_util::rt::TokioExecutor::new())
            };
            let service =
                hyper::service::service_fn(move |request: http::Request<hyper::body::Incoming>| {
                    let watched_drop = Arc::clone(&watched_drop);
                    let watched_polls = Arc::clone(&watched_polls);
                    let metrics = Arc::clone(&server_metrics);
                    async move {
                        let mut response = if request.uri().path() == "/blocked" {
                            let body = super::GatewayRequestBody::Stream(
                                WatchedIncoming {
                                    inner: request.into_body(),
                                    dropped: watched_drop,
                                    polls: watched_polls,
                                }
                                .boxed_unsync(),
                            );
                            let response = super::H2BodyDisposition::new(
                                full_body(Bytes::from_static(b"Service Unavailable")),
                                body,
                                super::RequestTrailerGuard::from_request_headers(
                                    WireProtocol::Http2,
                                    &HeaderMap::new(),
                                )
                                .expect("zero-window wire fixture"),
                                16 * 1024 * 1024,
                                Duration::from_secs(1),
                            );
                            assert_eq!(response.stream_deadline.is_some(), scoped);
                            let mut response = Response::new(response.boxed_unsync());
                            *response.status_mut() = http::StatusCode::SERVICE_UNAVAILABLE;
                            response
                                .headers_mut()
                                .insert(header::CONTENT_LENGTH, HeaderValue::from_static("19"));
                            response
                        } else {
                            assert!(request.body().is_end_stream());
                            let mut trailers = HeaderMap::new();
                            trailers.insert("x-proof", HeaderValue::from_static("complete"));
                            Response::new(
                                FrameSequenceBody::new([
                                    Ok(Frame::data(Bytes::from_static(b"healthy"))),
                                    Ok(Frame::trailers(trailers)),
                                ])
                                .boxed_unsync(),
                            )
                        };
                        response
                            .headers_mut()
                            .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
                        let active = metrics.request_started();
                        Ok::<_, std::convert::Infallible>(instrument_response_body(
                            response, metrics, active,
                        ))
                    }
                });
            hyper::server::conn::http2::Builder::new(executor)
                .timer(hyper_util::rt::TokioTimer::new())
                .serve_connection(hyper_util::rt::TokioIo::new(socket), service)
                .await
        });
        let socket = tokio::net::TcpStream::connect(address)
            .await
            .expect("zero-window wire fixture");
        let (mut sender, mut connection) = h2::client::Builder::new()
            .initial_window_size(0)
            .handshake::<_, Bytes>(socket)
            .await
            .expect("zero-window wire fixture");
        let mut ping = connection.ping_pong().expect("zero-window wire fixture");
        let (change_window, mut window_changed) = tokio::sync::mpsc::channel::<()>(1);
        let driver = tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = &mut connection => return result,
                    Some(()) = window_changed.recv() => {
                        connection.set_initial_window_size(65535).expect("zero-window wire fixture");
                    }
                }
            }
        });
        sender = sender.ready().await.expect("zero-window wire fixture");
        let (head, mut upload) = sender
            .send_request(
                http::Request::builder()
                    .method("POST")
                    .uri(format!("http://{address}/blocked"))
                    .body(())
                    .expect("zero-window wire fixture"),
                false,
            )
            .expect("zero-window wire fixture");
        upload
            .send_data(Bytes::from_static(b"unfinished"), false)
            .expect("zero-window wire fixture");
        let response = tokio::time::timeout(Duration::from_secs(1), head)
            .await
            .expect("zero-window wire fixture")
            .expect("zero-window wire fixture");
        assert_eq!(response.status(), http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::CONTENT_LENGTH], "19");
        let mut blocked = response.into_body();
        assert_eq!(blocked.flow_control().available_capacity(), 0);
        sender = sender.ready().await.expect("zero-window wire fixture");
        let (sibling_head, _) = sender
            .send_request(
                http::Request::builder()
                    .uri(format!("http://{address}/healthy"))
                    .body(())
                    .expect("zero-window wire fixture"),
                true,
            )
            .expect("zero-window wire fixture");
        let sibling = tokio::time::timeout(Duration::from_secs(1), sibling_head)
            .await
            .expect("zero-window wire fixture")
            .expect("zero-window wire fixture");
        assert_eq!(sibling.status(), http::StatusCode::OK);
        assert_eq!(sibling.headers()[header::CONTENT_TYPE], "text/plain");
        assert!(
            metrics
                .render_prometheus()
                .contains("oxidase_active_requests 2")
        );
        for _ in 0..5 {
            tokio::time::timeout(Duration::from_millis(200), ping.ping(h2::Ping::opaque()))
                .await
                .expect("zero-window wire fixture")
                .expect("zero-window wire fixture");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let first_poll_count = polls.load(Ordering::Relaxed);
        assert!(first_poll_count > 0, "request cleanup was actually polled");
        if scoped {
            tokio::time::timeout(Duration::from_secs(2), async {
                while !dropped.load(Ordering::Acquire) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("hard expiry drops Incoming even without send capacity");
            assert_eq!(
                polls.load(Ordering::Relaxed),
                first_poll_count,
                "expiry did not need another Body poll"
            );
            assert!(
                tokio::time::timeout(Duration::from_secs(1), blocked.data())
                    .await
                    .expect("zero-window wire fixture")
                    .expect("zero-window wire fixture")
                    .is_err(),
                "expired stream is reset, not fake EOF"
            );
            let rendered = metrics.render_prometheus();
            assert!(rendered.contains("oxidase_active_requests 1"));
            assert!(
                rendered.contains("oxidase_response_body_terminations_total{reason=\"timeout\"} 1")
            );
            // A sibling that was already active before expiry is not canceled.
            // The same connection remains live; restore its response window.
            ping.ping(h2::Ping::opaque())
                .await
                .expect("zero-window wire fixture");
            change_window
                .send(())
                .await
                .expect("zero-window wire fixture");
            let mut body = sibling.into_body();
            let mut bytes = Vec::new();
            while let Some(data) = tokio::time::timeout(Duration::from_secs(1), body.data())
                .await
                .expect("zero-window wire fixture")
            {
                let data = data.expect("zero-window wire fixture");
                body.flow_control()
                    .release_capacity(data.len())
                    .expect("zero-window wire fixture");
                bytes.extend_from_slice(&data);
            }
            assert_eq!(bytes, b"healthy");
            let trailers = body
                .trailers()
                .await
                .expect("zero-window wire fixture")
                .expect("zero-window wire fixture");
            assert_eq!(trailers["x-proof"], "complete");
            assert!(body.is_end_stream());
            assert!(
                metrics
                    .render_prometheus()
                    .contains("oxidase_active_requests 0")
            );
        } else {
            tokio::time::sleep(Duration::from_millis(800)).await;
            assert!(
                !dropped.load(Ordering::Acquire),
                "cooperative Body sleep alone cannot enforce a hard deadline"
            );
            assert_eq!(polls.load(Ordering::Relaxed), first_poll_count);
            assert!(
                metrics
                    .render_prometheus()
                    .contains("oxidase_active_requests 2")
            );
            assert!(
                !metrics
                    .render_prometheus()
                    .contains("oxidase_response_body_terminations_total{reason=\"timeout\"} 1")
            );
            drop(sibling);
        }
        drop(blocked);
        drop(upload);
        drop(sender);
        server.abort();
        assert!(
            server
                .await
                .expect_err("test server cancellation is acknowledged")
                .is_cancelled()
        );
        driver.abort();
        let _ = driver.await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while !dropped.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("test cleanup joins drivers and drops the actual Incoming");
    }

    #[tokio::test]
    async fn h2_zero_response_window_ping_cannot_bypass_stream_disposition_deadline() {
        zero_response_window_disposition_case(false).await;
        zero_response_window_disposition_case(true).await;
    }

    struct DispositionInput {
        receiver: tokio::sync::mpsc::Receiver<Result<Frame<Bytes>, BoxError>>,
        dropped: Arc<std::sync::atomic::AtomicBool>,
        polls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Body for DispositionInput {
        type Data = Bytes;
        type Error = BoxError;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
            self.polls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.receiver.poll_recv(context)
        }

        fn is_end_stream(&self) -> bool {
            self.receiver.is_closed() && self.receiver.is_empty()
        }
    }

    impl Drop for DispositionInput {
        fn drop(&mut self) {
            self.dropped
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }

    type DispositionTestInput = (
        tokio::sync::mpsc::Sender<Result<Frame<Bytes>, BoxError>>,
        super::GatewayRequestBody,
        Arc<std::sync::atomic::AtomicBool>,
        Arc<std::sync::atomic::AtomicUsize>,
    );

    fn disposition_input() -> DispositionTestInput {
        let (sender, receiver) = tokio::sync::mpsc::channel(8);
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        (
            sender,
            super::GatewayRequestBody::Stream(
                DispositionInput {
                    receiver,
                    dropped: Arc::clone(&dropped),
                    polls: Arc::clone(&polls),
                }
                .boxed_unsync(),
            ),
            dropped,
            polls,
        )
    }

    fn request_trailer_policy() -> crate::protocol::RequestTrailerGuard {
        crate::protocol::RequestTrailerGuard::from_request_headers(
            WireProtocol::Http2,
            &HeaderMap::new(),
        )
        .expect("normal H2 trailer policy")
    }

    #[tokio::test]
    async fn h2_disposition_sends_data_without_waiting_but_keeps_real_eos() {
        let (sender, input, dropped, _) = disposition_input();
        let mut body = super::H2BodyDisposition::new(
            full_body(Bytes::from_static(b"Service Unavailable")),
            input,
            request_trailer_policy(),
            16,
            Duration::from_secs(1),
        );
        assert_eq!(body.size_hint().exact(), Some(19));
        assert!(!body.is_end_stream());
        assert_eq!(
            body.frame()
                .await
                .expect("immediate DATA")
                .expect("DATA")
                .into_data()
                .expect("data"),
            Bytes::from_static(b"Service Unavailable")
        );
        assert!(
            !body.is_end_stream(),
            "Content-Length is not input disposition"
        );
        let mut next = Box::pin(body.frame());
        assert!(futures_util::poll!(&mut next).is_pending());
        sender
            .send(Ok(Frame::data(Bytes::from_static(b"request"))))
            .await
            .expect("input DATA");
        drop(sender);
        assert!(next.await.is_none());
        assert!(body.is_end_stream());
        assert!(dropped.load(std::sync::atomic::Ordering::Acquire));
    }

    #[tokio::test]
    async fn h2_disposition_defers_terminal_response_trailers_and_validates_input_trailers() {
        for forbidden in [false, true] {
            let (sender, input, dropped, _) = disposition_input();
            let mut trailers = HeaderMap::new();
            trailers.insert("grpc-status", HeaderValue::from_static("0"));
            let response = FrameSequenceBody::new([
                Ok(Frame::data(Bytes::from_static(b"prefix"))),
                Ok(Frame::trailers(trailers.clone())),
            ])
            .boxed_unsync();
            let mut body = super::H2BodyDisposition::new(
                response,
                input,
                request_trailer_policy(),
                16,
                Duration::from_secs(1),
            );
            assert_eq!(
                body.frame()
                    .await
                    .expect("response DATA")
                    .expect("frame")
                    .into_data()
                    .expect("data"),
                Bytes::from_static(b"prefix")
            );
            let mut terminal = Box::pin(body.frame());
            assert!(
                futures_util::poll!(&mut terminal).is_pending(),
                "response trailers cannot terminate before input"
            );
            let mut input_trailers = HeaderMap::new();
            input_trailers.insert(
                if forbidden {
                    header::CONTENT_LENGTH
                } else {
                    http::HeaderName::from_static("x-input")
                },
                HeaderValue::from_static("1"),
            );
            sender
                .send(Ok(Frame::trailers(input_trailers)))
                .await
                .expect("actual input trailer frame");
            drop(sender);
            let result = terminal.await.expect("terminal frame or real error");
            if forbidden {
                assert!(
                    result
                        .expect_err("forbidden request trailer is not swallowed")
                        .downcast_ref::<TrailerValidationError>()
                        .is_some()
                );
            } else {
                assert_eq!(
                    result
                        .expect("response trailer")
                        .into_trailers()
                        .expect("trailers"),
                    trailers
                );
                assert!(body.frame().await.is_none());
            }
            assert!(dropped.load(std::sync::atomic::Ordering::Acquire));
        }
    }

    #[tokio::test]
    async fn h2_disposition_exact_byte_cap_is_allowed_and_one_above_errors() {
        for bytes in [4, 5] {
            let (sender, input, dropped, _) = disposition_input();
            let mut body = super::H2BodyDisposition::new(
                full_body(Bytes::from_static(b"head-body")),
                input,
                request_trailer_policy(),
                4,
                Duration::from_secs(1),
            );
            body.frame().await.expect("early DATA").expect("response");
            sender
                .send(Ok(Frame::data(Bytes::from(vec![b'x'; bytes]))))
                .await
                .expect("input bytes");
            drop(sender);
            let terminal = body.frame().await;
            if bytes == 4 {
                assert!(terminal.is_none());
            } else {
                assert!(
                    terminal
                        .expect("post-head error")
                        .expect_err("cap+1 cannot become EOF")
                        .downcast_ref::<super::H2DispositionLimit>()
                        .is_some()
                );
            }
            assert!(dropped.load(std::sync::atomic::Ordering::Acquire));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn h2_disposition_absolute_deadline_is_not_refreshed_by_progress() {
        let (sender, input, dropped, _) = disposition_input();
        let mut body = super::H2BodyDisposition::new(
            full_body(Bytes::from_static(b"early")),
            input,
            request_trailer_policy(),
            16,
            Duration::from_secs(1),
        );
        body.frame().await.expect("early DATA").expect("frame");
        tokio::time::advance(Duration::from_millis(750)).await;
        sender
            .send(Ok(Frame::data(Bytes::from_static(b"x"))))
            .await
            .expect("progress inside deadline");
        let mut pending = Box::pin(body.frame());
        assert!(futures_util::poll!(&mut pending).is_pending());
        tokio::time::advance(Duration::from_millis(250)).await;
        assert!(
            pending
                .await
                .expect("real timeout frame")
                .expect_err("no renewed deadline")
                .downcast_ref::<super::H2DispositionDeadline>()
                .is_some()
        );
        assert!(dropped.load(std::sync::atomic::Ordering::Acquire));
    }

    #[tokio::test(start_paused = true)]
    async fn h2_disposition_preserves_request_idle_and_empty_response_cleanup() {
        let (_sender, input, dropped, _) = disposition_input();
        let input = super::GatewayRequestBody::Stream(super::timeout_proxy_request_body(
            input.boxed_unsync(),
            Duration::from_secs(1),
        ));
        let mut body = super::H2BodyDisposition::new(
            super::empty_body(),
            input,
            request_trailer_policy(),
            16,
            Duration::from_secs(2),
        );
        assert_eq!(body.size_hint().exact(), Some(0));
        assert!(
            !body.is_end_stream(),
            "HEAD/204 representation cannot skip request cleanup"
        );
        let mut pending = Box::pin(body.frame());
        assert!(futures_util::poll!(&mut pending).is_pending());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(
            pending
                .await
                .expect("idle error")
                .expect_err("idle timeout is preserved")
                .downcast_ref::<BodyIdleTimeout>()
                .is_some()
        );
        assert!(dropped.load(std::sync::atomic::Ordering::Acquire));
    }

    #[tokio::test]
    async fn h2_disposition_cancellation_drops_input_without_background_work() {
        let (_sender, input, dropped, _) = disposition_input();
        let mut body = super::H2BodyDisposition::new(
            full_body(Bytes::from_static(b"early")),
            input,
            request_trailer_policy(),
            16,
            Duration::from_secs(1),
        );
        body.frame().await.expect("early DATA").expect("frame");
        assert!(!dropped.load(std::sync::atomic::Ordering::Acquire));
        drop(body);
        assert!(dropped.load(std::sync::atomic::Ordering::Acquire));
    }

    #[tokio::test]
    async fn h2_unconsumed_payload_handoff_never_recovers_claimed_proxy_input() {
        use crate::upgrade::GatewayRequestPayload;
        for claimed in [false, true] {
            let (_sender, input, dropped, _) = disposition_input();
            let slot = super::UnconsumedH2Body::default();
            let payload = GatewayRequestPayload::new(input, None, request_trailer_policy())
                .with_unconsumed_h2(slot.clone());
            if claimed {
                let (input, _, _) = payload.into_parts();
                assert!(
                    slot.take().is_none(),
                    "Proxy claim permanently disarms root recovery"
                );
                assert!(!dropped.load(std::sync::atomic::Ordering::Acquire));
                drop(input);
            } else {
                drop(payload);
                assert!(
                    !dropped.load(std::sync::atomic::Ordering::Acquire),
                    "root slot owns genuinely unclaimed input"
                );
                drop(slot.take().expect("actual one-shot handoff"));
                assert!(slot.take().is_none());
            }
            assert!(dropped.load(std::sync::atomic::Ordering::Acquire));
        }
    }

    #[tokio::test]
    async fn h2_unconsumed_malformed_and_oversize_rejections_remain_fail_fast() {
        for status in [400, 413] {
            let (_sender, input, dropped, polls) = disposition_input();
            let slot = super::UnconsumedH2Body::default();
            slot.recover(input, request_trailer_policy());
            let response = Response::builder()
                .status(status)
                .body(full_body(Bytes::from_static(b"rejected")))
                .expect("response");
            let response = super::retain_unconsumed_h2_body(response, slot, Duration::from_secs(1));
            assert_eq!(response.status().as_u16(), status);
            assert_eq!(
                response
                    .into_body()
                    .collect()
                    .await
                    .expect("fail-fast response bytes")
                    .to_bytes(),
                Bytes::from_static(b"rejected")
            );
            assert!(dropped.load(std::sync::atomic::Ordering::Acquire));
            assert_eq!(
                polls.load(std::sync::atomic::Ordering::Relaxed),
                0,
                "rejected oversized/malformed body is not discarded"
            );
        }
    }

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

    #[tokio::test(start_paused = true)]
    async fn idle_time_starts_with_first_body_demand_and_terminates_once() {
        let mut body = TimeoutBody::new(
            PendingBody,
            Duration::from_secs(10),
            BodyIdleDirection::Request,
        );
        tokio::time::advance(Duration::from_secs(50)).await;
        {
            let next = body.frame();
            tokio::pin!(next);
            assert!(
                futures_util::poll!(&mut next).is_pending(),
                "construction is not demand"
            );
            tokio::time::advance(Duration::from_secs(9)).await;
            assert!(futures_util::poll!(&mut next).is_pending());
            tokio::time::advance(Duration::from_secs(1)).await;
            let error = next
                .await
                .expect("one terminal error frame")
                .expect_err("idle expires");
            assert!(error.downcast_ref::<BodyIdleTimeout>().is_some());
        }
        assert!(body.is_end_stream());
        assert!(
            body.frame().await.is_none(),
            "the error is not emitted repeatedly"
        );
    }

    struct DataThenPending(bool);

    impl Body for DataThenPending {
        type Data = Bytes;
        type Error = BoxError;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
            if self.0 {
                Poll::Pending
            } else {
                self.0 = true;
                Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"data")))))
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn returning_data_suspends_idle_time_during_send_backpressure() {
        let mut body = TimeoutBody::new(
            DataThenPending(false),
            Duration::from_secs(10),
            BodyIdleDirection::UpstreamResponse,
        );
        assert_eq!(
            body.frame()
                .await
                .expect("DATA")
                .expect("valid frame")
                .data_ref(),
            Some(&Bytes::from_static(b"data"))
        );
        // Hyper owns this DATA while blocked on send capacity. It does not
        // demand another frame, so the peer is not being charged idle time.
        tokio::time::advance(Duration::from_secs(50)).await;
        let next = body.frame();
        tokio::pin!(next);
        assert!(futures_util::poll!(&mut next).is_pending());
        tokio::time::advance(Duration::from_secs(9)).await;
        assert!(futures_util::poll!(&mut next).is_pending());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(next.await.expect("terminal error frame").is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn unrepresentable_legacy_body_timeout_fails_closed_without_panic() {
        let mut body = TimeoutBody::new(PendingBody, Duration::MAX, BodyIdleDirection::Request);
        assert!(body.frame().await.expect("terminal error frame").is_err());
        assert!(body.frame().await.is_none());
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

    #[tokio::test]
    async fn retired_respond_snapshot_is_held_by_actual_body_until_trailers_error_or_cancel() {
        use oxidase_runtime::{ResourceCensus, ResourceKind, ResourceState, SnapshotStore};

        for terminal in ["completed", "error", "cancelled"] {
            let census = Arc::new(ResourceCensus::default());
            let directory = tempfile::tempdir().expect("isolated fixture");
            let config = directory.path().join("gateway.yaml");
            std::fs::write(&config, "api_version: oxidase.dev/v1alpha1\nkind: gateway\nlisteners:\n  - name: test\n    bind: 127.0.0.1:0\n    service:\n      type: respond\n      body:\n        text: original\n").expect("Respond source");
            let compiled = Compiler::compile_path(&config).expect("compiled Respond");
            let snapshot =
                RuntimeSnapshot::prepare_reusing_in(compiled.clone(), None, census.clone())
                    .expect("prepared Respond")
                    .0;
            let store = SnapshotStore::new(snapshot);
            let pinned = store.pin();
            let weak = Arc::downgrade(&pinned);
            let metrics = Arc::new(Metrics::default());
            let mut trailers = HeaderMap::new();
            trailers.insert("grpc-status", HeaderValue::from_static("0"));
            let source = if terminal == "error" {
                failing_body(std::io::ErrorKind::BrokenPipe)
            } else {
                FrameSequenceBody::new([
                    Ok(Frame::data(Bytes::from_static(b"original bytes"))),
                    Ok(Frame::trailers(trailers.clone())),
                ])
                .boxed_unsync()
            };
            let response = instrument_response_body_with_snapshot(
                Response::new(source),
                metrics.clone(),
                metrics.request_started(),
                Some(pinned),
            );
            let next = RuntimeSnapshot::prepare_reusing_in(compiled, None, census.clone())
                .expect("next candidate")
                .0;
            drop(store.publish(next));
            let retired = || {
                census
                    .sample()
                    .resources
                    .into_iter()
                    .find(|row| row.kind == ResourceKind::Snapshot)
                    .expect("snapshot unit")
                    .states
                    .into_iter()
                    .find(|state| state.state == ResourceState::Retired)
                    .expect("retired role")
                    .live
            };
            assert_eq!(retired(), 1);
            assert!(
                weak.upgrade().is_some(),
                "held response retains old snapshot, no Proxy dependency"
            );
            for _ in 0..100 {
                assert_eq!(
                    retired(),
                    1,
                    "pure observations cannot reap the held instance"
                );
            }
            let mut body = response.into_body();
            let data = body
                .frame()
                .await
                .expect("DATA exists")
                .expect("DATA succeeds")
                .into_data()
                .expect("DATA frame");
            assert_eq!(
                data,
                if terminal == "error" {
                    Bytes::from_static(b"abc")
                } else {
                    Bytes::from_static(b"original bytes")
                }
            );
            assert_eq!(retired(), 1);
            match terminal {
                "completed" => {
                    assert_eq!(
                        body.frame()
                            .await
                            .expect("terminal trailers exist")
                            .expect("terminal trailers succeed")
                            .into_trailers()
                            .expect("trailer frame"),
                        trailers
                    );
                    assert!(body.frame().await.is_none());
                }
                "error" => {
                    assert!(body.frame().await.expect("body fault arrives").is_err());
                }
                "cancelled" => {}
                _ => unreachable!("closed fixture outcomes"),
            }
            drop(body);
            assert!(
                weak.upgrade().is_none(),
                "actual terminal ownership release, not scrape GC"
            );
            assert_eq!(retired(), 0);
            let row = census
                .sample()
                .resources
                .into_iter()
                .find(|row| row.kind == ResourceKind::ResponseBody)
                .expect("actual adapter unit");
            assert_eq!((row.created, row.destroyed, row.live), (1, 1, 0));
            assert_eq!(census.sample().invariant_failures, 0);
            assert!(metrics.render_prometheus().contains(&format!(
                "oxidase_response_body_terminations_total{{reason=\"{terminal}\"}} 1"
            )));
            drop(store);
            assert_eq!(
                census
                    .sample()
                    .resources
                    .into_iter()
                    .find(|row| row.kind == ResourceKind::Snapshot)
                    .expect("snapshot unit")
                    .live,
                0
            );
        }
    }
}
