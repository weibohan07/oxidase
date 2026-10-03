//! Frame-preserving request bodies for upstream Proxy attempts.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use http::HeaderMap;
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt as _;
use oxidase_runtime::{ClusterRequestPermit, PreparedCluster};

use crate::body::{
    BodyIdleDirection, BodyIdleTimeout, BoxError, GatewayBody, GatewayRequestBody,
    timeout_proxy_request_body,
};
use crate::protocol::RequestTrailerGuard;
use crate::upstream_timing::{AttemptLeaseGuard, LocalRequestFailure, RequestProgress};

/// Marks an error produced while decoding the untrusted downstream request
/// body. Keeping this provenance through Hyper's client error chain lets Proxy
/// return a safe 400 before any upstream response head, rather than misclassify
/// malformed chunking as an upstream 502.
#[derive(Debug)]
pub(crate) struct DownstreamRequestBodyError(hyper::Error);

impl std::fmt::Display for DownstreamRequestBodyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("downstream request body framing is invalid or incomplete")
    }
}

impl std::error::Error for DownstreamRequestBodyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

#[derive(Debug)]
pub(crate) struct RequestBodyLimitExceeded;

impl std::fmt::Display for RequestBodyLimitExceeded {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("request body exceeds the configured Service limit")
    }
}

impl std::error::Error for RequestBodyLimitExceeded {}

/// The single body type accepted by every long-lived upstream client pool.
///
/// Normal requests wrap Hyper's incoming stream without collection. `Replay`
/// is constructed only for an explicitly configured, bounded retry policy.
pub(crate) enum ProxyRequestBody {
    Streaming {
        body: GatewayRequestBody,
        trailer_guard: RequestTrailerGuard,
        max_bytes: Option<u64>,
        seen_bytes: u64,
    },
    Empty,
    Replay {
        data: Option<Bytes>,
        trailers: Option<HeaderMap>,
    },
    Tracked {
        body: GatewayBody,
        progress: RequestProgress,
        terminated: bool,
    },
}

impl ProxyRequestBody {
    pub(crate) fn streaming(
        body: impl Into<GatewayRequestBody>,
        trailer_guard: RequestTrailerGuard,
        max_bytes: Option<u64>,
    ) -> Self {
        Self::Streaming {
            body: body.into(),
            trailer_guard,
            max_bytes,
            seen_bytes: 0,
        }
    }

    pub(crate) const fn empty() -> Self {
        Self::Empty
    }

    /// Enables phased request-idle timing and local EOS/cancellation tracking.
    /// An empty input remains allocation-free and never starts an idle timer.
    pub(crate) fn with_progress(
        self,
        progress: RequestProgress,
        timeout: Option<std::time::Duration>,
    ) -> Self {
        if self.is_end_stream() {
            progress.mark_eos();
            progress.upload_dropped();
            return self;
        }
        let body = self.boxed_unsync();
        let body = match timeout {
            Some(timeout) => timeout_proxy_request_body(body, timeout),
            None => body,
        };
        Self::Tracked {
            body,
            progress,
            terminated: false,
        }
    }
}

impl Body for ProxyRequestBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match &mut *self {
            Self::Streaming {
                body,
                trailer_guard,
                max_bytes,
                seen_bytes,
            } => match Pin::new(body).poll_frame(context) {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        *seen_bytes = seen_bytes.saturating_add(data.len() as u64);
                        if max_bytes.is_some_and(|limit| *seen_bytes > limit) {
                            return Poll::Ready(Some(Err(Box::new(RequestBodyLimitExceeded))));
                        }
                    }
                    if let Some(trailers) = frame.trailers_ref()
                        && let Err(error) = trailer_guard.validate(trailers)
                    {
                        return Poll::Ready(Some(Err(Box::new(error))));
                    }
                    Poll::Ready(Some(Ok(frame)))
                }
                Poll::Ready(Some(Err(error))) => {
                    Poll::Ready(Some(Err(classify_downstream_body_error(error))))
                }
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
            Self::Empty => Poll::Ready(None),
            Self::Replay { data, trailers } => {
                if let Some(data) = data.take()
                    && !data.is_empty()
                {
                    return Poll::Ready(Some(Ok(Frame::data(data))));
                }
                if let Some(trailers) = trailers.take()
                    && !trailers.is_empty()
                {
                    return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
                }
                Poll::Ready(None)
            }
            Self::Tracked {
                body,
                progress,
                terminated,
            } => {
                if *terminated {
                    return Poll::Ready(None);
                }
                progress.register_upload_waker(context.waker());
                if progress.upload_cancelled() {
                    *terminated = true;
                    return Poll::Ready(Some(Err(Box::new(ProxyUploadCancelled))));
                }
                match Pin::new(&mut *body).poll_frame(context) {
                    Poll::Ready(Some(Ok(frame))) => {
                        // Hyper can drop the body after its last frame without
                        // polling None; report local EOS before handing it off.
                        if frame.trailers_ref().is_some() || body.is_end_stream() {
                            progress.mark_eos();
                        }
                        Poll::Ready(Some(Ok(frame)))
                    }
                    Poll::Ready(Some(Err(error))) => {
                        *terminated = true;
                        progress.fail(local_body_failure(error.as_ref()));
                        Poll::Ready(Some(Err(error)))
                    }
                    Poll::Ready(None) => {
                        *terminated = true;
                        progress.mark_eos();
                        Poll::Ready(None)
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Streaming { body, .. } => body.is_end_stream(),
            Self::Empty => true,
            Self::Replay { data, trailers } => {
                data.as_ref().is_none_or(Bytes::is_empty)
                    && trailers.as_ref().is_none_or(HeaderMap::is_empty)
            }
            Self::Tracked {
                body, terminated, ..
            } => *terminated || body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Streaming { body, .. } => body.size_hint(),
            Self::Empty => SizeHint::with_exact(0),
            Self::Replay { data, .. } => {
                SizeHint::with_exact(data.as_ref().map_or(0, |data| data.len() as u64))
            }
            Self::Tracked {
                body, terminated, ..
            } => {
                if *terminated {
                    SizeHint::with_exact(0)
                } else {
                    body.size_hint()
                }
            }
        }
    }
}

impl Drop for ProxyRequestBody {
    fn drop(&mut self) {
        if let Self::Tracked { progress, .. } = self {
            progress.upload_dropped();
        }
    }
}

#[derive(Debug)]
struct ProxyUploadCancelled;

impl std::fmt::Display for ProxyUploadCancelled {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("upstream request upload cancelled by response lifecycle")
    }
}

impl std::error::Error for ProxyUploadCancelled {}

fn local_body_failure(mut error: &(dyn std::error::Error + 'static)) -> LocalRequestFailure {
    loop {
        if error
            .downcast_ref::<BodyIdleTimeout>()
            .is_some_and(|timeout| timeout.direction() == BodyIdleDirection::Request)
        {
            return LocalRequestFailure::IdleTimeout;
        }
        if error.downcast_ref::<RequestBodyLimitExceeded>().is_some() {
            return LocalRequestFailure::LimitExceeded;
        }
        let Some(source) = error.source() else {
            return LocalRequestFailure::InvalidBody;
        };
        error = source;
    }
}

/// Immutable request data from one explicit bounded-buffer operation.
#[derive(Clone, Debug)]
pub(crate) struct ReplayBody {
    data: Bytes,
    trailers: Option<HeaderMap>,
}

impl ReplayBody {
    pub(crate) fn new_attempt(&self) -> ProxyRequestBody {
        ProxyRequestBody::Replay {
            data: Some(self.data.clone()),
            trailers: self.trailers.clone(),
        }
    }
}

#[derive(Debug)]
pub(crate) enum BufferRequestError {
    LimitExceeded,
    Body(BoxError),
    MultipleTrailerFrames,
}

impl std::fmt::Display for BufferRequestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LimitExceeded => {
                formatter.write_str("request body exceeds the configured retry buffer limit")
            }
            Self::Body(_) => {
                formatter.write_str("request body could not be read for bounded replay")
            }
            Self::MultipleTrailerFrames => {
                formatter.write_str("request body produced multiple trailer frames")
            }
        }
    }
}

impl std::error::Error for BufferRequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Body(error) => Some(error.as_ref()),
            Self::LimitExceeded | Self::MultipleTrailerFrames => None,
        }
    }
}

/// Collects DATA and trailers once, with an exact DATA-byte ceiling.
///
/// This function is never used by the default Proxy path. Callers must acquire
/// Cluster admission before entering it so overload never consumes an upload.
pub(crate) async fn buffer_for_replay(
    body: impl Into<GatewayRequestBody>,
    max_bytes: u64,
    trailer_guard: &RequestTrailerGuard,
) -> Result<ReplayBody, BufferRequestError> {
    use http_body_util::BodyExt as _;

    let mut body = body.into();
    let mut data = BytesMut::new();
    let mut trailers = None;
    while let Some(frame) = body
        .frame()
        .await
        .transpose()
        .map_err(|error| BufferRequestError::Body(classify_downstream_body_error(error)))?
    {
        let frame = match frame.into_data() {
            Ok(chunk) => {
                let next = (data.len() as u64).saturating_add(chunk.len() as u64);
                if next > max_bytes {
                    return Err(BufferRequestError::LimitExceeded);
                }
                data.extend_from_slice(&chunk);
                continue;
            }
            Err(frame) => frame,
        };
        if let Ok(frame_trailers) = frame.into_trailers() {
            trailer_guard
                .validate(&frame_trailers)
                .map_err(|error| BufferRequestError::Body(Box::new(error)))?;
            if trailers.replace(frame_trailers).is_some() {
                return Err(BufferRequestError::MultipleTrailerFrames);
            }
        }
    }
    Ok(ReplayBody {
        data: data.freeze(),
        trailers,
    })
}

fn classify_downstream_body_error(error: BoxError) -> BoxError {
    match error.downcast::<hyper::Error>() {
        Ok(error) => Box::new(DownstreamRequestBodyError(*error)),
        Err(error) => error,
    }
}

/// Holds admission until the proxied response body ends or is dropped.
///
/// A client-side cancellation only drops the permits. It deliberately does not
/// count as an endpoint failure. Upstream body errors are passive failures;
/// clean completion is a success unless a retryable/failing status was already
/// recorded from the response head.
pub(crate) struct ClusterResponseBody<B> {
    inner: Pin<Box<B>>,
    cluster: Arc<PreparedCluster>,
    endpoint: Arc<oxidase_runtime::PreparedEndpoint>,
    permit: Option<ClusterRequestPermit>,
    outcome_recorded: bool,
    request_progress: Option<RequestProgress>,
    lease: Option<AttemptLeaseGuard>,
}

impl<B> ClusterResponseBody<B>
where
    B: Body,
{
    #[cfg(test)]
    pub(crate) fn new(
        inner: B,
        cluster: Arc<PreparedCluster>,
        permit: ClusterRequestPermit,
        outcome_recorded: bool,
    ) -> Self {
        let endpoint = Arc::clone(permit.endpoint());
        let mut body = Self {
            inner: Box::pin(inner),
            cluster,
            endpoint,
            permit: Some(permit),
            outcome_recorded,
            request_progress: None,
            lease: None,
        };
        if body.inner.is_end_stream() {
            body.finish(true);
        }
        body
    }

    #[cfg(test)]
    fn new_with_progress(
        inner: B,
        cluster: Arc<PreparedCluster>,
        permit: ClusterRequestPermit,
        outcome_recorded: bool,
        progress: RequestProgress,
    ) -> Self {
        match progress.attach_permit(permit) {
            Ok(lease) => Self::new_with_lease(inner, cluster, lease, outcome_recorded),
            Err(permit) => Self::new(inner, cluster, permit, outcome_recorded),
        }
    }

    pub(crate) fn new_with_lease(
        inner: B,
        cluster: Arc<PreparedCluster>,
        lease: AttemptLeaseGuard,
        outcome_recorded: bool,
    ) -> Self {
        let endpoint = Arc::clone(lease.endpoint());
        let progress = lease.progress();
        let mut body = Self {
            inner: Box::pin(inner),
            cluster,
            endpoint,
            permit: None,
            outcome_recorded,
            request_progress: Some(progress),
            lease: Some(lease),
        };
        if body.inner.is_end_stream() {
            body.finish(true);
        }
        body
    }
}

impl<B> ClusterResponseBody<B> {
    fn finish(&mut self, succeeded: bool) {
        if !self.outcome_recorded {
            let local_failure = self
                .request_progress
                .as_ref()
                .and_then(RequestProgress::local_failure);
            if local_failure.is_some() {
                // A post-head reset can be caused by a failed downstream
                // upload. It is not evidence that the endpoint is unhealthy.
            } else if succeeded {
                self.cluster.record_passive_success_for(&self.endpoint);
            } else {
                self.cluster
                    .record_passive_failure_for(&self.endpoint, std::time::Instant::now());
            }
            self.outcome_recorded = true;
        }
        self.permit.take();
        self.lease.take();
    }
}

impl<B> Drop for ClusterResponseBody<B> {
    fn drop(&mut self) {
        // Cancellation does not constitute an endpoint failure. It still ends
        // the response leg and wakes a pending upload so Hyper can cancel it.
        self.permit.take();
        self.lease.take();
    }
}

impl<B> Body for ClusterResponseBody<B>
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
                if self.inner.is_end_stream() {
                    self.finish(true);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                self.finish(false);
                Poll::Ready(Some(Err(error.into())))
            }
            Poll::Ready(None) => {
                self.finish(true);
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

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use bytes::Bytes;
    use http::HeaderMap;
    use http_body::{Body, Frame};
    use http_body_util::BodyExt as _;

    use super::{ClusterResponseBody, ProxyRequestBody, RequestBodyLimitExceeded};
    use crate::body::{BoxError, full_body};
    use crate::protocol::{RequestTrailerGuard, WireProtocol};
    use crate::upstream_timing::{LocalRequestFailure, RequestProgress};

    struct PendingUpload;

    impl Body for PendingUpload {
        type Data = Bytes;
        type Error = BoxError;

        fn poll_frame(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
            Poll::Pending
        }
    }

    async fn prepared_cluster() -> Arc<oxidase_runtime::PreparedCluster> {
        let directory = tempfile::tempdir().expect("temporary fixture");
        let source = directory.path().join("oxidase.yaml");
        std::fs::write(&source, "api_version: oxidase.dev/v1alpha1\nkind: gateway\nresources:\n  clusters:\n    test:\n      endpoints: [http://127.0.0.1:12345]\nlisteners:\n  - name: test\n    bind: 127.0.0.1:0\n    service:\n      type: proxy\n      cluster: test\n").expect("fixture config");
        let snapshot = oxidase_runtime::RuntimeSnapshot::prepare(
            oxidase_config::Compiler::compile_path(&source).expect("fixture compiles"),
        )
        .expect("fixture prepares");
        Arc::clone(
            snapshot
                .resources
                .clusters
                .values()
                .next()
                .expect("fixture cluster"),
        )
    }

    fn guard() -> RequestTrailerGuard {
        RequestTrailerGuard::from_request_headers(WireProtocol::Http2, &HeaderMap::new())
            .expect("empty HTTP/2 trailer declaration is valid")
    }

    #[tokio::test]
    async fn streaming_request_body_limit_has_exact_byte_boundary() {
        let exact =
            ProxyRequestBody::streaming(full_body(Bytes::from_static(b"four")), guard(), Some(4))
                .collect()
                .await
                .expect("body exactly at the limit is forwarded")
                .to_bytes();
        assert_eq!(exact, Bytes::from_static(b"four"));

        let error =
            ProxyRequestBody::streaming(full_body(Bytes::from_static(b"five!")), guard(), Some(4))
                .collect()
                .await
                .expect_err("body above the limit fails before forwarding that frame");
        assert!(error.downcast_ref::<RequestBodyLimitExceeded>().is_some());
    }

    #[tokio::test]
    async fn reports_local_eos_before_hyper_drops_the_final_data_frame() {
        let progress = RequestProgress::new(false);
        let mut body =
            ProxyRequestBody::streaming(full_body(Bytes::from_static(b"last")), guard(), None)
                .with_progress(progress.clone(), None);
        assert!(progress.eos_at().is_none());
        assert_eq!(
            body.frame()
                .await
                .expect("DATA")
                .expect("valid DATA")
                .data_ref(),
            Some(&Bytes::from_static(b"last"))
        );
        assert!(
            progress.eos_at().is_some(),
            "last DATA is local EOS even without a subsequent poll"
        );
        assert!(body.is_end_stream());
    }

    #[tokio::test(start_paused = true)]
    async fn request_idle_error_keeps_downstream_provenance() {
        let progress = RequestProgress::new(false);
        let body = ProxyRequestBody::streaming(PendingUpload.boxed_unsync(), guard(), None)
            .with_progress(progress.clone(), Some(Duration::from_secs(2)));
        assert!(body.collect().await.is_err());
        assert_eq!(
            progress.local_failure(),
            Some(LocalRequestFailure::IdleTimeout)
        );
    }

    #[tokio::test]
    async fn response_completion_cancels_upload_and_holds_permit_until_upload_drop() {
        let cluster = prepared_cluster().await;
        let permit = cluster.acquire().await.expect("admitted");
        let progress = RequestProgress::new(false);
        let mut upload = ProxyRequestBody::streaming(PendingUpload.boxed_unsync(), guard(), None)
            .with_progress(progress.clone(), None);
        {
            let next = upload.frame();
            tokio::pin!(next);
            assert!(futures_util::poll!(&mut next).is_pending());
        }
        let body = ClusterResponseBody::new_with_progress(
            full_body(Bytes::from_static(b"early")),
            Arc::clone(&cluster),
            permit,
            false,
            progress.clone(),
        );
        assert_eq!(
            body.collect().await.expect("response completes").to_bytes(),
            Bytes::from_static(b"early")
        );
        assert!(progress.upload_cancelled());
        assert_eq!(
            cluster.active_requests(),
            1,
            "request leg still owns admission"
        );
        assert!(upload.frame().await.expect("cancel frame").is_err());
        drop(upload);
        assert_eq!(cluster.active_requests(), 0);
        assert_eq!(
            cluster.status(std::time::Instant::now()).endpoints[0]
                .runtime
                .failures,
            0
        );
    }

    #[tokio::test]
    async fn dropping_pre_head_owner_cancels_live_upload_before_releasing_admission() {
        let cluster = prepared_cluster().await;
        let permit = cluster.acquire().await.expect("admitted");
        let progress = RequestProgress::new(false);
        let lease = progress
            .attach_permit(permit)
            .unwrap_or_else(|_| panic!("fresh progress owns no permit"));
        let mut upload = ProxyRequestBody::streaming(PendingUpload.boxed_unsync(), guard(), None)
            .with_progress(progress.clone(), None);
        {
            let next = upload.frame();
            tokio::pin!(next);
            assert!(futures_util::poll!(&mut next).is_pending());
        }
        drop(lease); // An outer Timeout wrapper or client drop before head.
        assert_eq!(cluster.active_requests(), 1, "Hyper still owns upload");
        assert!(upload.frame().await.expect("cancel error").is_err());
        assert!(upload.frame().await.is_none(), "cancellation is terminal");
        drop(upload);
        assert_eq!(cluster.active_requests(), 0);
        assert_eq!(
            cluster.status(std::time::Instant::now()).endpoints[0]
                .runtime
                .failures,
            0
        );
    }

    #[tokio::test]
    async fn eos_does_not_allow_retry_to_take_a_still_owned_upload_permit() {
        let cluster = prepared_cluster().await;
        let permit = cluster.acquire().await.expect("admitted");
        let progress = RequestProgress::new(false);
        let mut lease = progress
            .attach_permit(permit)
            .unwrap_or_else(|_| panic!("fresh progress owns no permit"));
        let mut upload =
            ProxyRequestBody::streaming(full_body(Bytes::from_static(b"last")), guard(), None)
                .with_progress(progress.clone(), None);
        upload
            .frame()
            .await
            .expect("last frame")
            .expect("valid DATA");
        assert!(progress.eos_at().is_some());
        assert!(
            lease.take_for_retry().is_none(),
            "local EOS is not pipe termination"
        );
        drop(upload);
        lease.wait_request_closed().await;
        let permit = lease
            .take_for_retry()
            .expect("closed request permits retarget");
        assert!(
            lease.take_for_retry().is_none(),
            "permit can only be moved once"
        );
        drop(lease);
        assert_eq!(
            cluster.active_requests(),
            1,
            "retarget keeps Cluster admission"
        );
        drop(permit);
        assert_eq!(cluster.active_requests(), 0);
    }

    #[tokio::test]
    async fn response_drop_cancels_upload_without_passive_failure() {
        let cluster = prepared_cluster().await;
        let permit = cluster.acquire().await.expect("admitted");
        let progress = RequestProgress::new(false);
        let upload = ProxyRequestBody::streaming(PendingUpload.boxed_unsync(), guard(), None)
            .with_progress(progress.clone(), None);
        let response = ClusterResponseBody::new_with_progress(
            PendingUpload,
            Arc::clone(&cluster),
            permit,
            false,
            progress.clone(),
        );
        drop(response);
        assert!(progress.upload_cancelled());
        assert_eq!(cluster.active_requests(), 1);
        drop(upload);
        assert_eq!(cluster.active_requests(), 0);
        assert_eq!(
            cluster.status(std::time::Instant::now()).endpoints[0]
                .runtime
                .failures,
            0
        );
    }

    struct FailedResponse;

    impl Body for FailedResponse {
        type Data = Bytes;
        type Error = BoxError;

        fn poll_frame(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
            Poll::Ready(Some(Err(Box::new(std::io::Error::other("fixture reset")))))
        }
    }

    #[tokio::test]
    async fn post_head_local_request_timeout_does_not_eject_endpoint() {
        let cluster = prepared_cluster().await;
        let permit = cluster.acquire().await.expect("admitted");
        let progress = RequestProgress::new(false);
        progress.fail(LocalRequestFailure::IdleTimeout);
        progress.upload_dropped();
        let response = ClusterResponseBody::new_with_progress(
            FailedResponse,
            Arc::clone(&cluster),
            permit,
            false,
            progress,
        );
        assert!(response.collect().await.is_err());
        assert_eq!(cluster.active_requests(), 0);
        assert_eq!(
            cluster.status(std::time::Instant::now()).endpoints[0]
                .runtime
                .failures,
            0
        );
    }
}
