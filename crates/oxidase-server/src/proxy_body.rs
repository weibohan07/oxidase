//! Frame-preserving request bodies for upstream Proxy attempts.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use http::HeaderMap;
use http_body::{Body, Frame, SizeHint};
use oxidase_runtime::{ClusterRequestPermit, PreparedCluster};

use crate::body::{BoxError, GatewayRequestBody};
use crate::protocol::RequestTrailerGuard;

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
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Streaming { body, .. } => body.size_hint(),
            Self::Empty => SizeHint::with_exact(0),
            Self::Replay { data, .. } => {
                SizeHint::with_exact(data.as_ref().map_or(0, |data| data.len() as u64))
            }
        }
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
    endpoint: Box<str>,
    permit: Option<ClusterRequestPermit>,
    outcome_recorded: bool,
}

impl<B> ClusterResponseBody<B>
where
    B: Body,
{
    pub(crate) fn new(
        inner: B,
        cluster: Arc<PreparedCluster>,
        permit: ClusterRequestPermit,
        outcome_recorded: bool,
    ) -> Self {
        let endpoint = permit.endpoint().name().into();
        let mut body = Self {
            inner: Box::pin(inner),
            cluster,
            endpoint,
            permit: Some(permit),
            outcome_recorded,
        };
        if body.inner.is_end_stream() {
            body.finish(true);
        }
        body
    }

    fn finish(&mut self, succeeded: bool) {
        if !self.outcome_recorded {
            if succeeded {
                self.cluster.record_passive_success(&self.endpoint);
            } else {
                self.cluster
                    .record_passive_failure(&self.endpoint, std::time::Instant::now());
            }
            self.outcome_recorded = true;
        }
        self.permit.take();
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
    use bytes::Bytes;
    use http::HeaderMap;
    use http_body_util::BodyExt as _;

    use super::{ProxyRequestBody, RequestBodyLimitExceeded};
    use crate::body::full_body;
    use crate::protocol::{RequestTrailerGuard, WireProtocol};

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
}
