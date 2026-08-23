use std::convert::Infallible;
use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use tokio::time::{Instant, Sleep};

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

struct TimeoutBody {
    inner: Pin<Box<Incoming>>,
    deadline: Pin<Box<Sleep>>,
    timeout: Duration,
}

impl TimeoutBody {
    fn new(inner: Incoming, timeout: Duration) -> Self {
        Self {
            inner: Box::pin(inner),
            deadline: Box::pin(tokio::time::sleep(timeout)),
            timeout,
        }
    }
}

impl Body for TimeoutBody {
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
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(Box::new(error)))),
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
