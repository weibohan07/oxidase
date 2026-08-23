use std::convert::Infallible;
use std::error::Error;

use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full};

pub type BoxError = Box<dyn Error + Send + Sync>;
pub type GatewayBody = UnsyncBoxBody<Bytes, BoxError>;

pub enum GatewayBodyPlan {
    Empty,
    Bytes(Bytes),
    Stream(GatewayBody),
}

impl std::fmt::Debug for GatewayBodyPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => formatter.write_str("Empty"),
            Self::Bytes(bytes) => formatter
                .debug_struct("Bytes")
                .field("length", &bytes.len())
                .finish(),
            Self::Stream(_) => formatter.write_str("Stream(..)"),
        }
    }
}

impl GatewayBodyPlan {
    pub(crate) fn length(&self) -> Option<usize> {
        match self {
            Self::Empty => Some(0),
            Self::Bytes(bytes) => Some(bytes.len()),
            Self::Stream(_) => None,
        }
    }

    pub(crate) fn into_body(self, head_only: bool) -> GatewayBody {
        if head_only {
            return empty_body();
        }
        match self {
            Self::Empty => empty_body(),
            Self::Bytes(bytes) => full_body(bytes),
            Self::Stream(body) => body,
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
