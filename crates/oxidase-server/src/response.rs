use std::str::FromStr;

use http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode, header};
use http_body_util::BodyExt;
use oxidase_core::{ResponseHead, is_hop_by_hop_header};

use crate::body::{GatewayBody, GatewayBodyPlan, ProtocolBody};
use crate::protocol::{TrailerGuard, WireProtocol};

/// Protocol facts needed at the final response framing boundary.
///
/// This stays server-local so future trusted transport capabilities can extend
/// finalization without leaking Hyper details into the Service algebra.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResponseFinalizationContext {
    pub(crate) wire_protocol: WireProtocol,
    pub(crate) accepts_http1_trailers: bool,
}

impl ResponseFinalizationContext {
    pub(crate) const fn new(wire_protocol: WireProtocol, accepts_http1_trailers: bool) -> Self {
        Self {
            wire_protocol,
            accepts_http1_trailers,
        }
    }
}

impl Default for ResponseFinalizationContext {
    fn default() -> Self {
        Self::new(WireProtocol::Http1, false)
    }
}

/// The single protocol boundary between a handled Service response and Hyper.
pub(crate) struct ResponseFinalizer<'a> {
    method: &'a Method,
    context: ResponseFinalizationContext,
}

impl<'a> ResponseFinalizer<'a> {
    pub(crate) const fn new(method: &'a Method) -> Self {
        Self {
            method,
            context: ResponseFinalizationContext {
                wire_protocol: WireProtocol::Http1,
                accepts_http1_trailers: false,
            },
        }
    }

    pub(crate) const fn with_context(
        method: &'a Method,
        context: ResponseFinalizationContext,
    ) -> Self {
        Self { method, context }
    }

    pub(crate) fn finalize(
        self,
        mut response: ResponseHead<GatewayBodyPlan>,
    ) -> Response<GatewayBody> {
        // `Trailer` remains forbidden to source configuration. A declaration
        // reaching this boundary is trusted Proxy metadata, but it still must
        // parse and pass the protocol safety policy before being preserved.
        let trailer_guard = TrailerGuard::from_response_headers(
            self.context.wire_protocol,
            self.context.accepts_http1_trailers,
            &response.headers,
        );
        remove_hop_by_hop(&mut response.headers);

        // Framing metadata is derived only from the selected, trusted body plan.
        // This overwrites stale upstream or internally inconsistent values.
        response.headers.remove(header::CONTENT_LENGTH);
        response.headers.remove(header::TRANSFER_ENCODING);
        let representation_length = response.body.representation_length();
        let status_forbids_body = response.status.is_informational()
            || response.status == StatusCode::NO_CONTENT
            || response.status == StatusCode::RESET_CONTENT
            || response.status == StatusCode::NOT_MODIFIED;
        let head_only = self.method == Method::HEAD;
        let suppress_body = status_forbids_body || head_only;
        let body_can_have_trailers =
            !suppress_body && matches!(&response.body, GatewayBodyPlan::Stream { .. });
        let forwards_http1_trailers = self.context.wire_protocol == WireProtocol::Http1
            && body_can_have_trailers
            && trailer_guard.forwarded_declaration().is_some();
        if body_can_have_trailers && let Some(declaration) = trailer_guard.forwarded_declaration() {
            response
                .headers
                .insert(header::TRAILER, declaration.normalized_value());
        }
        if !status_forbids_body
            && !forwards_http1_trailers
            && let Some(length) = representation_length
            && let Ok(value) = HeaderValue::from_str(&length.to_string())
        {
            response.headers.insert(header::CONTENT_LENGTH, value);
        }

        let body = response.body.into_body(suppress_body);
        let body = if body_can_have_trailers {
            ProtocolBody::new(body, trailer_guard).boxed_unsync()
        } else {
            body
        };
        let mut output = Response::new(body);
        *output.status_mut() = response.status;
        *output.headers_mut() = response.headers;
        output
    }
}

pub(crate) fn remove_hop_by_hop(headers: &mut HeaderMap) {
    let nominated = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_str(name.trim()).ok())
        .collect::<Vec<_>>();
    for name in nominated {
        headers.remove(name);
    }
    let hop_headers = headers
        .keys()
        .filter(|name| is_hop_by_hop_header(name))
        .cloned()
        .collect::<Vec<_>>();
    for name in hop_headers {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use futures_util::stream;
    use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
    use http_body::Frame;
    use http_body_util::{BodyExt, StreamBody};
    use oxidase_core::ResponseHead;

    use super::{ResponseFinalizationContext, ResponseFinalizer};
    use crate::body::{BoxError, GatewayBodyPlan};
    use crate::protocol::{TrailerValidationError, WireProtocol};

    fn streaming_response(
        headers: HeaderMap,
        frames: impl IntoIterator<Item = Result<Frame<Bytes>, BoxError>>,
    ) -> ResponseHead<GatewayBodyPlan> {
        let frames = frames.into_iter().collect::<Vec<_>>();
        ResponseHead {
            status: StatusCode::OK,
            headers,
            body: GatewayBodyPlan::Stream {
                body: StreamBody::new(stream::iter(frames)).boxed_unsync(),
                known_length: Some(7),
            },
        }
    }

    #[tokio::test]
    async fn derives_framing_and_suppresses_forbidden_bodies() {
        for status in [
            StatusCode::SWITCHING_PROTOCOLS,
            StatusCode::NO_CONTENT,
            StatusCode::RESET_CONTENT,
            StatusCode::NOT_MODIFIED,
        ] {
            let mut response = ResponseHead::new(
                status,
                GatewayBodyPlan::Bytes(Bytes::from_static(b"discarded")),
            );
            response
                .headers
                .insert(header::CONTENT_LENGTH, HeaderValue::from_static("999"));
            response.headers.insert(
                header::TRANSFER_ENCODING,
                HeaderValue::from_static("chunked"),
            );
            let response = ResponseFinalizer::new(&Method::GET).finalize(response);
            assert!(!response.headers().contains_key(header::CONTENT_LENGTH));
            assert!(!response.headers().contains_key(header::TRANSFER_ENCODING));
            assert!(
                response
                    .into_body()
                    .collect()
                    .await
                    .expect("body is readable")
                    .to_bytes()
                    .is_empty()
            );
        }
    }

    #[tokio::test]
    async fn head_retains_representation_length_without_sending_body() {
        let response = ResponseHead::new(
            StatusCode::OK,
            GatewayBodyPlan::Bytes(Bytes::from_static(b"representation")),
        );
        let response = ResponseFinalizer::new(&Method::HEAD).finalize(response);
        assert_eq!(response.headers()[header::CONTENT_LENGTH], "14");
        assert!(
            response
                .into_body()
                .collect()
                .await
                .expect("body is readable")
                .to_bytes()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn http2_finalizer_normalizes_declaration_and_forwards_safe_trailers() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::TRAILER,
            HeaderValue::from_static("Grpc-Status, x-checksum"),
        );
        headers.append(
            header::TRAILER,
            HeaderValue::from_static("grpc-message, GRPC-STATUS"),
        );
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        trailers.insert("grpc-message", HeaderValue::from_static("complete"));
        let response = ResponseFinalizer::with_context(
            &Method::GET,
            ResponseFinalizationContext::new(WireProtocol::Http2, false),
        )
        .finalize(streaming_response(
            headers,
            [
                Ok(Frame::data(Bytes::from_static(b"payload"))),
                Ok(Frame::trailers(trailers.clone())),
            ],
        ));

        assert_eq!(
            response.headers()[header::TRAILER],
            "grpc-message, grpc-status, x-checksum"
        );
        assert_eq!(response.headers()[header::CONTENT_LENGTH], "7");
        let collected = response
            .into_body()
            .collect()
            .await
            .expect("HTTP/2 body is valid");
        assert_eq!(collected.trailers(), Some(&trailers));
        assert_eq!(collected.to_bytes(), Bytes::from_static(b"payload"));
    }

    #[tokio::test]
    async fn http1_finalizer_requires_acceptance_and_declared_names() {
        let mut headers = HeaderMap::new();
        headers.insert(header::TRAILER, HeaderValue::from_static("grpc-status"));
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        let response = ResponseFinalizer::with_context(
            &Method::GET,
            ResponseFinalizationContext::new(WireProtocol::Http1, true),
        )
        .finalize(streaming_response(
            headers.clone(),
            [Ok(Frame::trailers(trailers.clone()))],
        ));
        assert_eq!(response.headers()[header::TRAILER], "grpc-status");
        assert!(
            !response.headers().contains_key(header::CONTENT_LENGTH),
            "HTTP/1 trailers require chunked framing"
        );
        assert_eq!(
            response
                .into_body()
                .collect()
                .await
                .expect("declared trailer is forwarded")
                .trailers(),
            Some(&trailers)
        );

        let response = ResponseFinalizer::with_context(
            &Method::GET,
            ResponseFinalizationContext::new(WireProtocol::Http1, false),
        )
        .finalize(streaming_response(headers, [Ok(Frame::trailers(trailers))]));
        assert!(!response.headers().contains_key(header::TRAILER));
        assert_eq!(response.headers()[header::CONTENT_LENGTH], "7");
        let error = response
            .into_body()
            .collect()
            .await
            .expect_err("unaccepted HTTP/1 trailer fails after the head");
        assert_eq!(
            error.downcast_ref::<TrailerValidationError>(),
            Some(&TrailerValidationError::NotAcceptedByHttp1Client)
        );
    }

    #[tokio::test]
    async fn invalid_or_incomplete_trailer_declarations_are_not_silently_forwarded() {
        let mut invalid = HeaderMap::new();
        invalid.insert(
            header::TRAILER,
            HeaderValue::from_static("grpc-status, content-length"),
        );
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        let response = ResponseFinalizer::with_context(
            &Method::GET,
            ResponseFinalizationContext::new(WireProtocol::Http1, true),
        )
        .finalize(streaming_response(invalid, [Ok(Frame::trailers(trailers))]));
        assert!(!response.headers().contains_key(header::TRAILER));
        assert!(matches!(
            response
                .into_body()
                .collect()
                .await
                .expect_err("invalid declaration cannot authorize trailers")
                .downcast_ref::<TrailerValidationError>(),
            Some(TrailerValidationError::UndeclaredField(name))
                if name.as_str() == "grpc-status"
        ));

        let mut incomplete = HeaderMap::new();
        incomplete.insert(header::TRAILER, HeaderValue::from_static("grpc-status"));
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        trailers.insert("grpc-message", HeaderValue::from_static("complete"));
        let response = ResponseFinalizer::with_context(
            &Method::GET,
            ResponseFinalizationContext::new(WireProtocol::Http1, true),
        )
        .finalize(streaming_response(
            incomplete,
            [Ok(Frame::trailers(trailers))],
        ));
        assert!(matches!(
            response
                .into_body()
                .collect()
                .await
                .expect_err("undeclared trailer cannot cross HTTP/1")
                .downcast_ref::<TrailerValidationError>(),
            Some(TrailerValidationError::UndeclaredField(name))
                if name.as_str() == "grpc-message"
        ));
    }
}
