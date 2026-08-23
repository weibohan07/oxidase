use std::str::FromStr;

use http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode, header};
use oxidase_core::{ResponseHead, is_hop_by_hop_header};

use crate::body::{GatewayBody, GatewayBodyPlan};

/// The single protocol boundary between a handled Service response and Hyper.
pub(crate) struct ResponseFinalizer<'a> {
    method: &'a Method,
}

impl<'a> ResponseFinalizer<'a> {
    pub(crate) const fn new(method: &'a Method) -> Self {
        Self { method }
    }

    pub(crate) fn finalize(
        self,
        mut response: ResponseHead<GatewayBodyPlan>,
    ) -> Response<GatewayBody> {
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
        if !status_forbids_body
            && let Some(length) = representation_length
            && let Ok(value) = HeaderValue::from_str(&length.to_string())
        {
            response.headers.insert(header::CONTENT_LENGTH, value);
        }

        let mut output = Response::new(response.body.into_body(status_forbids_body || head_only));
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
    use http::{HeaderValue, Method, StatusCode, header};
    use http_body_util::BodyExt;
    use oxidase_core::ResponseHead;

    use super::ResponseFinalizer;
    use crate::body::GatewayBodyPlan;

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
}
