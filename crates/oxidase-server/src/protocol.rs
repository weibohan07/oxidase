//! Protocol-aware filtering for headers crossing the HTTP data-plane boundary.

use std::fmt;

use http::{HeaderMap, HeaderName, HeaderValue, header};

/// The wire protocol used on one side of a proxied HTTP exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WireProtocol {
    Http1,
    Http2,
}

/// A malformed connection-specific field that cannot be forwarded safely.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HeaderSanitizationError {
    InvalidConnectionValue,
}

impl fmt::Display for HeaderSanitizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConnectionValue => {
                formatter.write_str("Connection contains an invalid header name")
            }
        }
    }
}

impl std::error::Error for HeaderSanitizationError {}

/// Removes connection-specific fields before trusted runtime code forwards a
/// header map across a protocol boundary.
///
/// This is deliberately not part of the source-level header policy. Configured
/// headers remain subject to the stricter policy in `oxidase-core`; this helper
/// only normalizes metadata already accepted by the HTTP implementation.
/// When this returns an error, the map is left unchanged and must not be
/// forwarded.
pub(crate) fn sanitize_runtime_headers(
    headers: &mut HeaderMap,
    protocol: WireProtocol,
) -> Result<(), HeaderSanitizationError> {
    let nominated = connection_nominated_headers(headers)?;
    for name in nominated {
        headers.remove(name);
    }

    remove(headers, header::CONNECTION);
    remove(headers, HeaderName::from_static("keep-alive"));
    remove(headers, HeaderName::from_static("proxy-connection"));
    remove(headers, header::TRANSFER_ENCODING);
    remove(headers, header::UPGRADE);
    remove(headers, HeaderName::from_static("proxy-authenticate"));
    remove(headers, HeaderName::from_static("proxy-authorization"));

    match protocol {
        WireProtocol::Http1 => {
            remove(headers, header::TE);
            remove(headers, header::TRAILER);
        }
        WireProtocol::Http2 => normalize_http2_te(headers),
    }

    Ok(())
}

fn connection_nominated_headers(
    headers: &HeaderMap,
) -> Result<Vec<HeaderName>, HeaderSanitizationError> {
    let mut nominated = Vec::new();
    for value in headers.get_all(header::CONNECTION) {
        let value = value
            .to_str()
            .map_err(|_| HeaderSanitizationError::InvalidConnectionValue)?;
        for token in value.split(',') {
            let token = trim_optional_whitespace(token);
            if token.is_empty() {
                continue;
            }
            let name = HeaderName::from_bytes(token.as_bytes())
                .map_err(|_| HeaderSanitizationError::InvalidConnectionValue)?;
            nominated.push(name);
        }
    }
    Ok(nominated)
}

fn normalize_http2_te(headers: &mut HeaderMap) {
    let mut values = headers.get_all(header::TE).iter();
    let first = values.next();
    let single_trailers = first.is_some_and(is_trailers) && values.next().is_none();

    headers.remove(header::TE);
    if single_trailers {
        headers.insert(header::TE, HeaderValue::from_static("trailers"));
    }
}

fn is_trailers(value: &HeaderValue) -> bool {
    value
        .to_str()
        .ok()
        .map(trim_optional_whitespace)
        .is_some_and(|value| value.eq_ignore_ascii_case("trailers"))
}

fn trim_optional_whitespace(value: &str) -> &str {
    value.trim_matches([' ', '\t'])
}

fn remove(headers: &mut HeaderMap, name: HeaderName) {
    headers.remove(name);
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderName, HeaderValue, header};
    use oxidase_core::is_forbidden_user_header;

    use super::{HeaderSanitizationError, WireProtocol, sanitize_runtime_headers};

    #[test]
    fn http1_removes_standard_and_connection_nominated_fields() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::CONNECTION,
            HeaderValue::from_static("keep-alive, X-Request-Hop"),
        );
        headers.append(
            header::CONNECTION,
            HeaderValue::from_static(" x-second-hop "),
        );
        headers.insert(
            HeaderName::from_static("x-request-hop"),
            HeaderValue::from_static("remove"),
        );
        headers.insert(
            HeaderName::from_static("x-second-hop"),
            HeaderValue::from_static("remove"),
        );
        headers.insert(header::TE, HeaderValue::from_static("trailers"));
        headers.insert(header::TRAILER, HeaderValue::from_static("grpc-status"));
        headers.insert(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(
            HeaderName::from_static("x-end-to-end"),
            HeaderValue::from_static("keep"),
        );

        sanitize_runtime_headers(&mut headers, WireProtocol::Http1)
            .expect("valid HTTP/1 fields can be sanitized");

        for name in [
            header::CONNECTION,
            header::TE,
            header::TRAILER,
            header::TRANSFER_ENCODING,
            header::UPGRADE,
            HeaderName::from_static("x-request-hop"),
            HeaderName::from_static("x-second-hop"),
        ] {
            assert!(!headers.contains_key(&name), "{name} must be removed");
        }
        assert_eq!(headers["x-end-to-end"], "keep");
    }

    #[test]
    fn connection_names_are_case_insensitive_and_empty_list_items_are_ignored() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONNECTION,
            HeaderValue::from_static(", X-CuStOm-Hop, ,"),
        );
        headers.insert(
            HeaderName::from_static("x-custom-hop"),
            HeaderValue::from_static("remove"),
        );

        sanitize_runtime_headers(&mut headers, WireProtocol::Http1)
            .expect("field names are ASCII case-insensitive");

        assert!(!headers.contains_key("x-custom-hop"));
    }

    #[test]
    fn malformed_connection_value_is_rejected_before_forwarding() {
        let mut invalid_token = HeaderMap::new();
        invalid_token.insert(
            header::CONNECTION,
            HeaderValue::from_static("valid, not a field name"),
        );
        assert_eq!(
            sanitize_runtime_headers(&mut invalid_token, WireProtocol::Http1),
            Err(HeaderSanitizationError::InvalidConnectionValue)
        );
        assert!(invalid_token.contains_key(header::CONNECTION));

        let mut non_ascii = HeaderMap::new();
        non_ascii.insert(
            header::CONNECTION,
            HeaderValue::from_bytes(b"\xff").expect("obs-text is valid header field data"),
        );
        assert_eq!(
            sanitize_runtime_headers(&mut non_ascii, WireProtocol::Http2),
            Err(HeaderSanitizationError::InvalidConnectionValue)
        );

        assert!(HeaderValue::from_bytes(b"keep-alive\r\nx-injected: value").is_err());
    }

    #[test]
    fn http2_removes_prohibited_fields_and_preserves_trailer_declaration() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONNECTION,
            HeaderValue::from_static("x-connection-only"),
        );
        headers.insert(
            HeaderName::from_static("x-connection-only"),
            HeaderValue::from_static("remove"),
        );
        headers.insert(
            HeaderName::from_static("keep-alive"),
            HeaderValue::from_static("timeout=5"),
        );
        headers.insert(
            HeaderName::from_static("proxy-connection"),
            HeaderValue::from_static("keep-alive"),
        );
        headers.insert(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(header::TE, HeaderValue::from_static(" Trailers\t"));
        headers.insert(header::TRAILER, HeaderValue::from_static("grpc-status"));

        sanitize_runtime_headers(&mut headers, WireProtocol::Http2)
            .expect("valid HTTP/2 metadata can be sanitized");

        for name in [
            header::CONNECTION,
            header::TRANSFER_ENCODING,
            header::UPGRADE,
            HeaderName::from_static("keep-alive"),
            HeaderName::from_static("proxy-connection"),
            HeaderName::from_static("x-connection-only"),
        ] {
            assert!(!headers.contains_key(&name), "{name} must be removed");
        }
        assert_eq!(headers[header::TE], "trailers");
        assert_eq!(headers[header::TRAILER], "grpc-status");
    }

    #[test]
    fn http2_drops_non_trailers_and_multi_value_te() {
        for value in ["gzip", "trailers, deflate", "", "trailers,"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::TE,
                HeaderValue::from_str(value).expect("fixture is valid header data"),
            );
            sanitize_runtime_headers(&mut headers, WireProtocol::Http2)
                .expect("invalid TE semantics are removed safely");
            assert!(
                !headers.contains_key(header::TE),
                "{value:?} must be removed"
            );
        }

        let mut headers = HeaderMap::new();
        headers.append(header::TE, HeaderValue::from_static("trailers"));
        headers.append(header::TE, HeaderValue::from_static("trailers"));
        sanitize_runtime_headers(&mut headers, WireProtocol::Http2)
            .expect("multiple TE fields are removed safely");
        assert!(!headers.contains_key(header::TE));
    }

    #[test]
    fn runtime_sanitizer_does_not_relax_user_header_policy() {
        for name in [
            header::CONNECTION,
            header::TE,
            header::TRAILER,
            header::TRANSFER_ENCODING,
            header::UPGRADE,
            HeaderName::from_static("keep-alive"),
            HeaderName::from_static("proxy-connection"),
        ] {
            assert!(is_forbidden_user_header(&name), "{name} remains forbidden");
        }
    }
}
