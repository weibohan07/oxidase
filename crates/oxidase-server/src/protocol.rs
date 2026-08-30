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

/// A normalized declaration of trailer field names from an initial response
/// head.
///
/// Names are lower-cased by `HeaderName`, sorted, and de-duplicated so the
/// declaration can be emitted deterministically. Connection-specific and
/// framing fields are rejected before the declaration reaches the wire.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TrailerDeclaration {
    names: Vec<HeaderName>,
}

impl TrailerDeclaration {
    /// Parses all `Trailer` field lines in an initial header map.
    pub(crate) fn parse(headers: &HeaderMap) -> Result<Option<Self>, TrailerValidationError> {
        let mut values = headers.get_all(header::TRAILER).iter();
        let Some(first) = values.next() else {
            return Ok(None);
        };

        let mut names = Vec::new();
        parse_trailer_declaration_value(first, &mut names)?;
        for value in values {
            parse_trailer_declaration_value(value, &mut names)?;
        }
        names.sort_unstable_by(|left, right| left.as_str().cmp(right.as_str()));
        names.dedup();
        Ok(Some(Self { names }))
    }

    fn contains(&self, name: &HeaderName) -> bool {
        self.names
            .binary_search_by(|candidate| candidate.as_str().cmp(name.as_str()))
            .is_ok()
    }

    pub(crate) fn normalized_value(&self) -> HeaderValue {
        let value = self
            .names
            .iter()
            .map(HeaderName::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        HeaderValue::from_str(&value)
            .expect("validated trailer field names form a valid HeaderValue")
    }
}

/// Validates trailer frames received from an untrusted downstream request.
///
/// HTTP/1 request trailers must match the initial `Trailer` declaration. HTTP/2
/// does not require that declaration, but both protocols reject framing,
/// routing, and connection-nominated fields in a trailer frame.
#[derive(Clone, Debug)]
pub(crate) struct RequestTrailerGuard {
    protocol: WireProtocol,
    requires_declaration: bool,
    declaration: Option<TrailerDeclaration>,
    connection_nominated: Vec<HeaderName>,
}

impl RequestTrailerGuard {
    pub(crate) fn from_request_headers(
        protocol: WireProtocol,
        headers: &HeaderMap,
    ) -> Result<Self, TrailerValidationError> {
        let mut connection_nominated = connection_nominated_headers(headers)
            .map_err(|_| TrailerValidationError::InvalidConnectionValue)?;
        connection_nominated.sort_unstable_by(|left, right| left.as_str().cmp(right.as_str()));
        connection_nominated.dedup();
        let declaration = TrailerDeclaration::parse(headers)?;
        if connection_nominated
            .binary_search_by(|name| name.as_str().cmp(header::TRAILER.as_str()))
            .is_ok()
            || declaration.as_ref().is_some_and(|declaration| {
                declaration.names.iter().any(|name| {
                    connection_nominated
                        .binary_search_by(|candidate| candidate.as_str().cmp(name.as_str()))
                        .is_ok()
                })
            })
        {
            return Err(TrailerValidationError::ForbiddenField(header::TRAILER));
        }
        Ok(Self {
            protocol,
            requires_declaration: protocol == WireProtocol::Http1,
            declaration,
            connection_nominated,
        })
    }

    /// Returns the request guard for the selected upstream wire protocol.
    /// HTTP/2 permits undeclared trailers, but HTTP/1 encoders cannot preserve
    /// their field names unless the initial request declared them.
    pub(crate) fn for_upstream(&self, protocol: WireProtocol) -> Self {
        let mut guard = self.clone();
        guard.requires_declaration |= protocol == WireProtocol::Http1;
        guard
    }

    pub(crate) fn forwarded_declaration(&self) -> Option<HeaderValue> {
        self.declaration
            .as_ref()
            .map(TrailerDeclaration::normalized_value)
    }

    pub(crate) fn validate(&self, trailers: &HeaderMap) -> Result<(), TrailerValidationError> {
        if trailers.is_empty() {
            return Ok(());
        }
        for name in trailers.keys() {
            if is_forbidden_trailer_field(name)
                || self
                    .connection_nominated
                    .binary_search_by(|candidate| candidate.as_str().cmp(name.as_str()))
                    .is_ok()
            {
                return Err(TrailerValidationError::ForbiddenField(name.clone()));
            }
        }
        if self.protocol == WireProtocol::Http2 && !self.requires_declaration {
            return Ok(());
        }
        let Some(declaration) = &self.declaration else {
            return Err(TrailerValidationError::UndeclaredField(
                trailers.keys().next().cloned().unwrap_or(header::TRAILER),
            ));
        };
        for name in trailers.keys() {
            if !declaration.contains(name) {
                return Err(TrailerValidationError::UndeclaredField(name.clone()));
            }
        }
        Ok(())
    }
}

/// Why a trailer declaration or trailer frame cannot cross the selected wire
/// protocol safely.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TrailerValidationError {
    InvalidDeclarationValue,
    InvalidDeclarationName,
    InvalidConnectionValue,
    ForbiddenField(HeaderName),
    NotAcceptedByHttp1Client,
    UndeclaredField(HeaderName),
}

impl fmt::Display for TrailerValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDeclarationValue => {
                formatter.write_str("Trailer contains non-ASCII field data")
            }
            Self::InvalidDeclarationName => {
                formatter.write_str("Trailer contains an invalid field name")
            }
            Self::InvalidConnectionValue => {
                formatter.write_str("Connection cannot be parsed for trailer safety")
            }
            Self::ForbiddenField(name) => {
                write!(formatter, "trailer field `{name}` is not permitted")
            }
            Self::NotAcceptedByHttp1Client => {
                formatter.write_str("HTTP/1 client did not accept response trailers")
            }
            Self::UndeclaredField(name) => {
                write!(formatter, "HTTP/1 trailer field `{name}` was not declared")
            }
        }
    }
}

impl std::error::Error for TrailerValidationError {}

/// Runtime policy applied to every trailer frame sent downstream.
#[derive(Clone, Debug)]
pub struct TrailerGuard {
    protocol: WireProtocol,
    accepts_http1_trailers: bool,
    declaration: Option<TrailerDeclaration>,
    connection_nominated: Vec<HeaderName>,
    invalid_connection_value: bool,
}

impl TrailerGuard {
    #[cfg(test)]
    pub(crate) const fn new(
        protocol: WireProtocol,
        accepts_http1_trailers: bool,
        declaration: Option<TrailerDeclaration>,
    ) -> Self {
        Self {
            protocol,
            accepts_http1_trailers,
            declaration,
            connection_nominated: Vec::new(),
            invalid_connection_value: false,
        }
    }

    /// Builds a guard from the unsanitized trusted upstream response head.
    /// Connection-nominated names must be captured before the initial fields
    /// are stripped so matching future trailer fields cannot cross the hop.
    pub(crate) fn from_response_headers(
        protocol: WireProtocol,
        accepts_http1_trailers: bool,
        headers: &HeaderMap,
    ) -> Self {
        let (mut connection_nominated, invalid_connection_value) =
            match connection_nominated_headers(headers) {
                Ok(names) => (names, false),
                Err(HeaderSanitizationError::InvalidConnectionValue) => (Vec::new(), true),
            };
        connection_nominated.sort_unstable_by(|left, right| left.as_str().cmp(right.as_str()));
        connection_nominated.dedup();

        let mut declaration = TrailerDeclaration::parse(headers).ok().flatten();
        let trailer_is_nominated = connection_nominated
            .binary_search_by(|name| name.as_str().cmp(header::TRAILER.as_str()))
            .is_ok();
        if invalid_connection_value
            || trailer_is_nominated
            || declaration.as_ref().is_some_and(|declaration| {
                declaration.names.iter().any(|name| {
                    connection_nominated
                        .binary_search_by(|candidate| candidate.as_str().cmp(name.as_str()))
                        .is_ok()
                })
            })
        {
            declaration = None;
        }

        Self {
            protocol,
            accepts_http1_trailers,
            declaration,
            connection_nominated,
            invalid_connection_value,
        }
    }

    /// Returns the declaration that may safely remain in the initial response
    /// head for this downstream protocol.
    pub(crate) fn forwarded_declaration(&self) -> Option<&TrailerDeclaration> {
        match self.protocol {
            WireProtocol::Http2 => self.declaration.as_ref(),
            WireProtocol::Http1 if self.accepts_http1_trailers => self.declaration.as_ref(),
            WireProtocol::Http1 => None,
        }
    }

    pub(crate) fn validate(&self, trailers: &HeaderMap) -> Result<(), TrailerValidationError> {
        if trailers.is_empty() {
            return Ok(());
        }
        if self.invalid_connection_value {
            return Err(TrailerValidationError::InvalidConnectionValue);
        }
        for name in trailers.keys() {
            if is_forbidden_trailer_field(name)
                || self
                    .connection_nominated
                    .binary_search_by(|candidate| candidate.as_str().cmp(name.as_str()))
                    .is_ok()
            {
                return Err(TrailerValidationError::ForbiddenField(name.clone()));
            }
        }

        if self.protocol == WireProtocol::Http2 {
            return Ok(());
        }
        if !self.accepts_http1_trailers {
            return Err(TrailerValidationError::NotAcceptedByHttp1Client);
        }
        let Some(declaration) = &self.declaration else {
            return Err(TrailerValidationError::UndeclaredField(
                trailers.keys().next().cloned().unwrap_or(header::TRAILER),
            ));
        };
        for name in trailers.keys() {
            if !declaration.contains(name) {
                return Err(TrailerValidationError::UndeclaredField(name.clone()));
            }
        }
        Ok(())
    }
}

/// HTTP/1 trailers are accepted only for a single `TE` field whose complete
/// value is exactly `trailers` (case-insensitive, allowing surrounding OWS).
pub(crate) fn http1_accepts_trailers(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::TE).iter();
    values.next().is_some_and(is_trailers) && values.next().is_none()
}

fn parse_trailer_declaration_value(
    value: &HeaderValue,
    names: &mut Vec<HeaderName>,
) -> Result<(), TrailerValidationError> {
    let value = value
        .to_str()
        .map_err(|_| TrailerValidationError::InvalidDeclarationValue)?;
    for token in value.split(',') {
        let token = trim_optional_whitespace(token);
        if token.is_empty() {
            return Err(TrailerValidationError::InvalidDeclarationName);
        }
        let name = HeaderName::from_bytes(token.as_bytes())
            .map_err(|_| TrailerValidationError::InvalidDeclarationName)?;
        if is_forbidden_trailer_field(&name) {
            return Err(TrailerValidationError::ForbiddenField(name));
        }
        names.push(name);
    }
    Ok(())
}

fn is_forbidden_trailer_field(name: &HeaderName) -> bool {
    name == header::CONTENT_LENGTH
        || name == header::CONNECTION
        || name == header::HOST
        || name == header::TE
        || name == header::TRAILER
        || name == header::TRANSFER_ENCODING
        || name == header::UPGRADE
        || matches!(
            name.as_str(),
            "accept-ranges"
                | "age"
                | "authorization"
                | "cache-control"
                | "content-disposition"
                | "content-encoding"
                | "content-language"
                | "content-location"
                | "content-range"
                | "content-type"
                | "cookie"
                | "date"
                | "etag"
                | "expect"
                | "expires"
                | "forwarded"
                | "if-match"
                | "if-modified-since"
                | "if-none-match"
                | "if-range"
                | "if-unmodified-since"
                | "keep-alive"
                | "last-modified"
                | "location"
                | "max-forwards"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "proxy-connection"
                | "range"
                | "retry-after"
                | "set-cookie"
                | "vary"
                | "www-authenticate"
                | "x-forwarded-for"
                | "x-forwarded-host"
                | "x-forwarded-proto"
        )
}

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

    use super::{
        HeaderSanitizationError, RequestTrailerGuard, TrailerDeclaration, TrailerGuard,
        TrailerValidationError, WireProtocol, http1_accepts_trailers, sanitize_runtime_headers,
    };

    #[test]
    fn trailer_declarations_are_normalized_and_reject_unsafe_fields() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::TRAILER,
            HeaderValue::from_static("Grpc-Status, x-checksum"),
        );
        headers.append(
            header::TRAILER,
            HeaderValue::from_static("grpc-message, GRPC-STATUS"),
        );
        let declaration = TrailerDeclaration::parse(&headers)
            .expect("declaration is valid")
            .expect("declaration is present");
        assert_eq!(
            declaration.normalized_value(),
            "grpc-message, grpc-status, x-checksum"
        );

        for value in [
            "content-length",
            "connection",
            "transfer-encoding",
            "trailer",
            "upgrade",
            "host",
            "keep-alive",
            "authorization",
            "cookie",
            "set-cookie",
            "www-authenticate",
            "content-type",
            "content-encoding",
            "content-range",
            "cache-control",
            "location",
            "range",
            "vary",
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::TRAILER,
                HeaderValue::from_str(value).expect("fixture is valid header data"),
            );
            assert!(matches!(
                TrailerDeclaration::parse(&headers),
                Err(TrailerValidationError::ForbiddenField(_))
            ));
        }

        let mut malformed = HeaderMap::new();
        malformed.insert(
            header::TRAILER,
            HeaderValue::from_static("grpc-status, ,grpc-message"),
        );
        assert_eq!(
            TrailerDeclaration::parse(&malformed),
            Err(TrailerValidationError::InvalidDeclarationName)
        );
    }

    #[test]
    fn request_and_response_trailers_cannot_modify_auth_or_representation_metadata() {
        for name in [
            "authorization",
            "set-cookie",
            "content-type",
            "cache-control",
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
        ] {
            let name = HeaderName::from_bytes(name.as_bytes()).expect("fixture name is valid");
            let mut trailers = HeaderMap::new();
            trailers.insert(name.clone(), HeaderValue::from_static("late"));

            let request_guard =
                RequestTrailerGuard::from_request_headers(WireProtocol::Http2, &HeaderMap::new())
                    .expect("empty HTTP/2 request declaration is valid");
            assert_eq!(
                request_guard.validate(&trailers),
                Err(TrailerValidationError::ForbiddenField(name.clone()))
            );
            assert_eq!(
                TrailerGuard::new(WireProtocol::Http2, false, None).validate(&trailers),
                Err(TrailerValidationError::ForbiddenField(name))
            );
        }
    }

    #[test]
    fn http2_to_http1_request_trailers_require_an_initial_declaration() {
        let source =
            RequestTrailerGuard::from_request_headers(WireProtocol::Http2, &HeaderMap::new())
                .expect("empty HTTP/2 declaration is valid");
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        assert!(source.validate(&trailers).is_ok());
        assert_eq!(
            source.for_upstream(WireProtocol::Http1).validate(&trailers),
            Err(TrailerValidationError::UndeclaredField(
                HeaderName::from_static("grpc-status")
            ))
        );

        let mut headers = HeaderMap::new();
        headers.insert(header::TRAILER, HeaderValue::from_static("grpc-status"));
        let declared = RequestTrailerGuard::from_request_headers(WireProtocol::Http2, &headers)
            .expect("HTTP/2 request declaration is valid")
            .for_upstream(WireProtocol::Http1);
        assert!(declared.validate(&trailers).is_ok());
    }

    #[test]
    fn http1_trailer_acceptance_is_strict() {
        for value in ["trailers", " Trailers\t"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::TE,
                HeaderValue::from_str(value).expect("fixture is valid header data"),
            );
            assert!(http1_accepts_trailers(&headers));
        }

        for value in ["gzip", "trailers, deflate", "trailers; q=1", ""] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::TE,
                HeaderValue::from_str(value).expect("fixture is valid header data"),
            );
            assert!(!http1_accepts_trailers(&headers), "{value:?}");
        }

        let mut repeated = HeaderMap::new();
        repeated.append(header::TE, HeaderValue::from_static("trailers"));
        repeated.append(header::TE, HeaderValue::from_static("trailers"));
        assert!(!http1_accepts_trailers(&repeated));
    }

    #[test]
    fn trailer_guards_distinguish_http2_from_declared_http1() {
        let mut declaration_headers = HeaderMap::new();
        declaration_headers.insert(
            header::TRAILER,
            HeaderValue::from_static("grpc-status, grpc-message"),
        );
        let declaration = TrailerDeclaration::parse(&declaration_headers)
            .expect("declaration is valid")
            .expect("declaration is present");

        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        trailers.insert("grpc-message", HeaderValue::from_static("complete"));
        assert!(
            TrailerGuard::new(WireProtocol::Http2, false, None)
                .validate(&trailers)
                .is_ok(),
            "HTTP/2 does not require an initial Trailer declaration"
        );
        assert!(
            TrailerGuard::new(WireProtocol::Http1, true, Some(declaration.clone()))
                .validate(&trailers)
                .is_ok()
        );

        trailers.insert("x-undeclared", HeaderValue::from_static("value"));
        assert_eq!(
            TrailerGuard::new(WireProtocol::Http1, true, Some(declaration)).validate(&trailers),
            Err(TrailerValidationError::UndeclaredField(
                HeaderName::from_static("x-undeclared")
            ))
        );
        assert_eq!(
            TrailerGuard::new(WireProtocol::Http1, false, None).validate(&trailers),
            Err(TrailerValidationError::NotAcceptedByHttp1Client)
        );

        let mut unsafe_trailers = HeaderMap::new();
        unsafe_trailers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("10"));
        assert!(matches!(
            TrailerGuard::new(WireProtocol::Http2, false, None).validate(&unsafe_trailers),
            Err(TrailerValidationError::ForbiddenField(name))
                if name == header::CONTENT_LENGTH
        ));
    }

    #[test]
    fn response_guard_remembers_connection_nominations_before_sanitization() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONNECTION, HeaderValue::from_static("x-late-hop"));
        headers.insert(header::TRAILER, HeaderValue::from_static("x-late-hop"));
        let guard = TrailerGuard::from_response_headers(WireProtocol::Http2, false, &headers);
        assert!(
            guard.forwarded_declaration().is_none(),
            "a connection-nominated declaration cannot be restored"
        );
        let mut trailers = HeaderMap::new();
        trailers.insert("x-late-hop", HeaderValue::from_static("unsafe"));
        assert_eq!(
            guard.validate(&trailers),
            Err(TrailerValidationError::ForbiddenField(
                HeaderName::from_static("x-late-hop")
            ))
        );

        let mut malformed = HeaderMap::new();
        malformed.insert(
            header::CONNECTION,
            HeaderValue::from_bytes(b"\xff").expect("obs-text is valid header field data"),
        );
        let guard = TrailerGuard::from_response_headers(WireProtocol::Http2, false, &malformed);
        assert_eq!(
            guard.validate(&trailers),
            Err(TrailerValidationError::InvalidConnectionValue)
        );
    }

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
