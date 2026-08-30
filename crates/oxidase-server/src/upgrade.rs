//! Trusted HTTP/1 upgrade validation and tunnel execution.
//!
//! This boundary is intentionally server-local. Source configuration cannot
//! construct an [`UpgradeCandidate`] or [`TrustedUpgrade`]; only the HTTP/1
//! ingress and Proxy data-plane may create them after validating both sides of
//! the handshake.

use std::fmt;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use http::{HeaderValue, Method, Request, Response, StatusCode, Version, header};
use hyper::body::Incoming;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use oxidase_runtime::RuntimeSnapshot;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A validated, normalized HTTP Upgrade protocol identifier.
///
/// The protocol name and optional version use the HTTP `token` grammar. The
/// protocol name is normalized to lowercase ASCII; the optional version
/// remains case-sensitive, as required by HTTP Upgrade's protocol grammar.
#[derive(Clone, Eq, Hash, PartialEq)]
pub(crate) struct UpgradeToken {
    protocol: Box<str>,
    version: Option<Box<str>>,
    header_value: HeaderValue,
}

impl UpgradeToken {
    #[cfg(test)]
    pub(crate) fn protocol(&self) -> &str {
        &self.protocol
    }

    #[cfg(test)]
    pub(crate) fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
}

impl fmt::Debug for UpgradeToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpgradeToken")
            .field("protocol", &self.protocol)
            .field("version", &self.version)
            .finish()
    }
}

impl fmt::Display for UpgradeToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.protocol)?;
        if let Some(version) = &self.version {
            formatter.write_str("/")?;
            formatter.write_str(version)?;
        }
        Ok(())
    }
}

/// A validated downstream request that may enter the trusted Proxy upgrade
/// path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UpgradeCandidate {
    token: UpgradeToken,
}

impl UpgradeCandidate {
    pub(crate) fn token(&self) -> &UpgradeToken {
        &self.token
    }

    pub(crate) fn pending(self, downstream: OnUpgrade) -> PendingUpgrade {
        PendingUpgrade {
            candidate: self,
            downstream,
        }
    }
}

/// The request-body payload consumed by the Service executor.
///
/// Keeping the upgrade capability next to the one-shot incoming body prevents
/// fallback or a non-Proxy Service from recreating it from ordinary headers.
pub(crate) struct GatewayRequestPayload {
    body: Incoming,
    upgrade: Option<PendingUpgrade>,
}

impl GatewayRequestPayload {
    pub(crate) fn new(body: Incoming, upgrade: Option<PendingUpgrade>) -> Self {
        Self { body, upgrade }
    }

    pub(crate) fn into_parts(self) -> (Incoming, Option<PendingUpgrade>) {
        (self.body, self.upgrade)
    }
}

impl fmt::Debug for GatewayRequestPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayRequestPayload")
            .field("body", &"streaming")
            .field("has_upgrade", &self.upgrade.is_some())
            .finish()
    }
}

/// A downstream upgrade capability before it is pinned to a runtime snapshot.
pub(crate) struct PendingUpgrade {
    candidate: UpgradeCandidate,
    downstream: OnUpgrade,
}

impl PendingUpgrade {
    pub(crate) fn protocol_header_value(&self) -> HeaderValue {
        self.candidate.token.header_value.clone()
    }

    pub(crate) fn bind(self, snapshot: Arc<RuntimeSnapshot>) -> TrustedUpgrade {
        TrustedUpgrade {
            token: self.candidate.token,
            downstream: self.downstream,
            snapshot,
        }
    }
}

impl fmt::Debug for PendingUpgrade {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingUpgrade")
            .field("token", self.candidate.token())
            .finish_non_exhaustive()
    }
}

/// A validated downstream capability pinned to the snapshot that produced the
/// Proxy request.
pub(crate) struct TrustedUpgrade {
    token: UpgradeToken,
    downstream: OnUpgrade,
    snapshot: Arc<RuntimeSnapshot>,
}

impl TrustedUpgrade {
    /// Validates the upstream `101` response and joins both one-shot upgrade
    /// futures into a tunnel plan.
    pub(crate) fn accept<B>(
        self,
        response: &Response<B>,
        upstream: OnUpgrade,
    ) -> Result<TunnelPlan, UpgradeValidationError> {
        validate_upstream_switch(response, &self.token)?;
        Ok(TunnelPlan {
            token: self.token,
            downstream: self.downstream,
            upstream,
            snapshot: self.snapshot,
        })
    }
}

impl fmt::Debug for TrustedUpgrade {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedUpgrade")
            .field("token", &self.token)
            .field("config_version", &self.snapshot.config_version)
            .finish_non_exhaustive()
    }
}

/// A fully validated pair of HTTP/1 upgraded transports.
pub struct TunnelPlan {
    token: UpgradeToken,
    downstream: OnUpgrade,
    upstream: OnUpgrade,
    snapshot: Arc<RuntimeSnapshot>,
}

impl TunnelPlan {
    pub(crate) fn protocol_header_value(&self) -> HeaderValue {
        self.token.header_value.clone()
    }

    /// Waits for both Hyper state machines to yield their upgraded transports,
    /// then pumps bytes in both directions without spawning a detached task.
    ///
    /// Completion, EOF, or error in either direction cancels the other copy
    /// future. The pinned snapshot is retained until this method returns.
    pub(crate) async fn run(self) -> Result<TunnelReport, TunnelEstablishmentError> {
        let Self {
            token: _,
            downstream,
            upstream,
            snapshot: _snapshot,
        } = self;
        let (downstream, upstream) = tokio::try_join!(
            async {
                downstream
                    .await
                    .map_err(TunnelEstablishmentError::Downstream)
            },
            async { upstream.await.map_err(TunnelEstablishmentError::Upstream) }
        )?;
        Ok(run_tunnel_io(TokioIo::new(downstream), TokioIo::new(upstream)).await)
    }
}

impl fmt::Debug for TunnelPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TunnelPlan")
            .field("token", &self.token)
            .field("config_version", &self.snapshot.config_version)
            .finish_non_exhaustive()
    }
}

/// The fixed, non-sensitive reason a bidirectional tunnel stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TunnelTermination {
    DownstreamClosed,
    UpstreamClosed,
    DownstreamReadError(io::ErrorKind),
    DownstreamWriteError(io::ErrorKind),
    UpstreamReadError(io::ErrorKind),
    UpstreamWriteError(io::ErrorKind),
}

/// Byte counters and termination state for one completed tunnel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TunnelReport {
    pub(crate) downstream_to_upstream_bytes: u64,
    pub(crate) upstream_to_downstream_bytes: u64,
    pub(crate) termination: TunnelTermination,
}

/// A failure before both HTTP connection drivers released their upgraded IO.
#[derive(Debug, Error)]
pub(crate) enum TunnelEstablishmentError {
    #[error("downstream HTTP upgrade did not complete")]
    Downstream(#[source] hyper::Error),
    #[error("upstream HTTP upgrade did not complete")]
    Upstream(#[source] hyper::Error),
}

/// A strict error from either side of an HTTP/1 Upgrade handshake.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub(crate) enum UpgradeValidationError {
    #[error("CONNECT tunnels are not supported")]
    ConnectUnsupported,
    #[error("HTTP Upgrade is supported only over HTTP/1.1")]
    UnsupportedHttpVersion,
    #[error("Upgrade requires exactly one Connection: upgrade token")]
    MissingConnectionUpgrade,
    #[error("Connection contains the upgrade token more than once")]
    DuplicateConnectionUpgrade,
    #[error("Connection contains an invalid protocol token")]
    InvalidConnectionValue,
    #[error("Upgrade requires exactly one protocol value")]
    MissingUpgradeValue,
    #[error("Upgrade contains more than one protocol value")]
    DuplicateUpgradeValue,
    #[error("Upgrade contains an invalid protocol[/version]")]
    InvalidUpgradeValue,
    #[error("HTTP/2 upgrades are not supported")]
    Http2UpgradeUnsupported,
    #[error("upstream returned {0} instead of 101 Switching Protocols")]
    UnexpectedStatus(StatusCode),
    #[error("upstream selected `{actual}` instead of requested `{expected}`")]
    ProtocolMismatch {
        expected: Box<UpgradeToken>,
        actual: Box<UpgradeToken>,
    },
}

/// Validates a downstream request before trusted Proxy code may preserve its
/// hop-by-hop Upgrade fields.
pub(crate) fn validate_upgrade_request<B>(
    request: &Request<B>,
) -> Result<Option<UpgradeCandidate>, UpgradeValidationError> {
    if request.method() == Method::CONNECT {
        return Err(UpgradeValidationError::ConnectUnsupported);
    }

    let has_upgrade = request.headers().contains_key(header::UPGRADE);
    if !has_upgrade && !connection_mentions_upgrade(request.headers()) {
        return Ok(None);
    }
    if request.version() != Version::HTTP_11 {
        return Err(UpgradeValidationError::UnsupportedHttpVersion);
    }

    require_single_connection_upgrade(request.headers())?;
    let token = parse_upgrade_header(request.headers())?;
    Ok(Some(UpgradeCandidate { token }))
}

fn connection_mentions_upgrade(headers: &http::HeaderMap) -> bool {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| {
            token
                .trim_matches([' ', '\t'])
                .eq_ignore_ascii_case("upgrade")
        })
}

/// Validates that an upstream response accepted the exact protocol requested
/// by the downstream client.
pub(crate) fn validate_upstream_switch<B>(
    response: &Response<B>,
    expected: &UpgradeToken,
) -> Result<(), UpgradeValidationError> {
    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Err(UpgradeValidationError::UnexpectedStatus(response.status()));
    }
    if response.version() != Version::HTTP_11 {
        return Err(UpgradeValidationError::UnsupportedHttpVersion);
    }
    require_single_connection_upgrade(response.headers())?;
    let actual = parse_upgrade_header(response.headers())?;
    if actual != *expected {
        return Err(UpgradeValidationError::ProtocolMismatch {
            expected: Box::new(expected.clone()),
            actual: Box::new(actual),
        });
    }
    Ok(())
}

fn require_single_connection_upgrade(
    headers: &http::HeaderMap,
) -> Result<(), UpgradeValidationError> {
    let mut upgrade_tokens = 0usize;
    for value in headers.get_all(header::CONNECTION) {
        let value = value
            .to_str()
            .map_err(|_| UpgradeValidationError::InvalidConnectionValue)?;
        for token in value.split(',') {
            let token = token.trim_matches([' ', '\t']);
            if token.is_empty() || !token.bytes().all(is_token_byte) {
                return Err(UpgradeValidationError::InvalidConnectionValue);
            }
            if token.eq_ignore_ascii_case("upgrade") {
                upgrade_tokens += 1;
            }
        }
    }
    match upgrade_tokens {
        0 => Err(UpgradeValidationError::MissingConnectionUpgrade),
        1 => Ok(()),
        _ => Err(UpgradeValidationError::DuplicateConnectionUpgrade),
    }
}

fn parse_upgrade_header(headers: &http::HeaderMap) -> Result<UpgradeToken, UpgradeValidationError> {
    let mut values = headers.get_all(header::UPGRADE).iter();
    let Some(value) = values.next() else {
        return Err(UpgradeValidationError::MissingUpgradeValue);
    };
    if values.next().is_some() {
        return Err(UpgradeValidationError::DuplicateUpgradeValue);
    }
    parse_upgrade_value(value.as_bytes())
}

fn parse_upgrade_value(value: &[u8]) -> Result<UpgradeToken, UpgradeValidationError> {
    let value = trim_ascii_whitespace(value);
    if value.is_empty() || value.contains(&b',') {
        return Err(UpgradeValidationError::InvalidUpgradeValue);
    }
    let mut parts = value.split(|byte| *byte == b'/');
    let Some(protocol) = parts.next() else {
        return Err(UpgradeValidationError::InvalidUpgradeValue);
    };
    let version = parts.next();
    if parts.next().is_some()
        || protocol.is_empty()
        || !protocol.iter().copied().all(is_token_byte)
        || version.is_some_and(|version| {
            version.is_empty() || !version.iter().copied().all(is_token_byte)
        })
    {
        return Err(UpgradeValidationError::InvalidUpgradeValue);
    }

    let protocol = ascii_lowercase(protocol);
    let version = version.map(ascii_string);
    if is_http2_upgrade(&protocol, version.as_deref()) {
        return Err(UpgradeValidationError::Http2UpgradeUnsupported);
    }
    let wire_value = version.as_ref().map_or_else(
        || protocol.clone(),
        |version| format!("{protocol}/{version}"),
    );
    let header_value = HeaderValue::from_bytes(wire_value.as_bytes())
        .map_err(|_| UpgradeValidationError::InvalidUpgradeValue)?;
    Ok(UpgradeToken {
        protocol: protocol.into_boxed_str(),
        version: version.map(String::into_boxed_str),
        header_value,
    })
}

fn trim_ascii_whitespace(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn ascii_lowercase(value: &[u8]) -> String {
    value
        .iter()
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect()
}

fn ascii_string(value: &[u8]) -> String {
    value.iter().map(|byte| *byte as char).collect()
}

fn is_http2_upgrade(protocol: &str, version: Option<&str>) -> bool {
    protocol.eq_ignore_ascii_case("h2")
        || protocol.eq_ignore_ascii_case("h2c")
        || (protocol.eq_ignore_ascii_case("http")
            && version.is_some_and(|version| matches!(version, "2" | "2.0")))
}

fn is_token_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
            | b'0'..=b'9'
            | b'A'..=b'Z'
            | b'a'..=b'z'
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CopyCompletion {
    EndOfStream,
    ReadError(io::ErrorKind),
    WriteError(io::ErrorKind),
}

async fn run_tunnel_io<Downstream, Upstream>(
    downstream: Downstream,
    upstream: Upstream,
) -> TunnelReport
where
    Downstream: AsyncRead + AsyncWrite + Unpin,
    Upstream: AsyncRead + AsyncWrite + Unpin,
{
    let downstream_to_upstream_bytes = AtomicU64::new(0);
    let upstream_to_downstream_bytes = AtomicU64::new(0);
    let (mut downstream_read, mut downstream_write) = tokio::io::split(downstream);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

    let termination = {
        let downstream_to_upstream = copy_direction(
            &mut downstream_read,
            &mut upstream_write,
            &downstream_to_upstream_bytes,
        );
        let upstream_to_downstream = copy_direction(
            &mut upstream_read,
            &mut downstream_write,
            &upstream_to_downstream_bytes,
        );
        tokio::pin!(downstream_to_upstream);
        tokio::pin!(upstream_to_downstream);
        tokio::select! {
            completion = &mut downstream_to_upstream => {
                classify_copy_completion(CopyDirection::DownstreamToUpstream, completion)
            }
            completion = &mut upstream_to_downstream => {
                classify_copy_completion(CopyDirection::UpstreamToDownstream, completion)
            }
        }
    };

    TunnelReport {
        downstream_to_upstream_bytes: downstream_to_upstream_bytes.load(Ordering::Relaxed),
        upstream_to_downstream_bytes: upstream_to_downstream_bytes.load(Ordering::Relaxed),
        termination,
    }
}

async fn copy_direction<Reader, Writer>(
    reader: &mut Reader,
    writer: &mut Writer,
    bytes: &AtomicU64,
) -> CopyCompletion
where
    Reader: AsyncRead + Unpin,
    Writer: AsyncWrite + Unpin,
{
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let length = match reader.read(&mut buffer).await {
            Ok(0) => {
                return match writer.shutdown().await {
                    Ok(()) => CopyCompletion::EndOfStream,
                    Err(error) => CopyCompletion::WriteError(error.kind()),
                };
            }
            Ok(length) => length,
            Err(error) => return CopyCompletion::ReadError(error.kind()),
        };
        let mut written = 0usize;
        while written < length {
            match writer.write(&buffer[written..length]).await {
                Ok(0) => return CopyCompletion::WriteError(io::ErrorKind::WriteZero),
                Ok(count) => {
                    written += count;
                    bytes.fetch_add(count as u64, Ordering::Relaxed);
                }
                Err(error) => return CopyCompletion::WriteError(error.kind()),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CopyDirection {
    DownstreamToUpstream,
    UpstreamToDownstream,
}

fn classify_copy_completion(
    direction: CopyDirection,
    completion: CopyCompletion,
) -> TunnelTermination {
    match (direction, completion) {
        (CopyDirection::DownstreamToUpstream, CopyCompletion::EndOfStream) => {
            TunnelTermination::DownstreamClosed
        }
        (CopyDirection::DownstreamToUpstream, CopyCompletion::ReadError(kind)) => {
            TunnelTermination::DownstreamReadError(kind)
        }
        (CopyDirection::DownstreamToUpstream, CopyCompletion::WriteError(kind)) => {
            TunnelTermination::UpstreamWriteError(kind)
        }
        (CopyDirection::UpstreamToDownstream, CopyCompletion::EndOfStream) => {
            TunnelTermination::UpstreamClosed
        }
        (CopyDirection::UpstreamToDownstream, CopyCompletion::ReadError(kind)) => {
            TunnelTermination::UpstreamReadError(kind)
        }
        (CopyDirection::UpstreamToDownstream, CopyCompletion::WriteError(kind)) => {
            TunnelTermination::DownstreamWriteError(kind)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::{Context, Poll};
    use std::time::Duration;

    use http::{Method, Request, Response, StatusCode, Version, header};
    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, duplex};

    use super::{
        CopyCompletion, TunnelTermination, UpgradeValidationError, copy_direction,
        parse_upgrade_value, run_tunnel_io, validate_upgrade_request, validate_upstream_switch,
    };

    fn upgrade_request() -> Request<()> {
        Request::builder()
            .method(Method::GET)
            .version(Version::HTTP_11)
            .header(header::CONNECTION, "keep-alive, Upgrade")
            .header(header::UPGRADE, "websocket")
            .body(())
            .expect("valid upgrade request fixture")
    }

    fn switching_response(protocol: &str) -> Response<()> {
        Response::builder()
            .version(Version::HTTP_11)
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(header::CONNECTION, "upgrade")
            .header(header::UPGRADE, protocol)
            .body(())
            .expect("valid switching response fixture")
    }

    #[test]
    fn ordinary_http_request_is_not_an_upgrade_candidate() {
        let mut request = Request::builder()
            .method(Method::GET)
            .version(Version::HTTP_11)
            .body(())
            .expect("valid request fixture");
        assert_eq!(validate_upgrade_request(&request), Ok(None));

        request
            .headers_mut()
            .insert(header::CONNECTION, "keep-alive".parse().expect("header"));
        assert_eq!(
            validate_upgrade_request(&request),
            Ok(None),
            "ordinary HTTP/1 connection management is not an Upgrade attempt"
        );
    }

    #[test]
    fn validates_and_normalizes_single_protocol_with_optional_version() {
        let candidate = validate_upgrade_request(&upgrade_request())
            .expect("valid request")
            .expect("upgrade candidate");
        assert_eq!(candidate.token().protocol(), "websocket");
        assert_eq!(candidate.token().version(), None);

        let mut request = upgrade_request();
        request
            .headers_mut()
            .insert(header::UPGRADE, "Custom/Version-1".parse().expect("header"));
        let candidate = validate_upgrade_request(&request)
            .expect("valid versioned protocol")
            .expect("upgrade candidate");
        assert_eq!(candidate.token().protocol(), "custom");
        assert_eq!(candidate.token().version(), Some("Version-1"));
    }

    #[test]
    fn rejects_connect_http2_and_h2c() {
        let mut request = upgrade_request();
        *request.method_mut() = Method::CONNECT;
        assert_eq!(
            validate_upgrade_request(&request),
            Err(UpgradeValidationError::ConnectUnsupported)
        );

        let mut request = upgrade_request();
        *request.version_mut() = Version::HTTP_2;
        assert_eq!(
            validate_upgrade_request(&request),
            Err(UpgradeValidationError::UnsupportedHttpVersion)
        );

        for protocol in ["h2c", "H2", "HTTP/2", "http/2.0"] {
            let mut request = upgrade_request();
            request
                .headers_mut()
                .insert(header::UPGRADE, protocol.parse().expect("header"));
            assert_eq!(
                validate_upgrade_request(&request),
                Err(UpgradeValidationError::Http2UpgradeUnsupported),
                "{protocol} must not enter the HTTP/1 tunnel path"
            );
        }
    }

    #[test]
    fn rejects_missing_duplicate_and_malformed_handshake_fields() {
        let mut request = upgrade_request();
        request.headers_mut().remove(header::CONNECTION);
        assert_eq!(
            validate_upgrade_request(&request),
            Err(UpgradeValidationError::MissingConnectionUpgrade)
        );

        let mut request = upgrade_request();
        request.headers_mut().remove(header::UPGRADE);
        assert_eq!(
            validate_upgrade_request(&request),
            Err(UpgradeValidationError::MissingUpgradeValue)
        );

        let mut request = upgrade_request();
        request
            .headers_mut()
            .append(header::UPGRADE, "second".parse().expect("header"));
        assert_eq!(
            validate_upgrade_request(&request),
            Err(UpgradeValidationError::DuplicateUpgradeValue)
        );

        let mut request = upgrade_request();
        request.headers_mut().insert(
            header::CONNECTION,
            "upgrade, Upgrade".parse().expect("header"),
        );
        assert_eq!(
            validate_upgrade_request(&request),
            Err(UpgradeValidationError::DuplicateConnectionUpgrade)
        );

        for value in [
            b"websocket, custom".as_slice(),
            b"web socket",
            b"websocket/",
            b"/13",
            b"websocket/13/extra",
            b"websocket\r\nx-injected: value",
        ] {
            assert_eq!(
                parse_upgrade_value(value),
                Err(UpgradeValidationError::InvalidUpgradeValue),
                "{value:?} must be rejected"
            );
        }
    }

    #[test]
    fn upstream_switch_must_match_the_downstream_protocol() {
        let candidate = validate_upgrade_request(&upgrade_request())
            .expect("valid request")
            .expect("upgrade candidate");
        validate_upstream_switch(&switching_response("WebSocket"), candidate.token())
            .expect("protocol comparison is ASCII case-insensitive");

        let response = switching_response("custom");
        assert!(matches!(
            validate_upstream_switch(&response, candidate.token()),
            Err(UpgradeValidationError::ProtocolMismatch { .. })
        ));

        let mut response = switching_response("websocket");
        *response.status_mut() = StatusCode::OK;
        assert_eq!(
            validate_upstream_switch(&response, candidate.token()),
            Err(UpgradeValidationError::UnexpectedStatus(StatusCode::OK))
        );

        let mut response = switching_response("websocket");
        response.headers_mut().remove(header::CONNECTION);
        assert_eq!(
            validate_upstream_switch(&response, candidate.token()),
            Err(UpgradeValidationError::MissingConnectionUpgrade)
        );

        let mut versioned_request = upgrade_request();
        versioned_request
            .headers_mut()
            .insert(header::UPGRADE, "custom/Version-1".parse().expect("header"));
        let versioned = validate_upgrade_request(&versioned_request)
            .expect("valid versioned request")
            .expect("upgrade candidate");
        assert!(matches!(
            validate_upstream_switch(&switching_response("CUSTOM/version-1"), versioned.token()),
            Err(UpgradeValidationError::ProtocolMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn tunnel_forwards_both_directions_and_cancels_peer_on_first_eof() {
        let (mut client, gateway_downstream) = duplex(256);
        let (gateway_upstream, mut upstream) = duplex(256);

        let tunnel = run_tunnel_io(gateway_downstream, gateway_upstream);
        let client_flow = async {
            client.write_all(b"ping").await.expect("client writes");
            let mut reply = [0u8; 4];
            client
                .read_exact(&mut reply)
                .await
                .expect("client reads reply");
            assert_eq!(&reply, b"pong");
            client.shutdown().await.expect("client half-closes");
        };
        let upstream_flow = async {
            let mut request = [0u8; 4];
            upstream
                .read_exact(&mut request)
                .await
                .expect("upstream reads request");
            assert_eq!(&request, b"ping");
            upstream.write_all(b"pong").await.expect("upstream writes");
            let mut after_cancel = [0u8; 1];
            assert_eq!(
                upstream
                    .read(&mut after_cancel)
                    .await
                    .expect("tunnel closes the other direction"),
                0
            );
        };

        let (report, (), ()) = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(tunnel, client_flow, upstream_flow)
        })
        .await
        .expect("first EOF cancels the still-open direction");
        assert_eq!(report.downstream_to_upstream_bytes, 4);
        assert_eq!(report.upstream_to_downstream_bytes, 4);
        assert_eq!(report.termination, TunnelTermination::DownstreamClosed);
    }

    #[tokio::test]
    async fn partial_copy_count_survives_write_failure() {
        let mut reader = &b"abcdef"[..];
        let mut writer = FailAfter::new(3);
        let bytes = AtomicU64::new(0);
        let completion = copy_direction(&mut reader, &mut writer, &bytes).await;
        assert_eq!(
            completion,
            CopyCompletion::WriteError(io::ErrorKind::BrokenPipe)
        );
        assert_eq!(bytes.load(Ordering::Relaxed), 3);
    }

    struct FailAfter {
        remaining: usize,
    }

    impl FailAfter {
        fn new(remaining: usize) -> Self {
            Self { remaining }
        }
    }

    impl AsyncWrite for FailAfter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.remaining == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "fixture write failure",
                )));
            }
            let length = self.remaining.min(buffer.len());
            self.remaining -= length;
            Poll::Ready(Ok(length))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
}
