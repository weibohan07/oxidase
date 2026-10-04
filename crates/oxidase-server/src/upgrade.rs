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
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use oxidase_runtime::{
    ClusterRequestPermit, ConcurrencyPermit, PreparedCluster, ResourceKind, ResourceState,
    ResourceToken, RuntimeSnapshot,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::body::{GatewayRequestBody, UnconsumedH2Body};
use crate::protocol::RequestTrailerGuard;

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
    body: Option<GatewayRequestBody>,
    upgrade: Option<PendingUpgrade>,
    trailer_guard: Option<RequestTrailerGuard>,
    unconsumed_h2: Option<UnconsumedH2Body>,
}

impl GatewayRequestPayload {
    pub(crate) fn new(
        body: GatewayRequestBody,
        upgrade: Option<PendingUpgrade>,
        trailer_guard: RequestTrailerGuard,
    ) -> Self {
        Self {
            body: Some(body),
            upgrade,
            trailer_guard: Some(trailer_guard),
            unconsumed_h2: None,
        }
    }

    pub(crate) fn with_unconsumed_h2(mut self, slot: UnconsumedH2Body) -> Self {
        debug_assert!(
            self.upgrade.is_none(),
            "HTTP/1 Upgrade has no H2 disposition"
        );
        self.unconsumed_h2 = Some(slot);
        self
    }

    pub(crate) fn into_parts(
        mut self,
    ) -> (
        GatewayRequestBody,
        Option<PendingUpgrade>,
        RequestTrailerGuard,
    ) {
        // Once Proxy has claimed the payload, its upload/response guards own
        // it. Never return that body to the root, even if an attempt fails or
        // has not polled input yet.
        self.unconsumed_h2.take();
        (
            self.body.take().expect("one-shot request payload"),
            self.upgrade.take(),
            self.trailer_guard.take().expect("request trailer policy"),
        )
    }
}

impl Drop for GatewayRequestPayload {
    fn drop(&mut self) {
        if let Some(slot) = self.unconsumed_h2.take()
            && let Some(body) = self.body.take()
        {
            slot.recover(
                body,
                self.trailer_guard.take().expect("request trailer policy"),
            );
        }
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
        let resource = self
            .snapshot
            .resource_census()
            .token(ResourceKind::Tunnel, ResourceState::Scheduled);
        Ok(TunnelPlan {
            token: self.token,
            downstream: self.downstream,
            upstream,
            snapshot: self.snapshot,
            cluster_lease: None,
            concurrency_permits: Vec::new(),
            resource,
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
    cluster_lease: Option<TunnelClusterLease>,
    concurrency_permits: Vec<ConcurrencyPermit>,
    resource: ResourceToken,
}

impl TunnelPlan {
    pub(crate) fn protocol_header_value(&self) -> HeaderValue {
        self.token.header_value.clone()
    }

    pub(crate) fn retain_cluster_permit(
        mut self,
        cluster: Arc<PreparedCluster>,
        permit: ClusterRequestPermit,
    ) -> Self {
        let endpoint = permit.endpoint().name().into();
        self.cluster_lease = Some(TunnelClusterLease {
            cluster,
            endpoint,
            _permit: permit,
        });
        self
    }

    pub(crate) fn retain_concurrency_permit(mut self, permit: ConcurrencyPermit) -> Self {
        self.concurrency_permits.push(permit);
        self
    }

    /// Waits for both Hyper state machines to yield their upgraded transports,
    /// then pumps bytes in both directions without spawning a detached task.
    ///
    /// Completion, EOF, or error in either direction cancels the other copy
    /// future. Clean EOF finishes both transport write-half shutdowns without
    /// awaiting the cancelled reader; non-EOF errors keep their first cause.
    /// The pinned snapshot is retained until this method returns or its owning
    /// connection task is cancelled by the existing listener drain.
    pub(crate) async fn run(self) -> Result<TunnelReport, TunnelEstablishmentError> {
        let Self {
            token: _,
            downstream,
            upstream,
            snapshot: _snapshot,
            cluster_lease,
            concurrency_permits: _concurrency_permits,
            resource,
        } = self;
        resource.transition(ResourceState::Running);
        let upgrades = tokio::try_join!(
            async {
                downstream
                    .await
                    .map_err(TunnelEstablishmentError::Downstream)
            },
            async { upstream.await.map_err(TunnelEstablishmentError::Upstream) }
        );
        let (downstream, upstream) = match upgrades {
            Ok(upgrades) => upgrades,
            Err(error) => {
                if matches!(&error, TunnelEstablishmentError::Upstream(_))
                    && let Some(lease) = &cluster_lease
                {
                    lease.record_failure();
                }
                return Err(error);
            }
        };
        let report = run_tunnel_io(TokioIo::new(downstream), TokioIo::new(upstream)).await;
        if matches!(
            report.termination,
            TunnelTermination::UpstreamReadError(_) | TunnelTermination::UpstreamWriteError(_)
        ) && let Some(lease) = &cluster_lease
        {
            lease.record_failure();
        }
        Ok(report)
    }
}

struct TunnelClusterLease {
    cluster: Arc<PreparedCluster>,
    endpoint: Box<str>,
    _permit: ClusterRequestPermit,
}

impl TunnelClusterLease {
    fn record_failure(&self) {
        self.cluster
            .record_passive_failure(&self.endpoint, std::time::Instant::now());
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

    let mut termination = {
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

    // A clean first copy already shut down its writer. Cancellation drops the
    // other copy, but Drop does not send rustls close_notify. Finish only that
    // missing write-half shutdown; repeating the completed shutdown is not
    // required by AsyncWrite and can invent an unrelated BrokenPipe. Readers
    // stay cancelled, and the existing listener drain can still cancel this
    // future while a shutdown flush is pending. Keep a non-EOF first error.
    match termination {
        TunnelTermination::DownstreamClosed => {
            if let Err(error) = downstream_write.shutdown().await {
                termination = TunnelTermination::DownstreamWriteError(error.kind());
            }
        }
        TunnelTermination::UpstreamClosed => {
            if let Err(error) = upstream_write.shutdown().await {
                termination = TunnelTermination::UpstreamWriteError(error.kind());
            }
        }
        _ => {}
    }

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

        let mut request = upgrade_request();
        request.headers_mut().remove(header::CONNECTION);
        request
            .headers_mut()
            .append(header::CONNECTION, "Upgrade".parse().expect("header"));
        request.headers_mut().append(
            header::CONNECTION,
            "keep-alive, upgrade".parse().expect("header"),
        );
        assert_eq!(
            validate_upgrade_request(&request),
            Err(UpgradeValidationError::DuplicateConnectionUpgrade),
            "two Connection field lines cannot mint one ambiguous capability"
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

    fn tunnel_tls_test_configs() -> (
        std::sync::Arc<tokio_rustls::rustls::ClientConfig>,
        std::sync::Arc<tokio_rustls::rustls::ServerConfig>,
    ) {
        use std::sync::Arc;
        use tokio_rustls::rustls::crypto::ring::default_provider;
        use tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer;
        use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};

        // Ephemeral publicly generated test-only identity, never deployed.
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["tunnel.example.test".into()])
                .expect("test TLS identity");
        let provider = Arc::new(default_provider());
        let server = Arc::new(
            ServerConfig::builder_with_provider(Arc::clone(&provider))
                .with_safe_default_protocol_versions()
                .expect("safe TLS versions")
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
                )
                .expect("test TLS key"),
        );
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).expect("test trust");
        let client = Arc::new(
            ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("safe TLS versions")
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        (client, server)
    }

    #[tokio::test]
    async fn first_eof_sends_close_notify_on_both_tls_hops() {
        use std::sync::Arc;
        use tokio_rustls::rustls::pki_types::ServerName;
        use tokio_rustls::{TlsAcceptor, TlsConnector};

        let (client, server) = tunnel_tls_test_configs();
        for downstream_first in [true, false] {
            let (client_io, downstream_io) = duplex(4096);
            let (upstream_io, fixture_io) = duplex(4096);
            let name = ServerName::try_from("tunnel.example.test").expect("test name");
            let (client_tls, downstream_tls, upstream_tls, fixture_tls) = tokio::join!(
                TlsConnector::from(Arc::clone(&client)).connect(name.clone(), client_io),
                TlsAcceptor::from(Arc::clone(&server)).accept(downstream_io),
                TlsConnector::from(Arc::clone(&client)).connect(name, upstream_io),
                TlsAcceptor::from(Arc::clone(&server)).accept(fixture_io),
            );
            let mut client_tls = client_tls.expect("downstream TLS");
            let mut fixture_tls = fixture_tls.expect("upstream TLS");
            let client_flow = async {
                client_tls.write_all(b"round-trip").await.expect("request");
                let mut reply = [0; 10];
                client_tls.read_exact(&mut reply).await.expect("full echo");
                assert_eq!(&reply, b"round-trip");
                if downstream_first {
                    client_tls.shutdown().await.expect("client close_notify");
                }
                let mut after = [0; 1];
                assert_eq!(
                    client_tls
                        .read(&mut after)
                        .await
                        .expect("gateway close_notify"),
                    0
                );
                // A clean gateway write-half close is proved by this TLS EOF.
                // The peer need not send another alert after the gateway's IO
                // has already been dropped by the first-EOF tunnel contract.
            };
            let upstream_flow = async {
                let mut request = [0; 10];
                fixture_tls
                    .read_exact(&mut request)
                    .await
                    .expect("full request");
                assert_eq!(&request, b"round-trip");
                fixture_tls.write_all(&request).await.expect("full echo");
                if !downstream_first {
                    fixture_tls.shutdown().await.expect("fixture close_notify");
                }
                let mut after = [0; 1];
                assert_eq!(
                    fixture_tls
                        .read(&mut after)
                        .await
                        .expect("gateway close_notify"),
                    0
                );
            };
            let (report, (), ()) = tokio::time::timeout(Duration::from_secs(1), async {
                tokio::join!(
                    run_tunnel_io(
                        downstream_tls.expect("gateway TLS"),
                        upstream_tls.expect("proxy TLS")
                    ),
                    client_flow,
                    upstream_flow,
                )
            })
            .await
            .expect("both hop shutdowns finish without awaiting peer's read loop");
            assert_eq!(report.downstream_to_upstream_bytes, 10);
            assert_eq!(report.upstream_to_downstream_bytes, 10);
            assert_eq!(
                report.termination,
                if downstream_first {
                    TunnelTermination::DownstreamClosed
                } else {
                    TunnelTermination::UpstreamClosed
                }
            );
        }
    }

    /// TLS needs poll_shutdown on both owned writers. Drop is not close_notify.
    #[tokio::test]
    async fn first_eof_closes_both_transport_write_halves() {
        struct ShutdownObserved {
            io: tokio::io::DuplexStream,
            shutdowns: std::sync::Arc<AtomicU64>,
        }
        impl tokio::io::AsyncRead for ShutdownObserved {
            fn poll_read(
                self: Pin<&mut Self>,
                context: &mut Context<'_>,
                buffer: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().io).poll_read(context, buffer)
            }
        }
        impl AsyncWrite for ShutdownObserved {
            fn poll_write(
                self: Pin<&mut Self>,
                context: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<io::Result<usize>> {
                Pin::new(&mut self.get_mut().io).poll_write(context, bytes)
            }
            fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().io).poll_flush(context)
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                context: &mut Context<'_>,
            ) -> Poll<io::Result<()>> {
                let this = self.get_mut();
                // A transport may reject a repeated shutdown. The clean first
                // copy must not be shut down again during opposite-half cleanup.
                if this.shutdowns.load(Ordering::Relaxed) != 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "fixture second shutdown rejected",
                    )));
                }
                let result = Pin::new(&mut this.io).poll_shutdown(context);
                if result.is_ready() {
                    this.shutdowns.fetch_add(1, Ordering::Relaxed);
                }
                result
            }
        }

        for downstream_first in [true, false] {
            let (mut client, gateway_downstream) = duplex(256);
            let (gateway_upstream, mut upstream) = duplex(256);
            let downstream_shutdowns = std::sync::Arc::new(AtomicU64::new(0));
            let upstream_shutdowns = std::sync::Arc::new(AtomicU64::new(0));
            // Both readers stay alive. Only the selected peer half-closes;
            // cancelling the other copy future must not forget its writer.
            if downstream_first {
                client.shutdown().await.expect("client write EOF");
            } else {
                upstream.shutdown().await.expect("upstream write EOF");
            }
            let report = tokio::time::timeout(
                Duration::from_secs(1),
                run_tunnel_io(
                    ShutdownObserved {
                        io: gateway_downstream,
                        shutdowns: std::sync::Arc::clone(&downstream_shutdowns),
                    },
                    ShutdownObserved {
                        io: gateway_upstream,
                        shutdowns: std::sync::Arc::clone(&upstream_shutdowns),
                    },
                ),
            )
            .await
            .expect("first EOF does not wait for peer read completion");
            assert_eq!(
                report.termination,
                if downstream_first {
                    TunnelTermination::DownstreamClosed
                } else {
                    TunnelTermination::UpstreamClosed
                }
            );
            assert_eq!(downstream_shutdowns.load(Ordering::Relaxed), 1);
            assert_eq!(upstream_shutdowns.load(Ordering::Relaxed), 1);
        }
    }

    #[tokio::test]
    async fn clean_tls_shutdown_does_not_prove_a_complete_tunnel_message() {
        use std::sync::Arc;
        use tokio_rustls::rustls::pki_types::ServerName;
        use tokio_rustls::{TlsAcceptor, TlsConnector};

        let (client, server) = tunnel_tls_test_configs();
        let (client_io, downstream_io) = duplex(4096);
        let (upstream_io, fixture_io) = duplex(4096);
        let name = ServerName::try_from("tunnel.example.test").expect("test name");
        let (client_tls, downstream_tls, upstream_tls, fixture_tls) = tokio::join!(
            TlsConnector::from(Arc::clone(&client)).connect(name.clone(), client_io),
            TlsAcceptor::from(Arc::clone(&server)).accept(downstream_io),
            TlsConnector::from(client).connect(name, upstream_io),
            TlsAcceptor::from(server).accept(fixture_io),
        );
        let mut client_tls = client_tls.expect("downstream TLS");
        let mut fixture_tls = fixture_tls.expect("upstream TLS");
        let client_flow = async {
            client_tls.write_all(b"round-trip").await.expect("request");
            let mut reply = [0; 10];
            let error = client_tls
                .read_exact(&mut reply)
                .await
                .expect_err("three-byte prefix cannot satisfy a ten-byte application message");
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
            assert_eq!(&reply[..3], b"rou");
            let mut after = [0; 1];
            assert_eq!(
                client_tls.read(&mut after).await.expect("TLS close_notify"),
                0
            );
        };
        let upstream_flow = async {
            let mut request = [0; 10];
            fixture_tls
                .read_exact(&mut request)
                .await
                .expect("full request");
            assert_eq!(&request, b"round-trip");
            fixture_tls.write_all(b"rou").await.expect("truncated echo");
            fixture_tls.shutdown().await.expect("fixture close_notify");
            let mut after = [0; 1];
            assert_eq!(
                fixture_tls
                    .read(&mut after)
                    .await
                    .expect("gateway close_notify"),
                0
            );
        };
        let (report, (), ()) = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(
                run_tunnel_io(
                    downstream_tls.expect("gateway TLS"),
                    upstream_tls.expect("proxy TLS")
                ),
                client_flow,
                upstream_flow,
            )
        })
        .await
        .expect("transport shutdown cannot turn truncation into application success");
        assert_eq!(report.termination, TunnelTermination::UpstreamClosed);
        assert_eq!(report.downstream_to_upstream_bytes, 10);
        assert_eq!(report.upstream_to_downstream_bytes, 3);
    }

    struct IoDropReceipt(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for IoDropReceipt {
        fn drop(&mut self) {
            if let Some(receipt) = self.0.take() {
                let _ = receipt.send(());
            }
        }
    }

    struct ShutdownGatedIo {
        io: tokio::io::DuplexStream,
        read_error: Option<io::ErrorKind>,
        entered: Option<tokio::sync::oneshot::Sender<()>>,
        release: Option<tokio::sync::oneshot::Receiver<()>>,
        // Last field acknowledges actual transport-field destruction, not a
        // request to abort or the beginning of this owner's Drop.
        _drop_receipt: IoDropReceipt,
    }

    impl tokio::io::AsyncRead for ShutdownGatedIo {
        fn poll_read(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if let Some(kind) = this.read_error.take() {
                return Poll::Ready(Err(io::Error::new(kind, "fixture first read failed")));
            }
            Pin::new(&mut this.io).poll_read(context, buffer)
        }
    }

    impl AsyncWrite for ShutdownGatedIo {
        fn poll_write(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().io).poll_write(context, bytes)
        }

        fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().io).poll_flush(context)
        }

        fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if let Some(entered) = this.entered.take() {
                let _ = entered.send(());
            }
            if let Some(release) = &mut this.release {
                match std::future::Future::poll(Pin::new(release), context) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(_) => this.release = None,
                }
            }
            Pin::new(&mut this.io).poll_shutdown(context)
        }
    }

    #[tokio::test]
    async fn pending_opposite_shutdown_finishes_or_is_cancelled_with_actual_io_drop() {
        for downstream_first in [true, false] {
            for cancel in [false, true] {
                let (mut client, downstream) = duplex(256);
                let (upstream, mut fixture) = duplex(256);
                let (entered, observed) = tokio::sync::oneshot::channel();
                let (release, allowed) = tokio::sync::oneshot::channel();
                let (down_drop, down_dropped) = tokio::sync::oneshot::channel();
                let (up_drop, up_dropped) = tokio::sync::oneshot::channel();
                if downstream_first {
                    client.shutdown().await.expect("client write EOF");
                } else {
                    fixture.shutdown().await.expect("fixture write EOF");
                }
                let (gated_io, plain_io, gated_drop, plain_drop) = if downstream_first {
                    (downstream, upstream, down_drop, up_drop)
                } else {
                    (upstream, downstream, up_drop, down_drop)
                };
                let gated = ShutdownGatedIo {
                    io: gated_io,
                    read_error: None,
                    entered: Some(entered),
                    release: Some(allowed),
                    _drop_receipt: IoDropReceipt(Some(gated_drop)),
                };
                let plain = ShutdownGatedIo {
                    io: plain_io,
                    read_error: None,
                    entered: None,
                    release: None,
                    _drop_receipt: IoDropReceipt(Some(plain_drop)),
                };
                let task = if downstream_first {
                    tokio::spawn(run_tunnel_io(gated, plain))
                } else {
                    tokio::spawn(run_tunnel_io(plain, gated))
                };
                tokio::time::timeout(Duration::from_secs(1), observed)
                    .await
                    .expect("opposite shutdown is actually polled")
                    .expect("shutdown entry receipt");
                assert!(
                    !task.is_finished(),
                    "a Pending close flush must not be ignored"
                );
                if cancel {
                    // Listener drain cancels this same owned future. It need
                    // not release a peer gate or spawn detached close work.
                    task.abort();
                    let error = tokio::time::timeout(Duration::from_secs(1), task)
                        .await
                        .expect("drain cancellation finishes")
                        .expect_err("owned tunnel task was cancelled");
                    assert!(error.is_cancelled());
                } else {
                    release.send(()).expect("release close flush");
                    let report = tokio::time::timeout(Duration::from_secs(1), task)
                        .await
                        .expect("close flush completes")
                        .expect("tunnel joins");
                    assert_eq!(
                        report.termination,
                        if downstream_first {
                            TunnelTermination::DownstreamClosed
                        } else {
                            TunnelTermination::UpstreamClosed
                        }
                    );
                }
                tokio::time::timeout(Duration::from_secs(1), async {
                    down_dropped.await.expect("downstream IO destroyed");
                    up_dropped.await.expect("upstream IO destroyed");
                })
                .await
                .expect("both transports actually released without scrape or peer progress");
            }
        }
    }

    #[tokio::test]
    async fn non_eof_failure_keeps_its_first_cause_without_waiting_for_shutdown() {
        let (mut client, downstream) = duplex(256);
        let (upstream, mut fixture) = duplex(256);
        let (entered, observed) = tokio::sync::oneshot::channel();
        let (_release, allowed) = tokio::sync::oneshot::channel();
        let (dropped, destroyed) = tokio::sync::oneshot::channel();
        let report = tokio::time::timeout(
            Duration::from_secs(1),
            run_tunnel_io(
                ShutdownGatedIo {
                    io: downstream,
                    read_error: Some(io::ErrorKind::ConnectionReset),
                    entered: Some(entered),
                    release: Some(allowed),
                    _drop_receipt: IoDropReceipt(Some(dropped)),
                },
                upstream,
            ),
        )
        .await
        .expect("first read error does not wait for a close flush");
        assert_eq!(
            report.termination,
            TunnelTermination::DownstreamReadError(io::ErrorKind::ConnectionReset)
        );
        assert_eq!(report.downstream_to_upstream_bytes, 0);
        assert_eq!(report.upstream_to_downstream_bytes, 0);
        assert!(
            observed.await.is_err(),
            "no shutdown poll follows a non-EOF error"
        );
        destroyed.await.expect("failed downstream IO destroyed");
        let mut after = [0; 1];
        assert_eq!(
            client.read(&mut after).await.expect("client sees release"),
            0
        );
        assert_eq!(
            fixture
                .read(&mut after)
                .await
                .expect("fixture sees release"),
            0
        );
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
