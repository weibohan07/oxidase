//! Upstream connection identity: a logical HTTP origin is not a dial address.
//!
//! Each long-lived Client has one immutable connector. It can only dial its
//! selected `SocketAddr`; neither Hyper checkout nor TLS performs another DNS
//! lookup. Response-body demand and logical request deadlines remain outside
//! this module, so cancelling one request never changes shared transport policy.

use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use http::Uri;
use http_body::Body;
use hyper_rustls::MaybeHttpsStream;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioIo, TokioTimer};
use oxidase_config::ClusterProtocol;
use oxidase_core::{ContentDigest, ContentDigestBuilder, ResourceId};
use oxidase_runtime::{PreparedCluster, PreparedUpstreamTls};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{ClientConfig, pki_types::ServerName};
use tower_service::Service;

use crate::body::BoxError;

pub(crate) const MAX_STATIC_ADDRESSES: usize = 32;

/// Fixed scheme, HTTP authority and base path, never rewritten by DNS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LogicalOrigin {
    url: url::Url,
    scheme: http::uri::Scheme,
    authority: http::uri::Authority,
    host: String,
    port: u16,
}

impl LogicalOrigin {
    pub(crate) fn from_url(url: &url::Url) -> Result<Self, TransportError> {
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(TransportError::invalid_origin());
        }
        let host = match url.host() {
            Some(url::Host::Domain(host)) => host.to_owned(),
            Some(url::Host::Ipv4(address)) => address.to_string(),
            Some(url::Host::Ipv6(address)) => address.to_string(),
            None => return Err(TransportError::invalid_origin()),
        };
        let port = url
            .port_or_known_default()
            .filter(|port| *port != 0)
            .ok_or_else(TransportError::invalid_origin)?;
        // Url has already bracketed IPv6 exactly once and normalized default
        // ports. Its canonical authority must be preserved on the wire.
        let authority = url[url::Position::BeforeHost..url::Position::AfterPort]
            .parse()
            .map_err(|_| TransportError::invalid_origin())?;
        let scheme = url
            .scheme()
            .parse()
            .map_err(|_| TransportError::invalid_origin())?;
        Ok(Self {
            url: url.clone(),
            scheme,
            authority,
            host,
            port,
        })
    }

    pub(crate) fn authority(&self) -> &http::uri::Authority {
        &self.authority
    }

    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    pub(crate) const fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn is_tls(&self) -> bool {
        self.scheme == http::uri::Scheme::HTTPS
    }

    pub(crate) fn request_uri(&self, path_and_query: &str) -> Result<Uri, TransportError> {
        let path = path_and_query
            .parse::<http::uri::PathAndQuery>()
            .map_err(|_| TransportError::invalid_origin())?;
        if !path_and_query.starts_with('/') {
            return Err(TransportError::invalid_origin());
        }
        let base = self.url.path().trim_end_matches('/');
        let joined = format!("{base}{}", path.as_str());
        Uri::builder()
            .scheme(self.scheme.clone())
            .authority(self.authority.clone())
            .path_and_query(joined)
            .build()
            .map_err(|_| TransportError::invalid_origin())
    }

    fn accepts_connection_uri(&self, uri: &Uri) -> bool {
        uri.scheme() == Some(&self.scheme) && uri.authority() == Some(&self.authority)
    }
}

/// A validated physical address. Dynamic discovery additionally applies its
/// configured private/loopback/link-local policy before constructing this type.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct DialTarget(SocketAddr);

impl DialTarget {
    pub(crate) fn new(address: SocketAddr) -> Result<Self, TransportError> {
        let ip = match address.ip() {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
            ip => ip,
        };
        if address.port() == 0
            || ip.is_unspecified()
            || ip.is_multicast()
            || matches!(address, SocketAddr::V6(address) if address.scope_id() != 0)
        {
            return Err(TransportError::new(
                TransportPhase::Resolve,
                TransportErrorKind::AddressRejected,
                None,
            ));
        }
        Ok(Self(SocketAddr::new(ip, address.port())))
    }

    pub(crate) const fn address(self) -> SocketAddr {
        self.0
    }
}

/// Effective TLS verification/SNI name and opaque prepared security identity.
/// No certificate/private-key material or digest is exposed by Debug.
#[derive(Clone)]
pub(crate) struct TlsPeerIdentity {
    server_name: ServerName<'static>,
    policy_digest: ContentDigest,
}

impl TlsPeerIdentity {
    pub(crate) fn for_origin(
        origin: &LogicalOrigin,
        prepared: &PreparedUpstreamTls,
    ) -> Result<Self, TransportError> {
        let server_name = match prepared.server_name() {
            Some(name) => name,
            None => ServerName::try_from(origin.host().to_owned())
                .map_err(|_| TransportError::invalid_origin())?,
        };
        Ok(Self {
            server_name,
            policy_digest: prepared.digest(),
        })
    }
}

impl fmt::Debug for TlsPeerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsPeerIdentity")
            .field("server_name", &self.server_name)
            .field("policy", &"<prepared>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TransportTimeouts {
    pub connect: Duration,
    pub tls_handshake: Duration,
}

impl TransportTimeouts {
    pub(crate) fn for_cluster(cluster: &PreparedCluster) -> Self {
        cluster.spec().timeouts.as_ref().map_or_else(
            || Self {
                connect: cluster.spec().connect_timeout,
                tls_handshake: cluster
                    .spec()
                    .connect_timeout
                    .checked_add(cluster.spec().response_timeout)
                    .unwrap_or(cluster.spec().response_timeout),
            },
            |timeouts| Self {
                connect: timeouts.connect,
                tls_handshake: timeouts.tls_handshake,
            },
        )
    }
}

/// Internal key, not a public API or a metrics label. Stable length-prefixed
/// identity isolates one logical origin, endpoint, physical address, protocol,
/// TLS trust/client identity and immutable transport timeout policy.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct PoolIdentity(ContentDigest);

impl PoolIdentity {
    pub(crate) fn new(
        cluster: &ResourceId,
        endpoint: &str,
        origin: &LogicalOrigin,
        target: DialTarget,
        protocol: ClusterProtocol,
        tls: Option<&TlsPeerIdentity>,
        timeouts: TransportTimeouts,
    ) -> Self {
        let mut digest = ContentDigestBuilder::new("oxidase/upstream-pool/v1");
        digest
            .field_bytes("cluster", cluster.as_str().as_bytes())
            .field_bytes("endpoint", endpoint.as_bytes())
            .field_bytes("logical_origin", origin.url.as_str().as_bytes())
            .field_u64("port", u64::from(target.address().port()))
            .field_bytes("protocol", protocol_name(protocol).as_bytes())
            .field_u128("tcp_timeout_ns", timeouts.connect.as_nanos())
            .field_u128("tls_timeout_ns", timeouts.tls_handshake.as_nanos());
        match target.address().ip() {
            IpAddr::V4(ip) => {
                digest
                    .field_u64("family", 4)
                    .field_bytes("address", ip.octets());
            }
            IpAddr::V6(ip) => {
                digest
                    .field_u64("family", 6)
                    .field_bytes("address", ip.octets());
            }
        }
        digest.field_u64("tls", u64::from(tls.is_some()));
        if let Some(tls) = tls {
            digest
                .field_bytes("verification_name", tls.server_name.to_str().as_bytes())
                .field_digest("prepared_security_policy", tls.policy_digest);
        }
        Self(digest.finish())
    }
}

impl fmt::Debug for PoolIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PoolIdentity(<internal>)")
    }
}

const fn protocol_name(protocol: ClusterProtocol) -> &'static str {
    match protocol {
        ClusterProtocol::Auto => "auto",
        ClusterProtocol::Http1 => "http1",
        ClusterProtocol::H2 => "h2",
    }
}

#[derive(Clone)]
pub(crate) struct DirectConnector {
    origin: LogicalOrigin,
    target: DialTarget,
    protocol: ClusterProtocol,
    tls: Option<(TlsPeerIdentity, Arc<ClientConfig>)>,
    timeouts: TransportTimeouts,
    http1_upgrade_override: bool,
    warm: Arc<WarmTransport>,
    connect_admission: Option<Arc<tokio::sync::Semaphore>>,
}

impl DirectConnector {
    pub(crate) fn new(
        origin: LogicalOrigin,
        target: DialTarget,
        protocol: ClusterProtocol,
        tls: Option<&PreparedUpstreamTls>,
        timeouts: TransportTimeouts,
    ) -> Result<Self, TransportError> {
        let tls = tls
            .filter(|_| origin.is_tls())
            .map(|prepared| {
                Ok((
                    TlsPeerIdentity::for_origin(&origin, prepared)?,
                    prepared.client_config(),
                ))
            })
            .transpose()?;
        Self::from_parts(origin, target, protocol, tls, timeouts)
    }

    fn from_parts(
        origin: LogicalOrigin,
        target: DialTarget,
        protocol: ClusterProtocol,
        tls: Option<(TlsPeerIdentity, Arc<ClientConfig>)>,
        timeouts: TransportTimeouts,
    ) -> Result<Self, TransportError> {
        if origin.is_tls() != tls.is_some()
            || timeouts.connect.is_zero()
            || timeouts.tls_handshake.is_zero()
        {
            return Err(TransportError::invalid_origin());
        }
        let tls = tls.map(|(identity, config)| {
            let mut config = config.as_ref().clone();
            config.alpn_protocols = match protocol {
                ClusterProtocol::Auto => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
                ClusterProtocol::Http1 => vec![b"http/1.1".to_vec()],
                ClusterProtocol::H2 => vec![b"h2".to_vec()],
            };
            (identity, Arc::new(config))
        });
        Ok(Self {
            origin,
            target,
            protocol,
            tls,
            timeouts,
            http1_upgrade_override: false,
            warm: Arc::new(WarmTransport::default()),
            connect_admission: None,
        })
    }

    pub(crate) fn pool_identity(&self, cluster: &ResourceId, endpoint: &str) -> PoolIdentity {
        let base = PoolIdentity::new(
            cluster,
            endpoint,
            &self.origin,
            self.target,
            self.protocol,
            self.tls.as_ref().map(|(identity, _)| identity),
            self.timeouts,
        );
        let mut digest = ContentDigestBuilder::new("oxidase/upstream-pool-purpose/v1");
        digest.field_digest("transport", base.0).field_u64(
            "http1_upgrade_override",
            u64::from(self.http1_upgrade_override),
        );
        PoolIdentity(digest.finish())
    }

    pub(crate) fn for_http1_upgrade(mut self) -> Self {
        self.http1_upgrade_override = self.protocol == ClusterProtocol::Http1;
        self
    }

    pub(crate) fn with_connection_admission(
        mut self,
        admission: Arc<tokio::sync::Semaphore>,
    ) -> Self {
        self.connect_admission = Some(admission);
        self
    }

    /// Uses the cold address-selection budget for this one TCP attempt only.
    /// Restore the immutable transport policy before the resulting connector
    /// can be stored in a pool or used by a later shared reconnect.
    pub(crate) async fn preconnect_admitted_with_connect_timeout(
        mut self,
        permit: &tokio::sync::OwnedSemaphorePermit,
        connect_timeout: Duration,
    ) -> Result<Self, TransportError> {
        if !self
            .connect_admission
            .as_ref()
            .is_some_and(|admission| Arc::ptr_eq(admission, permit.semaphore()))
        {
            return Err(TransportError::new(
                TransportPhase::Connect,
                TransportErrorKind::ConnectionCapacity,
                None,
            ));
        }
        let admission = self.connect_admission.take();
        let configured_timeout = self.timeouts.connect;
        self.timeouts.connect = connect_timeout;
        self.preconnect().await.map(|mut connector| {
            connector.connect_admission = admission;
            connector.timeouts.connect = configured_timeout;
            connector
        })
    }

    /// Hands a winning preconnected socket to Hyper exactly once without
    /// changing its actual target, TLS identity or HTTP origin.
    pub(crate) async fn preconnect(mut self) -> Result<Self, TransportError> {
        let uri = self.origin.request_uri("/")?;
        let stream = self.call(uri).await?;
        *self
            .warm
            .stream
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(stream);
        let weak = Arc::downgrade(&self.warm);
        let task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(90)).await;
            if let Some(warm) = weak.upgrade() {
                warm.stream
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                warm.expiry
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
            }
        });
        *self
            .warm
            .expiry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(task.abort_handle());
        Ok(self)
    }

    pub(crate) fn compatible_with_cluster(
        &self,
        cluster: &PreparedCluster,
        endpoint: &str,
    ) -> bool {
        if (self.protocol != cluster.protocol() && !self.http1_upgrade_override)
            || !cluster
                .spec()
                .endpoints
                .iter()
                .any(|candidate| candidate.name == endpoint && candidate.url == self.origin.url)
            || self.timeouts != TransportTimeouts::for_cluster(cluster)
        {
            return false;
        }
        let expected_tls = cluster.upstream_tls().filter(|_| self.origin.is_tls());
        match (self.tls.as_ref(), expected_tls) {
            (None, None) => true,
            (Some((identity, _)), Some(prepared)) => {
                TlsPeerIdentity::for_origin(&self.origin, prepared).is_ok_and(|expected| {
                    expected.policy_digest == identity.policy_digest
                        && expected.server_name == identity.server_name
                })
            }
            _ => false,
        }
    }
}

type DirectStream = MaybeHttpsStream<TokioIo<TcpStream>>;

#[derive(Default)]
struct WarmTransport {
    stream: Mutex<Option<DirectStream>>,
    expiry: Mutex<Option<tokio::task::AbortHandle>>,
}

impl WarmTransport {
    fn take(&self) -> Option<DirectStream> {
        let stream = self
            .stream
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if stream.is_some()
            && let Some(task) = self
                .expiry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
        {
            task.abort();
        }
        stream
    }
}

impl Drop for WarmTransport {
    fn drop(&mut self) {
        if let Some(task) = self
            .expiry
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            task.abort();
        }
    }
}

impl Service<Uri> for DirectConnector {
    type Response = DirectStream;
    type Error = TransportError;
    type Future = Pin<Box<dyn Future<Output = Result<DirectStream, TransportError>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        if !self.origin.accepts_connection_uri(&uri) {
            return Box::pin(async { Err(TransportError::invalid_origin()) });
        }
        if let Some(stream) = self.warm.take() {
            return Box::pin(async move { Ok(stream) });
        }
        let connector = self.clone();
        Box::pin(async move {
            let _admission = connector
                .connect_admission
                .as_ref()
                .map(|admission| Arc::clone(admission).try_acquire_owned())
                .transpose()
                .map_err(|_| {
                    TransportError::new(
                        TransportPhase::Connect,
                        TransportErrorKind::ConnectionCapacity,
                        None,
                    )
                })?;
            // The overload accepts a SocketAddr, never a hostname. This is the
            // same immutable target carried by the endpoint lease and pool key.
            let connect_deadline =
                checked_transport_deadline(connector.timeouts.connect, TransportPhase::Connect)?;
            let socket = tokio::time::timeout_at(
                connect_deadline,
                TcpStream::connect(connector.target.address()),
            )
            .await
            .map_err(|_| TransportError::timeout(TransportPhase::Connect))?
            .map_err(|error| {
                TransportError::new(
                    TransportPhase::Connect,
                    TransportErrorKind::Io,
                    Some(Box::new(error)),
                )
            })?;
            socket.set_nodelay(true).map_err(|error| {
                TransportError::new(
                    TransportPhase::Connect,
                    TransportErrorKind::Io,
                    Some(Box::new(error)),
                )
            })?;
            let socket = TokioIo::new(socket);
            let Some((identity, config)) = connector.tls else {
                return Ok(MaybeHttpsStream::Http(socket));
            };
            let tls_deadline =
                checked_transport_deadline(connector.timeouts.tls_handshake, TransportPhase::Tls)?;
            let stream = tokio::time::timeout_at(
                tls_deadline,
                TlsConnector::from(config).connect(identity.server_name, TokioIo::new(socket)),
            )
            .await
            .map_err(|_| TransportError::timeout(TransportPhase::Tls))?
            .map_err(|error| {
                TransportError::new(
                    TransportPhase::Tls,
                    TransportErrorKind::Tls,
                    Some(Box::new(error)),
                )
            })?;
            if connector.protocol == ClusterProtocol::H2
                && stream.get_ref().1.alpn_protocol() != Some(b"h2")
            {
                return Err(TransportError::new(
                    TransportPhase::Tls,
                    TransportErrorKind::Alpn,
                    None,
                ));
            }
            Ok(MaybeHttpsStream::Https(TokioIo::new(stream)))
        })
    }
}

pub(crate) fn build_upstream_pool<B>(
    connector: DirectConnector,
    protocol: ClusterProtocol,
    max_idle: usize,
) -> Client<DirectConnector, B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    let mut builder = Client::builder(crate::upstream_timing::UpstreamExecutor);
    builder
        .pool_timer(TokioTimer::new())
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(max_idle)
        .http2_only(protocol == ClusterProtocol::H2)
        // Business retry is explicit, bounded and charged by the Proxy. An
        // unstarted reused request must not be transparently replayed here.
        .retry_canceled_requests(false);
    builder.build(connector)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransportPhase {
    Resolve,
    Connect,
    Tls,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransportErrorKind {
    InvalidOrigin,
    AddressRejected,
    AddressLimit,
    NoAddresses,
    Timeout,
    DeadlineOutOfRange,
    ResolutionCapacity,
    ConnectionCapacity,
    Io,
    Tls,
    Alpn,
}

#[derive(Debug, Clone)]
pub(crate) struct TransportError {
    phase: TransportPhase,
    kind: TransportErrorKind,
    source: Option<Arc<dyn std::error::Error + Send + Sync>>,
}

impl TransportError {
    pub(crate) fn new(
        phase: TransportPhase,
        kind: TransportErrorKind,
        source: Option<BoxError>,
    ) -> Self {
        Self {
            phase,
            kind,
            source: source.map(Arc::from),
        }
    }

    fn invalid_origin() -> Self {
        Self::new(
            TransportPhase::Connect,
            TransportErrorKind::InvalidOrigin,
            None,
        )
    }

    fn timeout(phase: TransportPhase) -> Self {
        Self::new(phase, TransportErrorKind::Timeout, None)
    }

    pub(crate) const fn phase(&self) -> TransportPhase {
        self.phase
    }

    pub(crate) const fn kind(&self) -> TransportErrorKind {
        self.kind
    }

    pub(crate) const fn is_timeout(&self) -> bool {
        matches!(self.kind, TransportErrorKind::Timeout)
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "upstream {:?} failed ({:?})",
            self.phase, self.kind
        )
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

fn checked_transport_deadline(
    timeout: Duration,
    phase: TransportPhase,
) -> Result<tokio::time::Instant, TransportError> {
    tokio::time::Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| TransportError::new(phase, TransportErrorKind::DeadlineOutOfRange, None))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use bytes::Bytes;
    use http::{Request, Response, header};
    use http_body_util::{BodyExt as _, Empty, Full};
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::client::legacy::connect::{Connection as _, HttpInfo};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer;
    use tokio_rustls::rustls::{RootCertStore, ServerConfig, crypto::ring::default_provider};

    use super::*;

    fn timeouts() -> TransportTimeouts {
        TransportTimeouts {
            connect: Duration::from_secs(1),
            tls_handshake: Duration::from_secs(1),
        }
    }

    fn origin(url: &str) -> LogicalOrigin {
        LogicalOrigin::from_url(&url.parse().expect("valid test URL")).expect("valid origin")
    }

    fn target(address: &str) -> DialTarget {
        DialTarget::new(address.parse().expect("valid test address")).expect("valid target")
    }

    #[test]
    fn preserves_logical_ipv6_authority_base_path_and_raw_query() {
        let origin = origin("https://[::1]:8443/base/");
        assert_eq!(origin.authority().as_str(), "[::1]:8443");
        assert_eq!(origin.host(), "::1");
        assert_eq!(
            origin
                .request_uri("//one?x=a%2f&x=2")
                .expect("valid raw target")
                .to_string(),
            "https://[::1]:8443/base//one?x=a%2f&x=2"
        );
        assert!(origin.request_uri("https://other.invalid/").is_err());
        assert!(
            LogicalOrigin::from_url(&"https://user:secret@origin.invalid/".parse().expect("URL"))
                .is_err()
        );
    }

    #[test]
    fn mapped_addresses_normalize_and_invalid_physical_targets_fail() {
        assert_eq!(target("[::ffff:127.0.0.1]:8000"), target("127.0.0.1:8000"));
        for address in [
            "0.0.0.0:80",
            "[::]:80",
            "224.0.0.1:80",
            "[ff02::1]:80",
            "127.0.0.1:0",
            "[fe80::1%2]:80",
            "[::ffff:0.0.0.0]:80",
            "[::ffff:224.0.0.1]:80",
        ] {
            assert!(
                DialTarget::new(address.parse().expect("test SocketAddr")).is_err(),
                "{address}"
            );
        }
    }

    #[test]
    fn every_origin_dial_protocol_and_security_boundary_has_a_distinct_pool() {
        let cluster = ResourceId::new("cluster:test");
        let origin_a = origin("https://a.invalid/base");
        let origin_b = origin("https://b.invalid/base");
        let base_changed = origin("https://a.invalid/other");
        let target_a = target("127.0.0.1:8000");
        let target_b = target("127.0.0.1:8001");
        let tls_a = TlsPeerIdentity {
            server_name: ServerName::try_from("peer-a.invalid".to_owned()).expect("DNS name"),
            policy_digest: ContentDigest::of_bytes("trust/client a"),
        };
        let tls_b = TlsPeerIdentity {
            server_name: tls_a.server_name.clone(),
            policy_digest: ContentDigest::of_bytes("trust/client b"),
        };
        let tls_name = TlsPeerIdentity {
            server_name: ServerName::try_from("peer-b.invalid".to_owned()).expect("DNS name"),
            policy_digest: tls_a.policy_digest,
        };
        let baseline = PoolIdentity::new(
            &cluster,
            "endpoint-a",
            &origin_a,
            target_a,
            ClusterProtocol::H2,
            Some(&tls_a),
            timeouts(),
        );
        let keys = [
            PoolIdentity::new(
                &cluster,
                "endpoint-b",
                &origin_a,
                target_a,
                ClusterProtocol::H2,
                Some(&tls_a),
                timeouts(),
            ),
            PoolIdentity::new(
                &cluster,
                "endpoint-a",
                &origin_b,
                target_a,
                ClusterProtocol::H2,
                Some(&tls_a),
                timeouts(),
            ),
            PoolIdentity::new(
                &cluster,
                "endpoint-a",
                &base_changed,
                target_a,
                ClusterProtocol::H2,
                Some(&tls_a),
                timeouts(),
            ),
            PoolIdentity::new(
                &cluster,
                "endpoint-a",
                &origin_a,
                target_b,
                ClusterProtocol::H2,
                Some(&tls_a),
                timeouts(),
            ),
            PoolIdentity::new(
                &cluster,
                "endpoint-a",
                &origin_a,
                target_a,
                ClusterProtocol::Http1,
                Some(&tls_a),
                timeouts(),
            ),
            PoolIdentity::new(
                &cluster,
                "endpoint-a",
                &origin_a,
                target_a,
                ClusterProtocol::H2,
                Some(&tls_b),
                timeouts(),
            ),
            PoolIdentity::new(
                &cluster,
                "endpoint-a",
                &origin_a,
                target_a,
                ClusterProtocol::H2,
                Some(&tls_name),
                timeouts(),
            ),
        ];
        assert!(keys.iter().all(|key| key != &baseline));
        assert_eq!(
            baseline,
            PoolIdentity::new(
                &cluster,
                "endpoint-a",
                &origin_a,
                target_a,
                ClusterProtocol::H2,
                Some(&tls_a),
                timeouts()
            )
        );
        assert!(!format!("{tls_a:?} {baseline:?}").contains(&tls_a.policy_digest.to_string()));
        // Field boundaries cannot merge endpoint/resource names ambiguously.
        assert_ne!(
            PoolIdentity::new(
                &ResourceId::new("ab"),
                "c",
                &origin_a,
                target_a,
                ClusterProtocol::H2,
                Some(&tls_a),
                timeouts()
            ),
            PoolIdentity::new(
                &ResourceId::new("a"),
                "bc",
                &origin_a,
                target_a,
                ClusterProtocol::H2,
                Some(&tls_a),
                timeouts()
            ),
        );
    }

    #[tokio::test]
    async fn fixed_dial_target_never_resolves_the_logical_name_again() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("fixture address");
        let count = Arc::new(AtomicU64::new(0));
        let task_count = Arc::clone(&count);
        let (observed, mut observations) = mpsc::channel(4);
        let fixture = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("direct physical connect");
            task_count.fetch_add(1, Ordering::Relaxed);
            http1::Builder::new()
                .serve_connection(
                    TokioIo::new(socket),
                    service_fn(move |request: Request<hyper::body::Incoming>| {
                        let observed = observed.clone();
                        async move {
                            observed
                                .send((
                                    request.headers()[header::HOST]
                                        .to_str()
                                        .expect("Host")
                                        .to_owned(),
                                    request.uri().to_string(),
                                ))
                                .await
                                .expect("observer active");
                            Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                                Bytes::from_static(b"ok"),
                            )))
                        }
                    }),
                )
                .await
                .expect("HTTP fixture connection");
        });
        // `.invalid` cannot be resolved by normal DNS. Success therefore proves
        // the actual socket uses the selected target, not the logical hostname.
        let logical = origin("http://not-resolvable.oxidase.invalid/base/");
        let connector = DirectConnector::new(
            logical.clone(),
            DialTarget::new(address).expect("target"),
            ClusterProtocol::Http1,
            None,
            timeouts(),
        )
        .expect("connector");
        let pool = build_upstream_pool::<Empty<Bytes>>(connector, ClusterProtocol::Http1, 2);
        for path in ["/one?x=a%2f&x=2", "/two"] {
            let response = pool
                .request(
                    Request::builder()
                        .uri(logical.request_uri(path).expect("URI"))
                        .body(Empty::new())
                        .expect("request"),
                )
                .await
                .expect("direct request");
            assert_eq!(
                response
                    .extensions()
                    .get::<HttpInfo>()
                    .expect("actual peer metadata")
                    .remote_addr(),
                address
            );
            response
                .into_body()
                .collect()
                .await
                .expect("small response");
        }
        assert_eq!(
            observations.recv().await.expect("first observation"),
            (
                "not-resolvable.oxidase.invalid".to_owned(),
                "/base/one?x=a%2f&x=2".to_owned()
            )
        );
        assert_eq!(
            observations.recv().await.expect("second observation").1,
            "/base/two"
        );
        assert_eq!(
            count.load(Ordering::Relaxed),
            1,
            "one long-lived pool reuses the socket"
        );
        drop(pool);
        fixture.abort();
        let _ = fixture.await;
    }

    fn tls_fixture(name: &str, alpn: &[&[u8]]) -> (Arc<ServerConfig>, Arc<ClientConfig>) {
        // Publicly generated test-only material, never a production identity.
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec![name.to_owned()]).expect("test identity");
        let provider = Arc::new(default_provider());
        let mut server = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .expect("safe TLS versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
            )
            .expect("test certificate/key");
        server.alpn_protocols = alpn.iter().map(|value| value.to_vec()).collect();
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).expect("test root");
        let client = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("safe TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        (Arc::new(server), Arc::new(client))
    }

    fn tls_connector(
        origin: LogicalOrigin,
        target: DialTarget,
        protocol: ClusterProtocol,
        config: Arc<ClientConfig>,
        timeout: Duration,
    ) -> DirectConnector {
        let identity = TlsPeerIdentity {
            server_name: ServerName::try_from(origin.host().to_owned()).expect("test TLS name"),
            policy_digest: ContentDigest::of_bytes("test-only prepared TLS policy"),
        };
        DirectConnector::from_parts(
            origin,
            target,
            protocol,
            Some((identity, config)),
            TransportTimeouts {
                connect: Duration::from_secs(1),
                tls_handshake: timeout,
            },
        )
        .expect("TLS connector")
    }

    #[tokio::test]
    async fn tls_uses_fixed_logical_sni_and_proves_h2_alpn_and_actual_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("loopback");
        let address = listener.local_addr().expect("fixture address");
        let (server, client) = tls_fixture("logical.oxidase.invalid", &[b"h2"]);
        let fixture = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("direct socket");
            let stream = TlsAcceptor::from(server)
                .accept(socket)
                .await
                .expect("verified TLS handshake");
            assert_eq!(
                stream.get_ref().1.server_name(),
                Some("logical.oxidase.invalid")
            );
            assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        });
        let logical = origin("https://logical.oxidase.invalid/");
        let mut connector = tls_connector(
            logical.clone(),
            DialTarget::new(address).expect("target"),
            ClusterProtocol::H2,
            client,
            Duration::from_secs(1),
        );
        let stream = connector
            .call(logical.request_uri("/").expect("URI"))
            .await
            .expect("real TLS without DNS");
        let connected = stream.connected();
        assert!(connected.is_negotiated_h2());
        let mut extras = http::Extensions::new();
        connected.get_extras(&mut extras);
        assert_eq!(
            extras
                .get::<HttpInfo>()
                .expect("actual connected address")
                .remote_addr(),
            address
        );
        fixture.await.expect("fixture finished");
    }

    #[tokio::test]
    async fn h2_requires_tls_alpn_and_certificate_verification_is_not_bypassed() {
        for (certificate_name, expected) in [
            ("logical.oxidase.invalid", TransportErrorKind::Alpn),
            ("wrong.oxidase.invalid", TransportErrorKind::Tls),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("loopback");
            let address = listener.local_addr().expect("fixture address");
            let (server, client) = tls_fixture(certificate_name, &[]);
            let fixture = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.expect("direct socket");
                let _ = TlsAcceptor::from(server).accept(socket).await;
            });
            let logical = origin("https://logical.oxidase.invalid/");
            let mut connector = tls_connector(
                logical.clone(),
                DialTarget::new(address).expect("target"),
                ClusterProtocol::H2,
                client,
                Duration::from_secs(1),
            );
            let error = connector
                .call(logical.request_uri("/").expect("URI"))
                .await
                .expect_err("required TLS identity/ALPN");
            assert_eq!(error.phase(), TransportPhase::Tls);
            assert_eq!(error.kind(), expected);
            fixture.await.expect("fixture finished");
        }
    }

    #[tokio::test]
    async fn tls_handshake_has_its_own_timeout_after_successful_tcp_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("loopback");
        let address = listener.local_addr().expect("fixture address");
        let (_server, client) = tls_fixture("logical.oxidase.invalid", &[b"h2"]);
        let fixture = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.expect("TCP connected");
            std::future::pending::<()>().await;
        });
        let logical = origin("https://logical.oxidase.invalid/");
        let mut connector = tls_connector(
            logical.clone(),
            DialTarget::new(address).expect("target"),
            ClusterProtocol::H2,
            client,
            Duration::from_millis(20),
        );
        let error = connector
            .call(logical.request_uri("/").expect("URI"))
            .await
            .expect_err("silent TLS peer");
        assert_eq!(error.phase(), TransportPhase::Tls);
        assert!(error.is_timeout());
        fixture.abort();
        let _ = fixture.await;
    }

    #[tokio::test]
    async fn connector_rejects_another_origin_before_any_network_operation() {
        let mut connector = DirectConnector::new(
            origin("http://logical.oxidase.invalid/"),
            target("127.0.0.1:9"),
            ClusterProtocol::Http1,
            None,
            timeouts(),
        )
        .expect("connector");
        let error = connector
            .call("http://another.oxidase.invalid/".parse().expect("URI"))
            .await
            .expect_err("foreign origin");
        assert_eq!(error.kind(), TransportErrorKind::InvalidOrigin);
        assert!(std::error::Error::source(&error).is_none());
    }

    #[tokio::test]
    async fn unrepresentable_legacy_transport_duration_returns_a_typed_error_without_panicking() {
        let logical = origin("http://logical.oxidase.invalid/");
        let mut connector = DirectConnector::new(
            logical.clone(),
            target("127.0.0.1:9"),
            ClusterProtocol::Http1,
            None,
            TransportTimeouts {
                connect: Duration::MAX,
                tls_handshake: Duration::from_secs(1),
            },
        )
        .expect("opaque legacy policy");
        let error = connector
            .call(logical.request_uri("/").expect("URI"))
            .await
            .expect_err("unrepresentable TCP deadline");
        assert_eq!(error.phase(), TransportPhase::Connect);
        assert_eq!(error.kind(), TransportErrorKind::DeadlineOutOfRange);
    }

    #[tokio::test]
    async fn preadmitted_single_slot_is_not_charged_twice_and_reconnect_is_still_guarded() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("loopback");
        let address = listener.local_addr().expect("address");
        let quota = Arc::new(tokio::sync::Semaphore::new(1));
        let admitted = Arc::clone(&quota)
            .acquire_owned()
            .await
            .expect("one physical connect slot");
        let logical = origin("http://logical.oxidase.invalid/");
        let connector = DirectConnector::new(
            logical.clone(),
            DialTarget::new(address).expect("target"),
            ClusterProtocol::Http1,
            None,
            timeouts(),
        )
        .expect("connector")
        .with_connection_admission(Arc::clone(&quota));
        let original_identity = connector.pool_identity(&ResourceId::new("fixture"), "endpoint");
        let mut connector = connector
            .preconnect_admitted_with_connect_timeout(&admitted, Duration::from_millis(200))
            .await
            .expect("cold connect cannot self-saturate slot1");
        assert_eq!(
            connector.pool_identity(&ResourceId::new("fixture"), "endpoint"),
            original_identity,
            "remaining cold TCP budget must not enter pool identity or later reconnect policy"
        );
        assert_eq!(quota.available_permits(), 0);
        let warm = connector
            .call(logical.request_uri("/").expect("URI"))
            .await
            .expect("winning warm socket needs no second connect permit");
        let first = listener.accept().await.expect("warm peer");
        drop(warm);
        drop(first);
        let error = connector
            .call(logical.request_uri("/").expect("URI"))
            .await
            .expect_err("actual reconnect still requires the held slot");
        assert_eq!(error.kind(), TransportErrorKind::ConnectionCapacity);
        drop(admitted);
        let next = connector
            .call(logical.request_uri("/").expect("URI"))
            .await
            .expect("reconnect can use the single released slot");
        assert_eq!(quota.available_permits(), 1);
        let second = listener.accept().await.expect("reconnect peer");
        drop(next);
        drop(second);
    }
}
