use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as _;
use std::str::FromStr;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use bytes::Bytes;
use futures_util::TryStreamExt;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri, Version, header};
use http_body::{Body as _, Frame};
use http_body_util::{BodyExt, StreamBody};
use hyper_rustls::{FixedServerNameResolver, HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use oxidase_config::{ClusterProtocol, RetryBodyMode, RetryCause, RetrySpec};
use oxidase_core::{
    ContentDigest, ErrorClass, RequestFrame, ResourceId, ResponseHead, ServiceError, ServiceOutcome,
};
use oxidase_runtime::{
    BoxLeafFuture, ClusterAdmissionError, ClusterRetryPermit, ConcurrencyPermit,
    GovernanceRegistry, LeafExecutor, PreparedCluster, RuntimeSnapshot,
};
use oxidase_site::{
    AssetPlan, AssetRepresentation, EntityTag, PreparedSiteBody, PreparedSiteResponse, SiteError,
};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;

use crate::body::{
    BodyIdleDirection, BodyIdleTimeout, BoxError, GatewayBodyPlan, GatewayRequestBody,
    timeout_upstream_response_body,
};
use crate::metrics::Metrics;
use crate::protocol::{
    RequestTrailerGuard, TrailerGuard, TrailerValidationError, WireProtocol,
    http1_accepts_trailers, sanitize_runtime_headers,
};
use crate::proxy_body::{
    BufferRequestError, ClusterResponseBody, DownstreamRequestBodyError, ProxyRequestBody,
    ReplayBody, RequestBodyLimitExceeded, buffer_for_replay,
};
use crate::upgrade::GatewayRequestPayload;

pub(crate) struct HyperLeaves {
    snapshot: Arc<RuntimeSnapshot>,
    proxy: Arc<ProxyClient>,
    metrics: Arc<Metrics>,
}

impl HyperLeaves {
    pub(crate) fn new(
        snapshot: Arc<RuntimeSnapshot>,
        proxy: Arc<ProxyClient>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            snapshot,
            proxy,
            metrics,
        }
    }
}

pub(crate) struct ProxyClient {
    default_tls_config: Arc<tokio_rustls::rustls::ClientConfig>,
    pool_registry: Mutex<ProxyPoolRegistry>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ProxyPoolKey {
    connect_timeout: Duration,
    tls_digest: Option<ContentDigest>,
}

#[derive(Default)]
struct ProxyPoolRegistry {
    active: BTreeMap<ProxyPoolKey, Arc<ProxyPools>>,
    cached: BTreeMap<ProxyPoolKey, Weak<ProxyPools>>,
}

struct ProxyPools {
    auto: ProxyPool,
    http1: ProxyPool,
    h2: ProxyPool,
}

type ProxyPool = Client<HttpsConnector<HttpConnector>, ProxyRequestBody>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProxyPoolKind {
    Auto,
    Http1,
    H2,
}

enum AttemptBody {
    Streaming(Option<GatewayRequestBody>),
    Empty,
    Replay(ReplayBody),
}

impl AttemptBody {
    fn next(
        &mut self,
        trailer_guard: &RequestTrailerGuard,
        max_request_body_bytes: Option<u64>,
    ) -> Option<ProxyRequestBody> {
        match self {
            Self::Streaming(body) => body.take().map(|body| {
                ProxyRequestBody::streaming(body, trailer_guard.clone(), max_request_body_bytes)
            }),
            Self::Empty => Some(ProxyRequestBody::empty()),
            Self::Replay(body) => Some(body.new_attempt()),
        }
    }

    const fn replayable(&self) -> bool {
        matches!(self, Self::Empty | Self::Replay(_))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttemptFailure {
    Connect,
    HeaderTimeout,
    RefusedStream,
    Reset,
    Protocol,
}

impl AttemptFailure {
    const fn retry_cause(self) -> Option<RetryCause> {
        match self {
            Self::Connect => Some(RetryCause::ConnectFailure),
            Self::HeaderTimeout => Some(RetryCause::ResponseHeaderTimeout),
            Self::RefusedStream => Some(RetryCause::RefusedStream),
            Self::Reset => Some(RetryCause::Reset),
            Self::Protocol => None,
        }
    }

    const fn error_class(self) -> ErrorClass {
        match self {
            Self::Connect => ErrorClass::UpstreamConnect,
            Self::HeaderTimeout => ErrorClass::Timeout,
            Self::RefusedStream | Self::Reset | Self::Protocol => ErrorClass::UpstreamProtocol,
        }
    }
}

impl ProxyPoolKind {
    const fn for_cluster(protocol: ClusterProtocol) -> Self {
        match protocol {
            ClusterProtocol::Auto => Self::Auto,
            ClusterProtocol::Http1 => Self::Http1,
            ClusterProtocol::H2 => Self::H2,
        }
    }

    const fn request_wire_protocol(self) -> WireProtocol {
        match self {
            // `auto` negotiates HTTPS with ALPN, so the exact wire protocol is
            // not known before the request is dispatched. Conservatively use
            // HTTP/1 rules; this removes TE/trailer metadata rather than
            // accidentally forwarding an HTTP/1 hop-by-hop field over H2.
            Self::Auto | Self::Http1 => WireProtocol::Http1,
            Self::H2 => WireProtocol::Http2,
        }
    }
}

fn cleartext_connector_tls_config() -> Result<tokio_rustls::rustls::ClientConfig, String> {
    use tokio_rustls::rustls::RootCertStore;
    use tokio_rustls::rustls::crypto::ring::default_provider;

    // This connector configuration is used only for clusters whose prepared
    // endpoint set is entirely cleartext HTTP. Every HTTPS cluster carries a
    // `PreparedUpstreamTls` built from its explicit/default trust policy. An
    // empty root set therefore avoids reading host trust merely to serve an
    // HTTP-only configuration without weakening any TLS request.
    let roots = RootCertStore::empty();
    tokio_rustls::rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("cannot enable safe upstream TLS versions: {error}"))
        .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
}

impl ProxyClient {
    pub(crate) fn new() -> Result<Self, String> {
        let default_tls_config = Arc::new(cleartext_connector_tls_config()?);
        Ok(Self {
            default_tls_config,
            pool_registry: Mutex::new(ProxyPoolRegistry::default()),
        })
    }

    pub(crate) fn reconcile_snapshot(&self, snapshot: &RuntimeSnapshot) {
        let active = snapshot
            .resources
            .clusters
            .values()
            .map(|cluster| (Self::pool_key(cluster), Arc::clone(cluster)))
            .collect::<BTreeMap<_, _>>();
        let mut registry = self
            .pool_registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry.active.retain(|key, _| active.contains_key(key));
        for (key, cluster) in active {
            if registry.active.contains_key(&key) {
                continue;
            }
            let pools = registry
                .cached
                .get(&key)
                .and_then(Weak::upgrade)
                .unwrap_or_else(|| self.build_pools(&cluster));
            registry.cached.insert(key, Arc::downgrade(&pools));
            registry.active.insert(key, pools);
        }
        let active_keys = registry.active.keys().copied().collect::<BTreeSet<_>>();
        registry
            .cached
            .retain(|key, pools| active_keys.contains(key) || pools.strong_count() > 0);
    }

    fn pools(&self, cluster: &Arc<PreparedCluster>) -> Arc<ProxyPools> {
        let key = Self::pool_key(cluster);
        let mut registry = self
            .pool_registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(pools) = registry.active.get(&key) {
            return Arc::clone(pools);
        }
        if let Some(pools) = registry.cached.get(&key).and_then(Weak::upgrade) {
            return pools;
        }
        // A request pinned to a retired snapshot can first reach Proxy after a
        // reload. Keep only a weak cache entry so that old transport policy is
        // released with the pinned request rather than retained indefinitely.
        let pools = self.build_pools(cluster);
        registry.cached.insert(key, Arc::downgrade(&pools));
        pools
    }

    fn pool_key(cluster: &PreparedCluster) -> ProxyPoolKey {
        ProxyPoolKey {
            connect_timeout: cluster.spec().connect_timeout,
            tls_digest: cluster.upstream_tls().map(|tls| tls.digest()),
        }
    }

    fn build_pools(&self, cluster: &PreparedCluster) -> Arc<ProxyPools> {
        let (tls_config, server_name) = cluster.upstream_tls().map_or_else(
            || (Arc::clone(&self.default_tls_config), None),
            |tls| (tls.client_config(), tls.server_name()),
        );
        Arc::new(ProxyPools::new(
            cluster.spec().connect_timeout,
            tls_config.as_ref(),
            server_name,
        ))
    }
}

impl ProxyPools {
    fn new(
        connect_timeout: Duration,
        tls_config: &tokio_rustls::rustls::ClientConfig,
        server_name: Option<tokio_rustls::rustls::pki_types::ServerName<'static>>,
    ) -> Self {
        let mut auto_http = HttpConnector::new();
        auto_http.enforce_http(false);
        auto_http.set_connect_timeout(Some(connect_timeout));
        let auto_builder = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config.clone())
            .https_or_http();
        let auto_builder = if let Some(server_name) = server_name.clone() {
            auto_builder.with_server_name_resolver(FixedServerNameResolver::new(server_name))
        } else {
            auto_builder
        };
        let auto_connector = auto_builder
            .enable_http1()
            .enable_http2()
            .wrap_connector(auto_http);
        let mut http1_http = HttpConnector::new();
        http1_http.enforce_http(false);
        http1_http.set_connect_timeout(Some(connect_timeout));
        let http1_builder = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config.clone())
            .https_or_http();
        let http1_builder = if let Some(server_name) = server_name.clone() {
            http1_builder.with_server_name_resolver(FixedServerNameResolver::new(server_name))
        } else {
            http1_builder
        };
        let http1_connector = http1_builder.enable_http1().wrap_connector(http1_http);
        let mut h2_http = HttpConnector::new();
        h2_http.enforce_http(false);
        h2_http.set_connect_timeout(Some(connect_timeout));
        let h2_builder = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config.clone())
            .https_or_http();
        let h2_builder = if let Some(server_name) = server_name {
            h2_builder.with_server_name_resolver(FixedServerNameResolver::new(server_name))
        } else {
            h2_builder
        };
        let h2_connector = h2_builder.enable_http2().wrap_connector(h2_http);
        Self {
            auto: build_proxy_pool(auto_connector, false),
            http1: build_proxy_pool(http1_connector, false),
            h2: build_proxy_pool(h2_connector, true),
        }
    }

    fn pool(&self, kind: ProxyPoolKind) -> &ProxyPool {
        match kind {
            ProxyPoolKind::Auto => &self.auto,
            ProxyPoolKind::Http1 => &self.http1,
            ProxyPoolKind::H2 => &self.h2,
        }
    }
}

impl ProxyClient {
    async fn execute(
        &self,
        cluster_id: &ResourceId,
        request: &RequestFrame,
        body: &mut Option<GatewayRequestPayload>,
        snapshot: &Arc<RuntimeSnapshot>,
        max_request_body_bytes: Option<u64>,
    ) -> ServiceOutcome<GatewayBodyPlan> {
        let Some(cluster) = snapshot.resources.clusters.get(cluster_id).cloned() else {
            return ServiceOutcome::Failed(ServiceError::new(
                ErrorClass::InvalidState,
                format!("prepared cluster `{cluster_id}` is missing"),
            ));
        };
        if body.is_none() {
            return ServiceOutcome::Failed(ServiceError::new(
                ErrorClass::BodyUnavailable,
                "Proxy request body is unavailable",
            ));
        }
        let mut permit = match cluster.acquire().await {
            Ok(permit) => permit,
            Err(error) => {
                cluster.record_admission_failure(error);
                return admission_failure(&cluster, error);
            }
        };
        let configured_pool = ProxyPoolKind::for_cluster(cluster.protocol());
        let pools = self.pools(&cluster);
        let Some(payload) = body.take() else {
            return ServiceOutcome::Failed(ServiceError::new(
                ErrorClass::BodyUnavailable,
                "Proxy request body is unavailable",
            ));
        };
        let (incoming, mut pending_upgrade, request_trailer_guard) = payload.into_parts();
        let retry = &cluster.spec().retry;
        let retry_method = pending_upgrade.is_none()
            && retry.max_attempts > 1
            && retry
                .methods
                .iter()
                .any(|method| method == request.method());
        let incoming_is_empty = incoming.is_end_stream();
        let request_trailer_guard = request_trailer_guard.for_upstream(
            if pending_upgrade.is_some() {
                ProxyPoolKind::Http1
            } else {
                configured_pool
            }
            .request_wire_protocol(),
        );
        let mut attempt_body = if retry_method && incoming_is_empty {
            AttemptBody::Empty
        } else if retry_method && retry.request_body.mode == RetryBodyMode::Buffer {
            let replay_limit = max_request_body_bytes
                .map_or(retry.request_body.max_bytes, |limit| {
                    limit.min(retry.request_body.max_bytes)
                });
            match buffer_for_replay(incoming, replay_limit, &request_trailer_guard).await {
                Ok(body) => AttemptBody::Replay(body),
                Err(BufferRequestError::LimitExceeded) => {
                    return ServiceOutcome::Handled(ResponseHead::new(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        GatewayBodyPlan::Bytes(Bytes::from_static(b"Payload Too Large")),
                    ));
                }
                Err(error) => {
                    if error_chain_contains_request_body_idle_timeout(&error) {
                        return ServiceOutcome::Handled(ResponseHead::new(
                            StatusCode::REQUEST_TIMEOUT,
                            GatewayBodyPlan::Bytes(Bytes::from_static(b"Request Timeout")),
                        ));
                    }
                    if error_chain_contains_request_validation(&error) {
                        return ServiceOutcome::Handled(ResponseHead::new(
                            StatusCode::BAD_REQUEST,
                            GatewayBodyPlan::Bytes(Bytes::from_static(b"Bad Request")),
                        ));
                    }
                    return ServiceOutcome::Failed(ServiceError::new(
                        ErrorClass::BodyUnavailable,
                        format!("request body cannot be replayed safely: {error}"),
                    ));
                }
            }
        } else {
            AttemptBody::Streaming(Some(incoming))
        };
        let timeout = cluster
            .spec()
            .connect_timeout
            .checked_add(cluster.spec().response_timeout)
            .unwrap_or(cluster.spec().response_timeout);
        let max_attempts = if retry_method && attempt_body.replayable() {
            retry.max_attempts
        } else {
            1
        };
        let mut attempt = 0_u32;
        let mut tried = BTreeSet::new();
        let mut retry_permit: Option<ClusterRetryPermit> = None;

        loop {
            attempt = attempt.saturating_add(1);
            let endpoint = Arc::clone(permit.endpoint());
            let uri = match upstream_uri(endpoint.url(), request.path_and_query()) {
                Ok(uri) => uri,
                Err(error) => return ServiceOutcome::Failed(error),
            };
            // Upgrade is an HTTP/1 connection capability even when the
            // Cluster's ordinary traffic policy is auto or H2.
            let pool_kind = if pending_upgrade.is_some() {
                ProxyPoolKind::Http1
            } else {
                configured_pool
            };
            let Some(request_body) =
                attempt_body.next(&request_trailer_guard, max_request_body_bytes)
            else {
                return ServiceOutcome::Failed(ServiceError::new(
                    ErrorClass::BodyUnavailable,
                    "Proxy request body is not replayable for another attempt",
                ));
            };
            let mut upstream = Request::new(request_body);
            *upstream.method_mut() = request.method().clone();
            *upstream.uri_mut() = uri;
            *upstream.headers_mut() = request.effective_headers().clone();
            if sanitize_runtime_headers(upstream.headers_mut(), pool_kind.request_wire_protocol())
                .is_err()
            {
                return ServiceOutcome::Failed(ServiceError::new(
                    ErrorClass::InvalidState,
                    "request contains invalid connection-specific metadata",
                ));
            }
            if let Some(declaration) = request_trailer_guard.forwarded_declaration() {
                upstream.headers_mut().insert(header::TRAILER, declaration);
            }
            if let Some(upgrade) = &pending_upgrade {
                upstream
                    .headers_mut()
                    .insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
                upstream
                    .headers_mut()
                    .insert(header::UPGRADE, upgrade.protocol_header_value());
            }
            apply_forwarding_headers(upstream.headers_mut(), request, endpoint.url());

            let response =
                tokio::time::timeout(timeout, pools.pool(pool_kind).request(upstream)).await;
            retry_permit.take();
            let mut response = match response {
                Ok(Ok(response)) => response,
                Ok(Err(error)) => {
                    if error_chain_contains_request_body_limit(&error) {
                        return ServiceOutcome::Handled(ResponseHead::new(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            GatewayBodyPlan::Bytes(Bytes::from_static(b"Payload Too Large")),
                        ));
                    }
                    if error_chain_contains_request_body_idle_timeout(&error) {
                        return ServiceOutcome::Handled(ResponseHead::new(
                            StatusCode::REQUEST_TIMEOUT,
                            GatewayBodyPlan::Bytes(Bytes::from_static(b"Request Timeout")),
                        ));
                    }
                    if error_chain_contains_request_validation(&error) {
                        return ServiceOutcome::Handled(ResponseHead::new(
                            StatusCode::BAD_REQUEST,
                            GatewayBodyPlan::Bytes(Bytes::from_static(b"Bad Request")),
                        ));
                    }
                    let failure = classify_proxy_error(&error);
                    cluster.record_passive_failure(endpoint.name(), std::time::Instant::now());
                    let detail =
                        format!("upstream request to `{}` failed: {error}", endpoint.name());
                    if retry_allows_failure(retry, failure) {
                        if attempt < max_attempts
                            && let Some(storm_permit) = cluster.try_acquire_retry()
                        {
                            tried.insert(endpoint.name().to_owned());
                            drop(permit);
                            match cluster.acquire_excluding(&tried).await {
                                Ok(next) => {
                                    permit = next;
                                    retry_permit = Some(storm_permit);
                                    cluster.record_retry_attempt();
                                    continue;
                                }
                                Err(_) => drop(storm_permit),
                            }
                        }
                        cluster.record_retry_exhausted();
                    }
                    return ServiceOutcome::Failed(ServiceError::new(
                        failure.error_class(),
                        detail,
                    ));
                }
                Err(_) => {
                    let failure = AttemptFailure::HeaderTimeout;
                    cluster.record_passive_failure(endpoint.name(), std::time::Instant::now());
                    let detail = format!(
                        "upstream `{}` did not produce response headers in {timeout:?}",
                        endpoint.name()
                    );
                    if retry_allows_failure(retry, failure) {
                        if attempt < max_attempts
                            && let Some(storm_permit) = cluster.try_acquire_retry()
                        {
                            tried.insert(endpoint.name().to_owned());
                            drop(permit);
                            match cluster.acquire_excluding(&tried).await {
                                Ok(next) => {
                                    permit = next;
                                    retry_permit = Some(storm_permit);
                                    cluster.record_retry_attempt();
                                    continue;
                                }
                                Err(_) => drop(storm_permit),
                            }
                        }
                        cluster.record_retry_exhausted();
                    }
                    return ServiceOutcome::Failed(ServiceError::new(
                        failure.error_class(),
                        detail,
                    ));
                }
            };

            if retry_allows_status(retry, response.status()) {
                if attempt < max_attempts
                    && let Some(storm_permit) = cluster.try_acquire_retry()
                {
                    let previous_endpoint = endpoint.name().to_owned();
                    tried.insert(previous_endpoint.clone());
                    if cluster.retarget_excluding(&mut permit, &tried).await {
                        if response.status().is_server_error() {
                            cluster.record_passive_failure(
                                &previous_endpoint,
                                std::time::Instant::now(),
                            );
                        }
                        drop(response);
                        retry_permit = Some(storm_permit);
                        cluster.record_retry_attempt();
                        continue;
                    }
                    drop(storm_permit);
                }
                cluster.record_retry_exhausted();
            }

            if let Some(pending_upgrade) = pending_upgrade.take() {
                if response.status() == StatusCode::SWITCHING_PROTOCOLS {
                    let upstream_upgrade = hyper::upgrade::on(&mut response);
                    let plan = match pending_upgrade
                        .bind(snapshot.clone())
                        .accept(&response, upstream_upgrade)
                    {
                        Ok(plan) => plan,
                        Err(error) => {
                            cluster
                                .record_passive_failure(endpoint.name(), std::time::Instant::now());
                            return ServiceOutcome::Failed(ServiceError::new(
                                ErrorClass::UpstreamProtocol,
                                format!("upstream Upgrade handshake is invalid: {error}"),
                            ));
                        }
                    };
                    let (mut parts, _body) = response.into_parts();
                    if sanitize_runtime_headers(&mut parts.headers, WireProtocol::Http1).is_err() {
                        cluster.record_passive_failure(endpoint.name(), std::time::Instant::now());
                        return ServiceOutcome::Failed(ServiceError::new(
                            ErrorClass::UpstreamProtocol,
                            "upstream Upgrade response has invalid connection metadata",
                        ));
                    }
                    cluster.record_passive_success(endpoint.name());
                    let plan = plan.retain_cluster_permit(Arc::clone(&cluster), permit);
                    return ServiceOutcome::Handled(ResponseHead {
                        status: StatusCode::SWITCHING_PROTOCOLS,
                        headers: parts.headers,
                        body: GatewayBodyPlan::TrustedUpgrade(plan),
                    });
                }
            } else if response.status() == StatusCode::SWITCHING_PROTOCOLS {
                cluster.record_passive_failure(endpoint.name(), std::time::Instant::now());
                return ServiceOutcome::Failed(ServiceError::new(
                    ErrorClass::UpstreamProtocol,
                    "upstream returned an unsolicited 101 response",
                ));
            }

            let downstream_protocol = response_wire_protocol(request.original().http_version);
            let accepts_http1_trailers = downstream_protocol == WireProtocol::Http1
                && http1_accepts_trailers(&request.original().headers);
            let trailer_guard = TrailerGuard::from_response_headers(
                downstream_protocol,
                accepts_http1_trailers,
                response.headers(),
            );
            let (mut parts, body) = response.into_parts();
            if sanitize_runtime_headers(&mut parts.headers, response_wire_protocol(parts.version))
                .is_err()
            {
                cluster.record_passive_failure(endpoint.name(), std::time::Instant::now());
                return ServiceOutcome::Failed(ServiceError::new(
                    ErrorClass::UpstreamProtocol,
                    "upstream response contains invalid connection-specific metadata",
                ));
            }
            parts.headers.remove(header::CONTENT_LENGTH);
            let outcome_recorded = parts.status.is_server_error();
            if outcome_recorded {
                cluster.record_passive_failure(endpoint.name(), std::time::Instant::now());
            }
            let body = if request.method() == Method::HEAD {
                if !outcome_recorded {
                    cluster.record_passive_success(endpoint.name());
                }
                drop(permit);
                GatewayBodyPlan::Head {
                    representation_length: None,
                }
            } else {
                let body = timeout_upstream_response_body(body, cluster.spec().response_timeout);
                GatewayBodyPlan::Stream {
                    body: ClusterResponseBody::new(
                        body,
                        Arc::clone(&cluster),
                        permit,
                        outcome_recorded,
                    )
                    .boxed_unsync(),
                    known_length: None,
                    trailer_guard: Some(trailer_guard),
                }
            };
            return ServiceOutcome::Handled(ResponseHead {
                status: parts.status,
                headers: parts.headers,
                body,
            });
        }
    }
}

fn admission_failure(
    cluster: &oxidase_runtime::PreparedCluster,
    error: ClusterAdmissionError,
) -> ServiceOutcome<GatewayBodyPlan> {
    match error {
        ClusterAdmissionError::Unavailable => ServiceOutcome::Failed(ServiceError::new(
            ErrorClass::UpstreamUnavailable,
            format!("cluster `{}` has no eligible endpoint", cluster.name()),
        )),
        ClusterAdmissionError::Overloaded => ServiceOutcome::Failed(ServiceError::new(
            ErrorClass::UpstreamOverloaded,
            format!(
                "cluster `{}` has no available request capacity",
                cluster.name()
            ),
        )),
    }
}

fn retry_allows_failure(retry: &RetrySpec, failure: AttemptFailure) -> bool {
    failure
        .retry_cause()
        .is_some_and(|cause| retry_allows_cause(retry, cause))
}

pub(crate) fn retry_allows_cause(retry: &RetrySpec, cause: RetryCause) -> bool {
    retry.retry_on.contains(&cause)
}

pub(crate) fn retry_allows_status(retry: &RetrySpec, status: StatusCode) -> bool {
    retry
        .statuses
        .iter()
        .any(|range| range.contains(status.as_u16()))
}

fn classify_proxy_error(error: &hyper_util::client::legacy::Error) -> AttemptFailure {
    if error.is_connect() {
        return AttemptFailure::Connect;
    }
    let mut source = error.source();
    while let Some(error) = source {
        if let Some(error) = error.downcast_ref::<h2::Error>() {
            return match error.reason() {
                Some(h2::Reason::REFUSED_STREAM) => AttemptFailure::RefusedStream,
                Some(_) => AttemptFailure::Reset,
                None => AttemptFailure::Protocol,
            };
        }
        source = error.source();
    }
    AttemptFailure::Protocol
}

fn error_chain_contains_request_validation(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error.downcast_ref::<TrailerValidationError>().is_some()
            || error.downcast_ref::<DownstreamRequestBodyError>().is_some()
        {
            return true;
        }
        current = error.source();
    }
    false
}

fn error_chain_contains_request_body_limit(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error.downcast_ref::<RequestBodyLimitExceeded>().is_some() {
            return true;
        }
        current = error.source();
    }
    false
}

fn error_chain_contains_request_body_idle_timeout(
    error: &(dyn std::error::Error + 'static),
) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error
            .downcast_ref::<BodyIdleTimeout>()
            .is_some_and(|timeout| timeout.direction() == BodyIdleDirection::Request)
        {
            return true;
        }
        current = error.source();
    }
    false
}

fn build_proxy_pool(connector: HttpsConnector<HttpConnector>, http2_only: bool) -> ProxyPool {
    let mut builder = Client::builder(TokioExecutor::new());
    builder
        .pool_timer(TokioTimer::new())
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(32);
    builder.http2_only(http2_only);
    builder.build(connector)
}

fn response_wire_protocol(version: Version) -> WireProtocol {
    if version == Version::HTTP_2 {
        WireProtocol::Http2
    } else {
        WireProtocol::Http1
    }
}

impl LeafExecutor<GatewayRequestPayload, GatewayBodyPlan> for HyperLeaves {
    fn body_from_bytes(&self, bytes: Bytes) -> GatewayBodyPlan {
        if bytes.is_empty() {
            GatewayBodyPlan::Empty
        } else {
            GatewayBodyPlan::Bytes(bytes)
        }
    }

    fn execute_site<'a>(
        &'a self,
        resource: &'a ResourceId,
        request: &'a RequestFrame,
    ) -> BoxLeafFuture<'a, GatewayBodyPlan> {
        let site = self.snapshot.resources.sites.get(resource).cloned();
        Box::pin(async move {
            let Some(site) = site else {
                return ServiceOutcome::Failed(ServiceError::new(
                    ErrorClass::InvalidState,
                    format!("prepared site `{resource}` is missing"),
                ));
            };
            match site.execute(request) {
                Ok(Some(response)) => prepare_site_body(response, request).await,
                Ok(None) => ServiceOutcome::Declined,
                Err(SiteError::InvalidRequestPath(_)) => {
                    ServiceOutcome::Handled(ResponseHead::new(
                        StatusCode::BAD_REQUEST,
                        GatewayBodyPlan::Bytes(Bytes::from_static(b"Bad Request")),
                    ))
                }
                Err(error @ SiteError::TemplateLimit { .. }) => ServiceOutcome::Failed(
                    ServiceError::new(ErrorClass::TemplateLimit, error.to_string()),
                ),
                Err(error) => ServiceOutcome::Failed(ServiceError::new(
                    ErrorClass::InvalidState,
                    error.to_string(),
                )),
            }
        })
    }

    fn execute_proxy<'a>(
        &'a self,
        cluster: &'a ResourceId,
        request: &'a RequestFrame,
        body: &'a mut Option<GatewayRequestPayload>,
        max_request_body_bytes: Option<u64>,
    ) -> BoxLeafFuture<'a, GatewayBodyPlan> {
        Box::pin(self.proxy.execute(
            cluster,
            request,
            body,
            &self.snapshot,
            max_request_body_bytes,
        ))
    }

    fn governance(&self) -> Option<&GovernanceRegistry> {
        Some(&self.snapshot.governance)
    }

    fn retain_concurrency_permit(
        &self,
        body: GatewayBodyPlan,
        permit: ConcurrencyPermit,
    ) -> GatewayBodyPlan {
        body.retain_concurrency_permit(permit)
    }

    fn record_governance_result(&self, kind: &'static str, name: &str, result: &'static str) {
        self.metrics.record_governance(kind, name, result);
    }
}

fn upstream_uri(endpoint: &url::Url, request_path: &str) -> Result<Uri, ServiceError> {
    let host = endpoint.host_str().ok_or_else(|| {
        ServiceError::new(ErrorClass::InvalidState, "cluster endpoint has no host")
    })?;
    let authority_host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let authority = endpoint.port().map_or(authority_host.clone(), |port| {
        format!("{authority_host}:{port}")
    });
    let base_path = endpoint.path().trim_end_matches('/');
    let request_path = request_path.strip_prefix('/').unwrap_or(request_path);
    let path = if base_path.is_empty() {
        format!("/{request_path}")
    } else {
        format!("{base_path}/{request_path}")
    };
    Uri::from_str(&format!("{}://{authority}{path}", endpoint.scheme())).map_err(|error| {
        ServiceError::new(
            ErrorClass::InvalidState,
            format!("cannot construct upstream URI: {error}"),
        )
    })
}

fn apply_forwarding_headers(headers: &mut HeaderMap, request: &RequestFrame, endpoint: &url::Url) {
    let host = endpoint.host_str().unwrap_or_default();
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let target_authority = endpoint
        .port()
        .map_or(host.clone(), |port| format!("{host}:{port}"));
    if let Ok(value) = HeaderValue::from_str(&target_authority) {
        headers.insert(header::HOST, value);
    }
    let peer_ip = request
        .original()
        .peer_address
        .as_ref()
        .map(|peer| peer.ip().to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    if let Ok(value) = HeaderValue::from_str(&peer_ip) {
        headers.insert(HeaderName::from_static("x-forwarded-for"), value);
    }
    let ingress_scheme = request.original().scheme.as_str();
    let ingress_authority = request.original().authority.as_str();
    if let Ok(value) = HeaderValue::from_str(ingress_scheme) {
        headers.insert(HeaderName::from_static("x-forwarded-proto"), value);
    }
    if let Ok(value) = HeaderValue::from_str(ingress_authority) {
        headers.insert(HeaderName::from_static("x-forwarded-host"), value);
    }
    let forwarded = format!(
        "for=\"{}\";proto={};host=\"{}\"",
        escape_forwarded(&peer_ip),
        ingress_scheme,
        escape_forwarded(ingress_authority)
    );
    if let Ok(value) = HeaderValue::from_str(&forwarded) {
        headers.insert(HeaderName::from_static("forwarded"), value);
    }
}

fn escape_forwarded(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

async fn prepare_site_body(
    mut response: PreparedSiteResponse,
    request: &RequestFrame,
) -> ServiceOutcome<GatewayBodyPlan> {
    let body = match response.body {
        PreparedSiteBody::Empty => GatewayBodyPlan::Empty,
        PreparedSiteBody::Bytes(bytes) => GatewayBodyPlan::Bytes(bytes),
        PreparedSiteBody::Asset(asset) => {
            match stream_asset(
                &asset,
                request.method(),
                request.effective_headers(),
                &mut response.status,
                &mut response.headers,
                response.head_only,
            )
            .await
            {
                Ok(body) => body,
                Err(error) => return ServiceOutcome::Failed(error),
            }
        }
    };
    ServiceOutcome::Handled(ResponseHead {
        status: response.status,
        headers: response.headers,
        body,
    })
}

async fn stream_asset(
    asset: &AssetPlan,
    request_method: &Method,
    request_headers: &HeaderMap,
    status: &mut StatusCode,
    response_headers: &mut HeaderMap,
    head_only: bool,
) -> Result<GatewayBodyPlan, ServiceError> {
    let parsed_range = parse_requested_range(request_headers);
    let range_eligible = request_method == Method::GET
        && *status == StatusCode::OK
        && asset.range_requests
        && matches!(parsed_range, ParsedRange::Single(_));
    let use_identity_for_range =
        range_eligible && encoding_preferences(request_headers).identity > 0;
    clear_representation_headers(response_headers);
    if asset.brotli.is_some() || asset.gzip.is_some() {
        merge_vary(response_headers, "accept-encoding");
    }
    let Some(representation) =
        select_representation(request_headers, asset, use_identity_for_range)
    else {
        *status = StatusCode::NOT_ACCEPTABLE;
        return Ok(GatewayBodyPlan::Empty);
    };
    apply_representation_headers(asset, representation, response_headers)?;

    if *status == StatusCode::OK && is_not_modified(request_headers, representation) {
        *status = StatusCode::NOT_MODIFIED;
        return Ok(GatewayBodyPlan::Empty);
    }
    if status.is_informational()
        || *status == StatusCode::NO_CONTENT
        || *status == StatusCode::NOT_MODIFIED
    {
        return Ok(GatewayBodyPlan::Empty);
    }

    let range = if use_identity_for_range && if_range_matches(request_headers, representation) {
        let ParsedRange::Single(range) = parsed_range else {
            unreachable!("identity is reserved only for a parsed single range")
        };
        match range.resolve(representation.length) {
            ResolvedRange::Satisfiable(range) => Some(range),
            ResolvedRange::Unsatisfiable => {
                *status = StatusCode::RANGE_NOT_SATISFIABLE;
                response_headers.insert(
                    header::CONTENT_RANGE,
                    header_value(format!("bytes */{}", representation.length))?,
                );
                return Ok(GatewayBodyPlan::Empty);
            }
        }
    } else {
        None
    };

    let (offset, response_length) = range.map_or((0, representation.length), |range| {
        *status = StatusCode::PARTIAL_CONTENT;
        (range.start, range.end - range.start + 1)
    });
    if let Some(range) = range {
        response_headers.insert(
            header::CONTENT_RANGE,
            header_value(format!(
                "bytes {}-{}/{}",
                range.start, range.end, representation.length
            ))?,
        );
    }
    if head_only {
        return Ok(GatewayBodyPlan::Head {
            representation_length: Some(response_length),
        });
    }

    let mut file = tokio::fs::File::open(&representation.path)
        .await
        .map_err(|error| {
            ServiceError::new(
                ErrorClass::SiteIo,
                format!(
                    "cannot open compiled asset `{}`: {error}",
                    representation.path.display()
                ),
            )
        })?;
    if offset > 0 {
        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|error| {
                ServiceError::new(
                    ErrorClass::SiteIo,
                    format!(
                        "cannot seek compiled asset `{}`: {error}",
                        representation.path.display()
                    ),
                )
            })?;
    }
    let reader = file.take(response_length);
    let stream = ReaderStream::new(reader)
        .map_ok(Frame::data)
        .map_err(|error| -> BoxError { Box::new(error) });
    Ok(GatewayBodyPlan::Stream {
        body: StreamBody::new(stream).boxed_unsync(),
        known_length: Some(response_length),
        trailer_guard: None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ByteRange {
    start: u64,
    end: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParsedRange {
    None,
    Ignore,
    Single(UnresolvedByteRange),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnresolvedByteRange {
    Inclusive { start: u64, end: Option<u64> },
    Suffix { length: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolvedRange {
    Satisfiable(ByteRange),
    Unsatisfiable,
}

impl UnresolvedByteRange {
    fn resolve(self, length: u64) -> ResolvedRange {
        if length == 0 {
            return ResolvedRange::Unsatisfiable;
        }
        match self {
            Self::Inclusive { start, end } => {
                if start >= length || end.is_some_and(|end| start > end) {
                    return ResolvedRange::Unsatisfiable;
                }
                ResolvedRange::Satisfiable(ByteRange {
                    start,
                    end: end.unwrap_or(length - 1).min(length - 1),
                })
            }
            Self::Suffix { length: suffix } => {
                if suffix == 0 {
                    return ResolvedRange::Unsatisfiable;
                }
                let suffix = suffix.min(length);
                ResolvedRange::Satisfiable(ByteRange {
                    start: length - suffix,
                    end: length - 1,
                })
            }
        }
    }
}

fn parse_requested_range(headers: &HeaderMap) -> ParsedRange {
    let mut values = headers.get_all(header::RANGE).iter();
    let Some(value) = values.next() else {
        return ParsedRange::None;
    };
    if values.next().is_some() {
        return ParsedRange::Ignore;
    }
    value.to_str().map_or(ParsedRange::Ignore, parse_range)
}

fn parse_range(value: &str) -> ParsedRange {
    let Some((unit, value)) = value.trim().split_once('=') else {
        return ParsedRange::Ignore;
    };
    if !unit.eq_ignore_ascii_case("bytes") {
        return ParsedRange::Ignore;
    }
    let value = value.trim();
    if value.contains(',') {
        return ParsedRange::Ignore;
    }
    let Some((start, end)) = value.split_once('-') else {
        return ParsedRange::Ignore;
    };
    let start = start.trim();
    let end = end.trim();
    if start.is_empty() {
        return end.parse::<u64>().map_or(ParsedRange::Ignore, |length| {
            ParsedRange::Single(UnresolvedByteRange::Suffix { length })
        });
    }
    let Ok(start) = start.parse::<u64>() else {
        return ParsedRange::Ignore;
    };
    let end = if end.is_empty() {
        None
    } else {
        let Ok(end) = end.parse::<u64>() else {
            return ParsedRange::Ignore;
        };
        Some(end)
    };
    ParsedRange::Single(UnresolvedByteRange::Inclusive { start, end })
}

#[derive(Debug, Clone, Copy)]
struct EncodingPreferences {
    brotli: u16,
    gzip: u16,
    identity: u16,
}

fn select_representation<'a>(
    headers: &HeaderMap,
    asset: &'a AssetPlan,
    range_requested: bool,
) -> Option<&'a AssetRepresentation> {
    let preferences = encoding_preferences(headers);
    if range_requested {
        return (preferences.identity > 0).then_some(&asset.identity);
    }
    let mut selected = (preferences.identity, 0u8, &asset.identity);
    if let Some(gzip) = &asset.gzip
        && (preferences.gzip, 1) > (selected.0, selected.1)
    {
        selected = (preferences.gzip, 1, gzip);
    }
    if let Some(brotli) = &asset.brotli
        && (preferences.brotli, 2) > (selected.0, selected.1)
    {
        selected = (preferences.brotli, 2, brotli);
    }
    (selected.0 > 0).then_some(selected.2)
}

fn encoding_preferences(headers: &HeaderMap) -> EncodingPreferences {
    if !headers.contains_key(header::ACCEPT_ENCODING) {
        return EncodingPreferences {
            brotli: 0,
            gzip: 0,
            identity: 1_000,
        };
    }
    let mut brotli: Option<u16> = None;
    let mut gzip: Option<u16> = None;
    let mut identity: Option<u16> = None;
    let mut wildcard: Option<u16> = None;
    for value in headers.get_all(header::ACCEPT_ENCODING) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for item in value.split(',') {
            let mut parts = item.trim().split(';');
            let coding = parts.next().unwrap_or("").trim();
            if coding.is_empty() {
                continue;
            }
            let mut quality = 1_000;
            let mut seen_quality = false;
            let mut malformed = false;
            for parameter in parts {
                let Some((name, value)) = parameter.trim().split_once('=') else {
                    malformed = true;
                    continue;
                };
                if !name.trim().eq_ignore_ascii_case("q") || seen_quality {
                    malformed = true;
                    continue;
                }
                seen_quality = true;
                match parse_quality(value.trim()) {
                    Some(value) => quality = value,
                    None => malformed = true,
                }
            }
            if malformed {
                quality = 0;
            }
            let target = if coding.eq_ignore_ascii_case("br") {
                Some(&mut brotli)
            } else if coding.eq_ignore_ascii_case("gzip") {
                Some(&mut gzip)
            } else if coding.eq_ignore_ascii_case("identity") {
                Some(&mut identity)
            } else if coding == "*" {
                Some(&mut wildcard)
            } else {
                None
            };
            if let Some(target) = target {
                *target = Some((*target).map_or(quality, |current| current.min(quality)));
            }
        }
    }
    let wildcard = wildcard.unwrap_or(0);
    EncodingPreferences {
        brotli: brotli.unwrap_or(wildcard),
        gzip: gzip.unwrap_or(wildcard),
        identity: identity.unwrap_or_else(|| {
            if wildcard == 0 && headers_contains_wildcard(headers) {
                0
            } else {
                1_000
            }
        }),
    }
}

fn headers_contains_wildcard(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|item| item.trim().split(';').next())
        .any(|coding| coding.trim() == "*")
}

fn parse_quality(source: &str) -> Option<u16> {
    let (integer, fraction) = source.split_once('.').unwrap_or((source, ""));
    if fraction.len() > 3 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    match integer {
        "0" => {
            let padded = format!("{fraction:0<3}");
            padded.parse().ok()
        }
        "1" if fraction.bytes().all(|byte| byte == b'0') => Some(1_000),
        _ => None,
    }
}

fn clear_representation_headers(headers: &mut HeaderMap) {
    for name in [
        header::CONTENT_ENCODING,
        header::ETAG,
        header::LAST_MODIFIED,
        header::ACCEPT_RANGES,
        header::CONTENT_RANGE,
    ] {
        headers.remove(name);
    }
}

fn apply_representation_headers(
    asset: &AssetPlan,
    representation: &AssetRepresentation,
    headers: &mut HeaderMap,
) -> Result<(), ServiceError> {
    if let Some(encoding) = representation.encoding {
        headers.insert(
            header::CONTENT_ENCODING,
            HeaderValue::from_static(encoding.as_str()),
        );
    }
    if let Some(etag) = &representation.etag {
        headers.insert(header::ETAG, header_value(etag.to_header_value())?);
    }
    if let Some(modified) = representation.modified {
        headers.insert(
            header::LAST_MODIFIED,
            header_value(httpdate::fmt_http_date(modified))?,
        );
    }
    if asset.range_requests && representation.encoding.is_none() {
        headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    }
    Ok(())
}

fn merge_vary(headers: &mut HeaderMap, token: &'static str) {
    let present = headers.get_all(header::VARY).iter().any(|value| {
        value.to_str().ok().is_some_and(|value| {
            value
                .split(',')
                .map(str::trim)
                .any(|value| value == "*" || value.eq_ignore_ascii_case(token))
        })
    });
    if !present {
        headers.append(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    }
}

fn is_not_modified(headers: &HeaderMap, representation: &AssetRepresentation) -> bool {
    if headers.contains_key(header::IF_NONE_MATCH) {
        return headers.get_all(header::IF_NONE_MATCH).iter().any(|value| {
            value.to_str().ok().is_some_and(|value| {
                value.split(',').any(|candidate| {
                    let candidate = candidate.trim();
                    candidate == "*"
                        || representation.etag.as_ref().is_some_and(|etag| {
                            EntityTag::parse(candidate)
                                .is_some_and(|candidate| etag.weak_eq(&candidate))
                        })
                })
            })
        });
    }
    let Some(modified) = representation.modified else {
        return false;
    };
    headers
        .get(header::IF_MODIFIED_SINCE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| httpdate::parse_http_date(value).ok())
        .is_some_and(|since| modified_not_after(modified, since))
}

fn if_range_matches(headers: &HeaderMap, representation: &AssetRepresentation) -> bool {
    let Some(value) = headers.get(header::IF_RANGE) else {
        return true;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    if let Some(candidate) = EntityTag::parse(value) {
        return representation
            .etag
            .as_ref()
            .is_some_and(|etag| etag.strong_eq(&candidate));
    }
    let (Some(modified), Ok(date)) = (
        representation.modified,
        httpdate::parse_http_date(value.trim()),
    ) else {
        return false;
    };
    modified_not_after(modified, date)
}

fn modified_not_after(modified: std::time::SystemTime, validator: std::time::SystemTime) -> bool {
    if let Some(upper_bound) = validator.checked_add(Duration::from_secs(1)) {
        modified < upper_bound
    } else {
        modified <= validator
    }
}

fn header_value(value: String) -> Result<HeaderValue, ServiceError> {
    HeaderValue::from_str(&value).map_err(|_| {
        ServiceError::new(
            ErrorClass::InvalidState,
            "compiled asset produced an invalid response header",
        )
    })
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue, Request, Response, Version, header};
    use http_body_util::{BodyExt, Full};
    use hyper::body::Incoming;
    use hyper::server::conn::{http1, http2};
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use oxidase_config::{ClusterProtocol, Compiler};
    use oxidase_core::{RequestFrame, RequestMetadata};
    use oxidase_runtime::RuntimeSnapshot;
    use oxidase_site::{AssetPlan, AssetRepresentation, ContentEncoding};
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::{mpsc, watch};

    use super::{
        ByteRange, ParsedRange, ProxyPoolKind, ResolvedRange, UnresolvedByteRange,
        apply_forwarding_headers, parse_quality, parse_range, response_wire_protocol,
        select_representation,
    };
    use crate::protocol::WireProtocol;
    use crate::server::GatewayServer;

    #[derive(Clone, Copy)]
    enum FixtureProtocol {
        Http1,
        Http2,
    }

    async fn spawn_protocol_fixture(
        protocol: FixtureProtocol,
    ) -> (
        std::net::SocketAddr,
        Arc<AtomicUsize>,
        mpsc::UnboundedReceiver<Version>,
        watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream fixture binds");
        let address = listener.local_addr().expect("fixture address is known");
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts_for_task = accepts.clone();
        let (versions, received_versions) = mpsc::unbounded_channel();
        let (shutdown, mut shutdown_receiver) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    changed = shutdown_receiver.changed() => {
                        if changed.is_err() || *shutdown_receiver.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else {
                            break;
                        };
                        accepts_for_task.fetch_add(1, Ordering::Relaxed);
                        let versions = versions.clone();
                        connections.spawn(async move {
                            let service = service_fn(move |request: Request<Incoming>| {
                                let versions = versions.clone();
                                async move {
                                    let version = request.version();
                                    let _ = versions.send(version);
                                    let request_body = request
                                        .into_body()
                                        .collect()
                                        .await
                                        .expect("fixture request body is readable")
                                        .to_bytes();
                                    let mut response = Response::new(Full::new(Bytes::from(
                                        format!("{}:{}", version_text(version), request_body.len()),
                                    )));
                                    response.headers_mut().insert(
                                        "x-fixture-version",
                                        HeaderValue::from_static("observed"),
                                    );
                                    Ok::<_, Infallible>(response)
                                }
                            });
                            match protocol {
                                FixtureProtocol::Http1 => {
                                    let _ = http1::Builder::new()
                                        .keep_alive(true)
                                        .serve_connection(TokioIo::new(stream), service)
                                        .await;
                                }
                                FixtureProtocol::Http2 => {
                                    let _ = http2::Builder::new(TokioExecutor::new())
                                        .serve_connection(TokioIo::new(stream), service)
                                        .await;
                                }
                            }
                        });
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        (address, accepts, received_versions, shutdown, task)
    }

    fn version_text(version: Version) -> &'static str {
        if version == Version::HTTP_2 {
            "h2"
        } else {
            "http1"
        }
    }

    async fn request_gateway(address: std::net::SocketAddr) -> String {
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut stream = tokio::net::TcpStream::connect(address)
                .await
                .expect("gateway accepts the request");
            stream
                .write_all(b"GET /pool HTTP/1.1\r\nHost: gateway.test\r\nConnection: close\r\n\r\n")
                .await
                .expect("gateway request can be written");
            let mut response = Vec::new();
            stream
                .read_to_end(&mut response)
                .await
                .expect("gateway response is readable");
            String::from_utf8(response).expect("fixture response is UTF-8")
        })
        .await
        .expect("gateway response arrives before timeout")
    }

    async fn assert_proxy_pool(
        cluster_protocol: ClusterProtocol,
        fixture_protocol: FixtureProtocol,
        expected_version: Version,
    ) {
        let (upstream, accepts, mut versions, upstream_shutdown, upstream_task) =
            spawn_protocol_fixture(fixture_protocol).await;
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        fs::write(
            &config,
            format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    upstream:
      protocol: {}
      endpoints:
        - http://{upstream}
      connect_timeout: 1s
      response_timeout: 1s
services:
  root:
    type: proxy
    cluster: upstream
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: root
"#,
                cluster_protocol.as_str()
            ),
        )
        .expect("gateway fixture config can be written");
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("gateway fixture config compiles"),
        )
        .expect("gateway fixture snapshot prepares");
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("gateway fixture binds")
            .spawn();
        let gateway = running.local_addresses()[0].1;

        for _ in 0..2 {
            let response = request_gateway(gateway).await;
            assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
            assert!(
                response.contains(version_text(expected_version)),
                "{response}"
            );
            let observed = tokio::time::timeout(Duration::from_secs(1), versions.recv())
                .await
                .expect("upstream observes a request")
                .expect("version channel remains open");
            assert_eq!(observed, expected_version);
        }
        assert_eq!(
            accepts.load(Ordering::Relaxed),
            1,
            "both requests must reuse one long-lived upstream pool connection"
        );

        running
            .shutdown()
            .await
            .expect("gateway fixture shuts down");
        let _ = upstream_shutdown.send(true);
        upstream_task.await.expect("upstream fixture shuts down");
    }

    fn representation(encoding: Option<ContentEncoding>) -> AssetRepresentation {
        AssetRepresentation {
            encoding,
            path: PathBuf::from("fixture"),
            length: 10,
            etag: None,
            modified: None,
        }
    }

    fn asset() -> AssetPlan {
        AssetPlan {
            identity: representation(None),
            brotli: Some(representation(Some(ContentEncoding::Brotli))),
            gzip: Some(representation(Some(ContentEncoding::Gzip))),
            content_type: "application/octet-stream".to_owned(),
            range_requests: true,
        }
    }

    fn encoding_headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_str(value).expect("valid test header"),
        );
        headers
    }

    #[test]
    fn distinguishes_ignored_and_resolvable_byte_ranges() {
        assert_eq!(
            parse_range("bytes=2-5"),
            ParsedRange::Single(UnresolvedByteRange::Inclusive {
                start: 2,
                end: Some(5)
            })
        );
        assert_eq!(
            parse_range("bytes=-3"),
            ParsedRange::Single(UnresolvedByteRange::Suffix { length: 3 })
        );
        assert_eq!(
            parse_range("bytes=8-"),
            ParsedRange::Single(UnresolvedByteRange::Inclusive {
                start: 8,
                end: None
            })
        );
        assert_eq!(
            UnresolvedByteRange::Inclusive {
                start: 11,
                end: Some(12)
            }
            .resolve(10),
            ResolvedRange::Unsatisfiable
        );
        assert_eq!(parse_range("bytes=0-1,4-5"), ParsedRange::Ignore);
        assert_eq!(parse_range("items=0-1"), ParsedRange::Ignore);
        assert_eq!(parse_range("bytes=abc"), ParsedRange::Ignore);
        assert_eq!(parse_range("bytes=-"), ParsedRange::Ignore);
        let _type_check = ByteRange { start: 0, end: 0 };
    }

    #[test]
    fn orders_encoding_quality_and_uses_a_stable_tie_break() {
        let asset = asset();
        let selected =
            select_representation(&encoding_headers("br;q=0.2, gzip;q=1"), &asset, false)
                .expect("gzip is acceptable");
        assert_eq!(selected.encoding, Some(ContentEncoding::Gzip));

        let selected = select_representation(
            &encoding_headers("identity;q=0.5, gzip;q=0.5, br;q=0.5"),
            &asset,
            false,
        )
        .expect("an encoding is acceptable");
        assert_eq!(selected.encoding, Some(ContentEncoding::Brotli));

        let selected = select_representation(&HeaderMap::new(), &asset, false)
            .expect("identity is the default");
        assert_eq!(selected.encoding, None);
    }

    #[test]
    fn honors_zero_quality_and_malformed_parameters_conservatively() {
        let asset = asset();
        assert!(
            select_representation(
                &encoding_headers("br;q=0, gzip;q=0, identity;q=0"),
                &asset,
                false,
            )
            .is_none()
        );
        assert!(
            select_representation(
                &encoding_headers("br;level=9;q=1, gzip;q=0, identity;q=0"),
                &asset,
                false,
            )
            .is_none()
        );
        assert_eq!(parse_quality("0"), Some(0));
        assert_eq!(parse_quality("0.125"), Some(125));
        assert_eq!(parse_quality("1.000"), Some(1_000));
        assert_eq!(parse_quality("1.1"), None);
        assert_eq!(parse_quality("0.1234"), None);
    }

    #[test]
    fn valid_range_prefers_identity_only_when_identity_is_acceptable() {
        let asset = asset();
        let selected = select_representation(&encoding_headers("br"), &asset, true)
            .expect("implicit identity remains acceptable");
        assert_eq!(selected.encoding, None);
        let selected = select_representation(&encoding_headers("br, identity;q=0"), &asset, false)
            .expect("the ignored range permits Brotli negotiation");
        assert_eq!(selected.encoding, Some(ContentEncoding::Brotli));
    }

    #[test]
    fn forwarding_headers_use_original_ingress_metadata_not_transform_overlay() {
        let mut request = RequestFrame::new(
            RequestMetadata::try_new(
                http::Method::GET,
                "https",
                "public.example:8443",
                "/original",
                HeaderMap::new(),
            )
            .expect("request metadata is valid"),
        );
        request.overlay_mut().scheme = Some(http::uri::Scheme::HTTP);
        request.overlay_mut().authority = Some(
            "internal.example:9000"
                .parse()
                .expect("overlay authority is valid"),
        );

        let endpoint =
            url::Url::parse("http://upstream.example:8080/base").expect("endpoint URL is valid");
        let mut headers = HeaderMap::new();
        apply_forwarding_headers(&mut headers, &request, &endpoint);

        assert_eq!(
            headers.get(header::HOST).expect("upstream Host is present"),
            "upstream.example:8080"
        );
        assert_eq!(
            headers
                .get("x-forwarded-proto")
                .expect("forwarded protocol is present"),
            "https",
            "the transform overlay must not rewrite ingress transport identity"
        );
        assert_eq!(
            headers
                .get("x-forwarded-host")
                .expect("forwarded authority is present"),
            "public.example:8443"
        );
        assert_eq!(
            headers
                .get("forwarded")
                .expect("Forwarded header is present"),
            "for=\"unknown\";proto=https;host=\"public.example:8443\""
        );
        assert!(!headers.values().any(|value| {
            value
                .to_str()
                .is_ok_and(|value| value.contains("internal.example"))
        }));
    }

    #[test]
    fn cluster_protocol_selects_the_matching_long_lived_pool_and_header_policy() {
        assert_eq!(
            ProxyPoolKind::for_cluster(ClusterProtocol::Auto),
            ProxyPoolKind::Auto
        );
        assert_eq!(
            ProxyPoolKind::for_cluster(ClusterProtocol::Http1),
            ProxyPoolKind::Http1
        );
        assert_eq!(
            ProxyPoolKind::for_cluster(ClusterProtocol::H2),
            ProxyPoolKind::H2
        );
        assert_eq!(
            ProxyPoolKind::Auto.request_wire_protocol(),
            WireProtocol::Http1,
            "auto uses conservative request filtering before ALPN is known"
        );
        assert_eq!(
            ProxyPoolKind::H2.request_wire_protocol(),
            WireProtocol::Http2
        );
        assert_eq!(
            response_wire_protocol(Version::HTTP_11),
            WireProtocol::Http1
        );
        assert_eq!(response_wire_protocol(Version::HTTP_2), WireProtocol::Http2);
    }

    #[tokio::test]
    async fn http1_cluster_reuses_a_long_lived_http1_pool_connection() {
        assert_proxy_pool(
            ClusterProtocol::Http1,
            FixtureProtocol::Http1,
            Version::HTTP_11,
        )
        .await;
    }

    #[tokio::test]
    async fn h2_cluster_uses_prior_knowledge_and_reuses_the_h2_connection() {
        assert_proxy_pool(ClusterProtocol::H2, FixtureProtocol::Http2, Version::HTTP_2).await;
    }

    #[tokio::test]
    async fn auto_cluster_uses_http1_for_cleartext_upstreams() {
        assert_proxy_pool(
            ClusterProtocol::Auto,
            FixtureProtocol::Http1,
            Version::HTTP_11,
        )
        .await;
    }
}
