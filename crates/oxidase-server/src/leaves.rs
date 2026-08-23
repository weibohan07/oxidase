use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use futures_util::TryStreamExt;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri, header};
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Incoming;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use oxidase_core::{
    ErrorClass, RequestFrame, ResourceId, ResponseHead, ServiceError, ServiceOutcome,
};
use oxidase_runtime::{BoxLeafFuture, LeafExecutor, RuntimeSnapshot};
use oxidase_site::{AssetPlan, PreparedSiteBody, PreparedSiteResponse, SiteError};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;

use crate::body::{BoxError, GatewayBodyPlan, timeout_incoming_body};
use crate::response::remove_hop_by_hop;

pub(crate) struct HyperLeaves {
    snapshot: Arc<RuntimeSnapshot>,
    proxy: Arc<ProxyClient>,
}

impl HyperLeaves {
    pub(crate) fn new(snapshot: Arc<RuntimeSnapshot>, proxy: Arc<ProxyClient>) -> Self {
        Self { snapshot, proxy }
    }
}

pub(crate) struct ProxyClient {
    client: Client<HttpsConnector<HttpConnector>, Incoming>,
    endpoint_sequence: AtomicU64,
}

impl ProxyClient {
    pub(crate) fn new() -> Result<Self, String> {
        let connector = HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|error| format!("cannot load native TLS roots: {error}"))?
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let client = Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(32)
            .build(connector);
        Ok(Self {
            client,
            endpoint_sequence: AtomicU64::new(0),
        })
    }

    async fn execute(
        &self,
        cluster: &ResourceId,
        request: &RequestFrame,
        body: &mut Option<Incoming>,
        snapshot: &RuntimeSnapshot,
    ) -> ServiceOutcome<GatewayBodyPlan> {
        let Some(cluster_spec) = snapshot.resources.clusters.get(cluster) else {
            return ServiceOutcome::Failed(ServiceError::new(
                ErrorClass::InvalidState,
                format!("prepared cluster `{cluster}` is missing"),
            ));
        };
        let sequence = self.endpoint_sequence.fetch_add(1, Ordering::Relaxed);
        let endpoint = &cluster_spec.endpoints[sequence as usize % cluster_spec.endpoints.len()];
        let uri = match upstream_uri(endpoint, request.path_and_query()) {
            Ok(uri) => uri,
            Err(error) => return ServiceOutcome::Failed(error),
        };
        let Some(body) = body.take() else {
            return ServiceOutcome::Failed(ServiceError::new(
                ErrorClass::BodyUnavailable,
                "Proxy request body is unavailable",
            ));
        };
        let mut upstream = Request::new(body);
        *upstream.method_mut() = request.method().clone();
        *upstream.uri_mut() = uri;
        *upstream.headers_mut() = request.headers();
        remove_hop_by_hop(upstream.headers_mut());
        apply_forwarding_headers(upstream.headers_mut(), request, endpoint);

        let timeout = cluster_spec
            .connect_timeout
            .checked_add(cluster_spec.response_timeout)
            .unwrap_or(cluster_spec.response_timeout);
        let response = match tokio::time::timeout(timeout, self.client.request(upstream)).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                let class = if error.is_connect() {
                    ErrorClass::UpstreamConnect
                } else {
                    ErrorClass::UpstreamProtocol
                };
                return ServiceOutcome::Failed(ServiceError::new(
                    class,
                    format!("upstream request to `{endpoint}` failed: {error}"),
                ));
            }
            Err(_) => {
                return ServiceOutcome::Failed(ServiceError::new(
                    ErrorClass::Timeout,
                    format!(
                        "upstream `{endpoint}` did not produce response headers in {timeout:?}"
                    ),
                ));
            }
        };
        let (mut parts, body) = response.into_parts();
        remove_hop_by_hop(&mut parts.headers);
        let representation_length = parts
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        parts.headers.remove(header::CONTENT_LENGTH);
        let body = if request.method() == Method::HEAD {
            GatewayBodyPlan::Head {
                representation_length,
            }
        } else {
            GatewayBodyPlan::Stream {
                body: timeout_incoming_body(body, cluster_spec.response_timeout),
                known_length: None,
            }
        };
        ServiceOutcome::Handled(ResponseHead {
            status: parts.status,
            headers: parts.headers,
            body,
        })
    }
}

impl LeafExecutor<Incoming, GatewayBodyPlan> for HyperLeaves {
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
                Err(error) => {
                    ServiceOutcome::Failed(ServiceError::new(ErrorClass::SiteIo, error.to_string()))
                }
            }
        })
    }

    fn execute_proxy<'a>(
        &'a self,
        cluster: &'a ResourceId,
        request: &'a RequestFrame,
        body: &'a mut Option<Incoming>,
    ) -> BoxLeafFuture<'a, GatewayBodyPlan> {
        Box::pin(self.proxy.execute(cluster, request, body, &self.snapshot))
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
        .as_deref()
        .and_then(|peer| peer.parse::<std::net::SocketAddr>().ok())
        .map(|peer| peer.ip().to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    if let Ok(value) = HeaderValue::from_str(&peer_ip) {
        headers.insert(HeaderName::from_static("x-forwarded-for"), value);
    }
    if let Ok(value) = HeaderValue::from_str(request.scheme()) {
        headers.insert(HeaderName::from_static("x-forwarded-proto"), value);
    }
    if let Ok(value) = HeaderValue::from_str(request.authority()) {
        headers.insert(HeaderName::from_static("x-forwarded-host"), value);
    }
    let forwarded = format!(
        "for=\"{}\";proto={};host=\"{}\"",
        escape_forwarded(&peer_ip),
        request.scheme(),
        escape_forwarded(request.authority())
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
                &request.headers(),
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
    request_headers: &HeaderMap,
    status: &mut StatusCode,
    response_headers: &mut HeaderMap,
    head_only: bool,
) -> Result<GatewayBodyPlan, ServiceError> {
    let range_requested = request_headers.contains_key(header::RANGE);
    let encoding = if range_requested {
        None
    } else {
        select_encoding(request_headers, asset)
    };
    let (path, length) = match encoding {
        Some(SelectedEncoding::Brotli) => {
            let compressed = asset.brotli.as_ref().ok_or_else(|| {
                ServiceError::new(ErrorClass::InvalidState, "selected Brotli asset is missing")
            })?;
            response_headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("br"));
            vary_etag(response_headers, "br");
            response_headers.remove(header::ACCEPT_RANGES);
            (&compressed.path, compressed.length)
        }
        Some(SelectedEncoding::Gzip) => {
            let compressed = asset.gzip.as_ref().ok_or_else(|| {
                ServiceError::new(ErrorClass::InvalidState, "selected gzip asset is missing")
            })?;
            response_headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
            vary_etag(response_headers, "gzip");
            response_headers.remove(header::ACCEPT_RANGES);
            (&compressed.path, compressed.length)
        }
        None => (&asset.path, asset.length),
    };

    let range = if asset.range_requests && encoding.is_none() {
        match request_headers.get(header::RANGE) {
            Some(value) => match value
                .to_str()
                .ok()
                .and_then(|value| parse_range(value, length))
            {
                Some(range) => Some(range),
                None => {
                    *status = StatusCode::RANGE_NOT_SATISFIABLE;
                    response_headers.insert(
                        header::CONTENT_RANGE,
                        header_value(format!("bytes */{length}"))?,
                    );
                    response_headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
                    return Ok(GatewayBodyPlan::Empty);
                }
            },
            None => None,
        }
    } else {
        None
    };

    let (offset, response_length) = range.map_or((0, length), |range| {
        *status = StatusCode::PARTIAL_CONTENT;
        (range.start, range.end - range.start + 1)
    });
    response_headers.insert(
        header::CONTENT_LENGTH,
        header_value(response_length.to_string())?,
    );
    if let Some(range) = range {
        response_headers.insert(
            header::CONTENT_RANGE,
            header_value(format!("bytes {}-{}/{length}", range.start, range.end))?,
        );
    }
    if head_only {
        return Ok(GatewayBodyPlan::Head {
            representation_length: Some(response_length),
        });
    }

    let mut file = tokio::fs::File::open(path).await.map_err(|error| {
        ServiceError::new(
            ErrorClass::SiteIo,
            format!("cannot open compiled asset `{}`: {error}", path.display()),
        )
    })?;
    if offset > 0 {
        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|error| {
                ServiceError::new(
                    ErrorClass::SiteIo,
                    format!("cannot seek compiled asset `{}`: {error}", path.display()),
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
    })
}

#[derive(Debug, Clone, Copy)]
struct ByteRange {
    start: u64,
    end: u64,
}

fn parse_range(value: &str, length: u64) -> Option<ByteRange> {
    let value = value.strip_prefix("bytes=")?;
    if value.contains(',') || length == 0 {
        return None;
    }
    let (start, end) = value.split_once('-')?;
    if start.is_empty() {
        let suffix = end.parse::<u64>().ok()?.min(length);
        if suffix == 0 {
            return None;
        }
        return Some(ByteRange {
            start: length - suffix,
            end: length - 1,
        });
    }
    let start = start.parse::<u64>().ok()?;
    if start >= length {
        return None;
    }
    let end = if end.is_empty() {
        length - 1
    } else {
        end.parse::<u64>().ok()?.min(length - 1)
    };
    (start <= end).then_some(ByteRange { start, end })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelectedEncoding {
    Brotli,
    Gzip,
}

fn select_encoding(headers: &HeaderMap, asset: &AssetPlan) -> Option<SelectedEncoding> {
    let value = headers.get(header::ACCEPT_ENCODING)?.to_str().ok()?;
    if asset.brotli.is_some() && accepts_encoding(value, "br") {
        Some(SelectedEncoding::Brotli)
    } else if asset.gzip.is_some() && accepts_encoding(value, "gzip") {
        Some(SelectedEncoding::Gzip)
    } else {
        None
    }
}

fn accepts_encoding(header: &str, expected: &str) -> bool {
    header.split(',').any(|item| {
        let mut parts = item.trim().split(';');
        let name = parts.next().unwrap_or("").trim();
        let quality_zero = parts.any(|parameter| {
            parameter
                .trim()
                .strip_prefix("q=")
                .is_some_and(|quality| quality == "0" || quality == "0.0" || quality == "0.00")
        });
        !quality_zero && (name.eq_ignore_ascii_case(expected) || name == "*")
    })
}

fn vary_etag(headers: &mut HeaderMap, encoding: &str) {
    let Some(etag) = headers
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
    else {
        return;
    };
    let varied = if let Some(value) = etag.strip_suffix('"') {
        format!("{value}-{encoding}\"")
    } else {
        format!("{etag}-{encoding}")
    };
    if let Ok(varied) = HeaderValue::from_str(&varied) {
        headers.insert(header::ETAG, varied);
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
    use super::{ByteRange, accepts_encoding, parse_range};

    #[test]
    fn parses_single_byte_ranges() {
        assert_eq!(
            parse_range("bytes=2-5", 10).map(|range| (range.start, range.end)),
            Some((2, 5))
        );
        assert_eq!(
            parse_range("bytes=-3", 10).map(|range| (range.start, range.end)),
            Some((7, 9))
        );
        assert_eq!(
            parse_range("bytes=8-", 10).map(|range| (range.start, range.end)),
            Some((8, 9))
        );
        assert!(parse_range("bytes=11-12", 10).is_none());
        let _type_check = ByteRange { start: 0, end: 0 };
    }

    #[test]
    fn honors_zero_quality_encoding() {
        assert!(accepts_encoding("gzip, br;q=1", "br"));
        assert!(!accepts_encoding("br;q=0, gzip", "br"));
    }
}
