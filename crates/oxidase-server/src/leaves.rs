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
use oxidase_site::{
    AssetPlan, AssetRepresentation, EntityTag, PreparedSiteBody, PreparedSiteResponse, SiteError,
};
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
    clear_representation_headers(response_headers);
    if asset.brotli.is_some() || asset.gzip.is_some() {
        merge_vary(response_headers, "accept-encoding");
    }
    let Some(representation) = select_representation(request_headers, asset, range_requested)
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

    let range = if *status == StatusCode::OK
        && asset.range_requests
        && range_requested
        && if_range_matches(request_headers, representation)
    {
        match requested_range(request_headers, representation.length) {
            Ok(range) => range,
            Err(()) => {
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
    })
}

#[derive(Debug, Clone, Copy)]
struct ByteRange {
    start: u64,
    end: u64,
}

fn requested_range(headers: &HeaderMap, length: u64) -> Result<Option<ByteRange>, ()> {
    let mut values = headers.get_all(header::RANGE).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    parse_range(value.to_str().map_err(|_| ())?, length).map(Some)
}

fn parse_range(value: &str, length: u64) -> Result<ByteRange, ()> {
    let (unit, value) = value.trim().split_once('=').ok_or(())?;
    if !unit.eq_ignore_ascii_case("bytes") {
        return Err(());
    }
    let value = value.trim();
    if value.contains(',') || length == 0 {
        return Err(());
    }
    let (start, end) = value.split_once('-').ok_or(())?;
    let start = start.trim();
    let end = end.trim();
    if start.is_empty() {
        let suffix = end.parse::<u64>().map_err(|_| ())?.min(length);
        if suffix == 0 {
            return Err(());
        }
        return Ok(ByteRange {
            start: length - suffix,
            end: length - 1,
        });
    }
    let start = start.parse::<u64>().map_err(|_| ())?;
    if start >= length {
        return Err(());
    }
    let end = if end.is_empty() {
        length - 1
    } else {
        end.parse::<u64>().map_err(|_| ())?.min(length - 1)
    };
    (start <= end).then_some(ByteRange { start, end }).ok_or(())
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
    let (integer, fraction) = source.split_once('.').map_or((source, ""), |parts| parts);
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
    use std::path::PathBuf;

    use http::{HeaderMap, HeaderValue, header};
    use oxidase_site::{AssetPlan, AssetRepresentation, ContentEncoding};

    use super::{ByteRange, parse_quality, parse_range, select_representation};

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
    fn parses_single_byte_ranges() {
        assert_eq!(
            parse_range("bytes=2-5", 10).map(|range| (range.start, range.end)),
            Ok((2, 5))
        );
        assert_eq!(
            parse_range("bytes=-3", 10).map(|range| (range.start, range.end)),
            Ok((7, 9))
        );
        assert_eq!(
            parse_range("bytes=8-", 10).map(|range| (range.start, range.end)),
            Ok((8, 9))
        );
        assert!(parse_range("bytes=11-12", 10).is_err());
        assert!(parse_range("bytes=0-1,4-5", 10).is_err());
        assert!(parse_range("items=0-1", 10).is_err());
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
    fn range_forces_identity_and_respects_identity_exclusion() {
        let asset = asset();
        let selected = select_representation(&encoding_headers("br"), &asset, true)
            .expect("implicit identity remains acceptable");
        assert_eq!(selected.encoding, None);
        assert!(
            select_representation(&encoding_headers("br, identity;q=0"), &asset, true,).is_none()
        );
    }
}
