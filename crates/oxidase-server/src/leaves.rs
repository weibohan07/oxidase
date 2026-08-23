use std::sync::Arc;

use bytes::Bytes;
use futures_util::TryStreamExt;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Incoming;
use oxidase_core::{
    ErrorClass, RequestFrame, ResourceId, ResponseHead, ServiceError, ServiceOutcome,
};
use oxidase_runtime::{BoxLeafFuture, LeafExecutor, RuntimeSnapshot};
use oxidase_site::{AssetPlan, PreparedSiteBody, PreparedSiteResponse, SiteError};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;

use crate::body::{BoxError, GatewayBodyPlan};

pub(crate) struct HyperLeaves {
    snapshot: Arc<RuntimeSnapshot>,
}

impl HyperLeaves {
    pub(crate) fn new(snapshot: Arc<RuntimeSnapshot>) -> Self {
        Self { snapshot }
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
        _request: &'a RequestFrame,
        _body: &'a mut Option<Incoming>,
    ) -> BoxLeafFuture<'a, GatewayBodyPlan> {
        Box::pin(async move {
            ServiceOutcome::Failed(ServiceError::new(
                ErrorClass::UpstreamConnect,
                format!("Proxy cluster `{cluster}` is not enabled in the listener phase"),
            ))
        })
    }
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
        return Ok(GatewayBodyPlan::Empty);
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
    Ok(GatewayBodyPlan::Stream(
        StreamBody::new(stream).boxed_unsync(),
    ))
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
