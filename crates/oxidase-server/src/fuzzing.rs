//! Narrow, unstable access to production protocol decisions for fuzzing.
//!
//! This module is intentionally hidden and available only with the `fuzzing`
//! feature. Its API is not part of the Oxidase data-plane contract.

use http::{HeaderMap, Method, Request, StatusCode, Version};
use oxidase_config::{RetryCause, RetrySpec};

use crate::protocol::{WireProtocol, sanitize_runtime_headers};
use crate::upgrade::{UpgradeValidationError, validate_upgrade_request};

/// Applies the production hop-by-hop sanitizer. `http2` selects the receiving
/// wire protocol without exposing the server's internal protocol type.
pub fn sanitize_headers(headers: &mut HeaderMap, http2: bool) -> Result<(), &'static str> {
    let protocol = if http2 {
        WireProtocol::Http2
    } else {
        WireProtocol::Http1
    };
    sanitize_runtime_headers(headers, protocol).map_err(|_| "invalid_connection_value")
}

/// Runs the production downstream Upgrade validator and returns whether the
/// request contains a trusted Upgrade candidate.
pub fn validate_upgrade(
    method: Method,
    version: Version,
    headers: HeaderMap,
) -> Result<bool, &'static str> {
    let mut request = Request::new(());
    *request.method_mut() = method;
    *request.version_mut() = version;
    *request.headers_mut() = headers;
    validate_upgrade_request(&request)
        .map(|candidate| candidate.is_some())
        .map_err(upgrade_error_code)
}

/// Runs the exact status-range decision used before a response head is sent.
#[must_use]
pub fn retry_allows_status(retry: &RetrySpec, status: u16) -> bool {
    StatusCode::from_u16(status)
        .ok()
        .is_some_and(|status| crate::leaves::retry_allows_status(retry, status))
}

/// Runs the exact configured-cause decision used before a response head is
/// sent. Body replayability and attempt limits remain separate caller gates.
#[must_use]
pub fn retry_allows_cause(retry: &RetrySpec, cause: RetryCause) -> bool {
    crate::leaves::retry_allows_cause(retry, cause)
}

fn upgrade_error_code(error: UpgradeValidationError) -> &'static str {
    match error {
        UpgradeValidationError::ConnectUnsupported => "connect_unsupported",
        UpgradeValidationError::UnsupportedHttpVersion => "unsupported_http_version",
        UpgradeValidationError::MissingConnectionUpgrade => "missing_connection_upgrade",
        UpgradeValidationError::DuplicateConnectionUpgrade => "duplicate_connection_upgrade",
        UpgradeValidationError::InvalidConnectionValue => "invalid_connection_value",
        UpgradeValidationError::MissingUpgradeValue => "missing_upgrade_value",
        UpgradeValidationError::DuplicateUpgradeValue => "duplicate_upgrade_value",
        UpgradeValidationError::InvalidUpgradeValue => "invalid_upgrade_value",
        UpgradeValidationError::Http2UpgradeUnsupported => "http2_upgrade_unsupported",
        UpgradeValidationError::UnexpectedStatus(_) => "unexpected_status",
        UpgradeValidationError::ProtocolMismatch { .. } => "protocol_mismatch",
    }
}
