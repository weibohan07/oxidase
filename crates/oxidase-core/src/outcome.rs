use http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    Configuration,
    Timeout,
    UpstreamConnect,
    UpstreamProtocol,
    UpstreamUnavailable,
    UpstreamOverloaded,
    SiteIo,
    TemplateLimit,
    BodyUnavailable,
    InvalidState,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceError {
    pub class: ErrorClass,
    pub public_status: StatusCode,
    pub internal_detail: String,
}

impl ServiceError {
    #[must_use]
    pub fn new(class: ErrorClass, internal_detail: impl Into<String>) -> Self {
        let public_status = match class {
            ErrorClass::Timeout => StatusCode::GATEWAY_TIMEOUT,
            ErrorClass::UpstreamConnect | ErrorClass::UpstreamProtocol => StatusCode::BAD_GATEWAY,
            ErrorClass::UpstreamUnavailable | ErrorClass::UpstreamOverloaded => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self {
            class,
            public_status,
            internal_detail: internal_detail.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use http::StatusCode;

    use super::{ErrorClass, ServiceError};

    #[test]
    fn upstream_error_classes_have_stable_default_statuses() {
        for class in [ErrorClass::UpstreamConnect, ErrorClass::UpstreamProtocol] {
            assert_eq!(
                ServiceError::new(class, "internal test detail").public_status,
                StatusCode::BAD_GATEWAY
            );
        }
        for class in [
            ErrorClass::UpstreamUnavailable,
            ErrorClass::UpstreamOverloaded,
        ] {
            assert_eq!(
                ServiceError::new(class, "internal test detail").public_status,
                StatusCode::SERVICE_UNAVAILABLE
            );
        }
        assert_eq!(
            ServiceError::new(ErrorClass::Timeout, "internal test detail").public_status,
            StatusCode::GATEWAY_TIMEOUT
        );
    }
}

#[derive(Debug, Clone)]
pub struct ResponseHead<B> {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: B,
}

impl<B> ResponseHead<B> {
    #[must_use]
    pub fn new(status: StatusCode, body: B) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            body,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ServiceOutcome<B> {
    Handled(ResponseHead<B>),
    Declined,
    Failed(ServiceError),
}

impl<B> ServiceOutcome<B> {
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Handled(_) => "handled",
            Self::Declined => "declined",
            Self::Failed(_) => "failed",
        }
    }
}
