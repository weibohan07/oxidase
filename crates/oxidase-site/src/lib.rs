//! Oxista source compilation and immutable site resources.

mod compiler;
mod error;
mod runtime;
mod source;
mod template;

pub use compiler::SiteCompiler;
pub use error::{SiteCompileError, SiteError};
pub use runtime::{
    AssetPlan, CompressedAsset, PreparedSiteBody, PreparedSiteResponse, SiteMissing, SiteSnapshot,
};
pub use template::{CompiledOxt, TemplateLimits};

pub const SITE_API_VERSION: &str = "site/v1";
pub const RESPONSE_API_VERSION: &str = "response/v1";
pub const TEMPLATE_API_VERSION: &str = "template/v1";

/// Validates and normalizes a URL path using the same security boundary as Site
/// request lookup. Exposed for fuzzing and integration tooling.
pub fn validate_request_path(path: &str) -> Result<String, SiteError> {
    runtime::normalize_request_path(path)
}
