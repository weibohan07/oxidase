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
