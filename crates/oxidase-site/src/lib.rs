//! Oxista source compilation and immutable site resources.

mod compiler;
mod error;
mod portable;
mod runtime;
mod source;
mod template;

pub use compiler::{SiteCompiler, SiteSourceEntry, SiteSourceIndex, SiteSourceKind};
pub use error::{
    SiteCompileError, SiteCompileFailure, SiteError, TemplateArgumentError, TemplateLimitKind,
    TemplateRenderError,
};
pub use portable::{
    PORTABLE_SITE_SCHEMA_V1, PortableAssetInputV1, PortableAssetPlanV1,
    PortableAssetRepresentationV1, PortableByteRangeV1, PortableCompiledValueV1,
    PortableContentEncodingV1, PortableEntityTagV1, PortableErrorPageV1, PortableHeaderPlanV1,
    PortableHeaderPolicyLayerV1, PortableHeaderTemplateV1, PortableIncludeCallV1, PortableOxtV1,
    PortableRedirectQueryV1, PortableSiteDurationV1, PortableSiteError, PortableSiteExportV1,
    PortableSiteMissingV1, PortableSiteResponseKindV1, PortableSiteResponsePlanV1,
    PortableSiteSnapshotV1, PortableSourceSpanV1, PortableSystemTimeV1, PortableTemplateBranchV1,
    PortableTemplateLimitsV1, PortableTemplateNodeV1, PortableTemplateOutputV1,
    PortableValueTypeV1,
};
pub use runtime::{
    AssetPlan, AssetRepresentation, AssetSource, ContentEncoding, EntityTag, PreparedSiteBody,
    PreparedSiteResponse, SiteMissing, SiteSnapshot,
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
