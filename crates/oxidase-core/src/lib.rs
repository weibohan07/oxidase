//! Protocol-independent language and execution-plan types for Oxidase.

pub mod diagnostic;
pub mod digest;
pub mod expression;
pub mod http_policy;
pub mod ids;
pub mod outcome;
pub mod pattern;
pub mod program;
pub mod request;
pub mod template;
pub mod value;

pub use diagnostic::{
    DIAGNOSTIC_SCHEMA_VERSION, Diagnostic, DiagnosticLabel, DiagnosticReference,
    DiagnosticSeverity, RelatedDiagnostic,
};
pub use digest::{ContentDigest, ContentDigestBuilder, ContentHasher};
pub use expression::{EvalContext, Expression, ExpressionError, PathSegment};
pub use http_policy::{is_forbidden_user_header, is_hop_by_hop_header};
pub use ids::{ConfigVersion, ListenerId, ResourceId, RouteId, ServiceId, SourceSpan};
pub use outcome::{ErrorClass, ResponseHead, ServiceError, ServiceOutcome};
pub use pattern::{CompiledPattern, PatternContext, PatternError};
pub use program::{
    CompiledMetadata, HeaderPredicate, HeaderTransform, HeaderTransforms, PredicatePlan,
    RateLimitKey, RecoverHandler, RequestTransform, RespondBody, ResponseTransform, RouteCase,
    ServiceGraph, ServiceKind, ServiceNode, ServiceProgram, ServiceProgramError,
};
pub use request::{
    Bindings, BodyState, RequestFrame, RequestMetadata, RequestMetadataError, RequestOverlay,
    TlsConnectionMetadata, parse_transform_authority, parse_transform_path_and_query,
    parse_transform_scheme,
};
pub use template::{CompiledTemplate, TemplateError};
pub use value::Value;
