//! Protocol-independent language and execution-plan types for Oxidase.

pub mod expression;
pub mod http_policy;
pub mod ids;
pub mod outcome;
pub mod pattern;
pub mod program;
pub mod request;
pub mod template;
pub mod value;

pub use expression::{EvalContext, Expression, ExpressionError, PathSegment};
pub use http_policy::{is_forbidden_user_header, is_hop_by_hop_header};
pub use ids::{ConfigVersion, ListenerId, ResourceId, RouteId, ServiceId, SourceSpan};
pub use outcome::{ErrorClass, ResponseHead, ServiceError, ServiceOutcome};
pub use pattern::{CompiledPattern, PatternContext, PatternError};
pub use program::{
    HeaderPredicate, HeaderTransform, HeaderTransforms, PredicatePlan, RecoverHandler,
    RequestTransform, RespondBody, ResponseTransform, RouteCase, ServiceGraph, ServiceKind,
    ServiceNode, ServiceProgram, ServiceProgramError,
};
pub use request::{Bindings, BodyState, RequestFrame, RequestMetadata, RequestOverlay};
pub use template::{CompiledTemplate, TemplateError};
pub use value::Value;
