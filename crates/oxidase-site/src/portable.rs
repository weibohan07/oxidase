//! Stable, source-free Oxista runtime representation for portable Bundles.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::str::FromStr as _;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::{HeaderName, HeaderValue, StatusCode};
use oxidase_core::{
    CompiledTemplate, ContentDigest, Expression, PortableValueV1, ResourceId, SourceSpan,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::compiler::validate_template_graph;
use crate::runtime::{
    AssetPlan, AssetRepresentation, AssetSource, ContentEncoding, EntityTag, ErrorPagePlan,
    HeaderPlan, HeaderPolicyLayer, RedirectQuery, SiteMissing, SiteResponseKind, SiteResponsePlan,
    SiteSnapshot, normalize_request_path,
};
use crate::template::{
    CompiledOxt, CompiledValue, IncludeCall, TemplateLimits, TemplateNode, TemplateOutput,
    ValueType, normalize_template_name, validate_binding, validate_local_binding,
};

pub const PORTABLE_SITE_SCHEMA_V1: &str = "oxidase.oxista-compiled/v1";

const MAX_TEMPLATES: usize = 100_000;
const MAX_ENTRIES: usize = 1_000_000;
const MAX_TEMPLATE_NODES: usize = 1_000_000;

/// A stable compiled Site plan. It contains no YAML or OXT source document and
/// can be reconstructed without invoking either source parser.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableSiteSnapshotV1 {
    pub schema_version: String,
    pub id: ResourceId,
    pub missing: PortableSiteMissingV1,
    pub data: BTreeMap<String, PortableValueV1>,
    pub limits: PortableTemplateLimitsV1,
    pub templates: BTreeMap<String, PortableOxtV1>,
    pub entries: BTreeMap<String, PortableSiteResponsePlanV1>,
    pub error_404: Option<PortableErrorPageV1>,
}

/// Non-serializable build input paired with a portable Site plan. Asset bytes
/// remain on disk (or in a prior Bundle slice) so a Bundle writer can stream
/// them exactly once into its content-addressed blob table.
#[derive(Debug, Clone)]
pub struct PortableSiteExportV1 {
    pub snapshot: PortableSiteSnapshotV1,
    pub assets: BTreeMap<String, PortableAssetInputV1>,
}

#[derive(Debug, Clone)]
pub struct PortableAssetInputV1 {
    pub source: AssetSource,
    pub digest: ContentDigest,
    pub length: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableSiteMissingV1 {
    Decline,
    Respond,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableTemplateLimitsV1 {
    pub render_time: PortableSiteDurationV1,
    pub output_size: u64,
    pub loop_iterations: u64,
    pub include_depth: u64,
    pub expression_steps: u64,
    pub strict_undefined: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableSiteDurationV1 {
    pub seconds: u64,
    pub nanoseconds: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableOxtV1 {
    pub name: String,
    pub nodes: Vec<PortableTemplateNodeV1>,
    pub params: BTreeMap<String, PortableValueTypeV1>,
    pub param_spans: BTreeMap<String, PortableSourceSpanV1>,
    pub autoescape_html: bool,
    pub output: PortableTemplateOutputV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PortableTemplateNodeV1 {
    Text {
        value: String,
    },
    Interpolation {
        expression: String,
    },
    If {
        branches: Vec<PortableTemplateBranchV1>,
        otherwise: Vec<Self>,
    },
    For {
        binding: String,
        values: String,
        body: Vec<Self>,
        otherwise: Vec<Self>,
    },
    With {
        binding: String,
        value: String,
        body: Vec<Self>,
    },
    Include {
        call: PortableIncludeCallV1,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableTemplateBranchV1 {
    pub condition: String,
    pub body: Vec<PortableTemplateNodeV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableIncludeCallV1 {
    pub name: String,
    pub arguments: BTreeMap<String, String>,
    pub only: bool,
    pub span: PortableSourceSpanV1,
    pub target_span: PortableSourceSpanV1,
    pub argument_spans: BTreeMap<String, PortableSourceSpanV1>,
    pub target_range: PortableByteRangeV1,
    pub argument_ranges: BTreeMap<String, PortableByteRangeV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableByteRangeV1 {
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableTemplateOutputV1 {
    Html,
    Text,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PortableValueTypeV1 {
    Any { optional: bool },
    Null,
    Bool { optional: bool },
    Int { optional: bool },
    Float { optional: bool },
    String { optional: bool },
    Url { optional: bool },
    List { item: Box<Self>, optional: bool },
    Map { item: Box<Self>, optional: bool },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PortableCompiledValueV1 {
    Constant { value: PortableValueV1 },
    Expression { source: String },
    Template { source: String },
    List { values: Vec<Self> },
    Map { values: BTreeMap<String, Self> },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableSiteResponsePlanV1 {
    pub status: u16,
    pub headers: PortableHeaderPlanV1,
    pub content_type: Option<String>,
    pub page: BTreeMap<String, PortableCompiledValueV1>,
    pub kind: PortableSiteResponseKindV1,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PortableSiteResponseKindV1 {
    Asset {
        plan: Box<PortableAssetPlanV1>,
    },
    Empty,
    Text {
        template: String,
    },
    Json {
        value: PortableCompiledValueV1,
    },
    Template {
        name: String,
        arguments: BTreeMap<String, PortableCompiledValueV1>,
    },
    Redirect {
        status: u16,
        location: String,
        query: PortableRedirectQueryV1,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableRedirectQueryV1 {
    Drop,
    Preserve,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableHeaderPlanV1 {
    pub layers: Vec<PortableHeaderPolicyLayerV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableHeaderPolicyLayerV1 {
    pub set: Vec<PortableHeaderTemplateV1>,
    pub add: Vec<PortableHeaderTemplateV1>,
    pub remove: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableHeaderTemplateV1 {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableAssetPlanV1 {
    pub identity: PortableAssetRepresentationV1,
    pub brotli: Option<PortableAssetRepresentationV1>,
    pub gzip: Option<PortableAssetRepresentationV1>,
    pub content_type: String,
    pub range_requests: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableAssetRepresentationV1 {
    pub encoding: Option<PortableContentEncodingV1>,
    pub asset_key: String,
    pub length: u64,
    pub digest: ContentDigest,
    pub etag: Option<PortableEntityTagV1>,
    pub modified: Option<PortableSystemTimeV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableContentEncodingV1 {
    Brotli,
    Gzip,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableEntityTagV1 {
    pub weak: bool,
    pub opaque: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "relation", rename_all = "snake_case", deny_unknown_fields)]
pub enum PortableSystemTimeV1 {
    AfterEpoch { seconds: u64, nanoseconds: u32 },
    BeforeEpoch { seconds: u64, nanoseconds: u32 },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableErrorPageV1 {
    pub template: String,
    pub headers: PortableHeaderPlanV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableSourceSpanV1 {
    pub file: String,
    pub start_byte: u64,
    pub end_byte: u64,
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
    pub field_path: String,
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct PortableSiteError {
    code: &'static str,
    message: String,
}

impl PortableSiteError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Creates a safe error at the archive-to-data-plane resolution boundary.
    /// Bundle loaders use this when a declared content key is absent, corrupt,
    /// or cannot be mapped to an immutable backing file.
    #[must_use]
    pub fn asset_resolution(message: impl Into<String>) -> Self {
        Self::new("bundle.asset_resolution", message)
    }

    /// Preserves a stable Bundle-loader diagnostic code while crossing the
    /// asset resolver callback boundary.
    ///
    /// The callback cannot return the CLI's error type directly because the
    /// portable Site layer is independent from the CLI. Keeping the static
    /// code here prevents path-policy failures such as deployment-root escape
    /// from being flattened into the generic asset-resolution code.
    #[must_use]
    pub fn asset_resolution_with_code(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(code, message)
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl SiteSnapshot {
    /// Exports this already-compiled Site without embedding source documents or
    /// reading Asset bytes. The returned content-key table lets the archive
    /// layer stream/deduplicate each representation independently.
    pub fn export_portable(&self) -> Result<PortableSiteExportV1, PortableSiteError> {
        if self.templates.len() > MAX_TEMPLATES {
            return Err(PortableSiteError::new(
                "bundle.site_limit",
                format!("Site contains more than {MAX_TEMPLATES} compiled templates"),
            ));
        }
        if self.entries.len() > MAX_ENTRIES {
            return Err(PortableSiteError::new(
                "bundle.site_limit",
                format!("Site contains more than {MAX_ENTRIES} public entries"),
            ));
        }
        let virtual_root = format!("<site:{}>", self.id);
        let mut assets = BTreeMap::new();
        let templates = self
            .templates
            .iter()
            .map(|(name, template)| {
                Ok((
                    name.clone(),
                    PortableOxtV1::from_compiled(template, &self.root, &virtual_root)?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, PortableSiteError>>()?;
        let entries = self
            .entries
            .iter()
            .map(|(path, plan)| {
                Ok((
                    path.clone(),
                    PortableSiteResponsePlanV1::from_plan(
                        plan,
                        &self.root,
                        &virtual_root,
                        &mut assets,
                    )?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, PortableSiteError>>()?;
        let error_404 = self
            .error_404
            .as_ref()
            .map(|error| {
                Ok(PortableErrorPageV1 {
                    template: error.template.clone(),
                    headers: PortableHeaderPlanV1::from_plan(&error.headers),
                })
            })
            .transpose()?;
        Ok(PortableSiteExportV1 {
            snapshot: PortableSiteSnapshotV1 {
                schema_version: PORTABLE_SITE_SCHEMA_V1.to_owned(),
                id: self.id.clone(),
                missing: match self.missing {
                    SiteMissing::Decline => PortableSiteMissingV1::Decline,
                    SiteMissing::Respond => PortableSiteMissingV1::Respond,
                },
                data: self
                    .data
                    .iter()
                    .map(|(name, value)| (name.clone(), PortableValueV1::from_value(value)))
                    .collect(),
                limits: PortableTemplateLimitsV1::from_limits(&self.limits)?,
                templates,
                entries,
                error_404,
            },
            assets,
        })
    }
}

impl PortableTemplateLimitsV1 {
    fn from_limits(limits: &TemplateLimits) -> Result<Self, PortableSiteError> {
        Ok(Self {
            render_time: PortableSiteDurationV1::from_duration(limits.render_time),
            output_size: portable_usize(limits.output_size, "limits.output_size")?,
            loop_iterations: portable_usize(limits.loop_iterations, "limits.loop_iterations")?,
            include_depth: portable_usize(limits.include_depth, "limits.include_depth")?,
            expression_steps: portable_usize(limits.expression_steps, "limits.expression_steps")?,
            strict_undefined: limits.strict_undefined,
        })
    }
}

impl PortableSiteDurationV1 {
    const fn from_duration(duration: Duration) -> Self {
        Self {
            seconds: duration.as_secs(),
            nanoseconds: duration.subsec_nanos(),
        }
    }
}

impl PortableOxtV1 {
    fn from_compiled(
        template: &CompiledOxt,
        root: &Path,
        virtual_root: &str,
    ) -> Result<Self, PortableSiteError> {
        let mut node_count = 0_usize;
        let nodes = template
            .nodes
            .iter()
            .map(|node| {
                PortableTemplateNodeV1::from_node(node, root, virtual_root, &mut node_count)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if node_count > MAX_TEMPLATE_NODES {
            return Err(PortableSiteError::new(
                "bundle.site_limit",
                format!(
                    "template `{}` exceeds {MAX_TEMPLATE_NODES} compiled nodes",
                    template.name
                ),
            ));
        }
        Ok(Self {
            name: template.name.clone(),
            nodes,
            params: template
                .params
                .iter()
                .map(|(name, kind)| (name.clone(), PortableValueTypeV1::from_type(kind)))
                .collect(),
            param_spans: template
                .param_spans
                .iter()
                .map(|(name, span)| {
                    Ok((
                        name.clone(),
                        PortableSourceSpanV1::from_span(span, root, virtual_root)?,
                    ))
                })
                .collect::<Result<_, PortableSiteError>>()?,
            autoescape_html: template.autoescape_html,
            output: match template.output {
                TemplateOutput::Html => PortableTemplateOutputV1::Html,
                TemplateOutput::Text => PortableTemplateOutputV1::Text,
                TemplateOutput::Json => PortableTemplateOutputV1::Json,
            },
        })
    }
}

impl PortableTemplateNodeV1 {
    fn from_node(
        node: &TemplateNode,
        root: &Path,
        virtual_root: &str,
        count: &mut usize,
    ) -> Result<Self, PortableSiteError> {
        *count = count.saturating_add(1);
        Ok(match node {
            TemplateNode::Text(value) => Self::Text {
                value: value.clone(),
            },
            TemplateNode::Interpolation(expression) => Self::Interpolation {
                expression: expression.source().to_owned(),
            },
            TemplateNode::If {
                branches,
                otherwise,
            } => Self::If {
                branches: branches
                    .iter()
                    .map(|(condition, body)| {
                        Ok(PortableTemplateBranchV1 {
                            condition: condition.source().to_owned(),
                            body: export_nodes(body, root, virtual_root, count)?,
                        })
                    })
                    .collect::<Result<_, PortableSiteError>>()?,
                otherwise: export_nodes(otherwise, root, virtual_root, count)?,
            },
            TemplateNode::For {
                binding,
                values,
                body,
                otherwise,
            } => Self::For {
                binding: binding.clone(),
                values: values.source().to_owned(),
                body: export_nodes(body, root, virtual_root, count)?,
                otherwise: export_nodes(otherwise, root, virtual_root, count)?,
            },
            TemplateNode::With {
                binding,
                value,
                body,
            } => Self::With {
                binding: binding.clone(),
                value: value.source().to_owned(),
                body: export_nodes(body, root, virtual_root, count)?,
            },
            TemplateNode::Include(call) => Self::Include {
                call: PortableIncludeCallV1::from_call(call, root, virtual_root)?,
            },
        })
    }
}

fn export_nodes(
    nodes: &[TemplateNode],
    root: &Path,
    virtual_root: &str,
    count: &mut usize,
) -> Result<Vec<PortableTemplateNodeV1>, PortableSiteError> {
    nodes
        .iter()
        .map(|node| PortableTemplateNodeV1::from_node(node, root, virtual_root, count))
        .collect()
}

impl PortableIncludeCallV1 {
    fn from_call(
        call: &IncludeCall,
        root: &Path,
        virtual_root: &str,
    ) -> Result<Self, PortableSiteError> {
        Ok(Self {
            name: call.name.clone(),
            arguments: call
                .arguments
                .iter()
                .map(|(name, value)| (name.clone(), value.source().to_owned()))
                .collect(),
            only: call.only,
            span: PortableSourceSpanV1::from_span(&call.span, root, virtual_root)?,
            target_span: PortableSourceSpanV1::from_span(&call.target_span, root, virtual_root)?,
            argument_spans: call
                .argument_spans
                .iter()
                .map(|(name, span)| {
                    Ok((
                        name.clone(),
                        PortableSourceSpanV1::from_span(span, root, virtual_root)?,
                    ))
                })
                .collect::<Result<_, PortableSiteError>>()?,
            target_range: PortableByteRangeV1::from_range(call.target_range)?,
            argument_ranges: call
                .argument_ranges
                .iter()
                .map(|(name, range)| Ok((name.clone(), PortableByteRangeV1::from_range(*range)?)))
                .collect::<Result<_, PortableSiteError>>()?,
        })
    }
}

impl PortableByteRangeV1 {
    fn from_range(range: (usize, usize)) -> Result<Self, PortableSiteError> {
        Ok(Self {
            start: portable_usize(range.0, "template.range.start")?,
            end: portable_usize(range.1, "template.range.end")?,
        })
    }
}

impl PortableValueTypeV1 {
    fn from_type(kind: &ValueType) -> Self {
        match kind {
            ValueType::Any { optional } => Self::Any {
                optional: *optional,
            },
            ValueType::Null => Self::Null,
            ValueType::Bool { optional } => Self::Bool {
                optional: *optional,
            },
            ValueType::Int { optional } => Self::Int {
                optional: *optional,
            },
            ValueType::Float { optional } => Self::Float {
                optional: *optional,
            },
            ValueType::String { optional } => Self::String {
                optional: *optional,
            },
            ValueType::Url { optional } => Self::Url {
                optional: *optional,
            },
            ValueType::List { item, optional } => Self::List {
                item: Box::new(Self::from_type(item)),
                optional: *optional,
            },
            ValueType::Map { item, optional } => Self::Map {
                item: Box::new(Self::from_type(item)),
                optional: *optional,
            },
        }
    }
}

impl PortableCompiledValueV1 {
    fn from_value(value: &CompiledValue) -> Self {
        match value {
            CompiledValue::Constant(value) => Self::Constant {
                value: PortableValueV1::from_value(value),
            },
            CompiledValue::Expression(expression) => Self::Expression {
                source: expression.source().to_owned(),
            },
            CompiledValue::Template(template) => Self::Template {
                source: template.source().to_owned(),
            },
            CompiledValue::List(values) => Self::List {
                values: values.iter().map(Self::from_value).collect(),
            },
            CompiledValue::Map(values) => Self::Map {
                values: values
                    .iter()
                    .map(|(name, value)| (name.clone(), Self::from_value(value)))
                    .collect(),
            },
        }
    }
}

impl PortableSiteResponsePlanV1 {
    fn from_plan(
        plan: &SiteResponsePlan,
        root: &Path,
        virtual_root: &str,
        assets: &mut BTreeMap<String, PortableAssetInputV1>,
    ) -> Result<Self, PortableSiteError> {
        let status = match &plan.kind {
            SiteResponseKind::Redirect { status, .. } => *status,
            _ => plan.status,
        };
        Ok(Self {
            status: status.as_u16(),
            headers: PortableHeaderPlanV1::from_plan(&plan.headers),
            content_type: plan.content_type.clone(),
            page: plan
                .page
                .iter()
                .map(|(name, value)| (name.clone(), PortableCompiledValueV1::from_value(value)))
                .collect(),
            kind: PortableSiteResponseKindV1::from_kind(&plan.kind, assets)?,
            source: portable_path(root, virtual_root, &plan.source),
        })
    }
}

impl PortableSiteResponseKindV1 {
    fn from_kind(
        kind: &SiteResponseKind,
        assets: &mut BTreeMap<String, PortableAssetInputV1>,
    ) -> Result<Self, PortableSiteError> {
        Ok(match kind {
            SiteResponseKind::Asset(plan) => Self::Asset {
                plan: Box::new(PortableAssetPlanV1::from_plan(plan, assets)?),
            },
            SiteResponseKind::Empty => Self::Empty,
            SiteResponseKind::Text(template) => Self::Text {
                template: template.source().to_owned(),
            },
            SiteResponseKind::Json(value) => Self::Json {
                value: PortableCompiledValueV1::from_value(value),
            },
            SiteResponseKind::Template { name, arguments } => Self::Template {
                name: name.clone(),
                arguments: arguments
                    .iter()
                    .map(|(name, value)| (name.clone(), PortableCompiledValueV1::from_value(value)))
                    .collect(),
            },
            SiteResponseKind::Redirect {
                status,
                location,
                query,
            } => Self::Redirect {
                status: status.as_u16(),
                location: location.source().to_owned(),
                query: match query {
                    RedirectQuery::Drop => PortableRedirectQueryV1::Drop,
                    RedirectQuery::Preserve => PortableRedirectQueryV1::Preserve,
                },
            },
        })
    }
}

impl PortableHeaderPlanV1 {
    fn from_plan(plan: &HeaderPlan) -> Self {
        Self {
            layers: plan
                .layers
                .iter()
                .map(|layer| PortableHeaderPolicyLayerV1 {
                    set: layer
                        .set
                        .iter()
                        .map(|(name, value)| PortableHeaderTemplateV1 {
                            name: name.as_str().to_owned(),
                            value: value.source().to_owned(),
                        })
                        .collect(),
                    add: layer
                        .add
                        .iter()
                        .map(|(name, value)| PortableHeaderTemplateV1 {
                            name: name.as_str().to_owned(),
                            value: value.source().to_owned(),
                        })
                        .collect(),
                    remove: layer
                        .remove
                        .iter()
                        .map(|name| name.as_str().to_owned())
                        .collect(),
                })
                .collect(),
        }
    }
}

impl PortableAssetPlanV1 {
    fn from_plan(
        plan: &AssetPlan,
        assets: &mut BTreeMap<String, PortableAssetInputV1>,
    ) -> Result<Self, PortableSiteError> {
        Ok(Self {
            identity: PortableAssetRepresentationV1::from_representation(&plan.identity, assets)?,
            brotli: plan
                .brotli
                .as_ref()
                .map(|representation| {
                    PortableAssetRepresentationV1::from_representation(representation, assets)
                })
                .transpose()?,
            gzip: plan
                .gzip
                .as_ref()
                .map(|representation| {
                    PortableAssetRepresentationV1::from_representation(representation, assets)
                })
                .transpose()?,
            content_type: plan.content_type.clone(),
            range_requests: plan.range_requests,
        })
    }
}

impl PortableAssetRepresentationV1 {
    fn from_representation(
        representation: &AssetRepresentation,
        assets: &mut BTreeMap<String, PortableAssetInputV1>,
    ) -> Result<Self, PortableSiteError> {
        let asset_key = format!("sha256-{}", representation.digest);
        if let Some(existing) = assets.get(&asset_key) {
            if existing.digest != representation.digest || existing.length != representation.length
            {
                return Err(PortableSiteError::new(
                    "bundle.asset_identity",
                    format!("asset key `{asset_key}` maps to inconsistent content metadata"),
                ));
            }
        } else {
            assets.insert(
                asset_key.clone(),
                PortableAssetInputV1 {
                    source: representation.source.clone(),
                    digest: representation.digest,
                    length: representation.length,
                },
            );
        }
        Ok(Self {
            encoding: representation.encoding.map(|encoding| match encoding {
                ContentEncoding::Brotli => PortableContentEncodingV1::Brotli,
                ContentEncoding::Gzip => PortableContentEncodingV1::Gzip,
            }),
            asset_key,
            length: representation.length,
            digest: representation.digest,
            etag: representation
                .etag
                .as_ref()
                .map(|etag| PortableEntityTagV1 {
                    weak: etag.is_weak(),
                    opaque: etag.opaque().to_owned(),
                }),
            modified: representation.modified.map(PortableSystemTimeV1::from_time),
        })
    }
}

impl PortableSystemTimeV1 {
    fn from_time(time: SystemTime) -> Self {
        match time.duration_since(UNIX_EPOCH) {
            Ok(duration) => Self::AfterEpoch {
                seconds: duration.as_secs(),
                nanoseconds: duration.subsec_nanos(),
            },
            Err(error) => {
                let duration = error.duration();
                Self::BeforeEpoch {
                    seconds: duration.as_secs(),
                    nanoseconds: duration.subsec_nanos(),
                }
            }
        }
    }
}

impl PortableSourceSpanV1 {
    fn from_span(
        span: &SourceSpan,
        root: &Path,
        virtual_root: &str,
    ) -> Result<Self, PortableSiteError> {
        Ok(Self {
            file: portable_path(root, virtual_root, &span.file),
            start_byte: portable_usize(span.start_byte, "source_span.start_byte")?,
            end_byte: portable_usize(span.end_byte, "source_span.end_byte")?,
            start_line: portable_u32(span.line, "source_span.start_line")?,
            start_column: portable_u32(span.column, "source_span.start_column")?,
            end_line: portable_u32(span.end_line, "source_span.end_line")?,
            end_column: portable_u32(span.end_column, "source_span.end_column")?,
            field_path: span.field_path.clone(),
        })
    }
}

fn portable_path(root: &Path, virtual_root: &str, path: &Path) -> String {
    let suffix = path
        .strip_prefix(root)
        .ok()
        .filter(|suffix| !suffix.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .or_else(|| path.file_name().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("source"));
    PathBuf::from(virtual_root)
        .join(suffix)
        .to_string_lossy()
        .replace('\\', "/")
}

fn portable_usize(value: usize, field: &'static str) -> Result<u64, PortableSiteError> {
    u64::try_from(value).map_err(|_| {
        PortableSiteError::new(
            "bundle.site_integer",
            format!("{field} does not fit the portable unsigned integer range"),
        )
    })
}

fn portable_u32(value: usize, field: &'static str) -> Result<u32, PortableSiteError> {
    u32::try_from(value).map_err(|_| {
        PortableSiteError::new(
            "bundle.site_integer",
            format!("{field} does not fit the portable 32-bit source-position range"),
        )
    })
}

impl PortableSiteSnapshotV1 {
    /// Reconstructs a compiled Site directly from the stable plan. The caller
    /// resolves each content key to either a verified external file or an
    /// immutable Bundle slice; no source document is parsed here.
    pub fn compile_with_assets<F>(
        &self,
        mut resolve_asset: F,
    ) -> Result<SiteSnapshot, PortableSiteError>
    where
        F: FnMut(&str, ContentDigest, u64) -> Result<AssetSource, PortableSiteError>,
    {
        if self.schema_version != PORTABLE_SITE_SCHEMA_V1 {
            return Err(PortableSiteError::new(
                "bundle.site_schema",
                format!(
                    "unsupported compiled Site schema `{}`; expected `{PORTABLE_SITE_SCHEMA_V1}`",
                    self.schema_version
                ),
            ));
        }
        if self.templates.len() > MAX_TEMPLATES {
            return Err(PortableSiteError::new(
                "bundle.site_limit",
                format!("compiled Site exceeds the {MAX_TEMPLATES} template limit"),
            ));
        }
        if self.entries.len() > MAX_ENTRIES {
            return Err(PortableSiteError::new(
                "bundle.site_limit",
                format!("compiled Site exceeds the {MAX_ENTRIES} entry limit"),
            ));
        }
        let mut templates = BTreeMap::new();
        for (key, source) in &self.templates {
            let normalized = normalize_template_name(key).map_err(|error| {
                PortableSiteError::new("bundle.template_identity", error.to_string())
            })?;
            if normalized != *key {
                return Err(PortableSiteError::new(
                    "bundle.template_identity",
                    format!("template name `{key}` is not canonical"),
                ));
            }
            if key != &source.name {
                return Err(PortableSiteError::new(
                    "bundle.template_identity",
                    format!("template map key `{key}` does not match `{}`", source.name),
                ));
            }
            let compiled = source.compile()?;
            if templates.insert(key.clone(), compiled).is_some() {
                return Err(PortableSiteError::new(
                    "bundle.template_duplicate",
                    format!("duplicate compiled template `{key}`"),
                ));
            }
        }
        validate_template_graph(&templates)
            .map_err(|error| PortableSiteError::new("bundle.template_graph", error.to_string()))?;

        let entries = self
            .entries
            .iter()
            .map(|(path, plan)| {
                validate_public_path(path)?;
                Ok((path.clone(), plan.compile(&mut resolve_asset)?))
            })
            .collect::<Result<BTreeMap<_, _>, PortableSiteError>>()?;
        validate_response_template_references(&entries, &templates)?;
        let error_404 = self
            .error_404
            .as_ref()
            .map(|error| {
                let template = templates.get(&error.template).ok_or_else(|| {
                    PortableSiteError::new(
                        "bundle.template_reference",
                        format!("404 template `{}` does not exist", error.template),
                    )
                })?;
                template
                    .validate_arguments_at(
                        &BTreeMap::new(),
                        SourceSpan::synthetic("errors[\"404\"].template"),
                        &BTreeMap::new(),
                    )
                    .map_err(|failure| {
                        PortableSiteError::new("bundle.template_arguments", failure.to_string())
                    })?;
                Ok(ErrorPagePlan {
                    template: error.template.clone(),
                    headers: error.headers.compile()?,
                })
            })
            .transpose()?;
        let root = PathBuf::from(format!("<bundle-site:{}>", self.id));
        Ok(SiteSnapshot {
            id: self.id.clone(),
            manifest: root.join("site.oxsite"),
            root,
            dependencies: Vec::new(),
            missing: match self.missing {
                PortableSiteMissingV1::Decline => SiteMissing::Decline,
                PortableSiteMissingV1::Respond => SiteMissing::Respond,
            },
            data: self
                .data
                .iter()
                .map(|(name, value)| (name.clone(), value.compile()))
                .collect(),
            limits: self.limits.compile()?,
            templates,
            entries,
            error_404,
        })
    }
}

impl PortableTemplateLimitsV1 {
    fn compile(&self) -> Result<TemplateLimits, PortableSiteError> {
        Ok(TemplateLimits {
            render_time: self.render_time.compile("limits.render_time")?,
            output_size: runtime_usize(self.output_size, "limits.output_size")?,
            loop_iterations: runtime_usize(self.loop_iterations, "limits.loop_iterations")?,
            include_depth: runtime_usize(self.include_depth, "limits.include_depth")?,
            expression_steps: runtime_usize(self.expression_steps, "limits.expression_steps")?,
            strict_undefined: self.strict_undefined,
        })
    }
}

impl PortableSiteDurationV1 {
    fn compile(&self, field: &'static str) -> Result<Duration, PortableSiteError> {
        if self.nanoseconds >= 1_000_000_000 {
            return Err(PortableSiteError::new(
                "bundle.site_duration",
                format!("{field} nanoseconds must be below one billion"),
            ));
        }
        Ok(Duration::new(self.seconds, self.nanoseconds))
    }
}

impl PortableOxtV1 {
    fn compile(&self) -> Result<CompiledOxt, PortableSiteError> {
        if self.output == PortableTemplateOutputV1::Json {
            return Err(PortableSiteError::new(
                "bundle.template_output",
                "compiled OXT JSON output is not supported",
            ));
        }
        let mut node_count = 0_usize;
        let nodes = compile_nodes(&self.nodes, &self.name, &mut node_count)?;
        if node_count > MAX_TEMPLATE_NODES {
            return Err(PortableSiteError::new(
                "bundle.site_limit",
                format!(
                    "template `{}` exceeds {MAX_TEMPLATE_NODES} compiled nodes",
                    self.name
                ),
            ));
        }
        let mut params = BTreeMap::new();
        for (name, kind) in &self.params {
            validate_binding(name, &self.name).map_err(|error| {
                PortableSiteError::new("bundle.template_parameter", error.to_string())
            })?;
            validate_local_binding(name, &self.name).map_err(|error| {
                PortableSiteError::new("bundle.template_parameter", error.to_string())
            })?;
            params.insert(name.clone(), kind.compile());
        }
        if self.param_spans.keys().collect::<BTreeSet<_>>()
            != params.keys().collect::<BTreeSet<_>>()
        {
            return Err(PortableSiteError::new(
                "bundle.template_parameter",
                format!(
                    "template `{}` parameter spans do not match its contract",
                    self.name
                ),
            ));
        }
        let dependencies = collect_dependencies(&nodes);
        Ok(CompiledOxt {
            name: self.name.clone(),
            nodes,
            params,
            param_spans: self
                .param_spans
                .iter()
                .map(|(name, span)| Ok((name.clone(), span.compile()?)))
                .collect::<Result<_, PortableSiteError>>()?,
            autoescape_html: self.autoescape_html,
            output: match self.output {
                PortableTemplateOutputV1::Html => TemplateOutput::Html,
                PortableTemplateOutputV1::Text => TemplateOutput::Text,
                PortableTemplateOutputV1::Json => unreachable!("rejected above"),
            },
            dependencies,
        })
    }
}

fn compile_nodes(
    nodes: &[PortableTemplateNodeV1],
    template: &str,
    count: &mut usize,
) -> Result<Vec<TemplateNode>, PortableSiteError> {
    nodes
        .iter()
        .map(|node| node.compile(template, count))
        .collect()
}

impl PortableTemplateNodeV1 {
    fn compile(
        &self,
        template: &str,
        count: &mut usize,
    ) -> Result<TemplateNode, PortableSiteError> {
        *count = count.saturating_add(1);
        if *count > MAX_TEMPLATE_NODES {
            return Err(PortableSiteError::new(
                "bundle.site_limit",
                format!("template `{template}` exceeds the compiled node limit"),
            ));
        }
        Ok(match self {
            Self::Text { value } => TemplateNode::Text(value.clone()),
            Self::Interpolation { expression } => {
                TemplateNode::Interpolation(compile_expression(expression, template)?)
            }
            Self::If {
                branches,
                otherwise,
            } => TemplateNode::If {
                branches: branches
                    .iter()
                    .map(|branch| {
                        Ok((
                            compile_expression(&branch.condition, template)?,
                            compile_nodes(&branch.body, template, count)?,
                        ))
                    })
                    .collect::<Result<_, PortableSiteError>>()?,
                otherwise: compile_nodes(otherwise, template, count)?,
            },
            Self::For {
                binding,
                values,
                body,
                otherwise,
            } => {
                validate_local_binding(binding, template).map_err(|error| {
                    PortableSiteError::new("bundle.template_binding", error.to_string())
                })?;
                TemplateNode::For {
                    binding: binding.clone(),
                    values: compile_expression(values, template)?,
                    body: compile_nodes(body, template, count)?,
                    otherwise: compile_nodes(otherwise, template, count)?,
                }
            }
            Self::With {
                binding,
                value,
                body,
            } => {
                validate_local_binding(binding, template).map_err(|error| {
                    PortableSiteError::new("bundle.template_binding", error.to_string())
                })?;
                TemplateNode::With {
                    binding: binding.clone(),
                    value: compile_expression(value, template)?,
                    body: compile_nodes(body, template, count)?,
                }
            }
            Self::Include { call } => TemplateNode::Include(call.compile(template)?),
        })
    }
}

impl PortableIncludeCallV1 {
    fn compile(&self, template: &str) -> Result<IncludeCall, PortableSiteError> {
        let normalized = normalize_template_name(&self.name).map_err(|error| {
            PortableSiteError::new("bundle.template_reference", error.to_string())
        })?;
        if normalized != self.name {
            return Err(PortableSiteError::new(
                "bundle.template_reference",
                format!("include target `{}` is not canonical", self.name),
            ));
        }
        let argument_names = self.arguments.keys().collect::<BTreeSet<_>>();
        if argument_names != self.argument_spans.keys().collect::<BTreeSet<_>>()
            || argument_names != self.argument_ranges.keys().collect::<BTreeSet<_>>()
        {
            return Err(PortableSiteError::new(
                "bundle.template_argument",
                "include argument values, spans, and byte ranges do not have identical names",
            ));
        }
        for name in self.arguments.keys() {
            validate_local_binding(name, template).map_err(|error| {
                PortableSiteError::new("bundle.template_argument", error.to_string())
            })?;
        }
        Ok(IncludeCall {
            name: self.name.clone(),
            arguments: self
                .arguments
                .iter()
                .map(|(name, source)| Ok((name.clone(), compile_expression(source, template)?)))
                .collect::<Result<_, PortableSiteError>>()?,
            only: self.only,
            span: self.span.compile()?,
            target_span: self.target_span.compile()?,
            argument_spans: self
                .argument_spans
                .iter()
                .map(|(name, span)| Ok((name.clone(), span.compile()?)))
                .collect::<Result<_, PortableSiteError>>()?,
            target_range: self.target_range.compile("include.target_range")?,
            argument_ranges: self
                .argument_ranges
                .iter()
                .map(|(name, range)| Ok((name.clone(), range.compile("include.argument_range")?)))
                .collect::<Result<_, PortableSiteError>>()?,
        })
    }
}

impl PortableByteRangeV1 {
    fn compile(&self, field: &'static str) -> Result<(usize, usize), PortableSiteError> {
        if self.start > self.end {
            return Err(PortableSiteError::new(
                "bundle.template_range",
                format!("{field} starts after it ends"),
            ));
        }
        Ok((
            runtime_usize(self.start, field)?,
            runtime_usize(self.end, field)?,
        ))
    }
}

impl PortableValueTypeV1 {
    fn compile(&self) -> ValueType {
        match self {
            Self::Any { optional } => ValueType::Any {
                optional: *optional,
            },
            Self::Null => ValueType::Null,
            Self::Bool { optional } => ValueType::Bool {
                optional: *optional,
            },
            Self::Int { optional } => ValueType::Int {
                optional: *optional,
            },
            Self::Float { optional } => ValueType::Float {
                optional: *optional,
            },
            Self::String { optional } => ValueType::String {
                optional: *optional,
            },
            Self::Url { optional } => ValueType::Url {
                optional: *optional,
            },
            Self::List { item, optional } => ValueType::List {
                item: Box::new(item.compile()),
                optional: *optional,
            },
            Self::Map { item, optional } => ValueType::Map {
                item: Box::new(item.compile()),
                optional: *optional,
            },
        }
    }
}

fn collect_dependencies(nodes: &[TemplateNode]) -> BTreeSet<String> {
    fn collect(nodes: &[TemplateNode], output: &mut BTreeSet<String>) {
        for node in nodes {
            match node {
                TemplateNode::Text(_) | TemplateNode::Interpolation(_) => {}
                TemplateNode::If {
                    branches,
                    otherwise,
                } => {
                    for (_, body) in branches {
                        collect(body, output);
                    }
                    collect(otherwise, output);
                }
                TemplateNode::For {
                    body, otherwise, ..
                } => {
                    collect(body, output);
                    collect(otherwise, output);
                }
                TemplateNode::With { body, .. } => collect(body, output),
                TemplateNode::Include(call) => {
                    output.insert(call.name.clone());
                }
            }
        }
    }
    let mut output = BTreeSet::new();
    collect(nodes, &mut output);
    output
}

fn compile_expression(source: &str, template: &str) -> Result<Expression, PortableSiteError> {
    Expression::compile(source).map_err(|error| {
        PortableSiteError::new(
            "bundle.template_expression",
            format!("template `{template}` contains an invalid expression: {error}"),
        )
    })
}

impl PortableCompiledValueV1 {
    fn compile(&self, field: &'static str) -> Result<CompiledValue, PortableSiteError> {
        Ok(match self {
            Self::Constant { value } => CompiledValue::Constant(value.compile()),
            Self::Expression { source } => {
                CompiledValue::Expression(compile_expression(source, field)?)
            }
            Self::Template { source } => {
                CompiledValue::Template(CompiledTemplate::compile(source).map_err(|error| {
                    PortableSiteError::new(
                        "bundle.site_template",
                        format!("{field} contains an invalid template: {error}"),
                    )
                })?)
            }
            Self::List { values } => CompiledValue::List(
                values
                    .iter()
                    .map(|value| value.compile(field))
                    .collect::<Result<_, _>>()?,
            ),
            Self::Map { values } => CompiledValue::Map(
                values
                    .iter()
                    .map(|(name, value)| Ok((name.clone(), value.compile(field)?)))
                    .collect::<Result<_, PortableSiteError>>()?,
            ),
        })
    }
}

impl PortableSiteResponsePlanV1 {
    fn compile<F>(&self, resolve_asset: &mut F) -> Result<SiteResponsePlan, PortableSiteError>
    where
        F: FnMut(&str, ContentDigest, u64) -> Result<AssetSource, PortableSiteError>,
    {
        let source = PathBuf::from(&self.source);
        let source_span = SourceSpan {
            file: source.clone(),
            start_byte: 0,
            end_byte: 0,
            line: 1,
            column: 1,
            end_line: 1,
            end_column: 1,
            field_path: "site.response.source".to_owned(),
        };
        source_span
            .validate_portable()
            .map_err(|message| PortableSiteError::new("bundle.site_source", message))?;
        if let Some(content_type) = &self.content_type {
            HeaderValue::from_str(content_type).map_err(|_| {
                PortableSiteError::new(
                    "bundle.site_content_type",
                    "compiled Site content type is not a valid HTTP header value",
                )
            })?;
        }
        let status = parse_status(self.status, "response.status")?;
        let kind = self.kind.compile(resolve_asset)?;
        if let SiteResponseKind::Redirect {
            status: redirect_status,
            ..
        } = &kind
            && *redirect_status != status
        {
            return Err(PortableSiteError::new(
                "bundle.site_redirect",
                "compiled redirect status disagrees with its response status",
            ));
        }
        Ok(SiteResponsePlan {
            status,
            headers: self.headers.compile()?,
            content_type: self.content_type.clone(),
            page: self
                .page
                .iter()
                .map(|(name, value)| Ok((name.clone(), value.compile("response.page")?)))
                .collect::<Result<_, PortableSiteError>>()?,
            kind,
            source,
        })
    }
}

impl PortableSiteResponseKindV1 {
    fn compile<F>(&self, resolve_asset: &mut F) -> Result<SiteResponseKind, PortableSiteError>
    where
        F: FnMut(&str, ContentDigest, u64) -> Result<AssetSource, PortableSiteError>,
    {
        Ok(match self {
            Self::Asset { plan } => SiteResponseKind::Asset(Box::new(plan.compile(resolve_asset)?)),
            Self::Empty => SiteResponseKind::Empty,
            Self::Text { template } => {
                SiteResponseKind::Text(CompiledTemplate::compile(template).map_err(|error| {
                    PortableSiteError::new(
                        "bundle.site_template",
                        format!("text response contains an invalid template: {error}"),
                    )
                })?)
            }
            Self::Json { value } => SiteResponseKind::Json(value.compile("response.json")?),
            Self::Template { name, arguments } => SiteResponseKind::Template {
                name: name.clone(),
                arguments: arguments
                    .iter()
                    .map(|(name, value)| {
                        Ok((name.clone(), value.compile("response.template.arguments")?))
                    })
                    .collect::<Result<_, PortableSiteError>>()?,
            },
            Self::Redirect {
                status,
                location,
                query,
            } => {
                let status = parse_status(*status, "response.redirect.status")?;
                if !status.is_redirection() {
                    return Err(PortableSiteError::new(
                        "bundle.site_redirect",
                        "compiled redirect status must be in the 3xx range",
                    ));
                }
                SiteResponseKind::Redirect {
                    status,
                    location: CompiledTemplate::compile(location).map_err(|error| {
                        PortableSiteError::new(
                            "bundle.site_template",
                            format!("redirect location contains an invalid template: {error}"),
                        )
                    })?,
                    query: match query {
                        PortableRedirectQueryV1::Drop => RedirectQuery::Drop,
                        PortableRedirectQueryV1::Preserve => RedirectQuery::Preserve,
                    },
                }
            }
        })
    }
}

impl PortableHeaderPlanV1 {
    fn compile(&self) -> Result<HeaderPlan, PortableSiteError> {
        Ok(HeaderPlan {
            layers: self
                .layers
                .iter()
                .map(PortableHeaderPolicyLayerV1::compile)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl PortableHeaderPolicyLayerV1 {
    fn compile(&self) -> Result<HeaderPolicyLayer, PortableSiteError> {
        Ok(HeaderPolicyLayer {
            set: self
                .set
                .iter()
                .map(|header| header.compile("headers.set"))
                .collect::<Result<_, _>>()?,
            add: self
                .add
                .iter()
                .map(|header| header.compile("headers.add"))
                .collect::<Result<_, _>>()?,
            remove: self
                .remove
                .iter()
                .map(|name| compile_header_name(name, "headers.remove"))
                .collect::<Result<_, _>>()?,
        })
    }
}

impl PortableHeaderTemplateV1 {
    fn compile(
        &self,
        field: &'static str,
    ) -> Result<(HeaderName, CompiledTemplate), PortableSiteError> {
        Ok((
            compile_header_name(&self.name, field)?,
            CompiledTemplate::compile(&self.value).map_err(|error| {
                PortableSiteError::new(
                    "bundle.site_header_template",
                    format!("{field} contains an invalid Header template: {error}"),
                )
            })?,
        ))
    }
}

fn compile_header_name(name: &str, field: &'static str) -> Result<HeaderName, PortableSiteError> {
    let name = HeaderName::from_str(name).map_err(|_| {
        PortableSiteError::new(
            "bundle.site_header_name",
            format!("{field} contains invalid Header name `{name}`"),
        )
    })?;
    if oxidase_core::is_forbidden_user_header(&name) {
        return Err(PortableSiteError::new(
            "bundle.site_header_policy",
            format!("{field} attempts to control protected Header `{name}`"),
        ));
    }
    Ok(name)
}

impl PortableAssetPlanV1 {
    fn compile<F>(&self, resolve_asset: &mut F) -> Result<AssetPlan, PortableSiteError>
    where
        F: FnMut(&str, ContentDigest, u64) -> Result<AssetSource, PortableSiteError>,
    {
        HeaderValue::from_str(&self.content_type).map_err(|_| {
            PortableSiteError::new(
                "bundle.site_content_type",
                "compiled Asset content type is not a valid HTTP header value",
            )
        })?;
        let identity = self.identity.compile(resolve_asset)?;
        if identity.encoding.is_some() {
            return Err(PortableSiteError::new(
                "bundle.asset_encoding",
                "identity representation cannot carry a content encoding",
            ));
        }
        let brotli = self
            .brotli
            .as_ref()
            .map(|representation| representation.compile(resolve_asset))
            .transpose()?;
        if brotli
            .as_ref()
            .is_some_and(|representation| representation.encoding != Some(ContentEncoding::Brotli))
        {
            return Err(PortableSiteError::new(
                "bundle.asset_encoding",
                "Brotli slot must contain a Brotli representation",
            ));
        }
        let gzip = self
            .gzip
            .as_ref()
            .map(|representation| representation.compile(resolve_asset))
            .transpose()?;
        if gzip
            .as_ref()
            .is_some_and(|representation| representation.encoding != Some(ContentEncoding::Gzip))
        {
            return Err(PortableSiteError::new(
                "bundle.asset_encoding",
                "gzip slot must contain a gzip representation",
            ));
        }
        Ok(AssetPlan {
            identity,
            brotli,
            gzip,
            content_type: self.content_type.clone(),
            range_requests: self.range_requests,
        })
    }
}

impl PortableAssetRepresentationV1 {
    fn compile<F>(&self, resolve_asset: &mut F) -> Result<AssetRepresentation, PortableSiteError>
    where
        F: FnMut(&str, ContentDigest, u64) -> Result<AssetSource, PortableSiteError>,
    {
        let expected_key = format!("sha256-{}", self.digest);
        if self.asset_key != expected_key {
            return Err(PortableSiteError::new(
                "bundle.asset_identity",
                format!(
                    "asset key `{}` does not match its content digest",
                    self.asset_key
                ),
            ));
        }
        let etag = self
            .etag
            .as_ref()
            .map(PortableEntityTagV1::compile)
            .transpose()?;
        if etag
            .as_ref()
            .is_some_and(|etag| etag.opaque() != format!("sha256-{}", self.digest))
        {
            return Err(PortableSiteError::new(
                "bundle.asset_etag",
                "compiled Asset ETag does not identify its representation bytes",
            ));
        }
        let modified = self
            .modified
            .as_ref()
            .map(PortableSystemTimeV1::compile)
            .transpose()?;
        let source = resolve_asset(&self.asset_key, self.digest, self.length)?;
        Ok(AssetRepresentation {
            encoding: self.encoding.map(|encoding| match encoding {
                PortableContentEncodingV1::Brotli => ContentEncoding::Brotli,
                PortableContentEncodingV1::Gzip => ContentEncoding::Gzip,
            }),
            source,
            length: self.length,
            digest: self.digest,
            etag,
            modified,
        })
    }
}

impl PortableEntityTagV1 {
    fn compile(&self) -> Result<EntityTag, PortableSiteError> {
        let source = if self.weak {
            format!("W/\"{}\"", self.opaque)
        } else {
            format!("\"{}\"", self.opaque)
        };
        EntityTag::parse(&source).ok_or_else(|| {
            PortableSiteError::new(
                "bundle.asset_etag",
                "compiled Asset contains an invalid entity tag",
            )
        })
    }
}

impl PortableSystemTimeV1 {
    fn compile(&self) -> Result<SystemTime, PortableSiteError> {
        let (after, seconds, nanoseconds) = match *self {
            Self::AfterEpoch {
                seconds,
                nanoseconds,
            } => (true, seconds, nanoseconds),
            Self::BeforeEpoch {
                seconds,
                nanoseconds,
            } => (false, seconds, nanoseconds),
        };
        if nanoseconds >= 1_000_000_000 {
            return Err(PortableSiteError::new(
                "bundle.asset_modified",
                "Asset modification nanoseconds must be below one billion",
            ));
        }
        let duration = Duration::new(seconds, nanoseconds);
        if after {
            UNIX_EPOCH.checked_add(duration)
        } else {
            UNIX_EPOCH.checked_sub(duration)
        }
        .ok_or_else(|| {
            PortableSiteError::new(
                "bundle.asset_modified",
                "Asset modification time is outside the supported system range",
            )
        })
    }
}

impl PortableSourceSpanV1 {
    fn compile(&self) -> Result<SourceSpan, PortableSiteError> {
        if self.start_byte > self.end_byte {
            return Err(PortableSiteError::new(
                "bundle.source_span",
                "source span starts after it ends",
            ));
        }
        if self.start_line == 0
            || self.start_column == 0
            || self.end_line == 0
            || self.end_column == 0
        {
            return Err(PortableSiteError::new(
                "bundle.source_span",
                "source span line and column positions are one-based",
            ));
        }
        let span = SourceSpan {
            file: PathBuf::from(&self.file),
            start_byte: runtime_usize(self.start_byte, "source_span.start_byte")?,
            end_byte: runtime_usize(self.end_byte, "source_span.end_byte")?,
            line: runtime_usize(u64::from(self.start_line), "source_span.start_line")?,
            column: runtime_usize(u64::from(self.start_column), "source_span.start_column")?,
            end_line: runtime_usize(u64::from(self.end_line), "source_span.end_line")?,
            end_column: runtime_usize(u64::from(self.end_column), "source_span.end_column")?,
            field_path: self.field_path.clone(),
        };
        span.validate_portable()
            .map_err(|message| PortableSiteError::new("bundle.source_span", message))?;
        Ok(span)
    }
}

fn parse_status(value: u16, field: &'static str) -> Result<StatusCode, PortableSiteError> {
    StatusCode::from_u16(value).map_err(|error| {
        PortableSiteError::new(
            "bundle.site_status",
            format!("{field} is not a valid HTTP status: {error}"),
        )
    })
}

fn validate_public_path(path: &str) -> Result<(), PortableSiteError> {
    let normalized = normalize_request_path(path).map_err(|error| {
        PortableSiteError::new(
            "bundle.site_path",
            format!("compiled Site entry `{path}` is invalid: {error}"),
        )
    })?;
    if normalized != path {
        return Err(PortableSiteError::new(
            "bundle.site_path",
            format!("compiled Site entry `{path}` is not a normalized public path"),
        ));
    }
    Ok(())
}

fn validate_response_template_references(
    entries: &BTreeMap<String, SiteResponsePlan>,
    templates: &BTreeMap<String, CompiledOxt>,
) -> Result<(), PortableSiteError> {
    for (path, plan) in entries {
        let SiteResponseKind::Template { name, arguments } = &plan.kind else {
            continue;
        };
        let template = templates.get(name).ok_or_else(|| {
            PortableSiteError::new(
                "bundle.template_reference",
                format!("Site entry `{path}` references missing template `{name}`"),
            )
        })?;
        template
            .validate_arguments_at(
                arguments,
                SourceSpan::synthetic(format!("entries[{path:?}].template")),
                &BTreeMap::new(),
            )
            .map_err(|error| {
                PortableSiteError::new("bundle.template_argument", error.to_string())
            })?;
    }
    Ok(())
}

fn runtime_usize(value: u64, field: &'static str) -> Result<usize, PortableSiteError> {
    usize::try_from(value).map_err(|_| {
        PortableSiteError::new(
            "bundle.site_integer",
            format!("{field} exceeds this runtime's addressable range"),
        )
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;

    use http::{HeaderMap, Method, StatusCode};
    use oxidase_core::{RequestFrame, RequestMetadata, ResourceId};
    use tempfile::tempdir;

    use super::{PORTABLE_SITE_SCHEMA_V1, PortableSiteSnapshotV1};
    use crate::{AssetSource, PreparedSiteBody, SiteCompiler};

    fn write_fixture() -> (tempfile::TempDir, crate::SiteSnapshot) {
        let directory = tempdir().expect("temporary directory exists");
        let root = directory.path().join("site");
        fs::create_dir_all(root.join("_templates")).expect("template directory can be created");
        fs::write(
            root.join("site.oxsite"),
            r#"oxista: site/v1
paths:
  indexes: []
  missing: respond
assets:
  range_requests: true
  etag: strong
  last_modified: true
  precompressed:
    brotli: .br
    gzip: .gz
templates:
  roots: [_templates]
  strict_undefined: true
  default_output: text
  default_autoescape: none
  limits:
    render_time: 25ms
    output_size: 1MiB
    loop_iterations: 100
    include_depth: 8
    expression_steps: 1000
defaults:
  response:
    headers:
      set:
        X-Site-Policy: portable
errors:
  404:
    template: _templates/404.oxt
"#,
        )
        .expect("manifest can be written");
        fs::write(
            root.join("_templates/leaf.oxt"),
            r#"---
oxista: template/v1
output: text
params:
  value: string
---
{{ value }}"#,
        )
        .expect("leaf template can be written");
        fs::write(
            root.join("_templates/page.oxt"),
            r#"---
oxista: template/v1
output: text
---
before:{% include "_templates/leaf.oxt" with value=request.path only %}:after"#,
        )
        .expect("page template can be written");
        fs::write(
            root.join("_templates/404.oxt"),
            r#"---
oxista: template/v1
output: text
---
missing {{ request.path }}"#,
        )
        .expect("404 template can be written");
        fs::write(
            root.join("page.txt.oxr"),
            r#"---
oxista: response/v1
response:
  headers:
    set:
      X-Page: "{{ request.path }}"
  body:
    template:
      source: _templates/page.oxt
---
"#,
        )
        .expect("response source can be written");
        fs::write(root.join("asset.bin"), b"identity-content")
            .expect("identity Asset can be written");
        fs::write(root.join("asset.bin.br"), b"brotli-content")
            .expect("Brotli Asset can be written");
        fs::write(root.join("asset.bin.gz"), b"gzip-content").expect("gzip Asset can be written");

        let snapshot = SiteCompiler::compile(
            ResourceId::new("site:web"),
            &root,
            root.join("site.oxsite"),
            BTreeMap::new(),
        )
        .expect("fixture Site compiles");
        (directory, snapshot)
    }

    fn request(path: &str) -> RequestFrame {
        RequestFrame::new(
            RequestMetadata::try_new(Method::GET, "http", "example.test", path, HeaderMap::new())
                .expect("fixture request is valid"),
        )
    }

    #[test]
    fn compiled_site_round_trips_without_source_parsing_and_preserves_behavior() {
        let (directory, original) = write_fixture();
        let first = original.export_portable().expect("Site exports");
        let second = original.export_portable().expect("Site exports repeatedly");
        let first_bytes = serde_json::to_vec(&first.snapshot).expect("portable Site serializes");
        let second_bytes = serde_json::to_vec(&second.snapshot).expect("portable Site serializes");
        assert_eq!(first_bytes, second_bytes, "stable output is deterministic");
        let encoded = String::from_utf8(first_bytes.clone()).expect("JSON is UTF-8");
        assert!(!encoded.contains("oxista: site/v1"));
        assert!(!encoded.contains("oxista: response/v1"));
        assert!(!encoded.contains("oxista: template/v1"));
        assert!(
            !encoded.contains(&directory.path().to_string_lossy().to_string()),
            "portable diagnostics must not depend on the build working directory"
        );
        assert_eq!(first.snapshot.schema_version, PORTABLE_SITE_SCHEMA_V1);
        assert_eq!(
            first.assets.len(),
            3,
            "three representations are content keyed"
        );

        let decoded: PortableSiteSnapshotV1 =
            serde_json::from_slice(&first_bytes).expect("portable Site decodes");
        let pinned_path = directory.path().join("pinned.oxb");
        fs::write(&pinned_path, vec![0_u8; 32 * 1024]).expect("pinned fixture can be written");
        let mut calls = Vec::new();
        let restored = decoded
            .compile_with_assets(|key, digest, length| {
                calls.push((key.to_owned(), digest, length));
                Ok(AssetSource::pinned(
                    std::fs::File::open(&pinned_path).expect("pinned fixture opens"),
                    pinned_path.clone(),
                    (calls.len() as u64) * 4096,
                ))
            })
            .expect("portable Site reconstructs");
        assert_eq!(calls.len(), 3, "resolver is called once per representation");
        assert!(calls.iter().all(|(key, digest, _)| {
            key == &format!("sha256-{digest}") && first.assets.contains_key(key)
        }));

        let original_page = original
            .execute(&request("/page.txt"))
            .expect("original page executes")
            .expect("page is handled");
        let restored_page = restored
            .execute(&request("/page.txt"))
            .expect("restored page executes")
            .expect("page is handled");
        assert_eq!(restored_page.status, original_page.status);
        assert_eq!(restored_page.headers, original_page.headers);
        let (PreparedSiteBody::Bytes(original_body), PreparedSiteBody::Bytes(restored_body)) =
            (original_page.body, restored_page.body)
        else {
            panic!("template responses are materialized bytes")
        };
        assert_eq!(restored_body, original_body);
        assert_eq!(restored_body, "before:/page.txt:after");

        let missing = restored
            .execute(&request("/does-not-exist"))
            .expect("restored 404 executes")
            .expect("404 is handled");
        assert_eq!(missing.status, StatusCode::NOT_FOUND);
        assert_eq!(missing.headers["x-site-policy"], "portable");
        let PreparedSiteBody::Bytes(body) = missing.body else {
            panic!("404 template is materialized bytes")
        };
        assert_eq!(body, "missing /does-not-exist");

        let asset = restored
            .execute(&request("/asset.bin"))
            .expect("restored Asset executes")
            .expect("Asset is handled");
        let PreparedSiteBody::Asset(asset) = asset.body else {
            panic!("ordinary Asset remains streaming")
        };
        assert!(matches!(asset.identity.source, AssetSource::Pinned { .. }));
        assert!(matches!(
            asset.brotli.as_ref().map(|value| &value.source),
            Some(AssetSource::Pinned { .. })
        ));
        assert!(matches!(
            asset.gzip.as_ref().map(|value| &value.source),
            Some(AssetSource::Pinned { .. })
        ));
    }

    #[test]
    fn portable_site_json_is_strict_and_tampered_expressions_fail_before_publication() {
        let (_directory, original) = write_fixture();
        let exported = original.export_portable().expect("Site exports");
        let mut value = serde_json::to_value(&exported.snapshot).expect("Site serializes");
        value
            .as_object_mut()
            .expect("portable Site is an object")
            .insert("unknown".to_owned(), serde_json::Value::Bool(true));
        let error = serde_json::from_value::<PortableSiteSnapshotV1>(value)
            .expect_err("unknown portable fields are rejected");
        assert!(error.to_string().contains("unknown field"));

        let mut unsafe_span = exported.snapshot.clone();
        unsafe_span
            .templates
            .get_mut("_templates/leaf.oxt")
            .expect("leaf template exists")
            .param_spans
            .get_mut("value")
            .expect("parameter span exists")
            .file = "/absolute/template.oxt".to_owned();
        let error = unsafe_span
            .compile_with_assets(|key, _, _| {
                Ok(AssetSource::File(PathBuf::from(format!("asset-{key}"))))
            })
            .expect_err("absolute portable template spans are rejected");
        assert_eq!(error.code(), "bundle.source_span");

        let mut unsafe_response_source = exported.snapshot.clone();
        unsafe_response_source
            .entries
            .get_mut("/page.txt")
            .expect("page entry exists")
            .source = "/private/compiler/path/page.oxr".to_owned();
        let error = unsafe_response_source
            .compile_with_assets(|key, _, _| {
                Ok(AssetSource::File(PathBuf::from(format!("asset-{key}"))))
            })
            .expect_err("absolute response source paths are rejected");
        assert_eq!(error.code(), "bundle.site_source");

        let mut mismatched_redirect = exported.snapshot.clone();
        let response = mismatched_redirect
            .entries
            .get_mut("/page.txt")
            .expect("page entry exists");
        response.status = StatusCode::OK.as_u16();
        response.kind = super::PortableSiteResponseKindV1::Redirect {
            status: StatusCode::FOUND.as_u16(),
            location: "/elsewhere".to_owned(),
            query: super::PortableRedirectQueryV1::Drop,
        };
        let error = mismatched_redirect
            .compile_with_assets(|key, _, _| {
                Ok(AssetSource::File(PathBuf::from(format!("asset-{key}"))))
            })
            .expect_err("redirect status aliases cannot disagree");
        assert_eq!(error.code(), "bundle.site_redirect");

        let mut empty_with_content_type = exported.snapshot.clone();
        let response = empty_with_content_type
            .entries
            .get_mut("/page.txt")
            .expect("page entry exists");
        response.kind = super::PortableSiteResponseKindV1::Empty;
        response.content_type = Some("application/example".to_owned());
        let restored = empty_with_content_type
            .compile_with_assets(|key, _, _| {
                Ok(AssetSource::File(PathBuf::from(format!("asset-{key}"))))
            })
            .expect("explicit Empty content type has runtime semantics");
        let prepared = restored
            .execute(&request("/page.txt"))
            .expect("empty response executes")
            .expect("empty response is handled");
        assert_eq!(
            prepared.headers[http::header::CONTENT_TYPE],
            "application/example"
        );

        let mut tampered = exported.snapshot;
        let page = tampered
            .templates
            .get_mut("_templates/page.oxt")
            .expect("page template exists");
        page.nodes = vec![super::PortableTemplateNodeV1::Interpolation {
            expression: "request.[".to_owned(),
        }];
        let error = tampered
            .compile_with_assets(|key, _, _| {
                Ok(AssetSource::File(PathBuf::from(format!("asset-{key}"))))
            })
            .expect_err("invalid stable expression must fail before publication");
        assert_eq!(error.code(), "bundle.template_expression");

        let mut invalid_404 = original.export_portable().expect("Site exports").snapshot;
        invalid_404
            .error_404
            .as_mut()
            .expect("fixture has a 404 template")
            .template = "_templates/leaf.oxt".to_owned();
        let error = invalid_404
            .compile_with_assets(|key, _, _| {
                Ok(AssetSource::File(PathBuf::from(format!("asset-{key}"))))
            })
            .expect_err("a 404 template with required arguments must fail activation");
        assert_eq!(error.code(), "bundle.template_arguments");
    }
}
