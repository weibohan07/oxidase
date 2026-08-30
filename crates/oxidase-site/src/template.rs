use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use oxidase_core::expression::html_escape;
use oxidase_core::{Diagnostic, EvalContext, Expression, SourceSpan, Value};
use oxidase_source::FieldSpanIndex;

use crate::source::{AutoescapeSource, OutputSource, OxtMetadataSource};
use crate::{SiteCompileError, TemplateArgumentError, TemplateLimitKind, TemplateRenderError};

#[derive(Debug, Clone)]
pub struct TemplateLimits {
    pub render_time: Duration,
    pub output_size: usize,
    pub loop_iterations: usize,
    pub include_depth: usize,
    pub expression_steps: usize,
    pub strict_undefined: bool,
}

#[derive(Debug, Clone)]
pub struct CompiledOxt {
    pub(crate) name: String,
    nodes: Vec<TemplateNode>,
    params: BTreeMap<String, ValueType>,
    param_spans: BTreeMap<String, SourceSpan>,
    autoescape_html: bool,
    output: TemplateOutput,
    dependencies: BTreeSet<String>,
}

const PUBLIC_TEMPLATE_ROOTS: [&str; 5] = ["request", "bindings", "site", "resource", "page"];

#[derive(Debug, Clone)]
struct TemplateContext {
    public_roots: Arc<EvalContext>,
    current: EvalContext,
}

impl TemplateContext {
    fn new(public_roots: EvalContext) -> Self {
        let public_roots = Arc::new(public_roots.without_scopes());
        Self {
            current: public_roots.as_ref().clone(),
            public_roots,
        }
    }

    fn with_scope(&self, values: BTreeMap<String, Value>) -> Self {
        Self {
            public_roots: self.public_roots.clone(),
            current: self.current.with_scope(values),
        }
    }

    fn only(&self) -> Self {
        Self {
            public_roots: self.public_roots.clone(),
            current: self.public_roots.as_ref().clone(),
        }
    }

    const fn values(&self) -> &EvalContext {
        &self.current
    }
}

impl CompiledOxt {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn compile(
        name: impl Into<String>,
        source_path: impl Into<PathBuf>,
        metadata: &OxtMetadataSource,
        metadata_spans: Option<&FieldSpanIndex>,
        source: &str,
        source_origin: (usize, usize),
        default_output: OutputSource,
        default_autoescape: Option<AutoescapeSource>,
    ) -> Result<Self, SiteCompileError> {
        let name = name.into();
        let source_path = source_path.into();
        let output = TemplateOutput::from(metadata.output.unwrap_or(default_output));
        if output == TemplateOutput::Json {
            return Err(SiteCompileError::at(
                "template.output",
                template_metadata_span(&source_path, metadata_spans, "output", false),
                "OXT `output: json` is not supported because text templates cannot guarantee valid JSON; use an OXR structured JSON body",
            ));
        }
        let mut params = BTreeMap::new();
        let mut param_spans = BTreeMap::new();
        for (parameter, kind) in &metadata.params {
            let field_path = template_field_child("params", parameter);
            validate_binding(parameter, &name).map_err(|error| {
                SiteCompileError::at(
                    "template.parameter",
                    template_metadata_span(&source_path, metadata_spans, &field_path, true),
                    error.to_string(),
                )
            })?;
            validate_local_binding(parameter, &name).map_err(|error| {
                SiteCompileError::at(
                    "template.parameter",
                    template_metadata_span(&source_path, metadata_spans, &field_path, true),
                    error.to_string(),
                )
            })?;
            let kind = ValueType::parse(kind).map_err(|message| {
                SiteCompileError::at(
                    "template.parameter_type",
                    template_metadata_span(&source_path, metadata_spans, &field_path, false),
                    message,
                )
            })?;
            param_spans.insert(
                parameter.clone(),
                template_metadata_span(&source_path, metadata_spans, &field_path, false),
            );
            params.insert(parameter.clone(), kind);
        }
        Self::compile_parts(
            name,
            source_path,
            params,
            param_spans,
            metadata
                .autoescape
                .or(default_autoescape)
                .is_some_and(|value| matches!(value, AutoescapeSource::Html))
                || metadata.autoescape.is_none()
                    && default_autoescape.is_none()
                    && output == TemplateOutput::Html,
            output,
            source,
            source_origin,
        )
    }

    #[cfg(test)]
    pub(crate) fn inline(
        name: impl Into<String>,
        source: &str,
        autoescape_html: bool,
    ) -> Result<Self, SiteCompileError> {
        let name = name.into();
        Self::compile_parts(
            name.clone(),
            PathBuf::from(name),
            BTreeMap::new(),
            BTreeMap::new(),
            autoescape_html,
            TemplateOutput::Html,
            source,
            (0, 0),
        )
    }

    pub(crate) fn inline_with_output(
        name: impl Into<String>,
        source_path: impl Into<PathBuf>,
        source: &str,
        source_origin: (usize, usize),
        output: OutputSource,
        autoescape: Option<AutoescapeSource>,
    ) -> Result<Self, SiteCompileError> {
        let name = name.into();
        let source_path = source_path.into();
        let output = TemplateOutput::from(output);
        if output == TemplateOutput::Json {
            return Err(SiteCompileError::source(
                name,
                "inline template `output: json` is not supported; use an OXR structured JSON body",
            ));
        }
        Self::compile_parts(
            name.clone(),
            source_path,
            BTreeMap::new(),
            BTreeMap::new(),
            autoescape.is_some_and(|value| matches!(value, AutoescapeSource::Html))
                || autoescape.is_none() && output == TemplateOutput::Html,
            output,
            source,
            source_origin,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn compile_parts(
        name: String,
        source_path: PathBuf,
        params: BTreeMap<String, ValueType>,
        param_spans: BTreeMap<String, SourceSpan>,
        autoescape_html: bool,
        output: TemplateOutput,
        source: &str,
        source_origin: (usize, usize),
    ) -> Result<Self, SiteCompileError> {
        let tokens = tokenize(&source_path, source, source_origin.0, source_origin.1)
            .map_err(|error| SiteCompileError::at("template.syntax", error.span, error.message))?;
        let (nodes, stop, dependencies) = {
            let mut parser = TemplateParser {
                name: &name,
                tokens: &tokens,
                position: 0,
                dependencies: BTreeSet::new(),
            };
            let (nodes, stop) = parser.parse_nodes(&[])?;
            (nodes, stop, parser.dependencies)
        };
        if let Some(stop) = stop {
            return Err(SiteCompileError::source(
                &name,
                format!("unexpected template tag `{stop}`"),
            ));
        }
        Ok(Self {
            name,
            nodes,
            params,
            param_spans,
            autoescape_html,
            output,
            dependencies,
        })
    }

    pub(crate) fn dependencies(&self) -> &BTreeSet<String> {
        &self.dependencies
    }

    pub(crate) fn validate_include_contracts(
        &self,
        templates: &BTreeMap<String, Self>,
    ) -> Result<(), SiteCompileError> {
        validate_include_nodes(&self.nodes, templates)
    }

    pub(crate) fn include_span(&self, target: &str) -> Option<&SourceSpan> {
        find_include_span(&self.nodes, target)
    }

    pub(crate) const fn content_type(&self) -> &'static str {
        match self.output {
            TemplateOutput::Html => "text/html; charset=utf-8",
            TemplateOutput::Text => "text/plain; charset=utf-8",
            TemplateOutput::Json => "application/json",
        }
    }

    pub(crate) fn validate_arguments_at(
        &self,
        arguments: &BTreeMap<String, CompiledValue>,
        call_span: SourceSpan,
        argument_spans: &BTreeMap<String, SourceSpan>,
    ) -> Result<(), SiteCompileError> {
        for (name, kind) in &self.params {
            let Some(argument) = arguments.get(name) else {
                if kind.optional() {
                    continue;
                }
                let mut diagnostic = Diagnostic::new(
                    "template.argument_missing",
                    format!("missing required template parameter `{name}`"),
                    call_span.clone(),
                );
                if let Some(declaration) = self.param_spans.get(name) {
                    diagnostic = diagnostic.with_related(
                        format!("parameter `{name}` is declared here"),
                        declaration.clone(),
                    );
                }
                return Err(SiteCompileError::from_diagnostic(diagnostic));
            };
            if let Some(value) = argument.constant_value()
                && !kind.accepts(value)
            {
                let mut diagnostic = Diagnostic::new(
                    "template.argument_type",
                    format!(
                        "parameter `{name}` expects {}, received {}",
                        kind.describe(),
                        value.type_name()
                    ),
                    argument_spans
                        .get(name)
                        .cloned()
                        .unwrap_or_else(|| call_span.clone()),
                );
                if let Some(declaration) = self.param_spans.get(name) {
                    diagnostic = diagnostic.with_related(
                        format!("parameter `{name}` is declared here"),
                        declaration.clone(),
                    );
                }
                return Err(SiteCompileError::from_diagnostic(diagnostic));
            }
        }
        for name in arguments.keys() {
            if !self.params.contains_key(name) {
                return Err(SiteCompileError::at(
                    "template.argument_unknown",
                    argument_spans
                        .get(name)
                        .cloned()
                        .unwrap_or_else(|| call_span.clone()),
                    format!("unknown template parameter `{name}`"),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn evaluate_arguments(
        &self,
        arguments: &BTreeMap<String, CompiledValue>,
        context: &EvalContext,
    ) -> Result<BTreeMap<String, Value>, TemplateArgumentError> {
        let mut values = BTreeMap::new();
        for (name, kind) in &self.params {
            let Some(argument) = arguments.get(name) else {
                if kind.optional() {
                    values.insert(name.clone(), Value::Null);
                    continue;
                }
                return Err(TemplateArgumentError::Missing {
                    template: self.name.clone(),
                    parameter: name.clone(),
                    expected: kind.describe().to_owned(),
                });
            };
            let value = argument.evaluate(context).map_err(|message| {
                TemplateArgumentError::Evaluation {
                    template: self.name.clone(),
                    parameter: name.clone(),
                    message,
                }
            })?;
            if !kind.accepts(&value) {
                return Err(TemplateArgumentError::Type {
                    template: self.name.clone(),
                    parameter: name.clone(),
                    expected: kind.describe().to_owned(),
                    actual: kind.actual_description(&value),
                });
            }
            values.insert(name.clone(), value);
        }
        for name in arguments.keys() {
            if !self.params.contains_key(name) {
                return Err(TemplateArgumentError::Unknown {
                    template: self.name.clone(),
                    parameter: name.clone(),
                });
            }
        }
        Ok(values)
    }

    pub(crate) fn render(
        &self,
        templates: &BTreeMap<String, Self>,
        context: &EvalContext,
        limits: &TemplateLimits,
    ) -> Result<String, TemplateRenderError> {
        self.render_with_arguments(templates, context, &BTreeMap::new(), limits)
    }

    pub(crate) fn render_with_arguments(
        &self,
        templates: &BTreeMap<String, Self>,
        public_context: &EvalContext,
        arguments: &BTreeMap<String, Value>,
        limits: &TemplateLimits,
    ) -> Result<String, TemplateRenderError> {
        let context = TemplateContext::new(public_context.clone()).with_scope(arguments.clone());
        let mut budget = RenderBudget::new();
        render_template(self, templates, &context, limits, 0, &mut budget)?;
        Ok(budget.output)
    }
}

#[derive(Debug, Clone)]
enum TemplateNode {
    Text(String),
    Interpolation(Expression),
    If {
        branches: Vec<(Expression, Vec<Self>)>,
        otherwise: Vec<Self>,
    },
    For {
        binding: String,
        values: Expression,
        body: Vec<Self>,
        otherwise: Vec<Self>,
    },
    With {
        binding: String,
        value: Expression,
        body: Vec<Self>,
    },
    Include(IncludeCall),
}

#[derive(Debug, Clone)]
struct IncludeCall {
    name: String,
    arguments: BTreeMap<String, Expression>,
    only: bool,
    span: SourceSpan,
    target_span: SourceSpan,
    argument_spans: BTreeMap<String, SourceSpan>,
    target_range: (usize, usize),
    argument_ranges: BTreeMap<String, (usize, usize)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TemplateOutput {
    Html,
    Text,
    Json,
}

impl From<OutputSource> for TemplateOutput {
    fn from(value: OutputSource) -> Self {
        match value {
            OutputSource::Html => Self::Html,
            OutputSource::Text => Self::Text,
            OutputSource::Json => Self::Json,
        }
    }
}

#[derive(Debug, Clone)]
enum ValueType {
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

impl ValueType {
    fn parse(source: &str) -> Result<Self, String> {
        let (source, optional) = source
            .strip_suffix('?')
            .map_or((source.trim(), false), |source| (source.trim(), true));
        match source {
            "any" => Ok(Self::Any { optional }),
            "null" if !optional => Ok(Self::Null),
            "bool" => Ok(Self::Bool { optional }),
            "int" => Ok(Self::Int { optional }),
            "float" => Ok(Self::Float { optional }),
            "string" => Ok(Self::String { optional }),
            "url" => Ok(Self::Url { optional }),
            "safe_html" => Err(
                "template parameter type `safe_html` is unavailable because runtime values do not carry trusted HTML provenance; use `string` and allow HTML autoescape"
                    .to_owned(),
            ),
            source if source.starts_with("list<") && source.ends_with('>') => Ok(Self::List {
                item: Box::new(Self::parse(&source[5..source.len() - 1])?),
                optional,
            }),
            source if source.starts_with("map<") && source.ends_with('>') => Ok(Self::Map {
                item: Box::new(Self::parse(&source[4..source.len() - 1])?),
                optional,
            }),
            _ => Err(format!("unknown template parameter type `{source}`")),
        }
    }

    const fn optional(&self) -> bool {
        match self {
            Self::Null => true,
            Self::Any { optional }
            | Self::Bool { optional }
            | Self::Int { optional }
            | Self::Float { optional }
            | Self::String { optional }
            | Self::Url { optional }
            | Self::List { optional, .. }
            | Self::Map { optional, .. } => *optional,
        }
    }

    fn accepts(&self, value: &Value) -> bool {
        if value.is_null() {
            return self.optional();
        }
        match self {
            Self::Any { .. } => true,
            Self::Null => false,
            Self::Bool { .. } => matches!(value, Value::Bool(_)),
            Self::Int { .. } => matches!(value, Value::Integer(_)),
            Self::Float { .. } => matches!(value, Value::Float(_) | Value::Integer(_)),
            Self::String { .. } => matches!(value, Value::String(_)),
            Self::Url { .. } => value
                .as_str()
                .and_then(|value| url::Url::parse(value).ok())
                .is_some(),
            Self::List { item, .. } => {
                matches!(value, Value::List(values) if values.iter().all(|value| item.accepts(value)))
            }
            Self::Map { item, .. } => {
                matches!(value, Value::Map(values) if values.values().all(|value| item.accepts(value)))
            }
        }
    }

    fn describe(&self) -> &'static str {
        match self {
            Self::Any { .. } => "any",
            Self::Null => "null",
            Self::Bool { .. } => "bool",
            Self::Int { .. } => "int",
            Self::Float { .. } => "float",
            Self::String { .. } => "string",
            Self::Url { .. } => "url",
            Self::List { .. } => "list",
            Self::Map { .. } => "map",
        }
    }

    fn actual_description(&self, value: &Value) -> String {
        if matches!(self, Self::Url { .. }) && matches!(value, Value::String(_)) {
            "string (not an absolute URL)".to_owned()
        } else {
            value.type_name().to_owned()
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum CompiledValue {
    Constant(Value),
    Expression(Expression),
    Template(oxidase_core::CompiledTemplate),
    List(Vec<Self>),
    Map(BTreeMap<String, Self>),
}

impl CompiledValue {
    pub(crate) fn evaluate(&self, context: &EvalContext) -> Result<Value, String> {
        match self {
            Self::Constant(value) => Ok(value.clone()),
            Self::Expression(expression) => expression
                .evaluate(context)
                .map_err(|error| error.to_string()),
            Self::Template(template) => template
                .render(context)
                .map(Value::String)
                .map_err(|error| error.to_string()),
            Self::List(values) => values
                .iter()
                .map(|value| value.evaluate(context))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::List),
            Self::Map(values) => values
                .iter()
                .map(|(key, value)| Ok((key.clone(), value.evaluate(context)?)))
                .collect::<Result<BTreeMap<_, _>, String>>()
                .map(Value::Map),
        }
    }

    fn constant_value(&self) -> Option<&Value> {
        if let Self::Constant(value) = self {
            Some(value)
        } else {
            None
        }
    }
}

struct TemplateParser<'a> {
    name: &'a str,
    tokens: &'a [TemplateToken],
    position: usize,
    dependencies: BTreeSet<String>,
}

impl TemplateParser<'_> {
    fn parse_nodes(
        &mut self,
        stops: &[&str],
    ) -> Result<(Vec<TemplateNode>, Option<String>), SiteCompileError> {
        let mut nodes = Vec::new();
        while let Some(token) = self.tokens.get(self.position) {
            match token {
                TemplateToken::Text(value) => {
                    nodes.push(TemplateNode::Text(value.clone()));
                    self.position += 1;
                }
                TemplateToken::Expression(source, span) => {
                    nodes.push(TemplateNode::Interpolation(
                        Expression::compile(source).map_err(|error| {
                            SiteCompileError::at(
                                "template.expression",
                                span.clone(),
                                error.to_string(),
                            )
                        })?,
                    ));
                    self.position += 1;
                }
                TemplateToken::Tag(tag, span) => {
                    let keyword = tag.split_whitespace().next().unwrap_or("");
                    if stops.contains(&keyword) {
                        self.position += 1;
                        return Ok((nodes, Some(tag.clone())));
                    }
                    self.position += 1;
                    match keyword {
                        "if" => nodes.push(self.parse_if(tag, span)?),
                        "for" => nodes.push(self.parse_for(tag, span)?),
                        "with" => nodes.push(self.parse_with(tag, span)?),
                        "include" => nodes.push(self.parse_include(tag, span)?),
                        "extends" | "block" | "endblock" => {
                            return Err(SiteCompileError::at(
                                "template.unsupported_tag",
                                span.clone(),
                                "`extends`/`block` is not implemented; use static `include` in this release",
                            ));
                        }
                        _ => {
                            return Err(SiteCompileError::at(
                                "template.tag",
                                span.clone(),
                                format!("unknown or misplaced template tag `{tag}`"),
                            ));
                        }
                    }
                }
            }
        }
        Ok((nodes, None))
    }

    fn parse_if(
        &mut self,
        opening: &str,
        opening_span: &SourceSpan,
    ) -> Result<TemplateNode, SiteCompileError> {
        let condition = tag_argument(opening, "if").map_err(|error| {
            SiteCompileError::at("template.tag", opening_span.clone(), error.to_string())
        })?;
        let mut branches = Vec::new();
        let mut current = Expression::compile(condition).map_err(|error| {
            SiteCompileError::at(
                "template.expression",
                opening_span.clone(),
                error.to_string(),
            )
        })?;
        loop {
            let (body, stop) = self.parse_nodes(&["elif", "else", "endif"])?;
            branches.push((current, body));
            match stop.as_deref() {
                Some(tag) if tag.starts_with("elif ") => {
                    current = Expression::compile(tag_argument(tag, "elif")?)
                        .map_err(|error| SiteCompileError::source(self.name, error.to_string()))?;
                }
                Some("else") => {
                    let (otherwise, stop) = self.parse_nodes(&["endif"])?;
                    if stop.as_deref() != Some("endif") {
                        return Err(SiteCompileError::at(
                            "template.unclosed_block",
                            opening_span.clone(),
                            "unclosed `if` block",
                        ));
                    }
                    return Ok(TemplateNode::If {
                        branches,
                        otherwise,
                    });
                }
                Some("endif") => {
                    return Ok(TemplateNode::If {
                        branches,
                        otherwise: Vec::new(),
                    });
                }
                _ => {
                    return Err(SiteCompileError::at(
                        "template.unclosed_block",
                        opening_span.clone(),
                        "unclosed `if` block",
                    ));
                }
            }
        }
    }

    fn parse_for(
        &mut self,
        opening: &str,
        opening_span: &SourceSpan,
    ) -> Result<TemplateNode, SiteCompileError> {
        let source = tag_argument(opening, "for").map_err(|error| {
            SiteCompileError::at("template.tag", opening_span.clone(), error.to_string())
        })?;
        let (binding, values) = source.split_once(" in ").ok_or_else(|| {
            SiteCompileError::at(
                "template.tag",
                opening_span.clone(),
                "`for` syntax is `for name in expression`",
            )
        })?;
        validate_binding(binding, self.name).map_err(|error| {
            SiteCompileError::at("template.binding", opening_span.clone(), error.to_string())
        })?;
        validate_local_binding(binding, self.name).map_err(|error| {
            SiteCompileError::at("template.binding", opening_span.clone(), error.to_string())
        })?;
        let values = Expression::compile(values).map_err(|error| {
            SiteCompileError::at(
                "template.expression",
                opening_span.clone(),
                error.to_string(),
            )
        })?;
        let (body, stop) = self.parse_nodes(&["else", "endfor"])?;
        let otherwise = if stop.as_deref() == Some("else") {
            let (otherwise, stop) = self.parse_nodes(&["endfor"])?;
            if stop.as_deref() != Some("endfor") {
                return Err(SiteCompileError::at(
                    "template.unclosed_block",
                    opening_span.clone(),
                    "unclosed `for` block",
                ));
            }
            otherwise
        } else if stop.as_deref() == Some("endfor") {
            Vec::new()
        } else {
            return Err(SiteCompileError::at(
                "template.unclosed_block",
                opening_span.clone(),
                "unclosed `for` block",
            ));
        };
        Ok(TemplateNode::For {
            binding: binding.to_owned(),
            values,
            body,
            otherwise,
        })
    }

    fn parse_with(
        &mut self,
        opening: &str,
        opening_span: &SourceSpan,
    ) -> Result<TemplateNode, SiteCompileError> {
        let source = tag_argument(opening, "with").map_err(|error| {
            SiteCompileError::at("template.tag", opening_span.clone(), error.to_string())
        })?;
        let (binding, value) = source.split_once('=').ok_or_else(|| {
            SiteCompileError::at(
                "template.tag",
                opening_span.clone(),
                "`with` syntax is `with name = expression`",
            )
        })?;
        let binding = binding.trim();
        validate_binding(binding, self.name).map_err(|error| {
            SiteCompileError::at("template.binding", opening_span.clone(), error.to_string())
        })?;
        validate_local_binding(binding, self.name).map_err(|error| {
            SiteCompileError::at("template.binding", opening_span.clone(), error.to_string())
        })?;
        let value = Expression::compile(value.trim()).map_err(|error| {
            SiteCompileError::at(
                "template.expression",
                opening_span.clone(),
                error.to_string(),
            )
        })?;
        let (body, stop) = self.parse_nodes(&["endwith"])?;
        if stop.as_deref() != Some("endwith") {
            return Err(SiteCompileError::at(
                "template.unclosed_block",
                opening_span.clone(),
                "unclosed `with` block",
            ));
        }
        Ok(TemplateNode::With {
            binding: binding.to_owned(),
            value,
            body,
        })
    }

    fn parse_include(
        &mut self,
        tag: &str,
        span: &SourceSpan,
    ) -> Result<TemplateNode, SiteCompileError> {
        let source = tag_argument(tag, "include")?;
        let mut include = parse_include_call(source, self.name).map_err(|_| {
            SiteCompileError::at(
                "template.include_syntax",
                span.clone(),
                "invalid include syntax; expected a static path, named expressions, and optional trailing `only`",
            )
        })?;
        include.span = span.clone();
        let source_offset = source.as_ptr() as usize - tag.as_ptr() as usize;
        include.target_span = template_subspan(
            span,
            tag,
            source_offset + include.target_range.0,
            source_offset + include.target_range.1,
            "template.include.target",
        );
        include.argument_spans = include
            .argument_ranges
            .iter()
            .map(|(name, (start, end))| {
                (
                    name.clone(),
                    template_subspan(
                        span,
                        tag,
                        source_offset + start,
                        source_offset + end,
                        &template_field_child("template.include.arguments", name),
                    ),
                )
            })
            .collect();
        self.dependencies.insert(include.name.clone());
        Ok(TemplateNode::Include(include))
    }
}

fn parse_include_call(source: &str, template: &str) -> Result<IncludeCall, SiteCompileError> {
    let (path, rest) = take_quoted_path(source).ok_or_else(|| {
        SiteCompileError::source(template, "include path must be a static quoted string")
    })?;
    let name = normalize_template_name(path)?;
    let target_range = (1, 1 + path.len());
    let mut rest = rest.trim_start();
    let mut arguments = BTreeMap::new();
    let mut argument_ranges = BTreeMap::new();
    let mut only = false;

    if rest.is_empty() {
        return Ok(IncludeCall {
            name,
            arguments,
            only,
            span: SourceSpan::synthetic("include"),
            target_span: SourceSpan::synthetic("template.include.target"),
            argument_spans: BTreeMap::new(),
            target_range,
            argument_ranges,
        });
    }
    if let Some(after_only) = strip_tag_keyword(rest, "only") {
        if !after_only.trim().is_empty() {
            return Err(SiteCompileError::source(
                template,
                "`only` must appear once at the end of an include tag",
            ));
        }
        return Ok(IncludeCall {
            name,
            arguments,
            only: true,
            span: SourceSpan::synthetic("include"),
            target_span: SourceSpan::synthetic("template.include.target"),
            argument_spans: BTreeMap::new(),
            target_range,
            argument_ranges,
        });
    }
    rest = strip_tag_keyword(rest, "with").ok_or_else(|| {
        SiteCompileError::source(
            template,
            "include syntax is `include \"path.oxt\" [with name=expression ...] [only]`",
        )
    })?;

    loop {
        rest = rest.trim_start();
        if rest.is_empty() {
            if arguments.is_empty() {
                return Err(SiteCompileError::source(
                    template,
                    "include `with` requires at least one named argument",
                ));
            }
            break;
        }
        if let Some(after_only) = strip_tag_keyword(rest, "only") {
            if arguments.is_empty() {
                return Err(SiteCompileError::source(
                    template,
                    "include `with` requires at least one named argument",
                ));
            }
            if !after_only.trim().is_empty() {
                return Err(SiteCompileError::source(
                    template,
                    "`only` must appear once at the end of an include tag",
                ));
            }
            only = true;
            break;
        }

        let parameter_start = source.len() - rest.len();
        let (parameter, after_parameter) = take_binding(rest).ok_or_else(|| {
            SiteCompileError::source(template, "include argument requires a binding name")
        })?;
        validate_binding(parameter, template)?;
        validate_local_binding(parameter, template)?;
        let after_parameter = after_parameter.trim_start();
        let Some(expression_source) = after_parameter.strip_prefix('=') else {
            return Err(SiteCompileError::source(
                template,
                format!("include argument `{parameter}` requires `=`"),
            ));
        };
        if expression_source.starts_with('=') {
            return Err(SiteCompileError::source(
                template,
                format!("include argument `{parameter}` has no value"),
            ));
        }
        let expression_source = expression_source.trim_start();
        let boundary = include_expression_boundary(expression_source);
        let expression = expression_source[..boundary].trim_end();
        if expression.is_empty() {
            return Err(SiteCompileError::source(
                template,
                format!("include argument `{parameter}` has no value"),
            ));
        }
        let expression = Expression::compile(expression)
            .map_err(|error| SiteCompileError::source(template, error.to_string()))?;
        if arguments.insert(parameter.to_owned(), expression).is_some() {
            return Err(SiteCompileError::source(
                template,
                format!("duplicate include argument `{parameter}`"),
            ));
        }
        argument_ranges.insert(
            parameter.to_owned(),
            (parameter_start, parameter_start + parameter.len()),
        );
        rest = &expression_source[boundary..];
    }

    Ok(IncludeCall {
        name,
        arguments,
        only,
        span: SourceSpan::synthetic("include"),
        target_span: SourceSpan::synthetic("template.include.target"),
        argument_spans: BTreeMap::new(),
        target_range,
        argument_ranges,
    })
}

fn take_quoted_path(source: &str) -> Option<(&str, &str)> {
    let quote = source.chars().next()?;
    if !matches!(quote, '\'' | '"') {
        return None;
    }
    let mut escaped = false;
    for (offset, character) in source[quote.len_utf8()..].char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if character == quote {
            let end = quote.len_utf8() + offset;
            return Some((
                &source[quote.len_utf8()..end],
                &source[end + quote.len_utf8()..],
            ));
        }
    }
    None
}

fn strip_tag_keyword<'a>(source: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = source.strip_prefix(keyword)?;
    if rest.is_empty() || rest.starts_with(char::is_whitespace) {
        Some(rest)
    } else {
        None
    }
}

fn take_binding(source: &str) -> Option<(&str, &str)> {
    let mut end = 0;
    for (offset, character) in source.char_indices() {
        if offset == 0 {
            if !matches!(character, '_' | 'a'..='z' | 'A'..='Z') {
                return None;
            }
        } else if character != '_' && !character.is_ascii_alphanumeric() {
            break;
        }
        end = offset + character.len_utf8();
    }
    (end > 0).then(|| (&source[..end], &source[end..]))
}

fn include_expression_boundary(source: &str) -> usize {
    let mut quote = None;
    let mut escaped = false;
    let mut depth = 0usize;
    for (offset, character) in source.char_indices() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == active_quote {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            character if character.is_whitespace() && depth == 0 => {
                let candidate = source[offset..].trim_start();
                if strip_tag_keyword(candidate, "only").is_some()
                    || looks_like_include_assignment(candidate)
                {
                    return offset;
                }
            }
            _ => {}
        }
    }
    source.len()
}

fn looks_like_include_assignment(source: &str) -> bool {
    let Some((_, rest)) = take_binding(source) else {
        return false;
    };
    let rest = rest.trim_start();
    rest.starts_with('=') && !rest.starts_with("==")
}

fn validate_include_nodes(
    nodes: &[TemplateNode],
    templates: &BTreeMap<String, CompiledOxt>,
) -> Result<(), SiteCompileError> {
    for node in nodes {
        match node {
            TemplateNode::Include(include) => {
                let target = templates.get(&include.name).ok_or_else(|| {
                    SiteCompileError::at(
                        "template.include_missing",
                        include.target_span.clone(),
                        format!("included template `{}` does not exist", include.name),
                    )
                })?;
                for parameter in include.arguments.keys() {
                    if !target.params.contains_key(parameter) {
                        return Err(SiteCompileError::at(
                            "template.include_argument_unknown",
                            include
                                .argument_spans
                                .get(parameter)
                                .cloned()
                                .unwrap_or_else(|| include.span.clone()),
                            format!(
                                "include `{}` has unknown parameter `{parameter}`",
                                include.name
                            ),
                        ));
                    }
                }
                for (parameter, kind) in &target.params {
                    let Some(argument) = include.arguments.get(parameter) else {
                        if kind.optional() {
                            continue;
                        }
                        let mut diagnostic = Diagnostic::new(
                            "template.include_argument_missing",
                            format!(
                                "include `{}` is missing required parameter `{parameter}` ({})",
                                include.name,
                                kind.describe()
                            ),
                            include.target_span.clone(),
                        );
                        if let Some(declaration) = target.param_spans.get(parameter) {
                            diagnostic = diagnostic.with_related(
                                format!("parameter `{parameter}` is declared here"),
                                declaration.clone(),
                            );
                        }
                        return Err(SiteCompileError::from_diagnostic(diagnostic));
                    };
                    if let Some(value) = argument.constant_value()
                        && !kind.accepts(value)
                    {
                        let mut diagnostic = Diagnostic::new(
                            "template.include_argument_type",
                            format!(
                                "include `{}` parameter `{parameter}` expects {}, received {}",
                                include.name,
                                kind.describe(),
                                value.type_name()
                            ),
                            include
                                .argument_spans
                                .get(parameter)
                                .cloned()
                                .unwrap_or_else(|| include.span.clone()),
                        );
                        if let Some(declaration) = target.param_spans.get(parameter) {
                            diagnostic = diagnostic.with_related(
                                format!("parameter `{parameter}` is declared here"),
                                declaration.clone(),
                            );
                        }
                        return Err(SiteCompileError::from_diagnostic(diagnostic));
                    }
                }
            }
            TemplateNode::If {
                branches,
                otherwise,
            } => {
                for (_, body) in branches {
                    validate_include_nodes(body, templates)?;
                }
                validate_include_nodes(otherwise, templates)?;
            }
            TemplateNode::For {
                body, otherwise, ..
            } => {
                validate_include_nodes(body, templates)?;
                validate_include_nodes(otherwise, templates)?;
            }
            TemplateNode::With { body, .. } => {
                validate_include_nodes(body, templates)?;
            }
            TemplateNode::Text(_) | TemplateNode::Interpolation(_) => {}
        }
    }
    Ok(())
}

fn find_include_span<'a>(nodes: &'a [TemplateNode], target: &str) -> Option<&'a SourceSpan> {
    for node in nodes {
        let found = match node {
            TemplateNode::Include(include) if include.name == target => Some(&include.target_span),
            TemplateNode::If {
                branches,
                otherwise,
            } => branches
                .iter()
                .find_map(|(_, body)| find_include_span(body, target))
                .or_else(|| find_include_span(otherwise, target)),
            TemplateNode::For {
                body, otherwise, ..
            } => find_include_span(body, target).or_else(|| find_include_span(otherwise, target)),
            TemplateNode::With { body, .. } => find_include_span(body, target),
            TemplateNode::Text(_) | TemplateNode::Interpolation(_) | TemplateNode::Include(_) => {
                None
            }
        };
        if found.is_some() {
            return found;
        }
    }
    None
}

fn evaluate_include_arguments(
    template: &CompiledOxt,
    include: &IncludeCall,
    context: &TemplateContext,
    caller: &str,
    limits: &TemplateLimits,
    budget: &mut RenderBudget,
) -> Result<BTreeMap<String, Value>, TemplateRenderError> {
    let mut values = BTreeMap::new();
    for (parameter, kind) in &template.params {
        let Some(argument) = include.arguments.get(parameter) else {
            if kind.optional() {
                values.insert(parameter.clone(), Value::Null);
                continue;
            }
            return Err(TemplateArgumentError::Missing {
                template: template.name.clone(),
                parameter: parameter.clone(),
                expected: kind.describe().to_owned(),
            }
            .into());
        };
        budget.charge_expression(caller, limits)?;
        let value = argument.evaluate(context.values()).map_err(|error| {
            TemplateArgumentError::Evaluation {
                template: template.name.clone(),
                parameter: parameter.clone(),
                message: error.to_string(),
            }
        })?;
        if !kind.accepts(&value) {
            return Err(TemplateArgumentError::Type {
                template: template.name.clone(),
                parameter: parameter.clone(),
                expected: kind.describe().to_owned(),
                actual: kind.actual_description(&value),
            }
            .into());
        }
        values.insert(parameter.clone(), value);
    }
    for parameter in include.arguments.keys() {
        if !template.params.contains_key(parameter) {
            return Err(TemplateArgumentError::Unknown {
                template: template.name.clone(),
                parameter: parameter.clone(),
            }
            .into());
        }
    }
    Ok(values)
}

fn render_template(
    template: &CompiledOxt,
    templates: &BTreeMap<String, CompiledOxt>,
    context: &TemplateContext,
    limits: &TemplateLimits,
    depth: usize,
    budget: &mut RenderBudget,
) -> Result<(), TemplateRenderError> {
    budget.enter_include(&template.name, depth, limits)?;
    render_nodes(
        &template.nodes,
        ActiveTemplate {
            name: &template.name,
            autoescape_html: template.autoescape_html,
        },
        templates,
        context,
        limits,
        depth,
        budget,
    )
}

#[derive(Clone, Copy)]
struct ActiveTemplate<'a> {
    name: &'a str,
    autoescape_html: bool,
}

fn render_nodes(
    nodes: &[TemplateNode],
    active: ActiveTemplate<'_>,
    templates: &BTreeMap<String, CompiledOxt>,
    context: &TemplateContext,
    limits: &TemplateLimits,
    depth: usize,
    budget: &mut RenderBudget,
) -> Result<(), TemplateRenderError> {
    for node in nodes {
        budget.checkpoint_time(active.name, limits)?;
        match node {
            TemplateNode::Text(value) => budget.write_output(active.name, value, limits)?,
            TemplateNode::Interpolation(expression) => {
                budget.charge_expression(active.name, limits)?;
                let value = expression.evaluate(context.values()).map_err(|error| {
                    TemplateRenderError::Evaluation {
                        template: active.name.to_owned(),
                        expression: expression.source().to_owned(),
                        message: error.to_string(),
                    }
                })?;
                if value.is_null() && limits.strict_undefined {
                    return Err(TemplateRenderError::MissingValue {
                        template: active.name.to_owned(),
                        expression: expression.source().to_owned(),
                    });
                }
                let value = value
                    .render()
                    .map_err(|message| TemplateRenderError::Evaluation {
                        template: active.name.to_owned(),
                        expression: expression.source().to_owned(),
                        message: message.to_owned(),
                    })?;
                if active.autoescape_html {
                    budget.write_output(active.name, &html_escape(&value), limits)?;
                } else {
                    budget.write_output(active.name, &value, limits)?;
                }
            }
            TemplateNode::If {
                branches,
                otherwise,
            } => {
                let mut rendered = false;
                for (condition, body) in branches {
                    budget.charge_expression(active.name, limits)?;
                    let value = condition.evaluate(context.values()).map_err(|error| {
                        TemplateRenderError::Evaluation {
                            template: active.name.to_owned(),
                            expression: condition.source().to_owned(),
                            message: error.to_string(),
                        }
                    })?;
                    let Some(value) = value.as_bool() else {
                        return Err(TemplateRenderError::Evaluation {
                            template: active.name.to_owned(),
                            expression: condition.source().to_owned(),
                            message: "if condition did not return bool".to_owned(),
                        });
                    };
                    if value {
                        render_nodes(body, active, templates, context, limits, depth, budget)?;
                        rendered = true;
                        break;
                    }
                }
                if !rendered {
                    render_nodes(otherwise, active, templates, context, limits, depth, budget)?;
                }
            }
            TemplateNode::For {
                binding,
                values,
                body,
                otherwise,
            } => {
                budget.charge_expression(active.name, limits)?;
                let expression_source = values.source().to_owned();
                let values = values.evaluate(context.values()).map_err(|error| {
                    TemplateRenderError::Evaluation {
                        template: active.name.to_owned(),
                        expression: expression_source.clone(),
                        message: error.to_string(),
                    }
                })?;
                let Value::List(values) = values else {
                    return Err(TemplateRenderError::Evaluation {
                        template: active.name.to_owned(),
                        expression: expression_source,
                        message: "for expression did not return a list".to_owned(),
                    });
                };
                if values.is_empty() {
                    render_nodes(otherwise, active, templates, context, limits, depth, budget)?;
                } else {
                    for value in values {
                        budget.charge_loop_iteration(active.name, limits)?;
                        let child = context.with_scope(BTreeMap::from([(binding.clone(), value)]));
                        render_nodes(body, active, templates, &child, limits, depth, budget)?;
                    }
                }
            }
            TemplateNode::With {
                binding,
                value,
                body,
            } => {
                budget.charge_expression(active.name, limits)?;
                let value = value.evaluate(context.values()).map_err(|error| {
                    TemplateRenderError::Evaluation {
                        template: active.name.to_owned(),
                        expression: value.source().to_owned(),
                        message: error.to_string(),
                    }
                })?;
                let child = context.with_scope(BTreeMap::from([(binding.clone(), value)]));
                render_nodes(body, active, templates, &child, limits, depth, budget)?;
            }
            TemplateNode::Include(include) => {
                let template = templates.get(&include.name).ok_or_else(|| {
                    TemplateRenderError::MissingValue {
                        template: active.name.to_owned(),
                        expression: format!("include {}", include.name),
                    }
                })?;
                let arguments = evaluate_include_arguments(
                    template,
                    include,
                    context,
                    active.name,
                    limits,
                    budget,
                )?;
                let child = if include.only {
                    context.only()
                } else {
                    context.clone()
                }
                .with_scope(arguments);
                render_template(template, templates, &child, limits, depth + 1, budget)?;
            }
        }
    }
    Ok(())
}

struct RenderBudget {
    started: Instant,
    output: String,
    output_bytes: usize,
    loop_iterations: usize,
    include_depth: usize,
    expression_steps: usize,
}

impl RenderBudget {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            output: String::new(),
            output_bytes: 0,
            loop_iterations: 0,
            include_depth: 0,
            expression_steps: 0,
        }
    }

    fn checkpoint_time(
        &self,
        template_name: &str,
        limits: &TemplateLimits,
    ) -> Result<(), TemplateRenderError> {
        if self.started.elapsed() > limits.render_time {
            return Err(limit_error(template_name, TemplateLimitKind::RenderTime));
        }
        Ok(())
    }

    fn charge_expression(
        &mut self,
        template_name: &str,
        limits: &TemplateLimits,
    ) -> Result<(), TemplateRenderError> {
        self.checkpoint_time(template_name, limits)?;
        if self.expression_steps >= limits.expression_steps {
            return Err(limit_error(
                template_name,
                TemplateLimitKind::ExpressionSteps,
            ));
        }
        self.expression_steps += 1;
        Ok(())
    }

    fn charge_loop_iteration(
        &mut self,
        template_name: &str,
        limits: &TemplateLimits,
    ) -> Result<(), TemplateRenderError> {
        self.checkpoint_time(template_name, limits)?;
        if self.loop_iterations >= limits.loop_iterations {
            return Err(limit_error(
                template_name,
                TemplateLimitKind::LoopIterations,
            ));
        }
        self.loop_iterations += 1;
        Ok(())
    }

    fn enter_include(
        &mut self,
        template_name: &str,
        depth: usize,
        limits: &TemplateLimits,
    ) -> Result<(), TemplateRenderError> {
        self.checkpoint_time(template_name, limits)?;
        if depth > limits.include_depth {
            return Err(limit_error(template_name, TemplateLimitKind::IncludeDepth));
        }
        self.include_depth = self.include_depth.max(depth);
        Ok(())
    }

    fn write_output(
        &mut self,
        template_name: &str,
        value: &str,
        limits: &TemplateLimits,
    ) -> Result<(), TemplateRenderError> {
        self.checkpoint_time(template_name, limits)?;
        let output_bytes = self.output_bytes.saturating_add(value.len());
        if output_bytes > limits.output_size {
            return Err(limit_error(template_name, TemplateLimitKind::OutputSize));
        }
        self.output.push_str(value);
        self.output_bytes = output_bytes;
        Ok(())
    }
}

fn limit_error(template: &str, kind: TemplateLimitKind) -> TemplateRenderError {
    TemplateRenderError::Limit {
        template: template.to_owned(),
        kind,
    }
}

#[derive(Debug)]
enum TemplateToken {
    Text(String),
    Expression(String, SourceSpan),
    Tag(String, SourceSpan),
}

struct TokenizeError {
    message: String,
    span: SourceSpan,
}

fn tokenize(
    path: &Path,
    source: &str,
    source_byte_offset: usize,
    source_line_offset: usize,
) -> Result<Vec<TemplateToken>, TokenizeError> {
    let span = |start, end| {
        template_source_span(
            path,
            source,
            source_byte_offset,
            source_line_offset,
            start,
            end,
        )
    };
    let mut tokens = Vec::new();
    let mut cursor = 0;
    while cursor < source.len() {
        let Some(relative) = source[cursor..].find('{') else {
            tokens.push(TemplateToken::Text(source[cursor..].to_owned()));
            break;
        };
        let start = cursor + relative;
        if start > cursor {
            tokens.push(TemplateToken::Text(source[cursor..start].to_owned()));
        }
        let rest = &source[start..];
        if let Some(raw) = rest.strip_prefix("{% raw %}") {
            let end = raw.find("{% endraw %}").ok_or_else(|| TokenizeError {
                message: "unclosed `raw` block".to_owned(),
                span: span(start, source.len()),
            })?;
            tokens.push(TemplateToken::Text(raw[..end].to_owned()));
            cursor = start + "{% raw %}".len() + end + "{% endraw %}".len();
        } else if rest.starts_with("{{") {
            let expression_start = start + 2;
            let end = source[expression_start..]
                .find("}}")
                .map(|end| expression_start + end)
                .ok_or_else(|| TokenizeError {
                    message: "unclosed interpolation".to_owned(),
                    span: span(start, source.len()),
                })?;
            let raw_expression = &source[expression_start..end];
            let expression = raw_expression.trim();
            if expression.is_empty() {
                return Err(TokenizeError {
                    message: "empty interpolation".to_owned(),
                    span: span(start, end + 2),
                });
            }
            let leading = raw_expression.len() - raw_expression.trim_start().len();
            let expression_offset = expression_start + leading;
            tokens.push(TemplateToken::Expression(
                expression.to_owned(),
                span(expression_offset, expression_offset + expression.len()),
            ));
            cursor = end + 2;
        } else if rest.starts_with("{#") {
            let comment_start = start + 2;
            let end = source[comment_start..]
                .find("#}")
                .map(|end| comment_start + end)
                .ok_or_else(|| TokenizeError {
                    message: "unclosed template comment".to_owned(),
                    span: span(start, source.len()),
                })?;
            cursor = end + 2;
        } else if rest.starts_with("{%") {
            let tag_start = start + 2;
            let end = source[tag_start..]
                .find("%}")
                .map(|end| tag_start + end)
                .ok_or_else(|| TokenizeError {
                    message: "unclosed template tag".to_owned(),
                    span: span(start, source.len()),
                })?;
            let raw_tag = &source[tag_start..end];
            let tag = raw_tag.trim();
            if tag.is_empty() {
                return Err(TokenizeError {
                    message: "empty template tag".to_owned(),
                    span: span(start, end + 2),
                });
            }
            let leading = raw_tag.len() - raw_tag.trim_start().len();
            let tag_offset = tag_start + leading;
            tokens.push(TemplateToken::Tag(
                tag.to_owned(),
                span(tag_offset, tag_offset + tag.len()),
            ));
            cursor = end + 2;
        } else {
            tokens.push(TemplateToken::Text("{".to_owned()));
            cursor = start + 1;
        }
    }
    Ok(tokens)
}

fn template_source_span(
    path: &Path,
    source: &str,
    source_byte_offset: usize,
    source_line_offset: usize,
    start: usize,
    end: usize,
) -> SourceSpan {
    let (line, column) = template_position(source, start);
    let (end_line, end_column) = template_position(source, end);
    SourceSpan {
        file: path.to_path_buf(),
        start_byte: source_byte_offset + start,
        end_byte: source_byte_offset + end,
        line: source_line_offset + line,
        column,
        end_line: source_line_offset + end_line,
        end_column,
        field_path: "template".to_owned(),
    }
}

fn template_subspan(
    parent: &SourceSpan,
    source: &str,
    start: usize,
    end: usize,
    field_path: &str,
) -> SourceSpan {
    let relative_position = |offset: usize| {
        let prefix = &source[..offset];
        let line_offset = prefix.bytes().filter(|byte| *byte == b'\n').count();
        let line_start = prefix.rfind('\n').map_or(0, |index| index + 1);
        let relative_column = source[line_start..offset].chars().count();
        let column = if line_offset == 0 {
            parent.column + relative_column
        } else {
            relative_column + 1
        };
        (parent.line + line_offset, column)
    };
    let (line, column) = relative_position(start);
    let (end_line, end_column) = relative_position(end);
    SourceSpan {
        file: parent.file.clone(),
        start_byte: parent.start_byte + start,
        end_byte: parent.start_byte + end,
        line,
        column,
        end_line,
        end_column,
        field_path: field_path.to_owned(),
    }
}

fn template_position(source: &str, offset: usize) -> (usize, usize) {
    let prefix = &source[..offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let line_start = prefix.rfind('\n').map_or(0, |index| index + 1);
    let column = source[line_start..offset].chars().count() + 1;
    (line, column)
}

fn tag_argument<'a>(tag: &'a str, keyword: &str) -> Result<&'a str, SiteCompileError> {
    tag.strip_prefix(keyword)
        .map(str::trim)
        .filter(|argument| !argument.is_empty())
        .ok_or_else(|| {
            SiteCompileError::source("<template>", format!("`{keyword}` needs an argument"))
        })
}

fn validate_binding(binding: &str, name: &str) -> Result<(), SiteCompileError> {
    let mut characters = binding.chars();
    if !matches!(characters.next(), Some('_' | 'a'..='z' | 'A'..='Z'))
        || !characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
    {
        return Err(SiteCompileError::source(
            name,
            format!("invalid template binding `{binding}`"),
        ));
    }
    Ok(())
}

fn validate_local_binding(binding: &str, name: &str) -> Result<(), SiteCompileError> {
    if PUBLIC_TEMPLATE_ROOTS.contains(&binding) {
        return Err(SiteCompileError::source(
            name,
            format!("template binding `{binding}` cannot shadow a public context root"),
        ));
    }
    Ok(())
}

fn template_metadata_span(
    path: &Path,
    spans: Option<&FieldSpanIndex>,
    field_path: &str,
    use_key: bool,
) -> SourceSpan {
    let range = spans
        .and_then(|spans| spans.nearest(field_path))
        .map(|field| if use_key { &field.key } else { &field.value });
    let Some(range) = range else {
        return SourceSpan {
            file: path.to_path_buf(),
            start_byte: 0,
            end_byte: 0,
            line: 1,
            column: 1,
            end_line: 1,
            end_column: 1,
            field_path: field_path.to_owned(),
        };
    };
    SourceSpan {
        file: path.to_path_buf(),
        start_byte: range.start_byte,
        end_byte: range.end_byte,
        line: range.start_line,
        column: range.start_column,
        end_line: range.end_line,
        end_column: range.end_column,
        field_path: field_path.to_owned(),
    }
}

fn template_field_child(parent: &str, key: &str) -> String {
    let mut characters = key.chars();
    if matches!(characters.next(), Some('_' | 'a'..='z' | 'A'..='Z'))
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
    {
        format!("{parent}.{key}")
    } else {
        let escaped = key.replace('\\', "\\\\").replace('"', "\\\"");
        format!("{parent}[\"{escaped}\"]")
    }
}

pub(crate) fn normalize_template_name(source: &str) -> Result<String, SiteCompileError> {
    let path = std::path::Path::new(source);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
        || !source.ends_with(".oxt")
    {
        return Err(SiteCompileError::source(
            source,
            "template path must be a relative `.oxt` path without `..`",
        ));
    }
    Ok(source.replace('\\', "/"))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    use oxidase_core::{EvalContext, Value};

    use super::{
        CompiledOxt, RenderBudget, TemplateLimits, TemplateOutput, ValueType, parse_include_call,
    };
    use crate::{TemplateLimitKind, TemplateRenderError};

    fn limits() -> TemplateLimits {
        TemplateLimits {
            render_time: Duration::from_secs(1),
            output_size: 1024,
            loop_iterations: 20,
            include_depth: 4,
            expression_steps: 100,
            strict_undefined: true,
        }
    }

    fn typed_template(
        name: &str,
        source: &str,
        params: &[(&str, &str)],
        output: TemplateOutput,
        autoescape_html: bool,
    ) -> CompiledOxt {
        let params = params
            .iter()
            .map(|(name, kind)| {
                (
                    (*name).to_owned(),
                    ValueType::parse(kind).expect("fixture parameter type is valid"),
                )
            })
            .collect();
        CompiledOxt::compile_parts(
            name.to_owned(),
            PathBuf::from(name),
            params,
            BTreeMap::new(),
            autoescape_html,
            output,
            source,
            (0, 0),
        )
        .expect("fixture template compiles")
    }

    fn public_context() -> EvalContext {
        EvalContext::new(BTreeMap::from([
            (
                "request".to_owned(),
                Value::Map(BTreeMap::from([("path".to_owned(), Value::from("/cards"))])),
            ),
            (
                "site".to_owned(),
                Value::Map(BTreeMap::from([("name".to_owned(), Value::from("docs"))])),
            ),
            (
                "resource".to_owned(),
                Value::Map(BTreeMap::from([("path".to_owned(), Value::from("/cards"))])),
            ),
            (
                "page".to_owned(),
                Value::Map(BTreeMap::from([
                    ("title".to_owned(), Value::from("Cards")),
                    ("value".to_owned(), Value::from("dynamic")),
                ])),
            ),
            ("bindings".to_owned(), Value::Map(BTreeMap::new())),
        ]))
    }

    #[test]
    fn renders_if_for_with_and_autoescape() {
        let template = CompiledOxt::inline(
            "page.oxt",
            "{% with title = page.title %}<h1>{{ title }}</h1>{% endwith %}{% for item in page.items %}[{{ item }}]{% else %}empty{% endfor %}",
            true,
        )
        .expect("valid template");
        let mut page = BTreeMap::new();
        page.insert("title".to_owned(), Value::from("<Oxidase>"));
        page.insert(
            "items".to_owned(),
            Value::List(vec![Value::from("one"), Value::from("two")]),
        );
        let context = EvalContext::new(BTreeMap::from([("page".to_owned(), Value::Map(page))]));
        let output = template
            .render(&BTreeMap::new(), &context, &limits())
            .expect("template renders");
        assert_eq!(output, "<h1>&lt;Oxidase&gt;</h1>[one][two]");
    }

    #[test]
    fn static_include_uses_compiled_registry() {
        let parent = CompiledOxt::inline("parent.oxt", "A{% include \"child.oxt\" %}Z", false)
            .expect("valid parent");
        let child =
            CompiledOxt::inline("child.oxt", "{{ page.value }}", false).expect("valid child");
        let templates = BTreeMap::from([
            ("parent.oxt".to_owned(), parent.clone()),
            ("child.oxt".to_owned(), child),
        ]);
        let context = EvalContext::new(BTreeMap::from([(
            "page".to_owned(),
            Value::Map(BTreeMap::from([("value".to_owned(), Value::from("B"))])),
        )]));
        assert_eq!(
            parent
                .render(&templates, &context, &limits())
                .expect("include renders"),
            "ABZ"
        );
    }

    #[test]
    fn rejects_dynamic_include_and_extends() {
        assert!(CompiledOxt::inline("bad.oxt", "{% include page.template %}", true).is_err());
        assert!(CompiledOxt::inline("bad.oxt", "{% extends \"base.oxt\" %}", true).is_err());
    }

    #[test]
    fn parses_typed_include_grammar_without_whitespace_splitting() {
        let include = parse_include_call(
            "\"_templates/card.oxt\" with title=page.title label=default(page.label, \"Hello world\") only",
            "parent.oxt",
        )
        .expect("typed include parses");
        assert_eq!(include.name, "_templates/card.oxt");
        assert!(include.only);
        assert_eq!(include.arguments["title"].source(), "page.title");
        assert_eq!(
            include.arguments["label"].source(),
            "default(page.label, \"Hello world\")"
        );

        let duplicate = parse_include_call("\"child.oxt\" with value=1 value=2", "parent.oxt")
            .expect_err("duplicate argument must fail");
        assert!(duplicate.to_string().contains("duplicate include argument"));
        assert!(parse_include_call("page.template with value=1", "parent.oxt").is_err());
        assert!(parse_include_call("\"child.oxt\" with", "parent.oxt").is_err());
        assert!(parse_include_call("\"child.oxt\" with only", "parent.oxt").is_err());
        assert!(parse_include_call("\"child.oxt\" only only", "parent.oxt").is_err());
    }

    #[test]
    fn validates_include_parameter_contracts_at_compile_time() {
        let child = typed_template(
            "child.oxt",
            "{{ count }}",
            &[("count", "int")],
            TemplateOutput::Text,
            false,
        );
        for (source, expected) in [
            ("{% include \"child.oxt\" %}", "missing required parameter"),
            (
                "{% include \"child.oxt\" with extra=1 %}",
                "unknown parameter",
            ),
            (
                "{% include \"child.oxt\" with count=\"wrong\" %}",
                "expects int",
            ),
        ] {
            let parent =
                CompiledOxt::inline("parent.oxt", source, false).expect("include syntax compiles");
            let templates = BTreeMap::from([
                ("parent.oxt".to_owned(), parent.clone()),
                ("child.oxt".to_owned(), child.clone()),
            ]);
            let error = parent
                .validate_include_contracts(&templates)
                .expect_err("invalid include contract must fail");
            assert!(error.to_string().contains(expected), "{error}");
        }

        let parent = CompiledOxt::inline(
            "parent.oxt",
            "{% include \"child.oxt\" with count=page.count %}",
            false,
        )
        .expect("dynamic include compiles");
        let templates = BTreeMap::from([
            ("parent.oxt".to_owned(), parent.clone()),
            ("child.oxt".to_owned(), child),
        ]);
        parent
            .validate_include_contracts(&templates)
            .expect("dynamic argument is checked at runtime");
    }

    #[test]
    fn include_arguments_are_typed_and_scoped_lexically() {
        let child = typed_template(
            "child.oxt",
            "{{ item }}",
            &[("item", "string")],
            TemplateOutput::Text,
            false,
        );
        let parent = CompiledOxt::inline(
            "parent.oxt",
            "{% include \"child.oxt\" with item=page.value %}|{{ item ?? \"parent-clean\" }}",
            false,
        )
        .expect("parent compiles");
        let templates = BTreeMap::from([
            ("parent.oxt".to_owned(), parent.clone()),
            ("child.oxt".to_owned(), child),
        ]);
        parent
            .validate_include_contracts(&templates)
            .expect("include contract is valid");
        assert_eq!(
            parent
                .render(&templates, &public_context(), &limits())
                .expect("include renders"),
            "dynamic|parent-clean"
        );

        let mut wrong_context = public_context();
        wrong_context.insert(
            "page",
            Value::Map(BTreeMap::from([("value".to_owned(), Value::Integer(7))])),
        );
        assert!(matches!(
            parent
                .render(&templates, &wrong_context, &limits())
                .expect_err("dynamic type mismatch must fail"),
            TemplateRenderError::Argument(crate::TemplateArgumentError::Type { .. })
        ));
    }

    #[test]
    fn include_only_controls_inherited_locals_but_preserves_public_roots() {
        let inherited = CompiledOxt::inline("inherited.oxt", "{{ item ?? \"none\" }}", false)
            .expect("child compiles");
        let public = CompiledOxt::inline(
            "public.oxt",
            "{{ request.path }}|{{ site.name }}|{{ page.title }}|{{ resource.path }}",
            false,
        )
        .expect("public child compiles");
        let parent = CompiledOxt::inline(
            "parent.oxt",
            "{% for item in page.items %}{% include \"inherited.oxt\" %}/{% include \"inherited.oxt\" only %}/{% include \"public.oxt\" only %}{% endfor %}",
            false,
        )
        .expect("parent compiles");
        let templates = BTreeMap::from([
            ("parent.oxt".to_owned(), parent.clone()),
            ("inherited.oxt".to_owned(), inherited),
            ("public.oxt".to_owned(), public),
        ]);
        parent
            .validate_include_contracts(&templates)
            .expect("include contracts are valid");
        let mut context = public_context();
        context.insert(
            "page",
            Value::Map(BTreeMap::from([
                ("title".to_owned(), Value::from("Cards")),
                ("items".to_owned(), Value::List(vec![Value::from("one")])),
            ])),
        );
        assert_eq!(
            parent
                .render(&templates, &context, &limits())
                .expect("scoped includes render"),
            "one/none//cards|docs|Cards|/cards"
        );
    }

    #[test]
    fn nested_includes_share_context_but_use_child_autoescape_and_output() {
        let leaf = typed_template(
            "leaf.oxt",
            "{{ value }}",
            &[("value", "string")],
            TemplateOutput::Html,
            true,
        );
        let middle = typed_template(
            "middle.oxt",
            "M{% include \"leaf.oxt\" with value=value %}",
            &[("value", "string")],
            TemplateOutput::Text,
            false,
        );
        let parent = CompiledOxt::inline(
            "parent.oxt",
            "P{% include \"middle.oxt\" with value=page.markup %}Z",
            false,
        )
        .expect("parent compiles");
        let templates = BTreeMap::from([
            ("parent.oxt".to_owned(), parent.clone()),
            ("middle.oxt".to_owned(), middle.clone()),
            ("leaf.oxt".to_owned(), leaf.clone()),
        ]);
        for template in templates.values() {
            template
                .validate_include_contracts(&templates)
                .expect("nested contract is valid");
        }
        let mut context = public_context();
        context.insert(
            "page",
            Value::Map(BTreeMap::from([(
                "markup".to_owned(),
                Value::from("<b>safe?</b>"),
            )])),
        );
        assert_eq!(
            parent
                .render(&templates, &context, &limits())
                .expect("nested includes render"),
            "PM&lt;b&gt;safe?&lt;/b&gt;Z"
        );
        assert_eq!(middle.content_type(), "text/plain; charset=utf-8");
        assert_eq!(leaf.content_type(), "text/html; charset=utf-8");
    }

    #[test]
    fn enforces_output_and_loop_limits() {
        let template = CompiledOxt::inline(
            "bounded.oxt",
            "{% for item in page.items %}{{ item }}{% endfor %}",
            false,
        )
        .expect("valid bounded template");
        let context = EvalContext::new(BTreeMap::from([(
            "page".to_owned(),
            Value::Map(BTreeMap::from([(
                "items".to_owned(),
                Value::List(vec![Value::from("abcd"), Value::from("efgh")]),
            )])),
        )]));
        let mut strict_limits = limits();
        strict_limits.output_size = 6;
        assert!(matches!(
            template
                .render(&BTreeMap::new(), &context, &strict_limits)
                .expect_err("output must be bounded"),
            TemplateRenderError::Limit {
                kind: TemplateLimitKind::OutputSize,
                ..
            }
        ));
        strict_limits.output_size = 1024;
        strict_limits.loop_iterations = 1;
        assert!(matches!(
            template
                .render(&BTreeMap::new(), &context, &strict_limits)
                .expect_err("loop count must be bounded"),
            TemplateRenderError::Limit {
                kind: TemplateLimitKind::LoopIterations,
                ..
            }
        ));
    }

    #[test]
    fn render_budget_charges_before_every_operation_with_exact_boundaries() {
        let interpolation = CompiledOxt::inline(
            "expressions.oxt",
            "{{ page.first }}{{ page.second }}",
            false,
        )
        .expect("template compiles");
        let context = EvalContext::new(BTreeMap::from([(
            "page".to_owned(),
            Value::Map(BTreeMap::from([
                ("first".to_owned(), Value::from("a")),
                ("second".to_owned(), Value::from("b")),
            ])),
        )]));
        let mut exact = limits();
        exact.expression_steps = 2;
        assert_eq!(
            interpolation
                .render(&BTreeMap::new(), &context, &exact)
                .expect("exact expression limit is allowed"),
            "ab"
        );
        exact.expression_steps = 1;
        assert!(matches!(
            interpolation
                .render(&BTreeMap::new(), &context, &exact)
                .expect_err("second expression must fail before evaluation"),
            TemplateRenderError::Limit {
                kind: TemplateLimitKind::ExpressionSteps,
                ..
            }
        ));

        let branches = CompiledOxt::inline(
            "branches.oxt",
            "{% if false %}a{% elif false %}b{% elif true %}c{% endif %}",
            false,
        )
        .expect("branches compile");
        exact.expression_steps = 2;
        assert!(matches!(
            branches
                .render(&BTreeMap::new(), &EvalContext::default(), &exact)
                .expect_err("third branch condition exceeds the budget"),
            TemplateRenderError::Limit {
                kind: TemplateLimitKind::ExpressionSteps,
                ..
            }
        ));

        let output = CompiledOxt::inline("output.oxt", "ab", false).expect("text compiles");
        exact.expression_steps = 100;
        exact.output_size = 2;
        assert_eq!(
            output
                .render(&BTreeMap::new(), &EvalContext::default(), &exact)
                .expect("exact byte limit is allowed"),
            "ab"
        );
        exact.output_size = 1;
        assert!(matches!(
            output
                .render(&BTreeMap::new(), &EvalContext::default(), &exact)
                .expect_err("one byte beyond output limit fails"),
            TemplateRenderError::Limit {
                kind: TemplateLimitKind::OutputSize,
                ..
            }
        ));
    }

    #[test]
    fn loop_include_and_time_budgets_are_shared_and_exact() {
        let loop_template = CompiledOxt::inline(
            "loop.oxt",
            "{% for item in page.items %}x{% endfor %}",
            false,
        )
        .expect("loop compiles");
        let context = EvalContext::new(BTreeMap::from([(
            "page".to_owned(),
            Value::Map(BTreeMap::from([(
                "items".to_owned(),
                Value::List(vec![Value::Integer(1), Value::Integer(2)]),
            )])),
        )]));
        let mut exact = limits();
        exact.loop_iterations = 2;
        assert_eq!(
            loop_template
                .render(&BTreeMap::new(), &context, &exact)
                .expect("exact loop limit is allowed"),
            "xx"
        );
        exact.loop_iterations = 1;
        assert!(matches!(
            loop_template
                .render(&BTreeMap::new(), &context, &exact)
                .expect_err("second iteration exceeds the budget"),
            TemplateRenderError::Limit {
                kind: TemplateLimitKind::LoopIterations,
                ..
            }
        ));

        let child =
            CompiledOxt::inline("child.oxt", "{{ page.value }}", false).expect("child compiles");
        let parent = CompiledOxt::inline(
            "parent.oxt",
            "{{ page.value }}{% include \"child.oxt\" %}",
            false,
        )
        .expect("parent compiles");
        let templates = BTreeMap::from([
            ("parent.oxt".to_owned(), parent.clone()),
            ("child.oxt".to_owned(), child),
        ]);
        exact.loop_iterations = 20;
        exact.expression_steps = 1;
        assert!(matches!(
            parent
                .render(&templates, &public_context(), &exact)
                .expect_err("include cannot reset expression budget"),
            TemplateRenderError::Limit {
                template,
                kind: TemplateLimitKind::ExpressionSteps,
            } if template == "child.oxt"
        ));
        exact.expression_steps = 100;
        exact.include_depth = 0;
        assert!(matches!(
            parent
                .render(&templates, &public_context(), &exact)
                .expect_err("depth zero rejects the first include"),
            TemplateRenderError::Limit {
                kind: TemplateLimitKind::IncludeDepth,
                ..
            }
        ));
        exact.include_depth = 1;
        assert_eq!(
            parent
                .render(&templates, &public_context(), &exact)
                .expect("depth one permits one include"),
            "dynamicdynamic"
        );

        let mut budget = RenderBudget::new();
        budget.started = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("fixture instant can move backwards");
        let mut timed = limits();
        timed.render_time = Duration::from_millis(1);
        assert!(matches!(
            budget
                .checkpoint_time("slow.oxt", &timed)
                .expect_err("cooperative time checkpoint must fail"),
            TemplateRenderError::Limit {
                template,
                kind: TemplateLimitKind::RenderTime,
            } if template == "slow.oxt"
        ));
    }

    #[test]
    #[ignore = "manual microbenchmark; run with --release --ignored --nocapture"]
    fn typed_include_render_smoke_benchmark() {
        let child = typed_template(
            "child.oxt",
            "<li>{{ item }}</li>",
            &[("item", "string")],
            TemplateOutput::Html,
            true,
        );
        let parent = CompiledOxt::inline(
            "parent.oxt",
            "<ul>{% include \"child.oxt\" with item=page.value only %}</ul>",
            true,
        )
        .expect("benchmark parent compiles");
        let templates = BTreeMap::from([
            ("parent.oxt".to_owned(), parent.clone()),
            ("child.oxt".to_owned(), child),
        ]);
        parent
            .validate_include_contracts(&templates)
            .expect("benchmark contract is valid");
        let context = public_context();
        let iterations = 50_000usize;
        let started = Instant::now();
        for _ in 0..iterations {
            std::hint::black_box(
                parent
                    .render(&templates, &context, &limits())
                    .expect("benchmark render succeeds"),
            );
        }
        eprintln!(
            "typed include render: {iterations} renders in {:?}",
            started.elapsed()
        );
    }
}
