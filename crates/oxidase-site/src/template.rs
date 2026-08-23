use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use oxidase_core::expression::html_escape;
use oxidase_core::{EvalContext, Expression, Value};

use crate::SiteCompileError;
use crate::source::{AutoescapeSource, OutputSource, OxtMetadataSource};

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
    autoescape_html: bool,
    output: TemplateOutput,
    dependencies: BTreeSet<String>,
}

impl CompiledOxt {
    pub(crate) fn compile(
        name: impl Into<String>,
        metadata: &OxtMetadataSource,
        source: &str,
    ) -> Result<Self, SiteCompileError> {
        let name = name.into();
        let output = TemplateOutput::from(metadata.output);
        if output == TemplateOutput::Json {
            return Err(SiteCompileError::source(
                &name,
                "OXT `output: json` is not supported because text templates cannot guarantee valid JSON; use an OXR structured JSON body",
            ));
        }
        let params = metadata
            .params
            .iter()
            .map(|(name, kind)| {
                ValueType::parse(kind)
                    .map(|kind| (name.clone(), kind))
                    .map_err(|message| SiteCompileError::source(name, message))
            })
            .collect::<Result<_, _>>()?;
        Self::compile_parts(
            name,
            params,
            metadata
                .autoescape
                .is_some_and(|value| matches!(value, AutoescapeSource::Html))
                || metadata.autoescape.is_none() && output == TemplateOutput::Html,
            output,
            source,
        )
    }

    #[cfg(test)]
    pub(crate) fn inline(
        name: impl Into<String>,
        source: &str,
        autoescape_html: bool,
    ) -> Result<Self, SiteCompileError> {
        Self::compile_parts(
            name.into(),
            BTreeMap::new(),
            autoescape_html,
            TemplateOutput::Html,
            source,
        )
    }

    pub(crate) fn inline_with_output(
        name: impl Into<String>,
        source: &str,
        output: OutputSource,
        autoescape: Option<AutoescapeSource>,
    ) -> Result<Self, SiteCompileError> {
        let name = name.into();
        let output = TemplateOutput::from(output);
        if output == TemplateOutput::Json {
            return Err(SiteCompileError::source(
                name,
                "inline template `output: json` is not supported; use an OXR structured JSON body",
            ));
        }
        Self::compile_parts(
            name,
            BTreeMap::new(),
            autoescape.is_some_and(|value| matches!(value, AutoescapeSource::Html))
                || autoescape.is_none() && output == TemplateOutput::Html,
            output,
            source,
        )
    }

    fn compile_parts(
        name: String,
        params: BTreeMap<String, ValueType>,
        autoescape_html: bool,
        output: TemplateOutput,
        source: &str,
    ) -> Result<Self, SiteCompileError> {
        let tokens =
            tokenize(source).map_err(|message| SiteCompileError::source(&name, message))?;
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
            autoescape_html,
            output,
            dependencies,
        })
    }

    pub(crate) fn dependencies(&self) -> &BTreeSet<String> {
        &self.dependencies
    }

    pub(crate) const fn content_type(&self) -> &'static str {
        match self.output {
            TemplateOutput::Html => "text/html; charset=utf-8",
            TemplateOutput::Text => "text/plain; charset=utf-8",
            TemplateOutput::Json => "application/json",
        }
    }

    pub(crate) fn validate_arguments(
        &self,
        arguments: &BTreeMap<String, CompiledValue>,
    ) -> Result<(), SiteCompileError> {
        for (name, kind) in &self.params {
            let Some(argument) = arguments.get(name) else {
                if kind.optional() {
                    continue;
                }
                return Err(SiteCompileError::source(
                    &self.name,
                    format!("missing required template parameter `{name}`"),
                ));
            };
            if let Some(value) = argument.constant_value()
                && !kind.accepts(value)
            {
                return Err(SiteCompileError::source(
                    &self.name,
                    format!(
                        "parameter `{name}` expects {}, received {}",
                        kind.describe(),
                        value.type_name()
                    ),
                ));
            }
        }
        for name in arguments.keys() {
            if !self.params.contains_key(name) {
                return Err(SiteCompileError::source(
                    &self.name,
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
    ) -> Result<BTreeMap<String, Value>, String> {
        let mut values = BTreeMap::new();
        for (name, kind) in &self.params {
            let Some(argument) = arguments.get(name) else {
                if kind.optional() {
                    continue;
                }
                return Err(format!(
                    "template `{}` is missing required parameter `{name}`",
                    self.name
                ));
            };
            let value = argument.evaluate(context).map_err(|error| {
                format!(
                    "template `{}` parameter `{name}` evaluation failed: {error}",
                    self.name
                )
            })?;
            if !kind.accepts(&value) {
                return Err(format!(
                    "template `{}` parameter `{name}` expects {}, received {}",
                    self.name,
                    kind.describe(),
                    kind.actual_description(&value)
                ));
            }
            values.insert(name.clone(), value);
        }
        for name in arguments.keys() {
            if !self.params.contains_key(name) {
                return Err(format!(
                    "template `{}` received unknown parameter `{name}`",
                    self.name
                ));
            }
        }
        Ok(values)
    }

    pub(crate) fn render(
        &self,
        templates: &BTreeMap<String, Self>,
        context: &EvalContext,
        limits: &TemplateLimits,
    ) -> Result<String, String> {
        let mut state = RenderState {
            started: Instant::now(),
            output: String::new(),
            iterations: 0,
            expression_steps: 0,
        };
        render_template(self, templates, context, limits, 0, &mut state)?;
        Ok(state.output)
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
    Include(String),
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
                TemplateToken::Expression(source) => {
                    nodes.push(TemplateNode::Interpolation(
                        Expression::compile(source).map_err(|error| {
                            SiteCompileError::source(self.name, error.to_string())
                        })?,
                    ));
                    self.position += 1;
                }
                TemplateToken::Tag(tag) => {
                    let keyword = tag.split_whitespace().next().unwrap_or("");
                    if stops.contains(&keyword) {
                        self.position += 1;
                        return Ok((nodes, Some(tag.clone())));
                    }
                    self.position += 1;
                    match keyword {
                        "if" => nodes.push(self.parse_if(tag)?),
                        "for" => nodes.push(self.parse_for(tag)?),
                        "with" => nodes.push(self.parse_with(tag)?),
                        "include" => nodes.push(self.parse_include(tag)?),
                        "extends" | "block" | "endblock" => {
                            return Err(SiteCompileError::source(
                                self.name,
                                "`extends`/`block` is not implemented; use static `include` in this release",
                            ));
                        }
                        _ => {
                            return Err(SiteCompileError::source(
                                self.name,
                                format!("unknown or misplaced template tag `{tag}`"),
                            ));
                        }
                    }
                }
            }
        }
        Ok((nodes, None))
    }

    fn parse_if(&mut self, opening: &str) -> Result<TemplateNode, SiteCompileError> {
        let condition = tag_argument(opening, "if")?;
        let mut branches = Vec::new();
        let mut current = Expression::compile(condition)
            .map_err(|error| SiteCompileError::source(self.name, error.to_string()))?;
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
                        return Err(SiteCompileError::source(self.name, "unclosed `if` block"));
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
                _ => return Err(SiteCompileError::source(self.name, "unclosed `if` block")),
            }
        }
    }

    fn parse_for(&mut self, opening: &str) -> Result<TemplateNode, SiteCompileError> {
        let source = tag_argument(opening, "for")?;
        let (binding, values) = source.split_once(" in ").ok_or_else(|| {
            SiteCompileError::source(self.name, "`for` syntax is `for name in expression`")
        })?;
        validate_binding(binding, self.name)?;
        let values = Expression::compile(values)
            .map_err(|error| SiteCompileError::source(self.name, error.to_string()))?;
        let (body, stop) = self.parse_nodes(&["else", "endfor"])?;
        let otherwise = if stop.as_deref() == Some("else") {
            let (otherwise, stop) = self.parse_nodes(&["endfor"])?;
            if stop.as_deref() != Some("endfor") {
                return Err(SiteCompileError::source(self.name, "unclosed `for` block"));
            }
            otherwise
        } else if stop.as_deref() == Some("endfor") {
            Vec::new()
        } else {
            return Err(SiteCompileError::source(self.name, "unclosed `for` block"));
        };
        Ok(TemplateNode::For {
            binding: binding.to_owned(),
            values,
            body,
            otherwise,
        })
    }

    fn parse_with(&mut self, opening: &str) -> Result<TemplateNode, SiteCompileError> {
        let source = tag_argument(opening, "with")?;
        let (binding, value) = source.split_once('=').ok_or_else(|| {
            SiteCompileError::source(self.name, "`with` syntax is `with name = expression`")
        })?;
        let binding = binding.trim();
        validate_binding(binding, self.name)?;
        let value = Expression::compile(value.trim())
            .map_err(|error| SiteCompileError::source(self.name, error.to_string()))?;
        let (body, stop) = self.parse_nodes(&["endwith"])?;
        if stop.as_deref() != Some("endwith") {
            return Err(SiteCompileError::source(self.name, "unclosed `with` block"));
        }
        Ok(TemplateNode::With {
            binding: binding.to_owned(),
            value,
            body,
        })
    }

    fn parse_include(&mut self, tag: &str) -> Result<TemplateNode, SiteCompileError> {
        let source = tag_argument(tag, "include")?;
        let name = quoted_static_path(source).ok_or_else(|| {
            SiteCompileError::source(self.name, "include path must be a static quoted string")
        })?;
        let name = normalize_template_name(name)?;
        self.dependencies.insert(name.clone());
        Ok(TemplateNode::Include(name))
    }
}

fn render_template(
    template: &CompiledOxt,
    templates: &BTreeMap<String, CompiledOxt>,
    context: &EvalContext,
    limits: &TemplateLimits,
    depth: usize,
    state: &mut RenderState,
) -> Result<(), String> {
    if depth > limits.include_depth {
        return Err("template include depth limit exceeded".to_owned());
    }
    render_nodes(
        &template.nodes,
        template.autoescape_html,
        templates,
        context,
        limits,
        depth,
        state,
    )
}

fn render_nodes(
    nodes: &[TemplateNode],
    autoescape_html: bool,
    templates: &BTreeMap<String, CompiledOxt>,
    context: &EvalContext,
    limits: &TemplateLimits,
    depth: usize,
    state: &mut RenderState,
) -> Result<(), String> {
    for node in nodes {
        check_limits(limits, state)?;
        match node {
            TemplateNode::Text(value) => push_output(value, limits, state)?,
            TemplateNode::Interpolation(expression) => {
                state.expression_steps += 1;
                let value = expression
                    .evaluate(context)
                    .map_err(|error| error.to_string())?;
                if value.is_null() && limits.strict_undefined {
                    return Err(format!(
                        "strict undefined value in expression `{}`",
                        expression.source()
                    ));
                }
                let value = value.render().map_err(str::to_owned)?;
                if autoescape_html {
                    push_output(&html_escape(&value), limits, state)?;
                } else {
                    push_output(&value, limits, state)?;
                }
            }
            TemplateNode::If {
                branches,
                otherwise,
            } => {
                let mut rendered = false;
                for (condition, body) in branches {
                    state.expression_steps += 1;
                    let value = condition
                        .evaluate(context)
                        .map_err(|error| error.to_string())?;
                    let Some(value) = value.as_bool() else {
                        return Err(format!(
                            "if expression `{}` did not return bool",
                            condition.source()
                        ));
                    };
                    if value {
                        render_nodes(
                            body,
                            autoescape_html,
                            templates,
                            context,
                            limits,
                            depth,
                            state,
                        )?;
                        rendered = true;
                        break;
                    }
                }
                if !rendered {
                    render_nodes(
                        otherwise,
                        autoescape_html,
                        templates,
                        context,
                        limits,
                        depth,
                        state,
                    )?;
                }
            }
            TemplateNode::For {
                binding,
                values,
                body,
                otherwise,
            } => {
                state.expression_steps += 1;
                let values = values
                    .evaluate(context)
                    .map_err(|error| error.to_string())?;
                let Value::List(values) = values else {
                    return Err("for expression must return a list".to_owned());
                };
                if values.is_empty() {
                    render_nodes(
                        otherwise,
                        autoescape_html,
                        templates,
                        context,
                        limits,
                        depth,
                        state,
                    )?;
                } else {
                    for value in values {
                        state.iterations += 1;
                        check_limits(limits, state)?;
                        let mut child = context.clone();
                        child.insert(binding, value);
                        render_nodes(
                            body,
                            autoescape_html,
                            templates,
                            &child,
                            limits,
                            depth,
                            state,
                        )?;
                    }
                }
            }
            TemplateNode::With {
                binding,
                value,
                body,
            } => {
                state.expression_steps += 1;
                let value = value.evaluate(context).map_err(|error| error.to_string())?;
                let mut child = context.clone();
                child.insert(binding, value);
                render_nodes(
                    body,
                    autoescape_html,
                    templates,
                    &child,
                    limits,
                    depth,
                    state,
                )?;
            }
            TemplateNode::Include(name) => {
                let template = templates
                    .get(name)
                    .ok_or_else(|| format!("compiled include `{name}` is missing"))?;
                render_template(template, templates, context, limits, depth + 1, state)?;
            }
        }
    }
    Ok(())
}

struct RenderState {
    started: Instant,
    output: String,
    iterations: usize,
    expression_steps: usize,
}

fn push_output(
    value: &str,
    limits: &TemplateLimits,
    state: &mut RenderState,
) -> Result<(), String> {
    if state.output.len().saturating_add(value.len()) > limits.output_size {
        return Err("template output size limit exceeded".to_owned());
    }
    state.output.push_str(value);
    Ok(())
}

fn check_limits(limits: &TemplateLimits, state: &RenderState) -> Result<(), String> {
    if state.started.elapsed() > limits.render_time {
        Err("template render time limit exceeded".to_owned())
    } else if state.iterations > limits.loop_iterations {
        Err("template loop iteration limit exceeded".to_owned())
    } else if state.expression_steps > limits.expression_steps {
        Err("template expression step limit exceeded".to_owned())
    } else {
        Ok(())
    }
}

#[derive(Debug)]
enum TemplateToken {
    Text(String),
    Expression(String),
    Tag(String),
}

fn tokenize(source: &str) -> Result<Vec<TemplateToken>, String> {
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
            let end = raw
                .find("{% endraw %}")
                .ok_or_else(|| "unclosed `raw` block".to_owned())?;
            tokens.push(TemplateToken::Text(raw[..end].to_owned()));
            cursor = start + "{% raw %}".len() + end + "{% endraw %}".len();
        } else if rest.starts_with("{{") {
            let expression_start = start + 2;
            let end = source[expression_start..]
                .find("}}")
                .map(|end| expression_start + end)
                .ok_or_else(|| "unclosed interpolation".to_owned())?;
            let expression = source[expression_start..end].trim();
            if expression.is_empty() {
                return Err("empty interpolation".to_owned());
            }
            tokens.push(TemplateToken::Expression(expression.to_owned()));
            cursor = end + 2;
        } else if rest.starts_with("{#") {
            let comment_start = start + 2;
            let end = source[comment_start..]
                .find("#}")
                .map(|end| comment_start + end)
                .ok_or_else(|| "unclosed template comment".to_owned())?;
            cursor = end + 2;
        } else if rest.starts_with("{%") {
            let tag_start = start + 2;
            let end = source[tag_start..]
                .find("%}")
                .map(|end| tag_start + end)
                .ok_or_else(|| "unclosed template tag".to_owned())?;
            let tag = source[tag_start..end].trim();
            if tag.is_empty() {
                return Err("empty template tag".to_owned());
            }
            tokens.push(TemplateToken::Tag(tag.to_owned()));
            cursor = end + 2;
        } else {
            tokens.push(TemplateToken::Text("{".to_owned()));
            cursor = start + 1;
        }
    }
    Ok(tokens)
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

fn quoted_static_path(source: &str) -> Option<&str> {
    source
        .strip_prefix('"')
        .and_then(|source| source.strip_suffix('"'))
        .or_else(|| {
            source
                .strip_prefix('\'')
                .and_then(|source| source.strip_suffix('\''))
        })
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
    use std::time::Duration;

    use oxidase_core::{EvalContext, Value};

    use super::{CompiledOxt, TemplateLimits};

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
        assert!(
            template
                .render(&BTreeMap::new(), &context, &strict_limits)
                .expect_err("output must be bounded")
                .contains("output size")
        );
        strict_limits.output_size = 1024;
        strict_limits.loop_iterations = 1;
        assert!(
            template
                .render(&BTreeMap::new(), &context, &strict_limits)
                .expect_err("loop count must be bounded")
                .contains("loop iteration")
        );
    }
}
