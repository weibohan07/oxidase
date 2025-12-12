use std::collections::BTreeMap;

use crate::build::service::LoadedService;
use crate::config::error::ConfigError;
use crate::config::http_method::HttpMethod;
use crate::pattern::{
    compile_host,
    compile_path,
    compile_value,
    CompiledPattern,
};
use crate::config::router::op::{CondNode, PatternCtxHint};
use crate::config::router::r#match::{
    CookieCond,
    HeaderCond,
    QueryCond,
    RouterMatch,
    Scheme as RouterScheme,
};
use crate::config::router::OnMatch;
use crate::config::url_scheme::Scheme;
use crate::template::CompiledTemplate;

#[derive(Debug, Clone)]
pub struct LoadedRule {
    pub when: CompiledRouterMatch,
    pub ops: Vec<LoadedOp>,
    pub on_match: OnMatch,
}

#[derive(Debug, Clone)]
pub struct CompiledRouterMatch {
    pub host: Option<CompiledPattern>,
    pub path: Option<CompiledPattern>,
    pub methods: Vec<HttpMethod>,
    pub headers: Vec<CompiledHeaderCond>,
    pub queries: Vec<CompiledQueryCond>,
    pub cookies: Vec<CompiledCookieCond>,
    pub scheme: Option<RouterScheme>,
}

#[derive(Debug, Clone)]
pub struct CompiledHeaderCond {
    pub name: String,
    pub pattern: CompiledPattern,
    pub not: bool,
}

#[derive(Debug, Clone)]
pub struct CompiledQueryCond {
    pub key: String,
    pub pattern: CompiledPattern,
    pub not: bool,
}

#[derive(Debug, Clone)]
pub struct CompiledCookieCond {
    pub name: String,
    pub pattern: CompiledPattern,
    pub not: bool,
}

#[derive(Debug, Clone)]
pub enum LoadedOp {
    Branch(CompiledCondNode, Vec<LoadedOp>, Vec<LoadedOp>),
    SetScheme(Scheme),
    SetHost(CompiledTemplate),
    SetPort(u16),
    SetPath(CompiledTemplate),
    HeaderSet(BTreeMap<String, CompiledTemplate>),
    HeaderAdd(BTreeMap<String, CompiledTemplate>),
    HeaderDelete(Vec<String>),
    HeaderClear,
    QuerySet(BTreeMap<String, CompiledTemplate>),
    QueryAdd(BTreeMap<String, CompiledTemplate>),
    QueryDelete(Vec<String>),
    QueryClear,
    InternalRewrite,
    Redirect { status: crate::config::router::op::RedirectCode, location: CompiledTemplate },
    Respond { status: u16, body: Option<CompiledTemplate>, headers: BTreeMap<String, CompiledTemplate> },
    Use(Box<LoadedService>),
}

#[derive(Debug, Clone)]
pub enum CompiledCondNode {
    All(Vec<CompiledCondNode>),
    Any(Vec<CompiledCondNode>),
    Not(Box<CompiledCondNode>),
    Test(CompiledTestCond),
}

#[derive(Debug, Clone)]
pub enum CompiledBasicCond {
    Equals(serde_yaml::Value),
    In(Vec<serde_yaml::Value>),
    Present(bool),
    Pattern(CompiledPattern),
}

#[derive(Debug, Clone)]
pub struct CompiledTestCond {
    pub var: String,
    pub cond: CompiledBasicCond,
}

pub fn compile_match(m: &RouterMatch) -> Result<CompiledRouterMatch, ConfigError> {
    Ok(CompiledRouterMatch {
        host: compile_opt_pattern(m.host.as_deref(), compile_host)?,
        path: compile_opt_pattern(m.path.as_deref(), compile_path)?,
        methods: m.methods.clone(),
        headers: compile_headers(&m.headers)?,
        queries: compile_queries(&m.queries)?,
        cookies: compile_cookies(&m.cookies)?,
        scheme: m.scheme.clone(),
    })
}

fn compile_headers(headers: &[HeaderCond]) -> Result<Vec<CompiledHeaderCond>, ConfigError> {
    headers.iter().map(|hc| {
        Ok(CompiledHeaderCond {
            name: hc.name.to_ascii_lowercase(),
            pattern: compile_value(&hc.pattern).map_err(to_config_err)?,
            not: hc.not,
        })
    }).collect()
}

fn compile_queries(queries: &[QueryCond]) -> Result<Vec<CompiledQueryCond>, ConfigError> {
    queries.iter().map(|qc| {
        Ok(CompiledQueryCond {
            key: qc.key.clone(),
            pattern: compile_value(&qc.pattern).map_err(to_config_err)?,
            not: qc.not,
        })
    }).collect()
}

fn compile_cookies(cookies: &[CookieCond]) -> Result<Vec<CompiledCookieCond>, ConfigError> {
    cookies.iter().map(|cc| {
        Ok(CompiledCookieCond {
            name: cc.name.clone(),
            pattern: compile_value(&cc.pattern).map_err(to_config_err)?,
            not: cc.not,
        })
    }).collect()
}

fn compile_opt_pattern<F>(
    input: Option<&str>,
    f: F,
) -> Result<Option<CompiledPattern>, ConfigError>
where
    F: Fn(&str) -> Result<CompiledPattern, crate::pattern::error::PatternError>,
{
    input.map(|s| f(s).map_err(to_config_err)).transpose()
}

pub fn compile_cond(node: &CondNode) -> Result<CompiledCondNode, ConfigError> {
    Ok(match node {
        CondNode::All { all } => CompiledCondNode::All(
            all.iter().map(compile_cond).collect::<Result<Vec<_>, _>>()?
        ),
        CondNode::Any { any } => CompiledCondNode::Any(
            any.iter().map(compile_cond).collect::<Result<Vec<_>, _>>()?
        ),
        CondNode::Not { not } => CompiledCondNode::Not(Box::new(compile_cond(not)?)),
        CondNode::Test(t) => CompiledCondNode::Test(CompiledTestCond {
            var: t.var.clone(),
            cond: compile_basic_cond(&t.var, &t.cond)?,
        }),
    })
}

fn compile_basic_cond(var: &str, cond: &crate::config::router::op::BasicCond) -> Result<CompiledBasicCond, ConfigError> {
    Ok(match cond {
        crate::config::router::op::BasicCond::Equals { is } => CompiledBasicCond::Equals(is.clone()),
        crate::config::router::op::BasicCond::In { r#in } => CompiledBasicCond::In(r#in.clone()),
        crate::config::router::op::BasicCond::Present { present } => CompiledBasicCond::Present(*present),
        crate::config::router::op::BasicCond::Pattern { pattern, ctx } => {
            let pat = match select_pattern_ctx(var, ctx) {
                PatternSelect::Host => compile_host(pattern),
                PatternSelect::Path => compile_path(pattern),
                PatternSelect::Value => compile_value(pattern),
            }.map_err(to_config_err)?;
            CompiledBasicCond::Pattern(pat)
        }
    })
}

enum PatternSelect { Host, Path, Value }

fn select_pattern_ctx(var: &str, hint: &Option<PatternCtxHint>) -> PatternSelect {
    if let Some(h) = hint {
        return match h {
            PatternCtxHint::Host => PatternSelect::Host,
            PatternCtxHint::Path => PatternSelect::Path,
            PatternCtxHint::Value => PatternSelect::Value,
        };
    }
    match var {
        "host" => PatternSelect::Host,
        "path" => PatternSelect::Path,
        _ => PatternSelect::Value,
    }
}

pub fn to_config_err<E: std::error::Error>(e: E) -> ConfigError {
    ConfigError::Invalid(e.to_string())
}

#[cfg(test)]
mod tests;
