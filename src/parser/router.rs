use crate::config::error::ConfigError;
use crate::config::router::op::RouterOp;
use crate::config::router::{OnMatch, RouterRule, RouterService};
use crate::config::service::ServiceRef;
use crate::parser::{ParseCache, ServiceDep, canonicalize, parse_service_ref_inner};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ParsedRouter {
    pub base_dir: PathBuf,
    pub rules: Vec<ParsedRouterRule>,
    pub next: Option<ServiceDep>,
    pub deps: Vec<ServiceDep>,
    pub max_steps: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct ParsedRouterRule {
    pub when: Option<crate::config::router::r#match::RouterMatch>,
    pub ops: Vec<ParsedRouterOp>,
    pub on_match: OnMatch,
}

#[derive(Debug, Clone)]
pub enum ParsedRouterOp {
    Branch(ParsedBranchOp),
    SetScheme(crate::config::url_scheme::Scheme),
    SetHost(String),
    SetPort(u16),
    SetPath(String),
    HeaderSet(std::collections::BTreeMap<String, String>),
    HeaderAdd(std::collections::BTreeMap<String, String>),
    HeaderDelete(Vec<String>),
    HeaderClear,
    QuerySet(std::collections::BTreeMap<String, String>),
    QueryAdd(std::collections::BTreeMap<String, String>),
    QueryDelete(Vec<String>),
    QueryClear,
    InternalRewrite,
    Redirect { status: crate::config::router::op::RedirectCode, location: String },
    Respond { status: u16, body: Option<String>, headers: std::collections::BTreeMap<String, String> },
    Use(ServiceDep),
}

#[derive(Debug, Clone)]
pub struct ParsedBranchOp {
    pub r#if: crate::config::router::op::CondNode,
    pub then: Vec<ParsedRouterOp>,
    pub r#else: Vec<ParsedRouterOp>,
}

pub fn parse_router(
    rt: &RouterService,
    base_dir: &Path,
    cache: &mut ParseCache,
    stack: &mut HashSet<PathBuf>,
) -> Result<ParsedRouter, ConfigError> {
    let (deps, next) = collect_deps_from_router(rt, base_dir, cache, stack)?;
    Ok(ParsedRouter {
        base_dir: base_dir.to_path_buf(),
        rules: parse_router_rules(&rt.rules, base_dir, cache, stack)?,
        next,
        deps,
        max_steps: rt.max_steps,
    })
}

fn parse_router_rules(
    rules: &[RouterRule],
    base_dir: &Path,
    cache: &mut ParseCache,
    stack: &mut HashSet<PathBuf>,
) -> Result<Vec<ParsedRouterRule>, ConfigError> {
    rules
        .iter()
        .map(|r| {
            Ok(ParsedRouterRule {
                when: r.when.clone(),
                ops: parse_ops(&r.ops, base_dir, cache, stack)?,
                on_match: r.on_match.clone(),
            })
        })
        .collect()
}

fn parse_ops(
    ops: &[RouterOp],
    base_dir: &Path,
    cache: &mut ParseCache,
    stack: &mut HashSet<PathBuf>,
) -> Result<Vec<ParsedRouterOp>, ConfigError> {
    ops.iter().map(|op| parse_op(op, base_dir, cache, stack)).collect()
}

fn parse_op(
    op: &RouterOp,
    base_dir: &Path,
    cache: &mut ParseCache,
    stack: &mut HashSet<PathBuf>,
) -> Result<ParsedRouterOp, ConfigError> {
    Ok(match op {
        RouterOp::Branch(b) => ParsedRouterOp::Branch(ParsedBranchOp {
            r#if: b.r#if.clone(),
            then: parse_ops(&b.then, base_dir, cache, stack)?,
            r#else: parse_ops(&b.r#else, base_dir, cache, stack)?,
        }),
        RouterOp::SetScheme(s) => ParsedRouterOp::SetScheme(*s),
        RouterOp::SetHost(h) => ParsedRouterOp::SetHost(h.clone()),
        RouterOp::SetPort(p) => ParsedRouterOp::SetPort(*p),
        RouterOp::SetPath(p) => ParsedRouterOp::SetPath(p.clone()),
        RouterOp::HeaderSet(m) => ParsedRouterOp::HeaderSet(m.clone()),
        RouterOp::HeaderAdd(m) => ParsedRouterOp::HeaderAdd(m.clone()),
        RouterOp::HeaderDelete(v) => ParsedRouterOp::HeaderDelete(v.clone()),
        RouterOp::HeaderClear => ParsedRouterOp::HeaderClear,
        RouterOp::QuerySet(m) => ParsedRouterOp::QuerySet(m.clone()),
        RouterOp::QueryAdd(m) => ParsedRouterOp::QueryAdd(m.clone()),
        RouterOp::QueryDelete(v) => ParsedRouterOp::QueryDelete(v.clone()),
        RouterOp::QueryClear => ParsedRouterOp::QueryClear,
        RouterOp::InternalRewrite => ParsedRouterOp::InternalRewrite,
        RouterOp::Redirect { status, location } => ParsedRouterOp::Redirect { status: *status, location: location.clone() },
        RouterOp::Respond { status, body, headers } => ParsedRouterOp::Respond { status: *status, body: body.clone(), headers: headers.clone() },
        RouterOp::Use(svc) => {
            let dep = match &**svc {
                ServiceRef::Import { import } => {
                    let path = if import.is_absolute() { import.clone() } else { base_dir.join(import) };
                    parse_service_ref_inner(svc, base_dir, cache, stack)?;
                    ServiceDep::ImportPath(canonicalize(&path))
                }
                ServiceRef::Inline(_) => {
                    let key = parse_service_ref_inner(svc, base_dir, cache, stack)?;
                    ServiceDep::Inline(key)
                }
            };
            ParsedRouterOp::Use(dep)
        }
    })
}

fn collect_deps_from_router(
    rt: &RouterService,
    base_dir: &Path,
    cache: &mut ParseCache,
    stack: &mut HashSet<PathBuf>,
) -> Result<(Vec<ServiceDep>, Option<ServiceDep>), ConfigError> {
    if let Some(next_ref) = &rt.next {
        let child_key = crate::parser::parse_service_ref_inner(next_ref, base_dir, cache, stack)?;
        let dep = match &**next_ref {
            ServiceRef::Import { import } => {
                let path = if import.is_absolute() { import.clone() } else { base_dir.join(import) };
                ServiceDep::ImportPath(canonicalize(&path))
            }
            ServiceRef::Inline(_) => ServiceDep::Inline(child_key),
        };
        return Ok((vec![dep.clone()], Some(dep)));
    }
    Ok((Vec::new(), None))
}
