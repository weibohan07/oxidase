use crate::config::error::ConfigError;
use crate::config::forward::ForwardService;
use crate::config::service::{Service, ServiceRef};
use crate::config::r#static::StaticService;
use crate::build::router::{LoadedOp, LoadedRule, compile_match};
use crate::parser::{
    ParseCache,
    ParseResult,
    ParsedRouter,
    ParsedRouterOp,
    ParsedRouterRule,
    ParsedService,
    ServiceDep,
    ServiceKey,
    canonicalize,
    parse_service_ref,
};
use std::path::Path;

const DEFAULT_MAX_STEPS: u32 = 16;

#[derive(Debug, Clone)]
pub enum LoadedService {
    Static(LoadedStatic),
    Router(LoadedRouter),
    Forward(LoadedForward),
}

#[derive(Debug, Clone)]
pub struct LoadedStatic {
    pub config: StaticService,
}

#[derive(Debug, Clone)]
pub struct LoadedForward {
    pub config: ForwardService,
}

#[derive(Debug, Clone)]
pub struct LoadedRouter {
    pub rules: Vec<LoadedRule>,
    pub next: Option<Box<LoadedService>>,
    pub max_steps: u32,
}

#[derive(Default)]
pub struct BuildCache {
    compiled: std::collections::HashMap<ServiceKey, LoadedService>,
}

#[allow(dead_code)]
pub fn build_service_ref(cfg: &ServiceRef, base_dir: &Path) -> Result<LoadedService, ConfigError> {
    let mut parse_cache = ParseCache::default();
    let mut cache = BuildCache::default();
    let parsed = parse_service_ref(cfg, base_dir, &mut parse_cache)?;
    build_from_parsed(&parsed, &parsed.root, &mut cache)
}

#[allow(dead_code)]
pub fn build_service(cfg: &Service, base_dir: &Path) -> Result<LoadedService, ConfigError> {
    let mut parse_cache = ParseCache::default();
    let mut cache = BuildCache::default();
    let parsed = parse_service_ref(&ServiceRef::Inline(cfg.clone()), base_dir, &mut parse_cache)?;
    build_from_parsed(&parsed, &parsed.root, &mut cache)
}

pub fn build_from_parsed(
    graph: &ParseResult,
    root: &ServiceKey,
    build_cache: &mut BuildCache,
) -> Result<LoadedService, ConfigError> {
    compile_key(root, graph, build_cache)
}

fn compile_key(
    key: &ServiceKey,
    graph: &ParseResult,
    build_cache: &mut BuildCache,
) -> Result<LoadedService, ConfigError> {
    if let Some(hit) = build_cache.compiled.get(key) {
        return Ok(hit.clone());
    }
    let parsed = graph.services.get(key).ok_or_else(|| ConfigError::Invalid("missing parsed service".into()))?;
    let built = match parsed {
        ParsedService::Static(st) => {
            let base = canonicalize(&st.base_dir);
            let _ = base;
            LoadedService::Static(LoadedStatic { config: st.config.clone() })
        }
        ParsedService::Forward(fw) => {
            let base = canonicalize(&fw.base_dir);
            let _ = base;
            LoadedService::Forward(LoadedForward { config: fw.config.clone() })
        }
        ParsedService::Router(rt) => {
            let base = canonicalize(&rt.base_dir);
            build_router(rt, &base, graph, build_cache)?
        }
    };
    build_cache.compiled.insert(key.clone(), built.clone());
    Ok(built)
}

fn build_router(
    rt: &ParsedRouter,
    base_dir: &Path,
    graph: &ParseResult,
    build_cache: &mut BuildCache,
) -> Result<LoadedService, ConfigError> {
    let next = match rt.next.as_ref() {
        Some(ServiceDep::Inline(k)) => Some(Box::new(compile_key(&k, graph, build_cache)?)),
        Some(ServiceDep::ImportPath(p)) => {
            let key = graph.import_to_key.get(p.as_path()).ok_or_else(|| ConfigError::Invalid(format!("missing import mapping for {}", p.display())))?;
            Some(Box::new(compile_key(key, graph, build_cache)?))
        }
        None => None,
    };
    let max_steps = rt.max_steps.unwrap_or(DEFAULT_MAX_STEPS);
    let rules = compile_parsed_rules(&rt.rules, base_dir, graph, build_cache)?;
    Ok(LoadedService::Router(LoadedRouter { rules, next, max_steps }))
}

fn compile_parsed_rules(
    rules: &[ParsedRouterRule],
    base_dir: &Path,
    graph: &ParseResult,
    build_cache: &mut BuildCache,
) -> Result<Vec<LoadedRule>, ConfigError> {
    rules.iter().map(|r| {
        Ok(LoadedRule {
            when: compile_match(r.when.as_ref().unwrap_or(&crate::config::router::r#match::RouterMatch::default()))?,
            ops: compile_parsed_ops(&r.ops, base_dir, graph, build_cache)?,
            on_match: r.on_match.clone(),
        })
    }).collect()
}

fn compile_parsed_ops(
    ops: &[ParsedRouterOp],
    base_dir: &Path,
    graph: &ParseResult,
    build_cache: &mut BuildCache,
) -> Result<Vec<LoadedOp>, ConfigError> {
    ops.iter().map(|op| compile_parsed_op(op, base_dir, graph, build_cache)).collect()
}

fn compile_parsed_op(
    op: &ParsedRouterOp,
    base_dir: &Path,
    graph: &ParseResult,
    build_cache: &mut BuildCache,
) -> Result<LoadedOp, ConfigError> {
    Ok(match op {
        ParsedRouterOp::Branch(b) => {
            let cond = crate::build::router::compile_cond(&b.r#if)?;
            let then_ops = compile_parsed_ops(&b.then, base_dir, graph, build_cache)?;
            let else_ops = compile_parsed_ops(&b.r#else, base_dir, graph, build_cache)?;
            LoadedOp::Branch(cond, then_ops, else_ops)
        }
        ParsedRouterOp::SetScheme(s) => LoadedOp::SetScheme(*s),
        ParsedRouterOp::SetHost(h) => LoadedOp::SetHost(crate::template::compile_template(h).map_err(crate::build::router::to_config_err)?),
        ParsedRouterOp::SetPort(p) => LoadedOp::SetPort(*p),
        ParsedRouterOp::SetPath(p) => LoadedOp::SetPath(crate::template::compile_template(p).map_err(crate::build::router::to_config_err)?),
        ParsedRouterOp::HeaderSet(m) => {
            let mut compiled = std::collections::BTreeMap::new();
            for (k, v) in m {
                compiled.insert(k.clone(), crate::template::compile_template(v).map_err(crate::build::router::to_config_err)?);
            }
            LoadedOp::HeaderSet(compiled)
        }
        ParsedRouterOp::HeaderAdd(m) => {
            let mut compiled = std::collections::BTreeMap::new();
            for (k, v) in m {
                compiled.insert(k.clone(), crate::template::compile_template(v).map_err(crate::build::router::to_config_err)?);
            }
            LoadedOp::HeaderAdd(compiled)
        }
        ParsedRouterOp::HeaderDelete(v) => LoadedOp::HeaderDelete(v.clone()),
        ParsedRouterOp::HeaderClear => LoadedOp::HeaderClear,
        ParsedRouterOp::QuerySet(m) => {
            let mut compiled = std::collections::BTreeMap::new();
            for (k, v) in m {
                compiled.insert(k.clone(), crate::template::compile_template(v).map_err(crate::build::router::to_config_err)?);
            }
            LoadedOp::QuerySet(compiled)
        }
        ParsedRouterOp::QueryAdd(m) => {
            let mut compiled = std::collections::BTreeMap::new();
            for (k, v) in m {
                compiled.insert(k.clone(), crate::template::compile_template(v).map_err(crate::build::router::to_config_err)?);
            }
            LoadedOp::QueryAdd(compiled)
        }
        ParsedRouterOp::QueryDelete(v) => LoadedOp::QueryDelete(v.clone()),
        ParsedRouterOp::QueryClear => LoadedOp::QueryClear,
        ParsedRouterOp::InternalRewrite => LoadedOp::InternalRewrite,
        ParsedRouterOp::Redirect { status, location } => {
            LoadedOp::Redirect { status: *status, location: crate::template::compile_template(location).map_err(crate::build::router::to_config_err)? }
        }
        ParsedRouterOp::Respond { status, body, headers } => {
            let compiled_body = match body {
                Some(b) => Some(crate::template::compile_template(b).map_err(crate::build::router::to_config_err)?),
                None => None,
            };
            let mut compiled_headers = std::collections::BTreeMap::new();
            for (k, v) in headers {
                compiled_headers.insert(k.clone(), crate::template::compile_template(v).map_err(crate::build::router::to_config_err)?);
            }
            LoadedOp::Respond { status: *status, body: compiled_body, headers: compiled_headers }
        }
        ParsedRouterOp::Use(dep) => {
            let key = match dep {
                ServiceDep::Inline(k) => k.clone(),
                ServiceDep::ImportPath(p) => graph.import_to_key.get(p).ok_or_else(|| ConfigError::Invalid(format!("missing import mapping for {}", p.display())))?.clone(),
            };
            let built = compile_key(&key, graph, build_cache)?;
            LoadedOp::Use(Box::new(built))
        }
    })
}

#[cfg(test)]
mod tests;
