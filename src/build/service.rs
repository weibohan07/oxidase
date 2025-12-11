use crate::config::error::ConfigError;
use crate::config::forward::ForwardService;
use crate::config::router::RouterService;
use crate::config::service::{Service, ServiceRef};
use crate::config::r#static::StaticService;
use crate::build::router::{
    LoadedRule,
    compile_rules,
};
use std::collections::HashSet;
use std::path::Path;
use std::fs::File;
use sha2::Digest;

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

#[derive(Debug, Clone)]
pub struct ParsedService {
    pub service: Service,
    pub base_dir: std::path::PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ServiceKey {
    pub base_dir: std::path::PathBuf,
    pub hash: String,
}

#[derive(Default, Clone)]
pub struct ParseCache {
    imports: std::collections::HashMap<std::path::PathBuf, ParsedService>,
    inline: std::collections::HashMap<ServiceKey, ParsedService>,
}

#[derive(Default)]
pub struct BuildCache {
    compiled: std::collections::HashMap<ServiceKey, LoadedService>,
}

pub(crate) fn service_hash(svc: &Service) -> Result<String, ConfigError> {
    let serialized = format!("{:?}", svc);
    let digest = sha2::Sha256::digest(serialized.as_bytes());
    Ok(format!("{:x}", digest))
}

fn canonicalize(path: &Path) -> std::path::PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

pub fn parse_service_ref(
    svc: &ServiceRef,
    base_dir: &Path,
    cache: &mut ParseCache,
) -> Result<ParsedService, ConfigError> {
    let mut stack = HashSet::new();
    parse_service_ref_inner(svc, base_dir, cache, &mut stack)
}

fn parse_service_ref_inner(
    svc: &ServiceRef,
    base_dir: &Path,
    cache: &mut ParseCache,
    stack: &mut HashSet<std::path::PathBuf>,
) -> Result<ParsedService, ConfigError> {
    match svc {
        ServiceRef::Inline(s) => {
            let base = canonicalize(base_dir);
            let key = ServiceKey { base_dir: base.clone(), hash: service_hash(s)? };
            if let Some(hit) = cache.inline.get(&key) {
                return Ok(hit.clone());
            }
            let parsed = ParsedService { service: s.clone(), base_dir: base };
            cache.inline.insert(key, parsed.clone());
            Ok(parsed)
        }
        ServiceRef::Import { import } => {
            let path = if import.is_absolute() { import.clone() } else { base_dir.join(import) };
            let canon = canonicalize(&path);
            if let Some(hit) = cache.imports.get(&canon) {
                return Ok(hit.clone());
            }
            if !stack.insert(canon.clone()) {
                return Err(ConfigError::Invalid(format!("service import cycle at {}", canon.display())));
            }
            let file = File::open(&canon)?;
            let nested: ServiceRef = serde_yaml::from_reader(file)?;
            let nested_base = canon.parent().unwrap_or(base_dir);
            let parsed = parse_service_ref_inner(&nested, nested_base, cache, stack)?;
            stack.remove(&canon);
            cache.imports.insert(canon.clone(), parsed.clone());
            Ok(parsed)
        }
    }
}

pub fn build_service_ref(cfg: &ServiceRef, base_dir: &Path) -> Result<LoadedService, ConfigError> {
    let mut parse_cache = ParseCache::default();
    let mut cache = BuildCache::default();
    let parsed = parse_service_ref(cfg, base_dir, &mut parse_cache)?;
    build_service_with_cache(&parsed.service, &parsed.base_dir, &mut parse_cache, &mut cache)
}

#[allow(dead_code)]
pub fn build_service(cfg: &Service, base_dir: &Path) -> Result<LoadedService, ConfigError> {
    let mut parse_cache = ParseCache::default();
    let mut cache = BuildCache::default();
    build_service_with_cache(cfg, base_dir, &mut parse_cache, &mut cache)
}

pub fn build_service_with_cache(
    cfg: &Service,
    base_dir: &Path,
    parse_cache: &mut ParseCache,
    build_cache: &mut BuildCache,
) -> Result<LoadedService, ConfigError> {
    let base = canonicalize(base_dir);
    Ok(match cfg {
        Service::Static(st) => {
            let key = ServiceKey { base_dir: base.clone(), hash: service_hash(cfg)? };
            if let Some(hit) = build_cache.compiled.get(&key) {
                return Ok(hit.clone());
            }
            let built = LoadedService::Static(LoadedStatic { config: st.clone() });
            build_cache.compiled.insert(key, built.clone());
            built
        }
        Service::Forward(fw) => {
            let key = ServiceKey { base_dir: base.clone(), hash: service_hash(cfg)? };
            if let Some(hit) = build_cache.compiled.get(&key) {
                return Ok(hit.clone());
            }
            let built = LoadedService::Forward(LoadedForward { config: fw.clone() });
            build_cache.compiled.insert(key, built.clone());
            built
        }
        Service::Router(rt) => {
            let key = ServiceKey { base_dir: base.clone(), hash: service_hash(cfg)? };
            if let Some(hit) = build_cache.compiled.get(&key) {
                return Ok(hit.clone());
            }
            let built = build_router(rt, &base, parse_cache, build_cache)?;
            build_cache.compiled.insert(key, built.clone());
            built
        }
    })
}

fn build_router(
    rt: &RouterService,
    base_dir: &Path,
    parse_cache: &mut ParseCache,
    build_cache: &mut BuildCache,
) -> Result<LoadedService, ConfigError> {
    let next = match &rt.next {
        Some(n) => {
            let parsed = parse_service_ref(n, base_dir, parse_cache)?;
            Some(Box::new(build_service_with_cache(&parsed.service, &parsed.base_dir, parse_cache, build_cache)?))
        }
        None => None,
    };
    let max_steps = rt.max_steps.unwrap_or(DEFAULT_MAX_STEPS);

    let rules = compile_rules(&rt.rules, base_dir)?;

    Ok(LoadedService::Router(LoadedRouter {
        rules,
        next,
        max_steps,
    }))
}

#[cfg(test)]
mod tests;
