use crate::config::error::ConfigError;
use crate::config::forward::ForwardService;
use crate::config::router::RouterService;
use crate::config::service::{Service, ServiceRef};
use crate::config::r#static::StaticService;
use crate::build::router::{
    LoadedRule,
    compile_rules,
};
use crate::parser::{ParseCache, ServiceKey, service_hash, parse_service_ref, canonicalize};
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
