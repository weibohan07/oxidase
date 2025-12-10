use crate::config::error::ConfigError;
use crate::config::forward::ForwardService;
use crate::config::router::RouterService;
use crate::config::service::{Service, ServiceRef, resolve_service_ref};
use crate::config::r#static::StaticService;
use crate::build::router::{
    LoadedRule,
    compile_rules,
};
use std::collections::HashSet;
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

pub fn build_service_ref(cfg: &ServiceRef, base_dir: &Path) -> Result<LoadedService, ConfigError> {
    let mut stack = HashSet::new();
    let resolved = resolve_service_ref(cfg, base_dir, &mut stack)?;
    build_service(&resolved, base_dir)
}

pub fn build_service(cfg: &Service, base_dir: &Path) -> Result<LoadedService, ConfigError> {
    Ok(match cfg {
        Service::Static(st) => LoadedService::Static(LoadedStatic { config: st.clone() }),
        Service::Forward(fw) => LoadedService::Forward(LoadedForward { config: fw.clone() }),
        Service::Router(rt) => build_router(rt, base_dir)?,
    })
}

fn build_router(rt: &RouterService, base_dir: &Path) -> Result<LoadedService, ConfigError> {
    let next = match &rt.next {
        Some(n) => Some(Box::new(build_service_ref(n, base_dir)?)),
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
