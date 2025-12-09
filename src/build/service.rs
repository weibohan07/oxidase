use crate::config::error::ConfigError;
use crate::config::forward::ForwardService;
use crate::config::http_server::HttpServer;
use crate::config::router::RouterService;
use crate::config::service::Service;
use crate::config::r#static::StaticService;

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
    pub rules: Vec<crate::config::router::RouterRule>,
    pub next: Box<LoadedService>,
    pub max_steps: u32,
}

#[derive(Debug, Clone)]
pub struct BuiltHttpServer {
    pub bind: String,
    pub tls: Option<crate::config::tls::TlsConfig>,
    pub service: LoadedService,
}

pub fn build_http_server(cfg: HttpServer) -> Result<BuiltHttpServer, ConfigError> {
    cfg.validate()?;
    let service = build_service(&cfg.service)?;
    Ok(BuiltHttpServer {
        bind: cfg.bind,
        tls: cfg.tls,
        service,
    })
}

pub fn build_service(cfg: &Service) -> Result<LoadedService, ConfigError> {
    Ok(match cfg {
        Service::Static(st) => LoadedService::Static(LoadedStatic { config: st.clone() }),
        Service::Forward(fw) => LoadedService::Forward(LoadedForward { config: fw.clone() }),
        Service::Router(rt) => build_router(rt)?,
    })
}

fn build_router(rt: &RouterService) -> Result<LoadedService, ConfigError> {
    let next = build_service(&rt.next)?;
    let max_steps = rt.max_steps.unwrap_or(DEFAULT_MAX_STEPS);

    // TODO: compile matchers/templates once available.
    let mut rules = Vec::new();
    for r in &rt.rules {
        rules.push(r.clone());
    }

    Ok(LoadedService::Router(LoadedRouter {
        rules,
        next: Box::new(next),
        max_steps,
    }))
}
