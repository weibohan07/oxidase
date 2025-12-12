use crate::config::error::ConfigError;
use crate::config::http_server::HttpServer;
use crate::build::service::{BuildCache, LoadedService, build_from_parsed};
use crate::parser::{ParseCache, parse_service_ref};

#[derive(Debug, Clone)]
pub struct BuiltHttpServer {
    pub bind: String,
    #[allow(dead_code)]
    pub tls: Option<crate::config::tls::TlsConfig>,
    pub service: LoadedService,
}

#[allow(dead_code)]
pub fn build_http_server(cfg: HttpServer) -> Result<BuiltHttpServer, ConfigError> {
    let mut parse_cache = ParseCache::default();
    let mut build_cache = BuildCache::default();
    build_http_server_with_caches(cfg, &mut parse_cache, &mut build_cache)
}

pub fn build_http_server_with_caches(
    cfg: HttpServer,
    parse_cache: &mut ParseCache,
    build_cache: &mut BuildCache,
) -> Result<BuiltHttpServer, ConfigError> {
    cfg.validate()?;
    let base = cfg.base_dir.as_deref().unwrap_or(std::path::Path::new("."));
    let parsed = parse_service_ref(&cfg.service, base, parse_cache)?;
    let service = build_from_parsed(&parsed, &parsed.root, build_cache)?;
    Ok(BuiltHttpServer {
        bind: cfg.bind,
        tls: cfg.tls,
        service,
    })
}
