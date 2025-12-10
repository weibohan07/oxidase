use crate::config::error::ConfigError;
use crate::config::http_server::HttpServer;
use crate::build::service::{LoadedService, build_service_ref};

#[derive(Debug, Clone)]
pub struct BuiltHttpServer {
    pub bind: String,
    pub tls: Option<crate::config::tls::TlsConfig>,
    pub service: LoadedService,
}

pub fn build_http_server(cfg: HttpServer) -> Result<BuiltHttpServer, ConfigError> {
    cfg.validate()?;
    let base = cfg.base_dir.as_deref().unwrap_or(std::path::Path::new("."));
    let service = build_service_ref(&cfg.service, base)?;
    Ok(BuiltHttpServer {
        bind: cfg.bind,
        tls: cfg.tls,
        service,
    })
}
