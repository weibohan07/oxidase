use serde::Deserialize;

use super::error::ConfigError;

use super::{
    r#static::StaticService,
    rewrite::RewriteService,
    forward::ForwardService,
    router::RouterService,
};

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "handler", rename_all = "lowercase")]
pub enum Service {
    Static(StaticService),
    Rewrite(RewriteService),
    Forward(ForwardService),
    Router(RouterService),
}

pub fn validate_service(svc: &Service) -> Result<(), ConfigError> {
    match svc {
        Service::Static(st) => {
            if st.source_dir.trim().is_empty() {
                return Err(ConfigError::Invalid("`static.source_dir` cannot be empty".into()));
            }
        }
        Service::Rewrite(rw) => {
            if rw.rules.is_empty() {
                return Err(ConfigError::Invalid("`rewrite.rules` cannot be empty".into()));
            }
            validate_service(&rw.next)?;
        }
        Service::Forward(fw) => {
            if fw.target.host.trim().is_empty() {
                return Err(ConfigError::Invalid("`forward.target.host` cannot be empty".into()));
            }
        }
        Service::Router(rt) => {
            if rt.routes.is_empty() {
                return Err(ConfigError::Invalid("`router.routes` cannot be empty".into()));
            }
            for r in &rt.routes {
                validate_service(&r.r#use)?;
            }
        }
    }
    Ok(())
}
