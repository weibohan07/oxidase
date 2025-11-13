use std::{fs::File, path::Path};
use serde::Deserialize;

use super::error::ConfigError;
use super::service::validate_service;

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct HttpServer {
    pub bind: String, // listened host + port
    #[serde(default)]
    pub tls: Option<super::tls::TlsConfig>,
    pub service: super::service::Service,
}

impl HttpServer {
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let file = File::open(path)?;
        let cfg: HttpServer = serde_yaml::from_reader(file)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.bind.trim().is_empty() {
            return Err(ConfigError::Invalid("`bind` cannot be empty".into()));
        }
        if let Some(tls) = &self.tls {
            if tls.enabled && (tls.cert_file.exists() || tls.key_file.exists()) {
                return Err(ConfigError::Invalid("`tls.enabled=true` requires `cert_file` & `key_file`".into()));
            }
        }
        validate_service(&self.service)?;
        Ok(())
    }
}
