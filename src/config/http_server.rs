use std::fs::File;
use serde::Deserialize;

use super::error::ConfigError;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::service::{validate_service, resolve_service_ref, ServiceRef};

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct HttpServer {
    #[serde(default)]
    pub name: Option<String>,
    pub bind: String, // listened host + port
    #[serde(default)]
    pub tls: Option<super::tls::TlsConfig>,
    pub service: ServiceRef,
    #[serde(skip)]
    pub base_dir: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServersFile {
    pub servers: Vec<HttpServer>,
}

impl HttpServer {
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let file_path = path.as_ref();
        let file = File::open(file_path)?;
        let mut cfg: HttpServer = serde_yaml::from_reader(file)?;
        cfg.base_dir = file_path.parent().map(|p| p.to_path_buf());
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.bind.trim().is_empty() {
            return Err(ConfigError::Invalid("`bind` cannot be empty".into()));
        }
        if let Some(name) = &self.name {
            if name.trim().is_empty() {
                return Err(ConfigError::Invalid("`name` cannot be empty if provided".into()));
            }
        }
        if let Some(tls) = &self.tls {
            if tls.enabled && (tls.cert_file.exists() || tls.key_file.exists()) {
                return Err(ConfigError::Invalid("`tls.enabled=true` requires `cert_file` & `key_file`".into()));
            }
        }
        let base = self.base_dir.as_deref().unwrap_or(Path::new("."));
        let mut stack = HashSet::new();
        let resolved = resolve_service_ref(&self.service, base, &mut stack)?;
        validate_service(&resolved, base)?;
        Ok(())
    }
}
