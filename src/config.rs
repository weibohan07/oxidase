use serde::Deserialize;
use std::{fs::File, path::Path};

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct HttpServer {
    pub bind: String, // listened host + port
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    pub service: Service,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert_file: String,
    pub key_file: String,
    #[serde(default)]
    pub alpn: Option<Vec<String>>, // only "http/1.1" supported for now
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "handler", rename_all = "lowercase")]
pub enum Service {
    Static(StaticService),
    Forward(ForwardService),
    #[serde(alias = "proxy")]
    Router(RouterService),
}

fn default_file_index() -> String { "index.html".into() }
fn default_file_404() -> String { "404.html".into() }
fn default_file_500() -> String { "500.html".into() }

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct StaticService {
    pub source_dir: String,
    #[serde(default = "default_file_index")]
    pub file_index: String,
    #[serde(default = "default_file_404")]
    pub file_404: String,
    #[serde(default = "default_file_500")]
    pub file_500: String,
    #[serde(default = "default_index_strategy")]
    pub index_strategy: IndexStrategy,
    #[serde(default)]
    pub evil_dir_strategy: EvilDirStrategy,
}

fn default_redirect_code() -> u16 { 308 }

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
pub struct EvilDirStrategy {
    pub if_index_exists: EvilDirStrategyIndexExists,
    pub if_index_missing: EvilDirStrategyIndexMissing,
}
impl Default for EvilDirStrategy {
    fn default() -> Self {
        Self {
            if_index_exists: EvilDirStrategyIndexExists::Redirect { code: default_redirect_code() },
            if_index_missing: EvilDirStrategyIndexMissing::NotFound,
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvilDirStrategyIndexExists {
    ServeIndex,
    Redirect { #[serde(default = "default_redirect_code")] code: u16 },
    NotFound,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvilDirStrategyIndexMissing {
    Redirect { #[serde(default = "default_redirect_code")] code: u16 },
    NotFound,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexStrategy {
    ServeIndex,
    Redirect { #[serde(default = "default_redirect_code")] code: u16 },
    NotFound,
}

fn default_index_strategy() -> IndexStrategy {
    IndexStrategy::Redirect { code: default_redirect_code() }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct ForwardService {
    pub target: String,
    #[serde(default)]
    pub rewrite: Option<Rewrite>,
    #[serde(default)]
    pub pass_host: Option<PassHost>,
    #[serde(default)]
    pub headers: Option<HeaderOps>,
    #[serde(default)]
    pub timeouts: Option<Timeouts>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Rewrite {
    #[serde(default)]
    pub strip_prefix: Option<String>,
    #[serde(default)]
    pub add_prefix: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum PassHost {
    Mode(PassHostMode),
    Custom { custom: String },
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum PassHostMode {
    Incoming,
    Target,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub struct HeaderOps {
    #[serde(default)]
    pub set: Option<std::collections::BTreeMap<String, String>>,
    #[serde(default)]
    pub remove: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Timeouts {
    #[serde(default)]
    pub connect_ms: Option<u32>,
    #[serde(default)]
    pub read_ms: Option<u32>,
    #[serde(default)]
    pub write_ms: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct RouterService {
    pub routes: Vec<Route>, // first-match-wins
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Route {
    pub when: Router,
    pub r#use: Service,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub struct Router {
    #[serde(default)]
    pub hosts: Option<Vec<HostMatch>>,
    #[serde(default)]
    pub path: Option<PathMatch>,
    #[serde(default)]
    pub methods: Option<Vec<HttpMethod>>,
    #[serde(default)]
    pub headers: Option<Vec<HeaderMatch>>,
    #[serde(default)]
    pub queries: Option<Vec<QueryMatch>>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum HostMatch {
    Exact { exact: String },
    Suffix { suffix: String },
    Prefix { prefix: String },
    Wildcard { wildcard: String },
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum PathMatch {
    Exact { exact: String },
    Prefix { prefix: String },
    Regex { regex: String },
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub struct HeaderMatch {
    pub name: String,
    #[serde(default)]
    pub exact: Option<String>,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default)]
    pub present: Option<bool>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub struct QueryMatch {
    pub key: String,
    #[serde(default)]
    pub exact: Option<String>,
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default)]
    pub present: Option<bool>,
}

#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("invalid: {0}")]
    Invalid(String),
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
            if tls.enabled && (tls.cert_file.is_empty() || tls.key_file.is_empty()) {
                return Err(ConfigError::Invalid("`tls.enabled=true` requires `cert_file` & `key_file`".into()));
            }
        }
        validate_service(&self.service)?;
        Ok(())
    }
}

fn validate_service(s: &Service) -> Result<(), ConfigError> {
    match s {
        Service::Static(st) => {
            if st.source_dir.trim().is_empty() {
                return Err(ConfigError::Invalid("`static.source_dir` cannot be empty".into()));
            }
        }
        Service::Forward(fw) => {
            if fw.target.trim().is_empty() {
                return Err(ConfigError::Invalid("`forward.target` cannot be empty".into()));
            }
            if let Some(rw) = &fw.rewrite {
                if let Some(sp) = &rw.strip_prefix {
                    if !sp.starts_with('/') {
                        return Err(ConfigError::Invalid("`forward.rewrite.strip_prefix` must start with '/'".into()));
                    }
                }
                if let Some(ap) = &rw.add_prefix {
                    if !ap.starts_with('/') {
                        return Err(ConfigError::Invalid("`forward.rewrite.add_prefix` must start with '/'".into()));
                    }
                }
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
