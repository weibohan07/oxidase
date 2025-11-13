use serde::Deserialize;

use super::service::Service;
use super::http_method::HttpMethod;

#[derive(Debug, Deserialize, Clone)]
pub struct RouterService {
    pub routes: Vec<Route>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Route {
    #[serde(default)]
    pub when: Option<Match>,
    pub r#use: Service,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct Match {
    #[serde(default)] pub host: Option<HostCond>,
    #[serde(default)] pub path: Option<PathCond>,
    #[serde(default)] pub methods: Option<Vec<HttpMethod>>,
}
impl Match {
    pub fn is_empty(&self) -> bool {
        self.host.is_none()
        && self.path.is_none()
        && self.methods.as_ref().map_or(true, |v| v.is_empty())
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum PathCond {
    Exact(String),
    Prefix(String),
    Pattern(String),
    Regex(String),
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum HostCond {
    Exact(String),
    Prefix(String),
    Suffix(String),
    Pattern(String),
    Regex(String),
}
