use serde::Deserialize;

use super::super::http_method::HttpMethod;

#[derive(Debug, Deserialize, Clone, Default)]
pub struct RewriteMatch {
    pub host: Option<String>,
    pub path: Option<String>,
    #[serde(default)]
    pub methods: Vec<HttpMethod>,
    #[serde(default)]
    pub headers: Vec<HeaderCond>,
    #[serde(default)]
    pub queries: Vec<QueryCond>,
    #[serde(default)]
    pub cookies: Vec<CookieCond>,
    pub scheme: Option<Scheme>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HeaderCond {
    pub name: String, // case-insensitive
    pub pattern: String,
    #[serde(default)]
    pub not: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct QueryCond {
    pub key: String, // case-sensitive
    pub pattern: String,
    #[serde(default)]
    pub not: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CookieCond {
    pub name: String, // case-sensitive
    pub pattern: String,
    #[serde(default)]
    pub not: bool,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Scheme { Http, Https }
