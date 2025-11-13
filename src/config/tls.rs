use std::path::PathBuf;
use serde::Deserialize;

use super::http_version::{default_alpn, AlpnProto};

fn default_true() -> bool { true }

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct TlsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    #[serde(default = "default_alpn")]
    pub alpn: Vec<AlpnProto>,
}
