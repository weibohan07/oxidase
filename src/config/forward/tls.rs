use serde::Deserialize;
use std::path::PathBuf;
use super::super::http_version::{AlpnProto, default_alpn};

fn default_true() -> bool { true }
fn default_min_tls() -> TlsVersion { TlsVersion::V12 }
fn default_max_tls() -> TlsVersion { TlsVersion::V13 }

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct TlsUpstream {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default)]
    pub sni: Option<String>,

    #[serde(default = "default_alpn")]
    pub alpn: Vec<AlpnProto>,

    #[serde(default = "default_true")]
    pub use_system_roots: bool,

    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    #[serde(default)]
    pub ca_files: Option<Vec<PathBuf>>,
    #[serde(default)]
    pub ca_inline: Option<String>,

    #[serde(default)]
    pub allow_invalid_hostnames: bool,
    #[serde(default)]
    pub insecure_skip_verify: bool,

    #[serde(default)]
    pub client_cert_file: Option<PathBuf>,
    #[serde(default)]
    pub client_key_file: Option<PathBuf>,

    #[serde(default = "default_min_tls")]
    pub min_tls: TlsVersion,
    #[serde(default = "default_max_tls")]
    pub max_tls: TlsVersion,

    #[serde(default)]
    pub cipher_suites: Option<Vec<String>>,

    #[serde(default)]
    pub handshake_timeout_ms: Option<u32>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    #[serde(rename = "1.2")] V12,
    #[serde(rename = "1.3")] V13,
}
