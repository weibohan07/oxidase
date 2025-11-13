pub mod tls;

use serde::Deserialize;

use super::http_version::{HttpVersion, default_http_version};
use super::url_scheme::Scheme;

fn default_true() -> bool { true }

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct ForwardService {
    pub target: ForwardTarget,
    #[serde(default)]
    pub pass_host: PassHost,
    #[serde(default = "default_true")]
    pub x_forwarded: bool,
    #[serde(default, flatten)]
    pub timeouts: Timeouts,
    #[serde(default = "default_http_version")]
    pub http_version: HttpVersion,
    #[serde(default)]
    pub tls: Option<tls::TlsUpstream>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ForwardTarget {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub path_prefix: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum PassHost { Mode(PassHostMode), Custom { custom: String } }

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum PassHostMode { Incoming, Target }

impl Default for PassHost {
    fn default() -> Self { PassHost::Mode(PassHostMode::Incoming) }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Timeouts {
    pub connect_ms: Option<u32>,
    pub read_ms: Option<u32>,
    pub write_ms: Option<u32>,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            connect_ms: None,
            read_ms: None,
            write_ms: None,
        }
    }
}
