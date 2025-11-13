use serde::Deserialize;

pub fn default_http_version() -> HttpVersion { HttpVersion::V1_1 }

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum HttpVersion {
    #[serde(rename = "1.1")]
    V1_1,
    #[serde(rename = "2")]
    V2,
}

pub fn default_alpn() -> Vec<AlpnProto> { vec![AlpnProto::Http1_1] }

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum AlpnProto {
    #[serde(rename = "http/1.1")]
    Http1_1,
    #[serde(rename = "http/2", alias = "h2")]
    Http2,
}
