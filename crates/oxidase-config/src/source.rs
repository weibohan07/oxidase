use std::collections::BTreeMap;
use std::path::PathBuf;

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GatewaySource {
    pub api_version: String,
    pub kind: String,
    #[serde(default)]
    pub imports: Vec<PathBuf>,
    #[serde(default)]
    pub resources: ResourcesSource,
    #[serde(default)]
    pub services: BTreeMap<String, ServiceSource>,
    #[serde(default)]
    pub listeners: Vec<ListenerSource>,
    #[serde(default)]
    pub tests: Vec<ConfigTestSource>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResourcesSource {
    #[serde(default)]
    pub certificates: BTreeMap<String, CertificateSource>,
    #[serde(default)]
    pub clusters: BTreeMap<String, ClusterSource>,
    #[serde(default)]
    pub sites: BTreeMap<String, SiteSource>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CertificateSource {
    pub cert_chain: PathBuf,
    pub private_key: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClusterSource {
    #[serde(default = "default_cluster_protocol")]
    pub protocol: String,
    pub endpoints: Vec<String>,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout: String,
    #[serde(default = "default_response_timeout")]
    pub response_timeout: String,
}

fn default_cluster_protocol() -> String {
    "auto".to_owned()
}

fn default_connect_timeout() -> String {
    "5s".to_owned()
}

fn default_response_timeout() -> String {
    "30s".to_owned()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SiteSource {
    pub root: PathBuf,
    #[serde(default = "default_site_manifest")]
    pub manifest: PathBuf,
    #[serde(default, rename = "with")]
    pub inputs: BTreeMap<String, serde_yaml_ng::Value>,
}

fn default_site_manifest() -> PathBuf {
    PathBuf::from("site.oxsite")
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListenerSource {
    pub name: String,
    pub bind: String,
    #[serde(default)]
    pub protocol: ListenerProtocolSource,
    pub tls: Option<TlsListenerSource>,
    #[serde(default)]
    pub http: HttpListenerSource,
    pub service: ServiceSource,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ListenerProtocolSource {
    #[default]
    Http,
    Https,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TlsListenerSource {
    pub default_certificate: String,
    #[serde(default)]
    pub sni: IndexMap<String, String>,
    #[serde(default = "default_tls_handshake_timeout")]
    pub handshake_timeout: String,
}

fn default_tls_handshake_timeout() -> String {
    "5s".to_owned()
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpListenerSource {
    pub versions: Option<Vec<HttpVersionSource>>,
    pub http1: Option<Http1SettingsSource>,
    pub http2: Option<Http2SettingsSource>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HttpVersionSource {
    Http1,
    H2,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Http1SettingsSource {
    #[serde(default = "default_header_read_timeout")]
    pub header_read_timeout: String,
}

impl Default for Http1SettingsSource {
    fn default() -> Self {
        Self {
            header_read_timeout: default_header_read_timeout(),
        }
    }
}

fn default_header_read_timeout() -> String {
    "30s".to_owned()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Http2SettingsSource {
    #[serde(default = "default_max_concurrent_streams")]
    pub max_concurrent_streams: u32,
    #[serde(default = "default_max_header_list_size")]
    pub max_header_list_size: String,
    #[serde(default = "default_http2_keep_alive_interval")]
    pub keep_alive_interval: String,
    #[serde(default = "default_http2_keep_alive_timeout")]
    pub keep_alive_timeout: String,
}

impl Default for Http2SettingsSource {
    fn default() -> Self {
        Self {
            max_concurrent_streams: default_max_concurrent_streams(),
            max_header_list_size: default_max_header_list_size(),
            keep_alive_interval: default_http2_keep_alive_interval(),
            keep_alive_timeout: default_http2_keep_alive_timeout(),
        }
    }
}

fn default_max_concurrent_streams() -> u32 {
    256
}

fn default_max_header_list_size() -> String {
    "64KiB".to_owned()
}

fn default_http2_keep_alive_interval() -> String {
    "30s".to_owned()
}

fn default_http2_keep_alive_timeout() -> String {
    "10s".to_owned()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum ServiceSource {
    Reference(ServiceReferenceSource),
    Inline(Box<InlineServiceSource>),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceReferenceSource {
    #[serde(rename = "ref")]
    pub reference: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum InlineServiceSource {
    Respond {
        #[serde(default = "default_status_ok")]
        status: u16,
        #[serde(default)]
        headers: HeadersSource,
        #[serde(default)]
        body: BodySource,
    },
    Redirect {
        #[serde(default = "default_redirect_status")]
        status: u16,
        location: String,
        #[serde(default)]
        query: RedirectQuerySource,
        #[serde(default)]
        headers: HeadersSource,
    },
    Site {
        site: String,
    },
    Proxy {
        cluster: String,
    },
    Transform {
        #[serde(default)]
        request: RequestTransformSource,
        #[serde(default)]
        response: ResponseTransformSource,
        service: Box<ServiceSource>,
    },
    Observe {
        name: String,
        service: Box<ServiceSource>,
    },
    Timeout {
        duration: String,
        service: Box<ServiceSource>,
    },
    Recover {
        service: Box<ServiceSource>,
        handlers: Vec<RecoverSource>,
    },
    Route {
        cases: Vec<RouteCaseSource>,
        #[serde(default)]
        default: Option<Box<ServiceSource>>,
    },
    Fallback {
        services: Vec<ServiceSource>,
    },
    Reenter {
        target: String,
        #[serde(default = "default_reenter_budget")]
        budget: u32,
    },
    /// Router remains source syntax only and is lowered to a Route node.
    Router {
        rules: Vec<RouteCaseSource>,
        #[serde(default)]
        default: Option<Box<ServiceSource>>,
    },
}

fn default_status_ok() -> u16 {
    200
}

fn default_redirect_status() -> u16 {
    308
}

fn default_reenter_budget() -> u32 {
    8
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BodySource {
    #[serde(default)]
    pub empty: bool,
    pub text: Option<String>,
    pub json: Option<serde_yaml_ng::Value>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HeadersSource {
    #[serde(default)]
    pub set: BTreeMap<String, String>,
    #[serde(default)]
    pub add: BTreeMap<String, String>,
    #[serde(default)]
    pub remove: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RequestTransformSource {
    pub method: Option<String>,
    pub scheme: Option<String>,
    pub authority: Option<String>,
    #[serde(alias = "path_and_query")]
    pub path: Option<String>,
    #[serde(default)]
    pub headers: HeadersSource,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResponseTransformSource {
    #[serde(default)]
    pub headers: HeadersSource,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoverSource {
    pub classes: Vec<ErrorClassSource>,
    pub service: ServiceSource,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ErrorClassSource {
    Configuration,
    Timeout,
    UpstreamConnect,
    UpstreamProtocol,
    SiteIo,
    TemplateLimit,
    BodyUnavailable,
    InvalidState,
    Internal,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RouteCaseSource {
    #[serde(rename = "when")]
    pub predicate: PredicateSource,
    pub service: ServiceSource,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PredicateSource {
    #[serde(default)]
    pub methods: Vec<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    pub expression: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RedirectQuerySource {
    Drop,
    #[default]
    Preserve,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigTestSource {
    pub name: String,
    pub listener: Option<String>,
    pub request: ExplainRequestSource,
    pub expect: TestExpectationSource,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExplainRequestSource {
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default = "default_scheme")]
    pub scheme: String,
    pub host: String,
    pub path: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

fn default_method() -> String {
    "GET".to_owned()
}

fn default_scheme() -> String {
    "http".to_owned()
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TestExpectationSource {
    pub status: Option<u16>,
    pub service: Option<String>,
    pub cluster: Option<String>,
    pub site: Option<String>,
    pub rewritten_path: Option<String>,
}
