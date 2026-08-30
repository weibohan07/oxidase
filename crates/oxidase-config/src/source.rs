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
    pub endpoints: Vec<ClusterEndpointSource>,
    #[serde(default)]
    pub load_balance: LoadBalanceSource,
    #[serde(default)]
    pub health: ClusterHealthSource,
    #[serde(default)]
    pub retry: RetrySource,
    #[serde(default)]
    pub limits: ClusterLimitsSource,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout: String,
    #[serde(default = "default_response_timeout")]
    pub response_timeout: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum ClusterEndpointSource {
    Shorthand(String),
    Structured(StructuredClusterEndpointSource),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StructuredClusterEndpointSource {
    pub name: String,
    pub url: String,
    #[serde(default = "default_endpoint_weight")]
    pub weight: u64,
}

fn default_endpoint_weight() -> u64 {
    1
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LoadBalanceSource {
    #[serde(default = "default_load_balance_policy")]
    pub policy: String,
}

impl Default for LoadBalanceSource {
    fn default() -> Self {
        Self {
            policy: default_load_balance_policy(),
        }
    }
}

fn default_load_balance_policy() -> String {
    "round_robin".to_owned()
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClusterHealthSource {
    pub active: Option<ActiveHealthSource>,
    pub passive: Option<PassiveHealthSource>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActiveHealthSource {
    #[serde(default = "default_health_path")]
    pub path: String,
    #[serde(default = "default_health_interval")]
    pub interval: String,
    #[serde(default = "default_health_timeout")]
    pub timeout: String,
    #[serde(default = "default_healthy_statuses")]
    pub healthy_statuses: Vec<StatusRangeSource>,
    #[serde(default = "default_health_threshold")]
    pub healthy_threshold: u32,
    #[serde(default = "default_health_threshold")]
    pub unhealthy_threshold: u32,
}

fn default_health_path() -> String {
    "/healthz".to_owned()
}

fn default_health_interval() -> String {
    "5s".to_owned()
}

fn default_health_timeout() -> String {
    "1s".to_owned()
}

fn default_healthy_statuses() -> Vec<StatusRangeSource> {
    vec![StatusRangeSource::Text("200-299".to_owned())]
}

fn default_health_threshold() -> u32 {
    2
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PassiveHealthSource {
    #[serde(default = "default_passive_failure_threshold")]
    pub consecutive_failures: u32,
    #[serde(default = "default_eject_for")]
    pub eject_for: String,
}

fn default_passive_failure_threshold() -> u32 {
    3
}

fn default_eject_for() -> String {
    "30s".to_owned()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum StatusRangeSource {
    Code(u16),
    Text(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetrySource {
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub retry_on: Vec<String>,
    #[serde(default)]
    pub statuses: Vec<StatusRangeSource>,
    #[serde(default)]
    pub request_body: RetryRequestBodySource,
    #[serde(default = "default_max_concurrent_retries")]
    pub max_concurrent_retries: u32,
}

impl Default for RetrySource {
    fn default() -> Self {
        Self {
            max_attempts: default_max_attempts(),
            methods: Vec::new(),
            retry_on: Vec::new(),
            statuses: Vec::new(),
            request_body: RetryRequestBodySource::default(),
            max_concurrent_retries: default_max_concurrent_retries(),
        }
    }
}

fn default_max_attempts() -> u32 {
    1
}

fn default_max_concurrent_retries() -> u32 {
    32
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetryRequestBodySource {
    #[serde(default = "default_retry_body_mode")]
    pub mode: String,
    #[serde(default = "default_retry_body_max_bytes")]
    pub max_bytes: String,
}

impl Default for RetryRequestBodySource {
    fn default() -> Self {
        Self {
            mode: default_retry_body_mode(),
            max_bytes: default_retry_body_max_bytes(),
        }
    }
}

fn default_retry_body_mode() -> String {
    "none".to_owned()
}

fn default_retry_body_max_bytes() -> String {
    "64KiB".to_owned()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClusterLimitsSource {
    #[serde(default = "default_cluster_max_in_flight")]
    pub max_in_flight: u32,
    #[serde(default = "default_endpoint_max_in_flight")]
    pub max_in_flight_per_endpoint: u32,
    #[serde(default = "default_queue_timeout")]
    pub queue_timeout: String,
}

impl Default for ClusterLimitsSource {
    fn default() -> Self {
        Self {
            max_in_flight: default_cluster_max_in_flight(),
            max_in_flight_per_endpoint: default_endpoint_max_in_flight(),
            queue_timeout: default_queue_timeout(),
        }
    }
}

fn default_cluster_max_in_flight() -> u32 {
    1_024
}

fn default_endpoint_max_in_flight() -> u32 {
    256
}

fn default_queue_timeout() -> String {
    "0ms".to_owned()
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
    UpstreamUnavailable,
    UpstreamOverloaded,
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
    /// Upstream protocol policy expected for the selected Cluster.
    pub cluster_protocol: Option<String>,
    /// Load-balancing policy expected for the selected Cluster.
    pub load_balance: Option<String>,
    pub site: Option<String>,
    pub rewritten_path: Option<String>,
}
