use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, OnceLock};

use http::uri::{Authority, PathAndQuery, Scheme};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Version};
use percent_encoding::percent_decode_str;
use thiserror::Error;

use crate::{EvalContext, Value};

#[derive(Debug, Clone)]
pub struct RequestMetadata {
    pub method: Method,
    pub scheme: Scheme,
    pub authority: Authority,
    /// The untouched origin-form path and query. It is retained byte-for-byte until
    /// a Transform deliberately replaces it.
    pub path_and_query: PathAndQuery,
    pub headers: HeaderMap,
    pub peer_address: Option<SocketAddr>,
    pub http_version: Version,
    pub tls: TlsConnectionMetadata,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsConnectionMetadata {
    pub enabled: bool,
    pub server_name: Option<String>,
    pub alpn: Option<String>,
    pub version: Option<String>,
}

impl RequestMetadata {
    pub fn try_new(
        method: Method,
        scheme: impl AsRef<str>,
        authority: impl AsRef<str>,
        path_and_query: impl AsRef<str>,
        headers: HeaderMap,
    ) -> Result<Self, RequestMetadataError> {
        Ok(Self {
            method,
            scheme: parse_transform_scheme(scheme.as_ref())?,
            authority: parse_transform_authority(authority.as_ref())?,
            path_and_query: parse_transform_path_and_query(path_and_query.as_ref())?,
            headers,
            peer_address: None,
            http_version: Version::HTTP_11,
            tls: TlsConnectionMetadata::default(),
        })
    }

    #[must_use]
    pub fn with_connection_metadata(
        mut self,
        http_version: Version,
        tls: TlsConnectionMetadata,
    ) -> Self {
        self.http_version = http_version;
        self.tls = tls;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RequestMetadataError {
    #[error("scheme must be `http` or `https`")]
    Scheme,
    #[error("authority must be a host or IP literal with an optional valid port and no userinfo")]
    Authority,
    #[error("path_and_query must be a valid origin-form value beginning with `/`")]
    PathAndQuery,
}

pub fn parse_transform_scheme(source: &str) -> Result<Scheme, RequestMetadataError> {
    if source.eq_ignore_ascii_case("http") {
        Ok(Scheme::HTTP)
    } else if source.eq_ignore_ascii_case("https") {
        Ok(Scheme::HTTPS)
    } else {
        Err(RequestMetadataError::Scheme)
    }
}

pub fn parse_transform_authority(source: &str) -> Result<Authority, RequestMetadataError> {
    if source.is_empty() || source.contains('@') || source.contains(['\r', '\n']) {
        return Err(RequestMetadataError::Authority);
    }
    let port = if let Some(rest) = source.strip_prefix('[') {
        let end = rest.find(']').ok_or(RequestMetadataError::Authority)?;
        let suffix = &rest[end + 1..];
        if suffix.is_empty() {
            None
        } else {
            Some(
                suffix
                    .strip_prefix(':')
                    .ok_or(RequestMetadataError::Authority)?,
            )
        }
    } else if let Some((host, port)) = source.split_once(':') {
        if host.is_empty() || port.contains(':') {
            return Err(RequestMetadataError::Authority);
        }
        Some(port)
    } else {
        None
    };
    if port.is_some_and(|port| port.is_empty() || port.parse::<u16>().is_err()) {
        return Err(RequestMetadataError::Authority);
    }
    let authority = Authority::from_str(source).map_err(|_| RequestMetadataError::Authority)?;
    if authority.host().is_empty() {
        return Err(RequestMetadataError::Authority);
    }
    Ok(authority)
}

pub fn parse_transform_path_and_query(source: &str) -> Result<PathAndQuery, RequestMetadataError> {
    if !source.starts_with('/') || source.contains(['\r', '\n', '#']) {
        return Err(RequestMetadataError::PathAndQuery);
    }
    PathAndQuery::from_str(source).map_err(|_| RequestMetadataError::PathAndQuery)
}

#[derive(Debug, Clone, Default)]
pub struct RequestOverlay {
    pub method: Option<Method>,
    pub scheme: Option<Scheme>,
    pub authority: Option<Authority>,
    pub path_and_query: Option<PathAndQuery>,
    header_mutations: Vec<HeaderMutation>,
}

impl RequestOverlay {
    pub fn set_header(&mut self, name: HeaderName, value: HeaderValue) {
        self.header_mutations.push(HeaderMutation::Set(name, value));
    }

    pub fn add_header(&mut self, name: HeaderName, value: HeaderValue) {
        self.header_mutations.push(HeaderMutation::Add(name, value));
    }

    pub fn remove_header(&mut self, name: HeaderName) {
        self.header_mutations.push(HeaderMutation::Remove(name));
    }
}

#[derive(Debug, Clone)]
enum HeaderMutation {
    Set(HeaderName, HeaderValue),
    Add(HeaderName, HeaderValue),
    Remove(HeaderName),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BodyState {
    #[default]
    Available,
    Consumed,
    Replayable {
        limit: usize,
    },
}

#[derive(Debug, Clone)]
pub struct Bindings {
    scopes: Vec<Arc<BTreeMap<String, Value>>>,
}

impl Default for Bindings {
    fn default() -> Self {
        Self {
            scopes: vec![Arc::new(BTreeMap::new())],
        }
    }
}

impl Bindings {
    #[must_use]
    pub fn push_scope(&self, values: BTreeMap<String, Value>) -> Self {
        let mut scopes = self.scopes.clone();
        scopes.push(Arc::new(values));
        Self { scopes }
    }

    #[must_use]
    pub fn resolve(&self, name: &str) -> Option<&Value> {
        self.scopes.iter().rev().find_map(|scope| scope.get(name))
    }

    #[must_use]
    pub fn visible_values(&self) -> BTreeMap<String, Value> {
        let mut values = BTreeMap::new();
        for scope in &self.scopes {
            values.extend(
                scope
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone())),
            );
        }
        values
    }

    #[must_use]
    pub fn depth(&self) -> usize {
        self.scopes.len()
    }
}

#[derive(Debug, Clone)]
pub struct RequestFrame {
    original: Arc<RequestMetadata>,
    overlay: RequestOverlay,
    bindings: Bindings,
    request_cache: Arc<RequestViewCache>,
    evaluation_cache: Arc<EvaluationCache>,
}

#[derive(Debug, Default)]
struct RequestViewCache {
    effective_headers: OnceLock<HeaderMap>,
    query: OnceLock<Value>,
    namespace: OnceLock<Value>,
    #[cfg(test)]
    header_builds: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    query_builds: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    namespace_builds: std::sync::atomic::AtomicUsize,
}

#[derive(Debug, Default)]
struct EvaluationCache {
    bindings: OnceLock<Value>,
    context: OnceLock<EvalContext>,
    #[cfg(test)]
    binding_builds: std::sync::atomic::AtomicUsize,
}

impl RequestFrame {
    #[must_use]
    pub fn new(metadata: RequestMetadata) -> Self {
        Self {
            original: Arc::new(metadata),
            overlay: RequestOverlay::default(),
            bindings: Bindings::default(),
            request_cache: Arc::new(RequestViewCache::default()),
            evaluation_cache: Arc::new(EvaluationCache::default()),
        }
    }

    #[must_use]
    pub fn original(&self) -> &RequestMetadata {
        &self.original
    }

    #[must_use]
    pub const fn overlay(&self) -> &RequestOverlay {
        &self.overlay
    }

    /// Invalidates frame-local derived views before granting mutable access to
    /// the transactional request overlay.
    pub fn overlay_mut(&mut self) -> &mut RequestOverlay {
        self.request_cache = Arc::new(RequestViewCache::default());
        self.evaluation_cache = Arc::new(EvaluationCache::default());
        &mut self.overlay
    }

    #[must_use]
    pub const fn bindings(&self) -> &Bindings {
        &self.bindings
    }

    #[must_use]
    pub fn method(&self) -> &Method {
        self.overlay
            .method
            .as_ref()
            .unwrap_or(&self.original.method)
    }

    #[must_use]
    pub fn scheme(&self) -> &str {
        self.overlay
            .scheme
            .as_ref()
            .unwrap_or(&self.original.scheme)
            .as_str()
    }

    #[must_use]
    pub fn authority(&self) -> &str {
        self.overlay
            .authority
            .as_ref()
            .unwrap_or(&self.original.authority)
            .as_str()
    }

    #[must_use]
    pub fn host(&self) -> &str {
        self.overlay
            .authority
            .as_ref()
            .unwrap_or(&self.original.authority)
            .host()
    }

    #[must_use]
    pub fn path_and_query(&self) -> &str {
        self.overlay
            .path_and_query
            .as_ref()
            .unwrap_or(&self.original.path_and_query)
            .as_str()
    }

    #[must_use]
    pub fn path(&self) -> &str {
        self.overlay
            .path_and_query
            .as_ref()
            .unwrap_or(&self.original.path_and_query)
            .path()
    }

    #[must_use]
    pub fn raw_query(&self) -> Option<&str> {
        self.overlay
            .path_and_query
            .as_ref()
            .unwrap_or(&self.original.path_and_query)
            .query()
    }

    #[must_use]
    pub fn headers(&self) -> HeaderMap {
        self.effective_headers().clone()
    }

    #[must_use]
    pub fn effective_headers(&self) -> &HeaderMap {
        self.request_cache.effective_headers.get_or_init(|| {
            #[cfg(test)]
            self.request_cache
                .header_builds
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut headers = self.original.headers.clone();
            for mutation in &self.overlay.header_mutations {
                match mutation {
                    HeaderMutation::Set(name, value) => {
                        headers.insert(name, value.clone());
                    }
                    HeaderMutation::Add(name, value) => {
                        headers.append(name, value.clone());
                    }
                    HeaderMutation::Remove(name) => {
                        headers.remove(name);
                    }
                }
            }
            headers
        })
    }

    #[must_use]
    pub fn with_bindings(&self, values: BTreeMap<String, Value>) -> Self {
        let mut child = self.clone();
        child.bindings = self.bindings.push_scope(values);
        child.evaluation_cache = Arc::new(EvaluationCache::default());
        child
    }

    #[must_use]
    pub fn evaluation_context(&self) -> EvalContext {
        self.evaluation_cache
            .context
            .get_or_init(|| {
                let mut roots = BTreeMap::new();
                roots.insert("request".to_owned(), self.request_namespace().clone());
                roots.insert("bindings".to_owned(), self.bindings_value().clone());
                EvalContext::new(roots)
            })
            .clone()
    }

    fn request_namespace(&self) -> &Value {
        self.request_cache.namespace.get_or_init(|| {
            #[cfg(test)]
            self.request_cache
                .namespace_builds
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut request = BTreeMap::new();
            request.insert("method".to_owned(), Value::from(self.method().as_str()));
            request.insert(
                "http_version".to_owned(),
                Value::from(http_version_name(self.original.http_version)),
            );
            request.insert("scheme".to_owned(), Value::from(self.scheme()));
            request.insert("authority".to_owned(), Value::from(self.authority()));
            request.insert("host".to_owned(), Value::from(self.host()));
            request.insert("path".to_owned(), Value::from(self.path()));
            request.insert(
                "path_and_query".to_owned(),
                Value::from(self.path_and_query()),
            );
            request.insert("query".to_owned(), self.query_value().clone());
            request.insert(
                "headers".to_owned(),
                headers_value(self.effective_headers()),
            );
            if let Some(peer_address) = &self.original.peer_address {
                request.insert(
                    "peer_address".to_owned(),
                    Value::from(peer_address.to_string()),
                );
            }
            request.insert("tls".to_owned(), tls_value(&self.original.tls));

            Value::Map(request)
        })
    }

    fn query_value(&self) -> &Value {
        self.request_cache.query.get_or_init(|| {
            #[cfg(test)]
            self.request_cache
                .query_builds
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            query_value(self.raw_query())
        })
    }

    fn bindings_value(&self) -> &Value {
        self.evaluation_cache.bindings.get_or_init(|| {
            #[cfg(test)]
            self.evaluation_cache
                .binding_builds
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Value::Map(self.bindings.visible_values())
        })
    }
}

fn http_version_name(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "0.9",
        Version::HTTP_10 => "1.0",
        Version::HTTP_11 => "1.1",
        Version::HTTP_2 => "2",
        Version::HTTP_3 => "3",
        _ => "unknown",
    }
}

fn tls_value(tls: &TlsConnectionMetadata) -> Value {
    Value::Map(BTreeMap::from([
        ("enabled".to_owned(), Value::Bool(tls.enabled)),
        (
            "server_name".to_owned(),
            tls.server_name.clone().map_or(Value::Null, Value::from),
        ),
        (
            "alpn".to_owned(),
            tls.alpn.clone().map_or(Value::Null, Value::from),
        ),
        (
            "version".to_owned(),
            tls.version.clone().map_or(Value::Null, Value::from),
        ),
    ]))
}

fn headers_value(headers: &HeaderMap) -> Value {
    let mut values = BTreeMap::<String, Vec<Value>>::new();
    for (name, value) in headers {
        let value = value
            .to_str()
            .map_or_else(|_| Value::Bytes(value.as_bytes().to_vec()), Value::from);
        values
            .entry(name.as_str().to_owned())
            .or_default()
            .push(value);
    }
    Value::Map(
        values
            .into_iter()
            .map(|(name, values)| {
                let first = values.first().cloned().unwrap_or(Value::Null);
                let mut view = BTreeMap::new();
                view.insert("first".to_owned(), first);
                view.insert("all".to_owned(), Value::List(values));
                (name, Value::Map(view))
            })
            .collect(),
    )
}

fn query_value(query: Option<&str>) -> Value {
    let mut values = BTreeMap::<String, Vec<Value>>::new();
    for pair in query.into_iter().flat_map(|query| query.split('&')) {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode_str(key).decode_utf8_lossy().into_owned();
        let value = percent_decode_str(value).decode_utf8_lossy().into_owned();
        values.entry(key).or_default().push(Value::String(value));
    }
    Value::Map(
        values
            .into_iter()
            .map(|(name, values)| {
                let first = values.first().cloned().unwrap_or(Value::Null);
                let mut view = BTreeMap::new();
                view.insert("first".to_owned(), first);
                view.insert("all".to_owned(), Value::List(values));
                (name, Value::Map(view))
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use http::{HeaderMap, HeaderValue, Method, Version};

    use super::{Bindings, RequestFrame, RequestMetadata, TlsConnectionMetadata};
    use crate::Value;

    #[test]
    fn lexical_scopes_shadow_without_mutating_the_parent() {
        let mut parent_values = BTreeMap::new();
        parent_values.insert("name".to_owned(), Value::from("parent"));
        let parent = Bindings::default().push_scope(parent_values);
        let mut child_values = BTreeMap::new();
        child_values.insert("name".to_owned(), Value::from("child"));
        let child = parent.push_scope(child_values);
        assert_eq!(child.resolve("name"), Some(&Value::from("child")));
        assert_eq!(parent.resolve("name"), Some(&Value::from("parent")));
    }

    #[test]
    fn untouched_query_keeps_exact_wire_representation() {
        let frame = RequestFrame::new(
            RequestMetadata::try_new(
                Method::GET,
                "http",
                "[::1]:7589",
                "/search?b=two%20words&a=1&a=2",
                HeaderMap::new(),
            )
            .expect("valid request metadata"),
        );
        assert_eq!(frame.path_and_query(), "/search?b=two%20words&a=1&a=2");
        assert_eq!(frame.authority(), "[::1]:7589");
        assert_eq!(frame.host(), "[::1]");
    }

    #[test]
    fn exposes_protocol_and_tls_connection_metadata_as_read_only_request_roots() {
        let metadata = RequestMetadata::try_new(
            Method::GET,
            "https",
            "api.example.test",
            "/",
            HeaderMap::new(),
        )
        .expect("request metadata is valid")
        .with_connection_metadata(
            Version::HTTP_2,
            TlsConnectionMetadata {
                enabled: true,
                server_name: Some("api.example.test".to_owned()),
                alpn: Some("h2".to_owned()),
                version: Some("TLS1.3".to_owned()),
            },
        );
        let context = RequestFrame::new(metadata).evaluation_context();
        let request = context.root("request").expect("request root exists");
        assert_eq!(
            request.get("http_version").and_then(Value::as_str),
            Some("2")
        );
        let tls = request.get("tls").expect("TLS namespace exists");
        assert_eq!(tls.get("enabled"), Some(&Value::Bool(true)));
        assert_eq!(
            tls.get("server_name").and_then(Value::as_str),
            Some("api.example.test")
        );
        assert_eq!(tls.get("alpn").and_then(Value::as_str), Some("h2"));
        assert_eq!(tls.get("version").and_then(Value::as_str), Some("TLS1.3"));
    }

    #[test]
    fn validates_typed_request_metadata_boundaries() {
        for authority in [
            "example.com",
            "example.com:443",
            "127.0.0.1:80",
            "[::1]:8080",
        ] {
            assert!(super::parse_transform_authority(authority).is_ok());
        }
        for authority in [
            "user@example.com",
            "example.com:99999",
            "example.com:not-a-port",
            "example.com\r\nforwarded: evil",
        ] {
            assert!(super::parse_transform_authority(authority).is_err());
        }
        for scheme in ["ftp", "javascript", "http\r\n"] {
            assert!(super::parse_transform_scheme(scheme).is_err());
        }
        for path in [
            "https://evil.test/path",
            "relative",
            "/ok#fragment",
            "/ok\r\n",
        ] {
            assert!(super::parse_transform_path_and_query(path).is_err());
        }
        let path = super::parse_transform_path_and_query("/ok?b=2&a=1&a=3")
            .expect("origin-form path is valid");
        assert_eq!(path.as_str(), "/ok?b=2&a=1&a=3");
    }

    #[test]
    fn repeated_evaluation_builds_each_frame_view_once() {
        let mut headers = HeaderMap::new();
        headers.insert("x-test", HeaderValue::from_static("value"));
        let frame = RequestFrame::new(
            RequestMetadata::try_new(
                Method::GET,
                "https",
                "example.test",
                "/search?b=2&a=1&a=3",
                headers,
            )
            .expect("request metadata is valid"),
        );
        assert_eq!(frame.request_cache.query_builds.load(Ordering::Relaxed), 0);
        assert_eq!(frame.raw_query(), Some("b=2&a=1&a=3"));
        assert_eq!(frame.request_cache.query_builds.load(Ordering::Relaxed), 0);

        for _ in 0..4 {
            let context = frame.evaluation_context();
            assert_eq!(
                context
                    .root("request")
                    .and_then(|request| request.get("path"))
                    .and_then(Value::as_str),
                Some("/search")
            );
        }
        assert_eq!(frame.request_cache.header_builds.load(Ordering::Relaxed), 1);
        assert_eq!(frame.request_cache.query_builds.load(Ordering::Relaxed), 1);
        assert_eq!(
            frame.request_cache.namespace_builds.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            frame
                .evaluation_cache
                .binding_builds
                .load(Ordering::Relaxed),
            1
        );

        let clone = frame.clone();
        let _ = clone.evaluation_context();
        assert!(Arc::ptr_eq(&frame.request_cache, &clone.request_cache));
        assert!(Arc::ptr_eq(
            &frame.evaluation_cache,
            &clone.evaluation_cache
        ));
        assert_eq!(
            frame.request_cache.namespace_builds.load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn overlay_and_binding_children_invalidate_only_the_views_they_change() {
        let mut headers = HeaderMap::new();
        headers.insert("x-scope", HeaderValue::from_static("parent"));
        let parent = RequestFrame::new(
            RequestMetadata::try_new(
                Method::GET,
                "http",
                "example.test",
                "/original?b=2&a=1",
                headers,
            )
            .expect("request metadata is valid"),
        );
        let _ = parent.evaluation_context();

        let child =
            parent.with_bindings(BTreeMap::from([("name".to_owned(), Value::from("child"))]));
        assert!(Arc::ptr_eq(&parent.request_cache, &child.request_cache));
        assert!(!Arc::ptr_eq(
            &parent.evaluation_cache,
            &child.evaluation_cache
        ));
        let child_context = child.evaluation_context();
        assert_eq!(
            child_context
                .root("bindings")
                .and_then(|bindings| bindings.get("name"))
                .and_then(Value::as_str),
            Some("child")
        );
        assert!(
            parent
                .evaluation_context()
                .root("bindings")
                .and_then(|bindings| bindings.get("name"))
                .is_none()
        );

        let mut transformed = parent.clone();
        let overlay = transformed.overlay_mut();
        overlay.path_and_query = Some(
            super::parse_transform_path_and_query("/changed?a=1&b=2")
                .expect("transformed path is valid"),
        );
        overlay.set_header(
            "x-scope".parse().expect("header name is valid"),
            HeaderValue::from_static("child"),
        );
        assert!(!Arc::ptr_eq(
            &parent.request_cache,
            &transformed.request_cache
        ));
        assert_eq!(transformed.path_and_query(), "/changed?a=1&b=2");
        assert_eq!(
            transformed.effective_headers()["x-scope"],
            HeaderValue::from_static("child")
        );
        assert_eq!(parent.path_and_query(), "/original?b=2&a=1");
        assert_eq!(
            parent.effective_headers()["x-scope"],
            HeaderValue::from_static("parent")
        );
    }

    #[test]
    #[ignore = "manual microbenchmark; run with --release --ignored --nocapture"]
    fn request_evaluation_context_smoke_benchmark() {
        let mut headers = HeaderMap::new();
        for index in 0..32 {
            headers.insert(
                format!("x-bench-{index}")
                    .parse::<http::HeaderName>()
                    .expect("benchmark header name is valid"),
                HeaderValue::from_static("benchmark-value"),
            );
        }
        let frame = RequestFrame::new(
            RequestMetadata::try_new(
                Method::GET,
                "https",
                "example.test",
                "/benchmark?z=9&a=1&a=2&message=hello%20world",
                headers,
            )
            .expect("benchmark metadata is valid"),
        )
        .with_bindings(BTreeMap::from([(
            "route".to_owned(),
            Value::from("benchmark"),
        )]));
        let iterations = 100_000usize;
        let started = std::time::Instant::now();
        for _ in 0..iterations {
            std::hint::black_box(frame.evaluation_context());
        }
        eprintln!(
            "request evaluation cache: {iterations} contexts in {:?}",
            started.elapsed()
        );
    }
}
