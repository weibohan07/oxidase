use std::collections::BTreeMap;
use std::sync::Arc;

use http::{HeaderMap, HeaderName, HeaderValue, Method};
use percent_encoding::percent_decode_str;

use crate::{EvalContext, Value};

#[derive(Debug, Clone)]
pub struct RequestMetadata {
    pub method: Method,
    pub scheme: String,
    pub authority: String,
    /// The untouched origin-form path and query. It is retained byte-for-byte until
    /// a Transform deliberately replaces it.
    pub path_and_query: String,
    pub headers: HeaderMap,
    pub peer_address: Option<String>,
}

impl RequestMetadata {
    #[must_use]
    pub fn new(
        method: Method,
        scheme: impl Into<String>,
        authority: impl Into<String>,
        path_and_query: impl Into<String>,
        headers: HeaderMap,
    ) -> Self {
        Self {
            method,
            scheme: scheme.into(),
            authority: authority.into(),
            path_and_query: path_and_query.into(),
            headers,
            peer_address: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RequestOverlay {
    pub method: Option<Method>,
    pub scheme: Option<String>,
    pub authority: Option<String>,
    pub path_and_query: Option<String>,
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
    pub overlay: RequestOverlay,
    pub bindings: Bindings,
}

impl RequestFrame {
    #[must_use]
    pub fn new(metadata: RequestMetadata) -> Self {
        Self {
            original: Arc::new(metadata),
            overlay: RequestOverlay::default(),
            bindings: Bindings::default(),
        }
    }

    #[must_use]
    pub fn original(&self) -> &RequestMetadata {
        &self.original
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
            .as_deref()
            .unwrap_or(&self.original.scheme)
    }

    #[must_use]
    pub fn authority(&self) -> &str {
        self.overlay
            .authority
            .as_deref()
            .unwrap_or(&self.original.authority)
    }

    #[must_use]
    pub fn host(&self) -> &str {
        authority_host(self.authority())
    }

    #[must_use]
    pub fn path_and_query(&self) -> &str {
        self.overlay
            .path_and_query
            .as_deref()
            .unwrap_or(&self.original.path_and_query)
    }

    #[must_use]
    pub fn path(&self) -> &str {
        self.path_and_query()
            .split_once('?')
            .map_or(self.path_and_query(), |(path, _)| path)
    }

    #[must_use]
    pub fn raw_query(&self) -> Option<&str> {
        self.path_and_query()
            .split_once('?')
            .map(|(_, query)| query)
    }

    #[must_use]
    pub fn headers(&self) -> HeaderMap {
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
    }

    #[must_use]
    pub fn with_bindings(&self, values: BTreeMap<String, Value>) -> Self {
        let mut child = self.clone();
        child.bindings = self.bindings.push_scope(values);
        child
    }

    #[must_use]
    pub fn evaluation_context(&self) -> EvalContext {
        let mut request = BTreeMap::new();
        request.insert("method".to_owned(), Value::from(self.method().as_str()));
        request.insert("scheme".to_owned(), Value::from(self.scheme()));
        request.insert("authority".to_owned(), Value::from(self.authority()));
        request.insert("host".to_owned(), Value::from(self.host()));
        request.insert("path".to_owned(), Value::from(self.path()));
        request.insert(
            "path_and_query".to_owned(),
            Value::from(self.path_and_query()),
        );
        request.insert("query".to_owned(), query_value(self.raw_query()));
        request.insert("headers".to_owned(), headers_value(&self.headers()));
        if let Some(peer_address) = &self.original.peer_address {
            request.insert("peer_address".to_owned(), Value::from(peer_address.clone()));
        }

        let mut roots = BTreeMap::new();
        roots.insert("request".to_owned(), Value::Map(request));
        roots.insert(
            "bindings".to_owned(),
            Value::Map(self.bindings.visible_values()),
        );
        EvalContext::new(roots)
    }
}

fn authority_host(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        return &rest[..end];
    }
    authority
        .rsplit_once(':')
        .filter(|(_, port)| port.chars().all(|character| character.is_ascii_digit()))
        .map_or(authority, |(host, _)| host)
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

    use http::{HeaderMap, Method};

    use super::{Bindings, RequestFrame, RequestMetadata};
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
        let frame = RequestFrame::new(RequestMetadata::new(
            Method::GET,
            "http",
            "[::1]:7589",
            "/search?b=two%20words&a=1&a=2",
            HeaderMap::new(),
        ));
        assert_eq!(frame.path_and_query(), "/search?b=two%20words&a=1&a=2");
        assert_eq!(frame.authority(), "[::1]:7589");
    }
}
