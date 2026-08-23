use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use oxidase_core::{CompiledTemplate, EvalContext, RequestFrame, ResourceId, Value};
use percent_encoding::percent_decode_str;

use crate::SiteError;
use crate::template::{CompiledOxt, CompiledValue, TemplateLimits};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteMissing {
    Decline,
    Respond,
}

#[derive(Debug, Clone)]
pub struct AssetPlan {
    pub identity: AssetRepresentation,
    pub brotli: Option<AssetRepresentation>,
    pub gzip: Option<AssetRepresentation>,
    pub content_type: String,
    pub range_requests: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentEncoding {
    Brotli,
    Gzip,
}

impl ContentEncoding {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Brotli => "br",
            Self::Gzip => "gzip",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AssetRepresentation {
    pub encoding: Option<ContentEncoding>,
    pub path: PathBuf,
    pub length: u64,
    pub etag: Option<EntityTag>,
    pub modified: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityTag {
    weak: bool,
    opaque: String,
}

impl EntityTag {
    #[must_use]
    pub fn new(weak: bool, opaque: impl Into<String>) -> Self {
        Self {
            weak,
            opaque: opaque.into(),
        }
    }

    #[must_use]
    pub const fn is_weak(&self) -> bool {
        self.weak
    }

    #[must_use]
    pub fn parse(source: &str) -> Option<Self> {
        let source = source.trim();
        let (weak, source) = source
            .strip_prefix("W/")
            .map_or((false, source), |source| (true, source));
        let opaque = source.strip_prefix('"')?.strip_suffix('"')?;
        if opaque
            .bytes()
            .any(|byte| byte == b'"' || byte < 0x21 || byte == 0x7f)
        {
            return None;
        }
        Some(Self::new(weak, opaque))
    }

    #[must_use]
    pub fn to_header_value(&self) -> String {
        if self.weak {
            format!("W/\"{}\"", self.opaque)
        } else {
            format!("\"{}\"", self.opaque)
        }
    }

    #[must_use]
    pub fn weak_eq(&self, other: &Self) -> bool {
        self.opaque == other.opaque
    }

    #[must_use]
    pub fn strong_eq(&self, other: &Self) -> bool {
        !self.weak && !other.weak && self.opaque == other.opaque
    }
}

#[derive(Debug, Clone)]
pub enum PreparedSiteBody {
    Empty,
    Bytes(Bytes),
    Asset(Box<AssetPlan>),
}

#[derive(Debug, Clone)]
pub struct PreparedSiteResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: PreparedSiteBody,
    pub head_only: bool,
}

#[derive(Debug, Clone)]
pub struct SiteSnapshot {
    pub id: ResourceId,
    pub root: PathBuf,
    pub manifest: PathBuf,
    pub dependencies: Vec<PathBuf>,
    pub missing: SiteMissing,
    pub data: BTreeMap<String, Value>,
    pub limits: TemplateLimits,
    pub(crate) templates: BTreeMap<String, CompiledOxt>,
    pub(crate) entries: BTreeMap<String, SiteResponsePlan>,
    pub(crate) error_404_template: Option<String>,
}

impl SiteSnapshot {
    pub fn public_paths(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    pub fn execute(
        &self,
        request: &RequestFrame,
    ) -> Result<Option<PreparedSiteResponse>, SiteError> {
        if !matches!(*request.method(), Method::GET | Method::HEAD) {
            return Ok(None);
        }
        let path = normalize_request_path(request.path())?;
        let Some(plan) = self.entries.get(&path) else {
            return self.missing_response(request);
        };
        self.prepare_plan(plan, request).map(Some)
    }

    fn missing_response(
        &self,
        request: &RequestFrame,
    ) -> Result<Option<PreparedSiteResponse>, SiteError> {
        if self.missing == SiteMissing::Decline {
            return Ok(None);
        }
        if let Some(template) = &self.error_404_template {
            let context = self.context(request, &BTreeMap::new(), &BTreeMap::new())?;
            let template = self.templates.get(template).ok_or_else(|| {
                SiteError::Template(format!("compiled 404 template `{template}` is missing"))
            })?;
            let body = template
                .render(&self.templates, &context, &self.limits)
                .map_err(SiteError::Template)?;
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
            headers.insert(
                header::CONTENT_LENGTH,
                header_value(body.len().to_string())?,
            );
            return Ok(Some(PreparedSiteResponse {
                status: StatusCode::NOT_FOUND,
                headers,
                body: PreparedSiteBody::Bytes(Bytes::from(body)),
                head_only: request.method() == Method::HEAD,
            }));
        }
        Ok(Some(PreparedSiteResponse {
            status: StatusCode::NOT_FOUND,
            headers: HeaderMap::new(),
            body: PreparedSiteBody::Bytes(Bytes::from_static(b"Not Found")),
            head_only: request.method() == Method::HEAD,
        }))
    }

    fn prepare_plan(
        &self,
        plan: &SiteResponsePlan,
        request: &RequestFrame,
    ) -> Result<PreparedSiteResponse, SiteError> {
        let mut headers = HeaderMap::new();
        let base_context = self.context(request, &plan.page, &BTreeMap::new())?;
        apply_headers(&plan.headers, &base_context, &mut headers)?;
        let head_only = request.method() == Method::HEAD;

        let (status, body) = match &plan.kind {
            SiteResponseKind::Asset(asset) => {
                ensure_content_type(
                    &mut headers,
                    plan.content_type.as_deref(),
                    &asset.content_type,
                )?;
                (plan.status, PreparedSiteBody::Asset(asset.clone()))
            }
            SiteResponseKind::Empty => (plan.status, PreparedSiteBody::Empty),
            SiteResponseKind::Text(template) => {
                let body = template
                    .render(&base_context)
                    .map_err(|error| SiteError::Template(error.to_string()))?;
                ensure_content_type(
                    &mut headers,
                    plan.content_type.as_deref(),
                    "text/plain; charset=utf-8",
                )?;
                headers.insert(
                    header::CONTENT_LENGTH,
                    header_value(body.len().to_string())?,
                );
                (plan.status, PreparedSiteBody::Bytes(Bytes::from(body)))
            }
            SiteResponseKind::Json(value) => {
                let value = value.evaluate(&base_context).map_err(SiteError::Template)?;
                let body = serde_json::to_vec(&value)
                    .map_err(|error| SiteError::Template(error.to_string()))?;
                ensure_content_type(
                    &mut headers,
                    plan.content_type.as_deref(),
                    "application/json",
                )?;
                headers.insert(
                    header::CONTENT_LENGTH,
                    header_value(body.len().to_string())?,
                );
                (plan.status, PreparedSiteBody::Bytes(Bytes::from(body)))
            }
            SiteResponseKind::Template { name, arguments } => {
                let template = self.templates.get(name).ok_or_else(|| {
                    SiteError::Template(format!("compiled template `{name}` is missing"))
                })?;
                let values = template
                    .evaluate_arguments(arguments, &base_context)
                    .map_err(SiteError::TemplateArgument)?;
                let context = self.context(request, &plan.page, &values)?;
                let body = template
                    .render(&self.templates, &context, &self.limits)
                    .map_err(SiteError::Template)?;
                ensure_content_type(
                    &mut headers,
                    plan.content_type.as_deref(),
                    template.content_type(),
                )?;
                headers.insert(
                    header::CONTENT_LENGTH,
                    header_value(body.len().to_string())?,
                );
                (plan.status, PreparedSiteBody::Bytes(Bytes::from(body)))
            }
            SiteResponseKind::Redirect {
                status,
                location,
                query,
            } => {
                let mut location = location
                    .render(&base_context)
                    .map_err(|error| SiteError::Response(error.to_string()))?;
                if *query == RedirectQuery::Preserve
                    && !location.contains('?')
                    && let Some(query) = request.raw_query()
                    && !query.is_empty()
                {
                    location.push('?');
                    location.push_str(query);
                }
                if !location.starts_with('/')
                    || location.starts_with("//")
                    || location.contains('\\')
                    || location.parse::<http::Uri>().is_err()
                {
                    return Err(SiteError::Response(
                        "redirect Location must be a local absolute path".to_owned(),
                    ));
                }
                headers.insert(header::LOCATION, header_value(location)?);
                (*status, PreparedSiteBody::Empty)
            }
        };
        Ok(PreparedSiteResponse {
            status,
            headers,
            body,
            head_only,
        })
    }

    fn context(
        &self,
        request: &RequestFrame,
        page: &BTreeMap<String, CompiledValue>,
        arguments: &BTreeMap<String, Value>,
    ) -> Result<EvalContext, SiteError> {
        let mut context = request.evaluation_context();
        context.insert("site", Value::Map(self.data.clone()));
        let mut page_values = BTreeMap::new();
        for (name, value) in page {
            page_values.insert(
                name.clone(),
                value.evaluate(&context).map_err(SiteError::Template)?,
            );
        }
        context.insert("page", Value::Map(page_values));
        for (name, value) in arguments {
            context.insert(name, value.clone());
        }
        Ok(context)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SiteResponsePlan {
    pub status: StatusCode,
    pub headers: HeaderPlan,
    pub content_type: Option<String>,
    pub page: BTreeMap<String, CompiledValue>,
    pub kind: SiteResponseKind,
    pub source: PathBuf,
}

#[derive(Debug, Clone)]
pub(crate) enum SiteResponseKind {
    Asset(Box<AssetPlan>),
    Empty,
    Text(CompiledTemplate),
    Json(CompiledValue),
    Template {
        name: String,
        arguments: BTreeMap<String, CompiledValue>,
    },
    Redirect {
        status: StatusCode,
        location: CompiledTemplate,
        query: RedirectQuery,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RedirectQuery {
    Drop,
    Preserve,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct HeaderPlan {
    pub layers: Vec<HeaderPolicyLayer>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct HeaderPolicyLayer {
    pub set: Vec<(HeaderName, CompiledTemplate)>,
    pub add: Vec<(HeaderName, CompiledTemplate)>,
    pub remove: Vec<HeaderName>,
}

impl HeaderPlan {
    pub(crate) fn merge(&mut self, other: Self) {
        self.layers.extend(other.layers);
    }
}

fn apply_headers(
    plan: &HeaderPlan,
    context: &EvalContext,
    headers: &mut HeaderMap,
) -> Result<(), SiteError> {
    for layer in &plan.layers {
        for name in &layer.remove {
            headers.remove(name);
        }
        for (name, value) in &layer.set {
            headers.insert(
                name.clone(),
                header_value(
                    value
                        .render(context)
                        .map_err(|error| SiteError::Response(error.to_string()))?,
                )?,
            );
        }
        for (name, value) in &layer.add {
            headers.append(
                name.clone(),
                header_value(
                    value
                        .render(context)
                        .map_err(|error| SiteError::Response(error.to_string()))?,
                )?,
            );
        }
    }
    Ok(())
}

fn ensure_content_type(
    headers: &mut HeaderMap,
    configured: Option<&str>,
    fallback: &str,
) -> Result<(), SiteError> {
    if !headers.contains_key(header::CONTENT_TYPE) {
        headers.insert(
            header::CONTENT_TYPE,
            header_value(configured.unwrap_or(fallback).to_owned())?,
        );
    }
    Ok(())
}

fn header_value(value: String) -> Result<HeaderValue, SiteError> {
    HeaderValue::from_str(&value)
        .map_err(|_| SiteError::Response("invalid HTTP header value".to_owned()))
}

pub(crate) fn normalize_request_path(path: &str) -> Result<String, SiteError> {
    if !path.starts_with('/') || path.contains('\\') || path.contains('\0') {
        return Err(SiteError::InvalidRequestPath(
            "path must be absolute and cannot contain backslashes or NUL".to_owned(),
        ));
    }
    let lower = path.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") || lower.contains("%00") {
        return Err(SiteError::InvalidRequestPath(
            "encoded separators or NUL are not allowed".to_owned(),
        ));
    }
    let decoded = percent_decode_str(path)
        .decode_utf8()
        .map_err(|_| SiteError::InvalidRequestPath("path is not valid UTF-8".to_owned()))?;
    if contains_encoded_octet(&decoded) {
        return Err(SiteError::InvalidRequestPath(
            "double-encoded path octets are not allowed".to_owned(),
        ));
    }
    let trailing_slash = decoded.ends_with('/');
    let mut segments = Vec::new();
    for segment in decoded.split('/') {
        if segment.is_empty() {
            continue;
        }
        if matches!(segment, "." | "..") {
            return Err(SiteError::InvalidRequestPath(
                "dot path segments are not allowed".to_owned(),
            ));
        }
        segments.push(segment);
    }
    let mut normalized = format!("/{}", segments.join("/"));
    if normalized != "/" && trailing_slash {
        normalized.push('/');
    }
    Ok(normalized)
}

fn contains_encoded_octet(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.windows(3).any(|window| {
        window[0] == b'%' && window[1].is_ascii_hexdigit() && window[2].is_ascii_hexdigit()
    })
}

pub(crate) fn path_is_within(path: &Path, root: &Path) -> bool {
    path.starts_with(root)
}

#[cfg(test)]
mod tests {
    use super::normalize_request_path;

    #[test]
    fn rejects_traversal_encoded_separators_and_double_encoding() {
        assert!(normalize_request_path("/../secret").is_err());
        assert!(normalize_request_path("/%2e%2e/secret").is_err());
        assert!(normalize_request_path("/safe%2fsecret").is_err());
        assert!(normalize_request_path("/%252e%252e/secret").is_err());
    }

    #[test]
    fn normalizes_redundant_slashes_without_touching_query_data() {
        assert_eq!(
            normalize_request_path("//docs///index.html").expect("path is safe"),
            "/docs/index.html"
        );
    }

    #[test]
    fn generated_paths_never_normalize_to_dot_segments() {
        const ALPHABET: &[u8] = b"abc./%25\\09";
        for seed in 0usize..512 {
            let suffix = (0..(seed % 40))
                .map(|index| {
                    ALPHABET[(seed.wrapping_mul(13) + index.wrapping_mul(29)) % ALPHABET.len()]
                        as char
                })
                .collect::<String>();
            let source = format!("/{suffix}");
            let result = std::panic::catch_unwind(|| normalize_request_path(&source));
            assert!(result.is_ok(), "path resolver panicked for {source:?}");
            if let Ok(Ok(path)) = result {
                assert!(!path.split('/').any(|segment| matches!(segment, "." | "..")));
            }
        }
    }
}
