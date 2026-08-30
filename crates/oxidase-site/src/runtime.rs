use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use oxidase_core::{CompiledTemplate, ContentDigest, EvalContext, RequestFrame, ResourceId, Value};
use percent_encoding::percent_decode_str;

use crate::template::{CompiledOxt, CompiledValue, TemplateLimits};
use crate::{SiteError, TemplateRenderError};

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
    pub source: AssetSource,
    pub length: u64,
    pub digest: ContentDigest,
    pub etag: Option<EntityTag>,
    pub modified: Option<SystemTime>,
}

/// Seekable backing storage for one immutable Asset representation.
///
/// Bundle blobs are stored uncompressed in the archive so the HTTP data plane
/// can seek to a byte range and stream exactly the selected representation
/// without collecting it or unpacking the rest of the archive.
#[derive(Clone)]
pub enum AssetSource {
    /// A standalone filesystem object prepared by the ordinary Site compiler.
    File(PathBuf),
    /// A verified, already-open regular file and the first representation byte
    /// within it. Holding the handle pins the validated inode even if its
    /// original path is atomically replaced after snapshot publication.
    Pinned {
        file: Arc<File>,
        display: Arc<PathBuf>,
        offset: u64,
        /// Original verified filesystem object when the served bytes were
        /// copied into a private spool. Retaining this handle lets snapshot
        /// preparation compare device/inode identity against sensitive
        /// Resources without serving from the mutable origin.
        origin: Option<Arc<File>>,
    },
}

impl AssetSource {
    /// Constructs a pinned representation from an already verified file.
    #[must_use]
    pub fn pinned(file: File, display: PathBuf, offset: u64) -> Self {
        Self::Pinned {
            file: Arc::new(file),
            display: Arc::new(display),
            offset,
            origin: None,
        }
    }

    /// Constructs a pinned representation while retaining the exact verified
    /// origin handle solely for sensitive-file identity checks.
    #[must_use]
    pub fn pinned_with_origin(file: File, origin: File, display: PathBuf, offset: u64) -> Self {
        Self::Pinned {
            file: Arc::new(file),
            display: Arc::new(display),
            offset,
            origin: Some(Arc::new(origin)),
        }
    }

    #[must_use]
    pub fn display_path(&self) -> &Path {
        match self {
            Self::File(path) => path,
            Self::Pinned { display, .. } => display,
        }
    }
}

impl fmt::Debug for AssetSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(path) => formatter.debug_tuple("File").field(path).finish(),
            Self::Pinned {
                display, offset, ..
            } => formatter
                .debug_struct("Pinned")
                .field("display", display)
                .field("offset", offset)
                .finish_non_exhaustive(),
        }
    }
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
    pub fn opaque(&self) -> &str {
        &self.opaque
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
    pub(crate) error_404: Option<ErrorPagePlan>,
}

#[derive(Debug, Clone)]
pub(crate) struct ErrorPagePlan {
    pub template: String,
    pub headers: HeaderPlan,
}

impl SiteSnapshot {
    pub fn public_paths(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    /// Returns every filesystem/archive source that can be exposed by this
    /// Site, including identity and precompressed representations.
    ///
    /// Runtime preparation uses this read-only view to prove that a public
    /// Asset is not backed by the same file as a Secret or certificate private
    /// key. The iterator deliberately exposes neither public URL paths nor
    /// response metadata, so callers cannot accidentally turn the check into a
    /// second Site index.
    pub fn asset_sources(&self) -> impl Iterator<Item = &AssetSource> {
        self.entries
            .values()
            .filter_map(|plan| match &plan.kind {
                SiteResponseKind::Asset(asset) => Some(asset.as_ref()),
                SiteResponseKind::Empty
                | SiteResponseKind::Text(_)
                | SiteResponseKind::Json(_)
                | SiteResponseKind::Template { .. }
                | SiteResponseKind::Redirect { .. } => None,
            })
            .flat_map(|asset| {
                std::iter::once(&asset.identity.source)
                    .chain(asset.brotli.iter().map(|value| &value.source))
                    .chain(asset.gzip.iter().map(|value| &value.source))
            })
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
        if let Some(error_page) = &self.error_404 {
            let context = self.context(request, &BTreeMap::new(), &error_page.template)?;
            let template = self.templates.get(&error_page.template).ok_or_else(|| {
                SiteError::TemplateRender(TemplateRenderError::MissingValue {
                    template: error_page.template.clone(),
                    expression: "compiled 404 template".to_owned(),
                })
            })?;
            let body = template
                .render(&self.templates, &context, &self.limits)
                .map_err(SiteError::from_template_render)?;
            let mut headers = HeaderMap::new();
            apply_headers(&error_page.headers, &context, &mut headers)?;
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(template.content_type()),
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
        let source_name = plan.source.to_string_lossy();
        let base_context = self.context(request, &plan.page, &source_name)?;
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
            SiteResponseKind::Empty => {
                ensure_configured_content_type(&mut headers, plan.content_type.as_deref())?;
                (plan.status, PreparedSiteBody::Empty)
            }
            SiteResponseKind::Text(template) => {
                let body = template.render(&base_context).map_err(|error| {
                    template_evaluation_error(&source_name, "response.body.text", error.to_string())
                })?;
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
                let value = value.evaluate(&base_context).map_err(|message| {
                    template_evaluation_error(&source_name, "response.body.json", message)
                })?;
                let body = serde_json::to_vec(&value)
                    .map_err(|error| SiteError::Response(error.to_string()))?;
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
                    SiteError::TemplateRender(TemplateRenderError::MissingValue {
                        template: name.clone(),
                        expression: "compiled template".to_owned(),
                    })
                })?;
                let values = template
                    .evaluate_arguments(arguments, &base_context)
                    .map_err(SiteError::TemplateArgument)?;
                let body = template
                    .render_with_arguments(&self.templates, &base_context, &values, &self.limits)
                    .map_err(SiteError::from_template_render)?;
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
                ensure_configured_content_type(&mut headers, plan.content_type.as_deref())?;
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
        source_name: &str,
    ) -> Result<EvalContext, SiteError> {
        let mut context = request.evaluation_context();
        context.insert("site", Value::Map(self.data.clone()));
        context.insert(
            "resource",
            Value::Map(BTreeMap::from([(
                "path".to_owned(),
                Value::from(request.path()),
            )])),
        );
        let mut page_values = BTreeMap::new();
        for (name, value) in page {
            page_values.insert(
                name.clone(),
                value.evaluate(&context).map_err(|message| {
                    template_evaluation_error(source_name, &format!("page.{name}"), message)
                })?,
            );
        }
        context.insert("page", Value::Map(page_values));
        Ok(context)
    }
}

fn template_evaluation_error(template: &str, expression: &str, message: String) -> SiteError {
    SiteError::TemplateRender(TemplateRenderError::Evaluation {
        template: template.to_owned(),
        expression: expression.to_owned(),
        message,
    })
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

fn ensure_configured_content_type(
    headers: &mut HeaderMap,
    configured: Option<&str>,
) -> Result<(), SiteError> {
    if let Some(configured) = configured
        && !headers.contains_key(header::CONTENT_TYPE)
    {
        headers.insert(header::CONTENT_TYPE, header_value(configured.to_owned())?);
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
