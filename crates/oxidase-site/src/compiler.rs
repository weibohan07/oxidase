use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::{HeaderName, HeaderValue, StatusCode};
use oxidase_core::{
    CompiledTemplate, ContentDigest, ContentDigestBuilder, ContentHasher, Diagnostic,
    DiagnosticReference, Expression, ResourceId, SourceSpan, Value, is_forbidden_user_header,
};
use walkdir::WalkDir;

use oxidase_source::{FieldSpanIndex, field_path_child};

use crate::error::{SiteCompileError, SiteCompileFailure};
use crate::runtime::{
    AssetPlan, AssetRepresentation, AssetSource, ContentEncoding, EntityTag, HeaderPlan,
    HeaderPolicyLayer, RedirectQuery, SiteMissing, SiteResponseKind, SiteResponsePlan,
    SiteSnapshot, path_is_within,
};
use crate::source::{
    EtagSource, HeadersSource, IndexCanonicalSource, ManifestSource, MissingSource, OutputSource,
    OxrBodySource, OxrSource, RedirectQuerySource, ResponsePolicySource, SymlinkModeSource,
    TemplateReferenceSource, TrailingSlashSource, VisibilityModeSource,
};
use crate::template::{CompiledOxt, CompiledValue, TemplateLimits, normalize_template_name};
use crate::{RESPONSE_API_VERSION, SITE_API_VERSION, TEMPLATE_API_VERSION};

#[derive(Debug, Clone, Copy)]
struct SourceLocator<'a> {
    path: &'a Path,
    spans: Option<&'a FieldSpanIndex>,
}

impl<'a> SourceLocator<'a> {
    const fn new(path: &'a Path, spans: Option<&'a FieldSpanIndex>) -> Self {
        Self { path, spans }
    }

    fn value(self, field_path: &str) -> SourceSpan {
        self.span(field_path, false)
    }

    fn key(self, field_path: &str) -> SourceSpan {
        self.span(field_path, true)
    }

    fn span(self, field_path: &str, use_key: bool) -> SourceSpan {
        let range = self
            .spans
            .and_then(|spans| spans.nearest(field_path))
            .map(|field| if use_key { &field.key } else { &field.value });
        let Some(range) = range else {
            return SourceSpan {
                file: self.path.to_path_buf(),
                start_byte: 0,
                end_byte: 0,
                line: 1,
                column: 1,
                end_line: 1,
                end_column: 1,
                field_path: field_path.to_owned(),
            };
        };
        SourceSpan {
            file: self.path.to_path_buf(),
            start_byte: range.start_byte,
            end_byte: range.end_byte,
            line: range.start_line,
            column: range.start_column,
            end_line: range.end_line,
            end_column: range.end_column,
            field_path: field_path.to_owned(),
        }
    }

    fn error(
        self,
        code: &'static str,
        field_path: &str,
        message: impl Into<String>,
    ) -> SiteCompileError {
        SiteCompileError::at(code, self.value(field_path), message)
    }

    fn key_error(
        self,
        code: &'static str,
        field_path: &str,
        message: impl Into<String>,
    ) -> SiteCompileError {
        SiteCompileError::at(code, self.key(field_path), message)
    }
}

#[derive(Debug, Default)]
pub struct SiteCompiler;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteSourceKind {
    Manifest,
    Response,
    Template,
    Asset,
}

#[derive(Debug, Clone)]
pub struct SiteSourceEntry {
    pub source_path: PathBuf,
    pub canonical_path: PathBuf,
    pub kind: SiteSourceKind,
    pub length: u64,
    pub modified: Option<SystemTime>,
    pub digest: ContentDigest,
    text: Option<Arc<str>>,
    spans: Option<Arc<FieldSpanIndex>>,
}

#[derive(Debug)]
pub struct SiteSourceIndex {
    root: PathBuf,
    manifest: PathBuf,
    source: ManifestSource,
    files: Vec<PathBuf>,
    entries: BTreeMap<PathBuf, SiteSourceEntry>,
    directories: BTreeSet<PathBuf>,
    dependencies: Vec<PathBuf>,
    source_digest: ContentDigest,
    #[cfg(test)]
    file_reads: BTreeMap<PathBuf, usize>,
}

impl SiteSourceIndex {
    #[must_use]
    pub const fn source_digest(&self) -> ContentDigest {
        self.source_digest
    }

    pub fn entries(&self) -> impl Iterator<Item = &SiteSourceEntry> {
        self.files.iter().filter_map(|path| self.entries.get(path))
    }

    #[must_use]
    pub fn dependencies(&self) -> &[PathBuf] {
        &self.dependencies
    }

    pub fn fingerprint(&self, inputs: &BTreeMap<String, Value>) -> Result<ContentDigest, String> {
        let mut digest = ContentDigestBuilder::new("oxidase/site/v1");
        digest.field_digest("source", self.source_digest);
        digest.field_bytes(
            "inputs",
            serde_json::to_vec(inputs)
                .map_err(|error| format!("cannot fingerprint site inputs: {error}"))?,
        );
        Ok(digest.finish())
    }

    fn text(&self, path: &Path) -> Result<&str, SiteCompileError> {
        self.indexed_entry(path)
            .and_then(|entry| entry.text.as_deref())
            .ok_or_else(|| {
                SiteCompileError::source(path, "indexed Oxista source text is unavailable")
            })
    }

    fn entry(&self, path: &Path) -> Result<&SiteSourceEntry, SiteCompileError> {
        self.indexed_entry(path).ok_or_else(|| {
            SiteCompileError::source(
                path,
                "file was not present in the prepared Site source index",
            )
        })
    }

    fn indexed_entry(&self, path: &Path) -> Option<&SiteSourceEntry> {
        self.entries.get(path).or_else(|| {
            path.canonicalize()
                .ok()
                .and_then(|canonical| self.entries.get(&canonical))
        })
    }

    fn spans(&self, path: &Path) -> Option<&FieldSpanIndex> {
        self.indexed_entry(path)
            .and_then(|entry| entry.spans.as_deref())
    }

    #[cfg(test)]
    fn file_read_count(&self, path: &Path) -> usize {
        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        self.file_reads.get(&canonical).copied().unwrap_or(0)
    }
}

impl SiteCompiler {
    pub fn scan(
        root: impl AsRef<Path>,
        manifest: impl AsRef<Path>,
    ) -> Result<SiteSourceIndex, SiteCompileFailure> {
        let root = root.as_ref().to_path_buf();
        let manifest = manifest.as_ref().to_path_buf();
        let mut dependencies = Vec::new();
        track_candidate(&mut dependencies, &root);
        track_candidate(&mut dependencies, &manifest);
        scan_site_source(&root, &manifest, &mut dependencies).map_err(|error| {
            normalize_paths(&mut dependencies);
            SiteCompileFailure::new(error, dependencies)
        })
    }

    pub fn compile(
        id: ResourceId,
        root: impl AsRef<Path>,
        manifest: impl AsRef<Path>,
        inputs: BTreeMap<String, Value>,
    ) -> Result<SiteSnapshot, SiteCompileFailure> {
        let index = Self::scan(root, manifest)?;
        Self::compile_indexed(id, &index, inputs)
    }

    pub fn compile_indexed(
        id: ResourceId,
        index: &SiteSourceIndex,
        inputs: BTreeMap<String, Value>,
    ) -> Result<SiteSnapshot, SiteCompileFailure> {
        Self::compile_indexed_with_input_spans(id, index, inputs, BTreeMap::new())
    }

    pub fn compile_indexed_with_input_spans(
        id: ResourceId,
        index: &SiteSourceIndex,
        inputs: BTreeMap<String, Value>,
        input_spans: BTreeMap<String, SourceSpan>,
    ) -> Result<SiteSnapshot, SiteCompileFailure> {
        let mut dependencies = index.dependencies.clone();
        Self::compile_inner(id, index, inputs, &input_spans, &mut dependencies).map_err(|error| {
            normalize_paths(&mut dependencies);
            SiteCompileFailure::new(error, dependencies)
        })
    }

    fn compile_inner(
        id: ResourceId,
        index: &SiteSourceIndex,
        inputs: BTreeMap<String, Value>,
        input_spans: &BTreeMap<String, SourceSpan>,
        dependencies: &mut Vec<PathBuf>,
    ) -> Result<SiteSnapshot, SiteCompileError> {
        let root = &index.root;
        let manifest = &index.manifest;
        let source = &index.source;
        let files = &index.files;
        let manifest_locator = SourceLocator::new(manifest, index.spans(manifest));
        validate_manifest(manifest_locator, source, &inputs, input_spans)?;
        let deny_patterns = compile_deny_patterns(manifest_locator, &source.visibility.deny)?;
        let limits = compile_limits(manifest_locator, source)?;
        let mut data = source
            .data
            .iter()
            .map(|(name, value)| {
                let field_path = field_path_child("data", name);
                Ok((
                    name.clone(),
                    compile_constant(value, manifest_locator, &field_path)?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, SiteCompileError>>()?;
        for (name, value) in &inputs {
            if data.insert(name.clone(), value.clone()).is_some() {
                let data_path = field_path_child("data", name);
                let primary = input_spans
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| manifest_locator.value(&data_path));
                return Err(SiteCompileError::from_diagnostic(
                    Diagnostic::new(
                        "site.input_conflict",
                        format!("site input `{name}` conflicts with a Site data key"),
                        primary,
                    )
                    .with_related("Site data definition", manifest_locator.key(&data_path)),
                ));
            }
        }

        let template_roots = template_roots(root, source, manifest_locator)?;
        let mut templates = compile_templates(
            index,
            root,
            files,
            &template_roots,
            source.templates.default_output,
            source.templates.default_autoescape,
            dependencies,
        )?;
        track_template_dependencies(root, &templates, dependencies);
        validate_template_graph(&templates)?;

        let oxr_files = files
            .iter()
            .filter(|path| has_extension(path, "oxr"))
            .cloned()
            .collect::<Vec<_>>();
        let mut backing_assets = BTreeSet::new();
        let mut entries = BTreeMap::new();
        for oxr in &oxr_files {
            let relative = oxr
                .strip_prefix(root)
                .map_err(|_| SiteCompileError::UnsafePath {
                    path: oxr.clone(),
                    message: "OXR escapes the site root".to_owned(),
                })?;
            if is_private(relative, source, &template_roots, root, &deny_patterns) {
                continue;
            }
            dependencies.push(oxr.clone());
            let (logical_path, plan, backing) =
                compile_oxr(index, root, oxr, source, &mut templates, dependencies)?;
            if let Some(backing) = backing {
                backing_assets.insert(backing);
            }
            insert_with_index_aliases(&mut entries, logical_path, plan, source)?;
        }

        let precompressed = precompressed_paths(files, source);
        for asset in files.iter().filter(|path| {
            !has_source_extension(path)
                && !backing_assets.contains(*path)
                && !precompressed.contains(*path)
        }) {
            let relative = asset
                .strip_prefix(root)
                .map_err(|_| SiteCompileError::UnsafePath {
                    path: asset.clone(),
                    message: "asset is outside the canonical site root".to_owned(),
                })?;
            if is_private(relative, source, &template_roots, root, &deny_patterns) {
                continue;
            }
            let headers = compile_resource_base_policy(relative, source, manifest_locator)?;
            let logical_path = logical_path(relative);
            let plan = SiteResponsePlan {
                status: StatusCode::OK,
                headers,
                content_type: None,
                page: BTreeMap::new(),
                kind: SiteResponseKind::Asset(Box::new(compile_asset(index, asset, source)?)),
                source: asset.clone(),
            };
            insert_with_index_aliases(&mut entries, logical_path, plan, source)?;
            track_site_dependency(dependencies, asset, root);
        }
        validate_template_graph(&templates)?;

        let error_404 = source
            .errors
            .get(&404)
            .map(|error| {
                let name = normalize_template_name(&error.template).map_err(|error| {
                    manifest_locator.error(
                        "template.reference",
                        "errors[\"404\"].template",
                        error.to_string(),
                    )
                })?;
                track_site_dependency(dependencies, &root.join(&name), root);
                let template = templates.get(&name).ok_or_else(|| {
                    manifest_locator.error(
                        "site.template_missing",
                        "errors[\"404\"].template",
                        format!("404 error template `{name}` does not exist"),
                    )
                })?;
                template.validate_arguments_at(
                    &BTreeMap::new(),
                    manifest_locator.value("errors[\"404\"].template"),
                    &BTreeMap::new(),
                )?;
                Ok(crate::runtime::ErrorPagePlan {
                    template: name,
                    headers: compile_response_policy(
                        &source.defaults.response,
                        manifest_locator,
                        "defaults.response",
                    )?,
                })
            })
            .transpose()?;

        normalize_paths(dependencies);
        Ok(SiteSnapshot {
            id,
            root: root.clone(),
            manifest: manifest.clone(),
            dependencies: dependencies.clone(),
            missing: match source.paths.missing {
                MissingSource::Decline => SiteMissing::Decline,
                MissingSource::Respond => SiteMissing::Respond,
            },
            data,
            limits,
            templates,
            entries,
            error_404,
        })
    }
}

#[derive(Debug)]
struct CollectedFiles {
    files: Vec<PathBuf>,
    symlinks: Vec<(PathBuf, PathBuf)>,
    directories: BTreeSet<PathBuf>,
}

fn scan_site_source(
    root: &Path,
    manifest: &Path,
    dependencies: &mut Vec<PathBuf>,
) -> Result<SiteSourceIndex, SiteCompileError> {
    let root = root
        .canonicalize()
        .map_err(|error| SiteCompileError::io(root, error))?;
    track_site_dependency(dependencies, &root, &root);
    let manifest = manifest
        .canonicalize()
        .map_err(|error| SiteCompileError::io(manifest, error))?;
    track_site_dependency(dependencies, &manifest, &root);
    if !path_is_within(&manifest, &root) {
        return Err(SiteCompileError::UnsafePath {
            path: manifest,
            message: "manifest escapes the site root".to_owned(),
        });
    }

    let manifest_entry = read_site_source_entry(&manifest, &manifest, SiteSourceKind::Manifest)?;
    let manifest_text = manifest_entry
        .text
        .as_deref()
        .expect("manifest entries retain source text");
    let manifest_locator = SourceLocator::new(&manifest, manifest_entry.spans.as_deref());
    let source: ManifestSource = parse_yaml(
        &manifest,
        manifest_text,
        (0, 0),
        manifest_entry.spans.as_deref(),
    )?;
    if source.oxista != SITE_API_VERSION {
        return Err(manifest_locator.error(
            "site.version",
            "oxista",
            format!(
                "unsupported Oxista version `{}`; expected `{SITE_API_VERSION}`",
                source.oxista
            ),
        ));
    }
    let deny_patterns = compile_deny_patterns(manifest_locator, &source.visibility.deny)?;
    let template_roots = template_roots(&root, &source, manifest_locator)?;
    let collection = collect_files(
        &root,
        &source,
        &template_roots,
        &deny_patterns,
        dependencies,
    )?;
    let mut files = collection.files;
    files.sort();
    files.dedup();
    for path in &files {
        track_site_dependency(dependencies, path, &root);
    }
    for (link, target) in &collection.symlinks {
        track_site_dependency(dependencies, link, &root);
        track_site_dependency(dependencies, target, &root);
    }
    for path in &template_roots {
        track_site_dependency(dependencies, path, &root);
    }
    track_precompressed_candidates(&files, &source, &root, dependencies);

    let mut entries = BTreeMap::new();
    entries.insert(manifest.clone(), manifest_entry);
    #[cfg(test)]
    let mut file_reads = BTreeMap::from([(manifest.clone(), 1usize)]);
    for path in &files {
        if entries.contains_key(path) {
            continue;
        }
        let entry = read_site_source_entry(path, path, site_source_kind(path, &manifest))?;
        #[cfg(test)]
        {
            *file_reads.entry(path.clone()).or_default() += 1;
        }
        entries.insert(path.clone(), entry);
    }
    for (link, target) in &collection.symlinks {
        if let Some(target_entry) = entries.get(target).cloned() {
            entries.insert(
                link.clone(),
                SiteSourceEntry {
                    source_path: link.clone(),
                    ..target_entry
                },
            );
        }
    }

    let mut digest = ContentDigestBuilder::new("oxidase/site-source-index/v1");
    digest.field_bytes(
        "manifest",
        relative_source_name(&manifest, &root).as_bytes(),
    );
    digest.field_u64("file_count", files.len() as u64);
    for path in &files {
        let entry = entries
            .get(path)
            .expect("every collected file has an indexed entry");
        digest
            .field_bytes("path", relative_source_name(path, &root).as_bytes())
            .field_bytes("kind", site_source_kind_name(entry.kind).as_bytes())
            .field_u64("length", entry.length)
            .field_digest("content", entry.digest);
        if source.assets.last_modified && entry.kind == SiteSourceKind::Asset {
            match entry.modified {
                Some(modified) => {
                    let (side, duration) = match modified.duration_since(UNIX_EPOCH) {
                        Ok(duration) => (b"after".as_slice(), duration),
                        Err(error) => (b"before".as_slice(), error.duration()),
                    };
                    digest
                        .field_bytes("modified_side", side)
                        .field_u64("modified_seconds", duration.as_secs())
                        .field_u64("modified_nanos", u64::from(duration.subsec_nanos()));
                }
                None => {
                    digest.field_bytes("modified", b"unavailable");
                }
            }
        }
    }
    let mut symlinks = collection.symlinks;
    symlinks.sort();
    for (link, target) in symlinks {
        digest
            .field_bytes("symlink", relative_source_name(&link, &root).as_bytes())
            .field_bytes("target", relative_source_name(&target, &root).as_bytes());
    }
    normalize_paths(dependencies);

    Ok(SiteSourceIndex {
        root,
        manifest,
        source,
        files,
        entries,
        directories: collection.directories,
        dependencies: dependencies.clone(),
        source_digest: digest.finish(),
        #[cfg(test)]
        file_reads,
    })
}

fn read_site_source_entry(
    source_path: &Path,
    canonical_path: &Path,
    kind: SiteSourceKind,
) -> Result<SiteSourceEntry, SiteCompileError> {
    let metadata = canonical_path
        .metadata()
        .map_err(|error| SiteCompileError::io(source_path, error))?;
    if !metadata.is_file() {
        return Err(SiteCompileError::source(
            source_path,
            "indexed Site source is not a regular file",
        ));
    }
    let mut file =
        fs::File::open(canonical_path).map_err(|error| SiteCompileError::io(source_path, error))?;
    let retain_text = kind != SiteSourceKind::Asset;
    let mut text_bytes = retain_text.then(|| Vec::with_capacity(metadata.len() as usize));
    let mut hasher = ContentHasher::new();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| SiteCompileError::io(source_path, error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        if let Some(text) = &mut text_bytes {
            text.extend_from_slice(&buffer[..read]);
        }
    }
    let text = text_bytes
        .map(|bytes| {
            String::from_utf8(bytes)
                .map(Arc::<str>::from)
                .map_err(|error| {
                    SiteCompileError::io(
                        source_path,
                        std::io::Error::new(std::io::ErrorKind::InvalidData, error),
                    )
                })
        })
        .transpose()?;
    let spans = match (kind, text.as_deref()) {
        (SiteSourceKind::Manifest, Some(text)) => Some(Arc::new(
            oxidase_source::parse_document::<serde_yaml_ng::Value>(source_path, text)
                .map_err(|error| strict_yaml_error(source_path, text, (0, 0), error))?
                .spans,
        )),
        (SiteSourceKind::Response | SiteSourceKind::Template, Some(text)) => {
            let (front_matter, _) = split_front_matter(source_path, text)?;
            let byte_offset = text.split_inclusive('\n').next().map_or(0, str::len);
            let spans =
                oxidase_source::parse_document::<serde_yaml_ng::Value>(source_path, front_matter)
                    .map_err(|error| {
                        strict_yaml_error(source_path, front_matter, (byte_offset, 1), error)
                    })?
                    .spans
                    .shifted(byte_offset, 1);
            Some(Arc::new(spans))
        }
        _ => None,
    };
    Ok(SiteSourceEntry {
        source_path: source_path.to_path_buf(),
        canonical_path: canonical_path.to_path_buf(),
        kind,
        length: metadata.len(),
        modified: metadata.modified().ok(),
        digest: hasher.finish(),
        text,
        spans,
    })
}

fn site_source_kind(path: &Path, manifest: &Path) -> SiteSourceKind {
    if path == manifest || has_extension(path, "oxsite") {
        SiteSourceKind::Manifest
    } else if has_extension(path, "oxr") {
        SiteSourceKind::Response
    } else if has_extension(path, "oxt") {
        SiteSourceKind::Template
    } else {
        SiteSourceKind::Asset
    }
}

const fn site_source_kind_name(kind: SiteSourceKind) -> &'static str {
    match kind {
        SiteSourceKind::Manifest => "manifest",
        SiteSourceKind::Response => "response",
        SiteSourceKind::Template => "template",
        SiteSourceKind::Asset => "asset",
    }
}

fn relative_source_name(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn normalize_paths(paths: &mut Vec<PathBuf>) {
    paths.sort();
    paths.dedup();
}

fn track_candidate(dependencies: &mut Vec<PathBuf>, path: &Path) {
    dependencies.push(path.to_path_buf());
    if let Some(parent) = path.parent() {
        dependencies.push(parent.to_path_buf());
    }
}

fn track_site_dependency(dependencies: &mut Vec<PathBuf>, path: &Path, root: &Path) {
    dependencies.push(path.to_path_buf());
    let mut parent = path.parent();
    while let Some(directory) = parent {
        if !directory.starts_with(root) {
            break;
        }
        dependencies.push(directory.to_path_buf());
        if directory == root {
            break;
        }
        parent = directory.parent();
    }
}

fn track_template_dependencies(
    root: &Path,
    templates: &BTreeMap<String, CompiledOxt>,
    dependencies: &mut Vec<PathBuf>,
) {
    for template in templates.values() {
        for dependency in template.dependencies() {
            track_site_dependency(dependencies, &root.join(dependency), root);
        }
    }
}

fn track_precompressed_candidates(
    files: &[PathBuf],
    source: &ManifestSource,
    root: &Path,
    dependencies: &mut Vec<PathBuf>,
) {
    let existing_precompressed = precompressed_paths(files, source);
    for path in files
        .iter()
        .filter(|path| !has_source_extension(path) && !existing_precompressed.contains(*path))
    {
        for suffix in [
            source.assets.precompressed.brotli.as_deref(),
            source.assets.precompressed.gzip.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            let candidate = PathBuf::from(format!("{}{suffix}", path.to_string_lossy()));
            track_site_dependency(dependencies, &candidate, root);
        }
    }
}

fn validate_manifest(
    locator: SourceLocator<'_>,
    source: &ManifestSource,
    inputs: &BTreeMap<String, Value>,
    input_spans: &BTreeMap<String, SourceSpan>,
) -> Result<(), SiteCompileError> {
    if !matches!(source.paths.trailing_slash, TrailingSlashSource::Canonical) {
        return Err(locator.error(
            "site.unsupported_field",
            "paths.trailing_slash",
            "paths.trailing_slash only supports `canonical` in Oxista v1; remove the field or set it to `canonical`",
        ));
    }
    if source.paths.directory_listing {
        return Err(locator.error(
            "site.unsupported_field",
            "paths.directory_listing",
            "directory_listing is intentionally unavailable in Oxista v1",
        ));
    }
    if source.paths.clean_html_urls {
        return Err(locator.error(
            "site.unsupported_field",
            "paths.clean_html_urls",
            "clean_html_urls is not implemented in this release",
        ));
    }
    if matches!(source.templates.default_output, OutputSource::Json) {
        return Err(locator.error(
            "template.output",
            "templates.default_output",
            "templates.default_output `json` is not supported; use an OXR structured JSON body",
        ));
    }
    if let Some(status) = source.errors.keys().find(|status| **status != 404) {
        let field_path = field_path_child("errors", &status.to_string());
        return Err(locator.key_error(
            "site.unsupported_error_status",
            &field_path,
            format!(
                "errors.{status} is not supported in Oxista v1 alpha; only a 404 template is implemented"
            ),
        ));
    }
    for (name, contract) in &source.inputs {
        let input_path = field_path_child("inputs", name);
        validate_input_kind(locator, &format!("{input_path}.type"), name, &contract.kind)?;
        match inputs.get(name) {
            None if contract.required => {
                return Err(locator.error(
                    "site.input_missing",
                    &format!("{input_path}.required"),
                    format!("site input `{name}` is required but was not injected"),
                ));
            }
            Some(value) if !input_accepts(&contract.kind, value) => {
                let declaration = locator.value(&format!("{input_path}.type"));
                let mut diagnostic = Diagnostic::new(
                    "site.input_type",
                    format!(
                        "site input `{name}` expects type `{}`, received {}",
                        contract.kind,
                        value.type_name()
                    ),
                    declaration.clone(),
                );
                if let Some(injected) = input_spans.get(name) {
                    diagnostic = diagnostic
                        .with_label("injected value", injected.clone())
                        .with_related("Site input declaration", declaration)
                        .with_reference_chain([
                            DiagnosticReference::new("Gateway injected value", injected.clone()),
                            DiagnosticReference::new(
                                "Site input declaration",
                                locator.value(&input_path),
                            ),
                        ]);
                }
                return Err(SiteCompileError::from_diagnostic(diagnostic));
            }
            _ => {}
        }
    }
    for name in inputs.keys() {
        if !source.inputs.contains_key(name) {
            let declaration_container = locator.value("inputs");
            let primary = input_spans
                .get(name)
                .cloned()
                .unwrap_or_else(|| declaration_container.clone());
            return Err(SiteCompileError::from_diagnostic(
                Diagnostic::new(
                    "site.input_unknown",
                    format!("site input `{name}` is not declared by the Site manifest"),
                    primary,
                )
                .with_related("Site input declarations", declaration_container),
            ));
        }
    }
    for (position, index) in source.paths.indexes.iter().enumerate() {
        if index.contains('/') || index.contains('\\') || index.is_empty() {
            return Err(locator.error(
                "site.index_name",
                &format!("paths.indexes[{position}]"),
                format!("index name `{index}` must be one file name"),
            ));
        }
    }
    validate_cache_policy(locator, &source.defaults.response, "defaults.response")?;
    compile_response_policy(&source.defaults.response, locator, "defaults.response")?;
    for (extension, policy) in &source.defaults.by_extension {
        let field_path = field_path_child("defaults.by_extension", extension);
        validate_cache_policy(locator, policy, &field_path)?;
        compile_response_policy(policy, locator, &field_path)?;
    }
    for (name, policy) in &source.profiles {
        let field_path = field_path_child("profiles", name);
        validate_cache_policy(locator, policy, &field_path)?;
        compile_response_policy(policy, locator, &field_path)?;
    }
    for (extension, content_type) in &source.assets.mime_overrides {
        let field_path = field_path_child("assets.mime_overrides", extension);
        HeaderValue::from_str(content_type).map_err(|_| {
            locator.error(
                "site.asset_content_type",
                &field_path,
                format!("asset MIME override `{content_type}` is not a valid HTTP header value"),
            )
        })?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DenyPattern {
    ExactPath(Vec<String>),
    ComponentName(String),
    FileExtension(String),
}

impl DenyPattern {
    fn matches(&self, relative: &Path) -> bool {
        let components = relative
            .components()
            .filter_map(|component| match component {
                Component::Normal(value) => value.to_str(),
                _ => None,
            })
            .collect::<Vec<_>>();
        match self {
            Self::ExactPath(expected) => {
                components.len() >= expected.len()
                    && components
                        .iter()
                        .zip(expected)
                        .all(|(actual, expected)| actual == expected)
            }
            Self::ComponentName(expected) => {
                components.iter().any(|component| component == expected)
            }
            Self::FileExtension(extension) => components
                .last()
                .is_some_and(|name| name.ends_with(extension)),
        }
    }
}

fn compile_deny_patterns(
    locator: SourceLocator<'_>,
    patterns: &[String],
) -> Result<Vec<DenyPattern>, SiteCompileError> {
    patterns
        .iter()
        .enumerate()
        .map(|(index, pattern)| {
            compile_deny_pattern(pattern).map_err(|message| {
                locator.error(
                    "site.visibility_pattern",
                    &format!("visibility.deny[{index}]"),
                    format!(
                        "visibility.deny[{index}] `{pattern}` is invalid: {message}; use an exact relative path, `**/name`, or `**/*.ext`"
                    ),
                )
            })
        })
        .collect()
}

fn compile_deny_pattern(pattern: &str) -> Result<DenyPattern, &'static str> {
    if pattern.is_empty() {
        return Err("pattern cannot be empty");
    }
    if pattern.contains('\\') {
        return Err("backslashes are not allowed");
    }
    if pattern.starts_with('/') || looks_like_windows_absolute(pattern) {
        return Err("absolute paths are not allowed");
    }
    if let Some(extension) = pattern.strip_prefix("**/*.") {
        if !valid_pattern_component(extension) || extension.contains('/') {
            return Err("extension pattern must contain one non-empty extension");
        }
        return Ok(DenyPattern::FileExtension(format!(".{extension}")));
    }
    if let Some(name) = pattern.strip_prefix("**/") {
        if !valid_pattern_component(name) || name.contains('/') {
            return Err("component pattern must contain one exact path component");
        }
        return Ok(DenyPattern::ComponentName(name.to_owned()));
    }
    if pattern.contains(['*', '?', '[', ']']) {
        return Err("unsupported wildcard syntax");
    }
    let components = pattern.split('/').collect::<Vec<_>>();
    if components
        .iter()
        .any(|component| !valid_pattern_component(component))
    {
        return Err("exact paths cannot contain empty, `.` or `..` components");
    }
    Ok(DenyPattern::ExactPath(
        components.into_iter().map(str::to_owned).collect(),
    ))
}

fn valid_pattern_component(component: &str) -> bool {
    !component.is_empty()
        && !matches!(component, "." | "..")
        && !component.contains(['*', '?', '[', ']'])
}

fn looks_like_windows_absolute(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/'
}

fn validate_input_kind(
    locator: SourceLocator<'_>,
    field_path: &str,
    name: &str,
    kind: &str,
) -> Result<(), SiteCompileError> {
    let base = kind.strip_suffix('?').unwrap_or(kind);
    if base == "safe_html" {
        return Err(locator.error(
            "site.input_type",
            field_path,
            format!(
                "inputs.{name}.type `safe_html` is unavailable because runtime values do not carry trusted HTML provenance; use `string`"
            ),
        ));
    }
    if !matches!(
        base,
        "any" | "null" | "bool" | "int" | "float" | "string" | "url"
    ) {
        return Err(locator.error(
            "site.input_type",
            field_path,
            format!("inputs.{name}.type uses unknown value type `{kind}`"),
        ));
    }
    Ok(())
}

fn input_accepts(kind: &str, value: &Value) -> bool {
    match kind {
        "any" => true,
        "null" => value.is_null(),
        "bool" => matches!(value, Value::Bool(_)),
        "int" => matches!(value, Value::Integer(_)),
        "float" => matches!(value, Value::Integer(_) | Value::Float(_)),
        "string" => matches!(value, Value::String(_)),
        "url" => value
            .as_str()
            .and_then(|value| url::Url::parse(value).ok())
            .is_some(),
        kind if kind.ends_with('?') => {
            value.is_null() || input_accepts(&kind[..kind.len() - 1], value)
        }
        _ => false,
    }
}

fn validate_cache_policy(
    locator: SourceLocator<'_>,
    policy: &ResponsePolicySource,
    field_path: &str,
) -> Result<(), SiteCompileError> {
    if let Some(cache) = &policy.cache {
        if let Some(visibility) = &cache.visibility
            && !matches!(visibility.as_str(), "public" | "private" | "no_store")
        {
            return Err(locator.error(
                "site.cache_visibility",
                &format!("{field_path}.cache.visibility"),
                format!("invalid cache visibility `{visibility}`"),
            ));
        }
        if let Some(max_age) = &cache.max_age {
            parse_seconds(max_age).map_err(|message| {
                locator.error(
                    "site.cache_max_age",
                    &format!("{field_path}.cache.max_age"),
                    message,
                )
            })?;
        }
    }
    Ok(())
}

fn compile_limits(
    locator: SourceLocator<'_>,
    source: &ManifestSource,
) -> Result<TemplateLimits, SiteCompileError> {
    Ok(TemplateLimits {
        render_time: parse_duration(&source.templates.limits.render_time).map_err(|message| {
            locator.error("template.limit", "templates.limits.render_time", message)
        })?,
        output_size: parse_size(&source.templates.limits.output_size).map_err(|message| {
            locator.error("template.limit", "templates.limits.output_size", message)
        })?,
        loop_iterations: source.templates.limits.loop_iterations,
        include_depth: source.templates.limits.include_depth,
        expression_steps: source.templates.limits.expression_steps,
        strict_undefined: source.templates.strict_undefined,
    })
}

fn collect_files(
    root: &Path,
    source: &ManifestSource,
    template_roots: &[PathBuf],
    deny_patterns: &[DenyPattern],
    dependencies: &mut Vec<PathBuf>,
) -> Result<CollectedFiles, SiteCompileError> {
    let mut files = Vec::new();
    let mut symlinks = Vec::new();
    let mut directories = BTreeSet::new();
    let mut entries = WalkDir::new(root).follow_links(false).into_iter();
    while let Some(entry) = entries.next() {
        let entry = entry.map_err(|error| {
            let path = error
                .path()
                .map_or_else(|| root.to_path_buf(), Path::to_path_buf);
            SiteCompileError::source(path, error.to_string())
        })?;
        if entry.path() == root {
            continue;
        }
        track_site_dependency(dependencies, entry.path(), root);
        let relative =
            entry
                .path()
                .strip_prefix(root)
                .map_err(|_| SiteCompileError::UnsafePath {
                    path: entry.path().to_path_buf(),
                    message: "site scan escaped the canonical root".to_owned(),
                })?;
        if entry.file_type().is_dir() {
            directories.insert(entry.path().to_path_buf());
        }
        if entry.file_type().is_dir()
            && !is_template_scan_path(entry.path(), template_roots)
            && denied_by_visibility(relative, source, deny_patterns, true)
        {
            validate_pruned_subtree_symlinks(entry.path(), source, root)?;
            entries.skip_current_dir();
            continue;
        }
        if entry.file_type().is_symlink() {
            let canonical = validate_symlink(entry.path(), source, root)?;
            track_site_dependency(dependencies, &canonical, root);
            symlinks.push((entry.path().to_path_buf(), canonical.clone()));
            files.push(canonical);
        } else if entry.file_type().is_file() {
            files.push(entry.path().to_path_buf());
        }
    }
    Ok(CollectedFiles {
        files,
        symlinks,
        directories,
    })
}

fn is_template_scan_path(path: &Path, template_roots: &[PathBuf]) -> bool {
    template_roots
        .iter()
        .any(|root| path.starts_with(root) || root.starts_with(path))
}

fn validate_pruned_subtree_symlinks(
    directory: &Path,
    source: &ManifestSource,
    root: &Path,
) -> Result<(), SiteCompileError> {
    for entry in WalkDir::new(directory).follow_links(false).min_depth(1) {
        let entry = entry.map_err(|error| {
            let path = error
                .path()
                .map_or_else(|| directory.to_path_buf(), Path::to_path_buf);
            SiteCompileError::source(path, error.to_string())
        })?;
        if entry.file_type().is_symlink() {
            validate_symlink(entry.path(), source, root)?;
        }
    }
    Ok(())
}

fn validate_symlink(
    path: &Path,
    source: &ManifestSource,
    root: &Path,
) -> Result<PathBuf, SiteCompileError> {
    let canonical = path
        .canonicalize()
        .map_err(|error| SiteCompileError::io(path, error))?;
    if source.visibility.symlinks == SymlinkModeSource::Deny || !path_is_within(&canonical, root) {
        return Err(SiteCompileError::UnsafePath {
            path: path.to_path_buf(),
            message: "symlink is denied or escapes the site root".to_owned(),
        });
    }
    if canonical.is_dir() {
        return Err(SiteCompileError::UnsafePath {
            path: path.to_path_buf(),
            message: "directory symlinks are not traversed in Oxista v1".to_owned(),
        });
    }
    Ok(canonical)
}

fn template_roots(
    root: &Path,
    source: &ManifestSource,
    locator: SourceLocator<'_>,
) -> Result<Vec<PathBuf>, SiteCompileError> {
    source
        .templates
        .roots
        .iter()
        .enumerate()
        .map(|(index, template_root)| {
            let relative = Path::new(template_root);
            if relative.is_absolute()
                || relative.components().any(|component| {
                    matches!(component, Component::ParentDir | Component::Prefix(_))
                })
            {
                return Err(locator.error(
                    "template.root",
                    &format!("templates.roots[{index}]"),
                    "template root must be relative and cannot contain `..`",
                ));
            }
            Ok(root.join(relative))
        })
        .collect()
}

fn compile_templates(
    index: &SiteSourceIndex,
    root: &Path,
    files: &[PathBuf],
    template_roots: &[PathBuf],
    default_output: OutputSource,
    default_autoescape: Option<crate::source::AutoescapeSource>,
    dependencies: &mut Vec<PathBuf>,
) -> Result<BTreeMap<String, CompiledOxt>, SiteCompileError> {
    let mut templates = BTreeMap::new();
    for path in files.iter().filter(|path| has_extension(path, "oxt")) {
        if !template_roots
            .iter()
            .any(|template_root| path.starts_with(template_root))
        {
            return Err(SiteCompileError::UnsafePath {
                path: path.clone(),
                message: "OXT file is outside every configured template root".to_owned(),
            });
        }
        let name = path
            .strip_prefix(root)
            .map_err(|_| SiteCompileError::UnsafePath {
                path: path.clone(),
                message: "template escapes the site root".to_owned(),
            })?
            .to_string_lossy()
            .replace('\\', "/");
        let text = index.text(path)?;
        let (front_matter, body) = split_front_matter(path, text)?;
        let body_offset = text.len() - body.len();
        let body_line_offset = text[..body_offset]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        let front_matter_offset = text.split_inclusive('\n').next().map_or(0, str::len);
        let metadata: crate::source::OxtMetadataSource = parse_yaml(
            path,
            front_matter,
            (front_matter_offset, 1),
            index.spans(path),
        )?;
        let locator = SourceLocator::new(path, index.spans(path));
        if metadata.oxista != TEMPLATE_API_VERSION {
            return Err(locator.error(
                "template.version",
                "oxista",
                format!("expected `oxista: {TEMPLATE_API_VERSION}`"),
            ));
        }
        let template = CompiledOxt::compile(
            name.clone(),
            path,
            &metadata,
            index.spans(path),
            body,
            (body_offset, body_line_offset),
            default_output,
            default_autoescape,
        )?;
        if templates.insert(name.clone(), template).is_some() {
            return Err(locator.error(
                "template.duplicate",
                "oxista",
                format!("duplicate template name `{name}`"),
            ));
        }
        dependencies.push(path.clone());
    }
    Ok(templates)
}

pub(crate) fn validate_template_graph(
    templates: &BTreeMap<String, CompiledOxt>,
) -> Result<(), SiteCompileError> {
    fn visit(
        name: &str,
        templates: &BTreeMap<String, CompiledOxt>,
        visiting: &mut Vec<String>,
        visited: &mut BTreeSet<String>,
    ) -> Result<(), SiteCompileError> {
        if visited.contains(name) {
            return Ok(());
        }
        if let Some(position) = visiting.iter().position(|candidate| candidate == name) {
            let mut cycle = visiting[position..].to_vec();
            cycle.push(name.to_owned());
            let edges = cycle
                .windows(2)
                .map(|edge| {
                    let span = templates
                        .get(&edge[0])
                        .and_then(|template| template.include_span(&edge[1]))
                        .cloned()
                        .unwrap_or_else(|| SourceSpan::synthetic("template.include.target"));
                    (edge[0].clone(), edge[1].clone(), span)
                })
                .collect::<Vec<_>>();
            let primary = edges
                .first()
                .map(|(_, _, span)| span.clone())
                .unwrap_or_else(|| SourceSpan::synthetic("template.include.target"));
            let mut diagnostic = Diagnostic::new(
                "template.include_cycle",
                format!("template dependency cycle: {}", cycle.join(" -> ")),
                primary,
            );
            for (index, (caller, target, span)) in edges.iter().enumerate() {
                if index > 0 {
                    diagnostic = diagnostic
                        .with_related(format!("`{caller}` includes `{target}`"), span.clone());
                }
            }
            diagnostic =
                diagnostic.with_reference_chain(edges.iter().map(|(caller, target, span)| {
                    DiagnosticReference::new(
                        format!("`{caller}` includes `{target}`"),
                        span.clone(),
                    )
                }));
            return Err(SiteCompileError::from_diagnostic(diagnostic));
        }
        let template = templates.get(name).ok_or_else(|| {
            SiteCompileError::source(name, format!("included template `{name}` does not exist"))
        })?;
        template.validate_include_contracts(templates)?;
        visiting.push(name.to_owned());
        for dependency in template.dependencies() {
            visit(dependency, templates, visiting, visited)?;
        }
        visiting.pop();
        visited.insert(name.to_owned());
        Ok(())
    }

    let mut visited = BTreeSet::new();
    for name in templates.keys() {
        visit(name, templates, &mut Vec::new(), &mut visited)?;
    }
    Ok(())
}

fn compile_oxr(
    index: &SiteSourceIndex,
    root: &Path,
    path: &Path,
    manifest: &ManifestSource,
    templates: &mut BTreeMap<String, CompiledOxt>,
    dependencies: &mut Vec<PathBuf>,
) -> Result<(String, SiteResponsePlan, Option<PathBuf>), SiteCompileError> {
    let text = index.text(path)?;
    let (front_matter, inline_body) = split_front_matter(path, text)?;
    let front_matter_offset = text.split_inclusive('\n').next().map_or(0, str::len);
    let locator = SourceLocator::new(path, index.spans(path));
    let manifest_locator = SourceLocator::new(&index.manifest, index.spans(&index.manifest));
    let source: OxrSource = parse_yaml(
        path,
        front_matter,
        (front_matter_offset, 1),
        index.spans(path),
    )?;
    if source.oxista != RESPONSE_API_VERSION {
        return Err(locator.error(
            "site.response_version",
            "oxista",
            format!("expected `oxista: {RESPONSE_API_VERSION}`"),
        ));
    }
    if source.response.redirect.is_some() && source.response.body.is_some() {
        let diagnostic = Diagnostic::new(
            "site.response_shape",
            "OXR response cannot contain both `redirect` and `body`",
            locator.value("response"),
        )
        .with_label("redirect is selected", locator.value("response.redirect"))
        .with_label("body is selected", locator.value("response.body"));
        return Err(SiteCompileError::from_diagnostic(diagnostic));
    }

    let relative = path
        .strip_prefix(root)
        .map_err(|_| SiteCompileError::UnsafePath {
            path: path.to_path_buf(),
            message: "OXR escapes the site root".to_owned(),
        })?;
    let relative_without_oxr = PathBuf::from(
        relative
            .to_string_lossy()
            .strip_suffix(".oxr")
            .ok_or_else(|| SiteCompileError::source(path, "OXR must end with `.oxr`"))?,
    );
    let logical_path = logical_path(&relative_without_oxr);
    let mut headers =
        compile_resource_base_policy(&relative_without_oxr, manifest, manifest_locator)?;
    for (index, profile) in source.apply.iter().enumerate() {
        let policy = manifest.profiles.get(profile).ok_or_else(|| {
            locator.error(
                "site.profile_reference",
                &format!("apply[{index}]"),
                format!("unknown response profile `{profile}`"),
            )
        })?;
        headers.merge(compile_response_policy(
            policy,
            manifest_locator,
            &field_path_child("profiles", profile),
        )?);
    }
    headers.merge(compile_headers(
        &source.response.headers,
        path,
        "response.headers",
        index.spans(path),
    )?);
    let page = source
        .page
        .iter()
        .map(|(name, value)| {
            let field_path = field_path_child("page", name);
            Ok((name.clone(), compile_value(value, locator, &field_path)?))
        })
        .collect::<Result<_, SiteCompileError>>()?;

    let mut status =
        StatusCode::from_u16(source.response.status.unwrap_or(200)).map_err(|error| {
            locator.error("site.response_status", "response.status", error.to_string())
        })?;
    if let Some(content_type) = source.response.content_type.as_deref() {
        HeaderValue::from_str(content_type).map_err(|_| {
            locator.error(
                "site.response_content_type",
                "response.content_type",
                "response.content_type is not a valid HTTP header value",
            )
        })?;
    }
    let (kind, backing) = if let Some(redirect) = &source.response.redirect {
        if source.response.status.is_some() {
            return Err(locator.error(
                "site.redirect_status_ambiguity",
                "response.status",
                "response.status is not allowed with response.redirect; use response.redirect.status",
            ));
        }
        let redirect_status = StatusCode::from_u16(redirect.status).map_err(|error| {
            locator.error(
                "site.redirect_status",
                "response.redirect.status",
                error.to_string(),
            )
        })?;
        if !redirect_status.is_redirection() {
            return Err(locator.error(
                "site.redirect_status",
                "response.redirect.status",
                "redirect status must be 3xx",
            ));
        }
        if !redirect.location.contains("{{")
            && (!redirect.location.starts_with('/')
                || redirect.location.starts_with("//")
                || redirect.location.contains('\\'))
        {
            return Err(locator.error(
                "site.redirect_location",
                "response.redirect.location",
                "redirect Location must be a local absolute path",
            ));
        }
        let query = match redirect.query {
            RedirectQuerySource::Drop => RedirectQuery::Drop,
            RedirectQuerySource::Preserve => RedirectQuery::Preserve,
            RedirectQuerySource::Replace => {
                return Err(locator.error(
                    "site.redirect_query",
                    "response.redirect.query",
                    "response.redirect.query `replace` is not supported because Oxista v1 has no replacement query field; use `drop`, `preserve`, or include a fixed query in `location`",
                ));
            }
        };
        status = redirect_status;
        (
            SiteResponseKind::Redirect {
                status: redirect_status,
                location: CompiledTemplate::compile(&redirect.location).map_err(|error| {
                    locator.error(
                        "site.redirect_location",
                        "response.redirect.location",
                        error.to_string(),
                    )
                })?,
                query,
            },
            None,
        )
    } else {
        let body = source.response.body.as_ref().ok_or_else(|| {
            locator.error(
                "site.response_shape",
                "response",
                "OXR response requires `redirect` or `body`",
            )
        })?;
        let body_offset = text.len() - inline_body.len();
        let body_line_offset = text[..body_offset]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        compile_oxr_body(
            index,
            path,
            locator,
            body,
            inline_body,
            (body_offset, body_line_offset),
            manifest,
            templates,
            dependencies,
        )?
    };
    Ok((
        logical_path,
        SiteResponsePlan {
            status,
            headers,
            content_type: source.response.content_type,
            page,
            kind,
            source: path.to_path_buf(),
        },
        backing,
    ))
}

#[allow(clippy::too_many_arguments)]
fn compile_oxr_body(
    index: &SiteSourceIndex,
    oxr: &Path,
    locator: SourceLocator<'_>,
    body: &OxrBodySource,
    inline_body: &str,
    inline_origin: (usize, usize),
    manifest: &ManifestSource,
    templates: &mut BTreeMap<String, CompiledOxt>,
    dependencies: &mut Vec<PathBuf>,
) -> Result<(SiteResponseKind, Option<PathBuf>), SiteCompileError> {
    let root = &index.root;
    let selected = usize::from(body.asset.is_some())
        + usize::from(body.template.is_some())
        + usize::from(body.json.is_some())
        + usize::from(body.empty)
        + usize::from(body.text.is_some());
    if selected != 1 {
        let mut diagnostic = Diagnostic::new(
            "site.response_body_shape",
            "OXR body must select exactly one of asset, template, json, empty, or text",
            locator.value("response.body"),
        );
        for field in ["asset", "template", "json", "empty", "text"] {
            let field_path = format!("response.body.{field}");
            if locator
                .spans
                .is_some_and(|spans| spans.get(&field_path).is_some())
            {
                diagnostic = diagnostic.with_label(
                    format!("body alternative `{field}` is selected"),
                    locator.value(&field_path),
                );
            }
        }
        return Err(SiteCompileError::from_diagnostic(diagnostic));
    }
    if let Some(asset) = &body.asset {
        let asset = if asset == "sibling" {
            PathBuf::from(oxr.to_string_lossy().strip_suffix(".oxr").ok_or_else(|| {
                locator.error(
                    "site.asset_path",
                    "response.body.asset",
                    "invalid sibling OXR path",
                )
            })?)
        } else {
            let relative = Path::new(asset);
            if relative.is_absolute() {
                return Err(locator.error(
                    "site.asset_path",
                    "response.body.asset",
                    "OXR asset path must be relative",
                ));
            }
            oxr.parent().unwrap_or(root).join(relative)
        };
        track_site_dependency(dependencies, &asset, root);
        let asset = asset.canonicalize().map_err(|error| {
            locator.error(
                "site.asset_missing",
                "response.body.asset",
                format!("cannot access backing asset `{}`: {error}", asset.display()),
            )
        })?;
        if !path_is_within(&asset, root) || has_source_extension(&asset) {
            return Err(locator.error(
                "site.asset_path",
                "response.body.asset",
                "OXR backing asset escapes the root or references source",
            ));
        }
        dependencies.push(asset.clone());
        return Ok((
            SiteResponseKind::Asset(Box::new(compile_asset(index, &asset, manifest)?)),
            Some(asset),
        ));
    }
    if let Some(template) = &body.template {
        return match template {
            TemplateReferenceSource::Inline(kind) if kind == "inline" => {
                if inline_body.is_empty() {
                    return Err(locator.error(
                        "template.inline_empty",
                        "response.body.template",
                        "inline template body is empty",
                    ));
                }
                let name = format!(
                    "@inline/{}",
                    oxr.strip_prefix(root).unwrap_or(oxr).to_string_lossy()
                );
                let template = CompiledOxt::inline_with_output(
                    name.clone(),
                    oxr,
                    inline_body,
                    inline_origin,
                    manifest.templates.default_output,
                    manifest.templates.default_autoescape,
                )?;
                templates.insert(name.clone(), template);
                Ok((
                    SiteResponseKind::Template {
                        name,
                        arguments: BTreeMap::new(),
                    },
                    None,
                ))
            }
            TemplateReferenceSource::Inline(kind) => Err(locator.error(
                "template.reference",
                "response.body.template",
                format!("unknown template mode `{kind}`"),
            )),
            TemplateReferenceSource::External(external) => {
                let name = normalize_template_name(&external.source).map_err(|error| {
                    locator.error(
                        "template.reference",
                        "response.body.template.source",
                        error.to_string(),
                    )
                })?;
                track_site_dependency(dependencies, &root.join(&name), root);
                let template = templates.get(&name).ok_or_else(|| {
                    locator.error(
                        "template.missing",
                        "response.body.template.source",
                        format!("template `{name}` does not exist"),
                    )
                })?;
                let arguments = external
                    .arguments
                    .iter()
                    .map(|(name, value)| {
                        let field_path = field_path_child("response.body.template.with", name);
                        Ok((name.clone(), compile_value(value, locator, &field_path)?))
                    })
                    .collect::<Result<BTreeMap<_, _>, SiteCompileError>>()?;
                let argument_spans = external
                    .arguments
                    .keys()
                    .map(|name| {
                        let field_path = field_path_child("response.body.template.with", name);
                        (name.clone(), locator.value(&field_path))
                    })
                    .collect();
                template.validate_arguments_at(
                    &arguments,
                    locator.value("response.body.template.source"),
                    &argument_spans,
                )?;
                Ok((SiteResponseKind::Template { name, arguments }, None))
            }
        };
    }
    if let Some(json) = &body.json {
        return Ok((
            SiteResponseKind::Json(compile_value(json, locator, "response.body.json")?),
            None,
        ));
    }
    if let Some(text) = &body.text {
        return Ok((
            SiteResponseKind::Text(CompiledTemplate::compile(text).map_err(|error| {
                locator.error(
                    "template.expression",
                    "response.body.text",
                    error.to_string(),
                )
            })?),
            None,
        ));
    }
    Ok((SiteResponseKind::Empty, None))
}

fn compile_value(
    source: &serde_yaml_ng::Value,
    locator: SourceLocator<'_>,
    field_path: &str,
) -> Result<CompiledValue, SiteCompileError> {
    match source {
        serde_yaml_ng::Value::Mapping(values) if values.len() == 1 => {
            let expression_key = serde_yaml_ng::Value::String("$expr".to_owned());
            if let Some(serde_yaml_ng::Value::String(expression)) = values.get(&expression_key) {
                return Expression::compile(expression)
                    .map(CompiledValue::Expression)
                    .map_err(|error| {
                        locator.error(
                            "site.expression",
                            &format!("{field_path}.$expr"),
                            error.to_string(),
                        )
                    });
            }
            compile_value_mapping(values, locator, field_path)
        }
        serde_yaml_ng::Value::Mapping(values) => compile_value_mapping(values, locator, field_path),
        serde_yaml_ng::Value::Sequence(values) => values
            .iter()
            .enumerate()
            .map(|(index, value)| compile_value(value, locator, &format!("{field_path}[{index}]")))
            .collect::<Result<Vec<_>, _>>()
            .map(CompiledValue::List),
        serde_yaml_ng::Value::String(value) if value.contains("{{") => {
            CompiledTemplate::compile(value)
                .map(CompiledValue::Template)
                .map_err(|error| locator.error("site.expression", field_path, error.to_string()))
        }
        value => compile_constant(value, locator, field_path).map(CompiledValue::Constant),
    }
}

fn compile_value_mapping(
    values: &serde_yaml_ng::Mapping,
    locator: SourceLocator<'_>,
    field_path: &str,
) -> Result<CompiledValue, SiteCompileError> {
    values
        .iter()
        .map(|(key, value)| {
            let serde_yaml_ng::Value::String(key) = key else {
                return Err(locator.error(
                    "site.value_key",
                    field_path,
                    "map keys must be strings",
                ));
            };
            let child_path = field_path_child(field_path, key);
            Ok((key.clone(), compile_value(value, locator, &child_path)?))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()
        .map(CompiledValue::Map)
}

fn compile_constant(
    source: &serde_yaml_ng::Value,
    locator: SourceLocator<'_>,
    field_path: &str,
) -> Result<Value, SiteCompileError> {
    match source {
        serde_yaml_ng::Value::Null => Ok(Value::Null),
        serde_yaml_ng::Value::Bool(value) => Ok(Value::Bool(*value)),
        serde_yaml_ng::Value::Number(value) => value
            .as_i64()
            .map(Value::Integer)
            .or_else(|| value.as_f64().map(Value::Float))
            .ok_or_else(|| {
                locator.error(
                    "site.value_range",
                    field_path,
                    "number is outside the supported range",
                )
            }),
        serde_yaml_ng::Value::String(value) => Ok(Value::String(value.clone())),
        serde_yaml_ng::Value::Sequence(values) => values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                compile_constant(value, locator, &format!("{field_path}[{index}]"))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Value::List),
        serde_yaml_ng::Value::Mapping(values) => values
            .iter()
            .map(|(key, value)| {
                let serde_yaml_ng::Value::String(key) = key else {
                    return Err(locator.error(
                        "site.value_key",
                        field_path,
                        "map keys must be strings",
                    ));
                };
                let child_path = field_path_child(field_path, key);
                Ok((key.clone(), compile_constant(value, locator, &child_path)?))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()
            .map(Value::Map),
        serde_yaml_ng::Value::Tagged(_) => {
            Err(locator.error("site.value_tag", field_path, "YAML tags are not supported"))
        }
    }
}

fn compile_response_policy(
    source: &ResponsePolicySource,
    locator: SourceLocator<'_>,
    field_path: &str,
) -> Result<HeaderPlan, SiteCompileError> {
    let mut headers = compile_headers(
        &source.headers,
        locator.path,
        &format!("{field_path}.headers"),
        locator.spans,
    )?;
    if let Some(cache) = &source.cache {
        let mut directives = Vec::new();
        if let Some(visibility) = &cache.visibility {
            directives.push(visibility.replace('_', "-"));
        }
        if let Some(max_age) = &cache.max_age {
            directives.push(format!(
                "max-age={}",
                parse_seconds(max_age).map_err(|message| {
                    locator.error(
                        "site.cache_max_age",
                        &format!("{field_path}.cache.max_age"),
                        message,
                    )
                })?
            ));
        }
        if cache.immutable {
            directives.push("immutable".to_owned());
        }
        if !directives.is_empty() {
            let layer = headers
                .layers
                .last_mut()
                .expect("compiled header policy always has one layer");
            layer.set.push((
                HeaderName::from_static("cache-control"),
                CompiledTemplate::compile(directives.join(", ")).map_err(|error| {
                    locator.error(
                        "site.cache_policy",
                        &format!("{field_path}.cache"),
                        error.to_string(),
                    )
                })?,
            ));
        }
    }
    Ok(headers)
}

fn compile_headers(
    source: &HeadersSource,
    path: &Path,
    field_path: &str,
    spans: Option<&FieldSpanIndex>,
) -> Result<HeaderPlan, SiteCompileError> {
    Ok(HeaderPlan {
        layers: vec![HeaderPolicyLayer {
            set: compile_header_map(&source.set, path, &format!("{field_path}.set"), spans)?,
            add: compile_header_map(&source.add, path, &format!("{field_path}.add"), spans)?,
            remove: source
                .remove
                .iter()
                .enumerate()
                .map(|(index, name)| {
                    compile_user_header_name(
                        name,
                        path,
                        &format!("{field_path}.remove[{index}]"),
                        spans,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?,
        }],
    })
}

fn compile_resource_base_policy(
    logical_relative_path: &Path,
    manifest: &ManifestSource,
    manifest_locator: SourceLocator<'_>,
) -> Result<HeaderPlan, SiteCompileError> {
    let mut headers = compile_response_policy(
        &manifest.defaults.response,
        manifest_locator,
        "defaults.response",
    )?;
    if let Some(extension) = logical_relative_path
        .extension()
        .map(|extension| format!(".{}", extension.to_string_lossy()))
        && let Some(policy) = manifest.defaults.by_extension.get(&extension)
    {
        headers.merge(compile_response_policy(
            policy,
            manifest_locator,
            &field_path_child("defaults.by_extension", &extension),
        )?);
    }
    Ok(headers)
}

fn compile_header_map(
    source: &BTreeMap<String, String>,
    path: &Path,
    field_path: &str,
    spans: Option<&FieldSpanIndex>,
) -> Result<Vec<(HeaderName, CompiledTemplate)>, SiteCompileError> {
    source
        .iter()
        .map(|(name, value)| {
            let header_path = field_path_child(field_path, name);
            let name = compile_user_header_name(name, path, &header_path, spans)?;
            let template = CompiledTemplate::compile(value).map_err(|error| {
                site_source_error(
                    "site.header_value",
                    path,
                    &header_path,
                    spans,
                    error.to_string(),
                )
            })?;
            if template.is_constant() {
                let rendered = template
                    .render(&oxidase_core::EvalContext::default())
                    .map_err(|error| {
                        site_source_error(
                            "site.header_value",
                            path,
                            &header_path,
                            spans,
                            error.to_string(),
                        )
                    })?;
                HeaderValue::from_str(&rendered).map_err(|_| {
                    site_source_error(
                        "site.header_value",
                        path,
                        &header_path,
                        spans,
                        format!("header `{name}` has an invalid constant value"),
                    )
                })?;
            }
            Ok((name, template))
        })
        .collect()
}

fn compile_user_header_name(
    source: &str,
    path: &Path,
    field_path: &str,
    spans: Option<&FieldSpanIndex>,
) -> Result<HeaderName, SiteCompileError> {
    let name = HeaderName::from_str(source).map_err(|error| {
        site_source_key_error(
            "site.header_name",
            path,
            field_path,
            spans,
            format!("invalid header name `{source}`: {error}"),
        )
    })?;
    if is_forbidden_user_header(&name) {
        return Err(site_source_key_error(
            "site.forbidden_header",
            path,
            field_path,
            spans,
            format!("header `{name}` is managed by the HTTP response finalizer"),
        ));
    }
    Ok(name)
}

fn site_source_error(
    code: &'static str,
    path: &Path,
    field_path: &str,
    spans: Option<&FieldSpanIndex>,
    message: impl Into<String>,
) -> SiteCompileError {
    site_source_error_at(code, path, field_path, spans, false, message)
}

fn site_source_key_error(
    code: &'static str,
    path: &Path,
    field_path: &str,
    spans: Option<&FieldSpanIndex>,
    message: impl Into<String>,
) -> SiteCompileError {
    site_source_error_at(code, path, field_path, spans, true, message)
}

fn site_source_error_at(
    code: &'static str,
    path: &Path,
    field_path: &str,
    spans: Option<&FieldSpanIndex>,
    use_key: bool,
    message: impl Into<String>,
) -> SiteCompileError {
    let message = message.into();
    let Some(source) = spans.and_then(|spans| spans.nearest(field_path)) else {
        return SiteCompileError::at(
            code,
            SourceLocator::new(path, spans).value(field_path),
            format!("{field_path}: {message}"),
        );
    };
    let source = if use_key { &source.key } else { &source.value };
    SiteCompileError::at(
        code,
        SourceSpan {
            file: path.to_path_buf(),
            start_byte: source.start_byte,
            end_byte: source.end_byte,
            line: source.start_line,
            column: source.start_column,
            end_line: source.end_line,
            end_column: source.end_column,
            field_path: field_path.to_owned(),
        },
        format!("{field_path}: {message}"),
    )
}

fn compile_asset(
    index: &SiteSourceIndex,
    path: &Path,
    source: &ManifestSource,
) -> Result<AssetPlan, SiteCompileError> {
    let extension = path
        .extension()
        .map(|extension| format!(".{}", extension.to_string_lossy()));
    let content_type = extension
        .as_ref()
        .and_then(|extension| source.assets.mime_overrides.get(extension))
        .cloned()
        .unwrap_or_else(|| {
            mime_guess::from_path(path)
                .first_or_octet_stream()
                .to_string()
        });
    Ok(AssetPlan {
        identity: compile_representation(index, path, None, source)?,
        brotli: compressed_representation(
            index,
            path,
            source.assets.precompressed.brotli.as_deref(),
            ContentEncoding::Brotli,
            source,
        )?,
        gzip: compressed_representation(
            index,
            path,
            source.assets.precompressed.gzip.as_deref(),
            ContentEncoding::Gzip,
            source,
        )?,
        content_type,
        range_requests: source.assets.range_requests,
    })
}

fn compile_representation(
    index: &SiteSourceIndex,
    path: &Path,
    encoding: Option<ContentEncoding>,
    source: &ManifestSource,
) -> Result<AssetRepresentation, SiteCompileError> {
    let entry = index.entry(path)?;
    let etag = match source.assets.etag {
        EtagSource::None => None,
        EtagSource::Weak | EtagSource::Strong => Some(EntityTag::new(
            matches!(source.assets.etag, EtagSource::Weak),
            format!("sha256-{}", entry.digest),
        )),
    };
    Ok(AssetRepresentation {
        encoding,
        source: AssetSource::File(path.to_path_buf()),
        length: entry.length,
        digest: entry.digest,
        etag,
        modified: source
            .assets
            .last_modified
            .then_some(entry.modified)
            .flatten(),
    })
}

fn compressed_representation(
    index: &SiteSourceIndex,
    path: &Path,
    suffix: Option<&str>,
    encoding: ContentEncoding,
    source: &ManifestSource,
) -> Result<Option<AssetRepresentation>, SiteCompileError> {
    let Some(suffix) = suffix else {
        return Ok(None);
    };
    let candidate = PathBuf::from(format!("{}{}", path.to_string_lossy(), suffix));
    if index.entries.contains_key(&candidate) {
        compile_representation(index, &candidate, Some(encoding), source).map(Some)
    } else if index.directories.contains(&candidate) {
        Err(SiteCompileError::source(
            candidate,
            "precompressed asset is not a regular file",
        ))
    } else {
        Ok(None)
    }
}

fn precompressed_paths(files: &[PathBuf], source: &ManifestSource) -> BTreeSet<PathBuf> {
    let suffixes = [
        source.assets.precompressed.brotli.as_deref(),
        source.assets.precompressed.gzip.as_deref(),
    ];
    files
        .iter()
        .filter(|path| {
            suffixes
                .iter()
                .flatten()
                .any(|suffix| path.to_string_lossy().ends_with(suffix))
        })
        .cloned()
        .collect()
}

fn insert_with_index_aliases(
    entries: &mut BTreeMap<String, SiteResponsePlan>,
    logical: String,
    plan: SiteResponsePlan,
    source: &ManifestSource,
) -> Result<(), SiteCompileError> {
    let file_name = logical.rsplit('/').next().unwrap_or("");
    let is_index = source.paths.indexes.iter().any(|index| index == file_name);
    if !is_index {
        return insert_entry(entries, logical, plan);
    }
    let directory = logical.strip_suffix(file_name).unwrap_or("/").to_owned();
    match source.paths.index_canonical {
        IndexCanonicalSource::Directory => {
            insert_entry(entries, directory.clone(), plan.clone())?;
            insert_entry(
                entries,
                logical,
                redirect_plan(&directory, &plan.source, StatusCode::PERMANENT_REDIRECT)?,
            )
        }
        IndexCanonicalSource::File => {
            insert_entry(entries, logical.clone(), plan.clone())?;
            insert_entry(
                entries,
                directory,
                redirect_plan(&logical, &plan.source, StatusCode::PERMANENT_REDIRECT)?,
            )
        }
    }
}

fn redirect_plan(
    location: &str,
    source: &Path,
    status: StatusCode,
) -> Result<SiteResponsePlan, SiteCompileError> {
    Ok(SiteResponsePlan {
        status,
        headers: HeaderPlan::default(),
        content_type: None,
        page: BTreeMap::new(),
        kind: SiteResponseKind::Redirect {
            status,
            location: CompiledTemplate::compile(location)
                .map_err(|error| SiteCompileError::source(source, error.to_string()))?,
            query: RedirectQuery::Preserve,
        },
        source: source.to_path_buf(),
    })
}

fn insert_entry(
    entries: &mut BTreeMap<String, SiteResponsePlan>,
    logical: String,
    plan: SiteResponsePlan,
) -> Result<(), SiteCompileError> {
    if let Some(previous) = entries.get(&logical) {
        return Err(SiteCompileError::DuplicatePath {
            logical_path: logical,
            first: previous.source.clone(),
            second: plan.source,
        });
    }
    entries.insert(logical, plan);
    Ok(())
}

fn is_private(
    relative: &Path,
    source: &ManifestSource,
    template_roots: &[PathBuf],
    site_root: &Path,
    deny_patterns: &[DenyPattern],
) -> bool {
    if template_roots
        .iter()
        .filter_map(|root| root.strip_prefix(site_root).ok())
        .any(|root| relative.starts_with(root))
    {
        return true;
    }
    denied_by_visibility(relative, source, deny_patterns, false)
}

fn denied_by_visibility(
    relative: &Path,
    source: &ManifestSource,
    deny_patterns: &[DenyPattern],
    is_directory: bool,
) -> bool {
    let components = relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy()),
            _ => None,
        })
        .collect::<Vec<_>>();
    if source.visibility.dotfiles != VisibilityModeSource::Allow
        && components
            .iter()
            .any(|component| component.starts_with('.'))
    {
        return true;
    }
    if source.visibility.underscore_directories != VisibilityModeSource::Allow
        && components
            .iter()
            .take(if is_directory {
                components.len()
            } else {
                components.len().saturating_sub(1)
            })
            .any(|component| component.starts_with('_'))
    {
        return true;
    }
    deny_patterns
        .iter()
        .any(|pattern| pattern.matches(relative))
}

fn logical_path(relative: &Path) -> String {
    format!("/{}", relative.to_string_lossy().replace('\\', "/"))
}

fn has_source_extension(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("oxsite" | "oxr" | "oxt")
    )
}

fn has_extension(path: &Path, extension: &str) -> bool {
    path.extension().and_then(|value| value.to_str()) == Some(extension)
}

fn split_front_matter<'a>(
    path: &Path,
    source: &'a str,
) -> Result<(&'a str, &'a str), SiteCompileError> {
    let mut offset = 0;
    let mut lines = source.split_inclusive('\n');
    let first = lines
        .next()
        .ok_or_else(|| SiteCompileError::source(path, "source is empty"))?;
    if first.trim_end_matches(['\r', '\n']) != "---" {
        return Err(SiteCompileError::source(
            path,
            "source must start with a `---` front-matter delimiter",
        ));
    }
    offset += first.len();
    let header_start = offset;
    for line in lines {
        if line.trim_end_matches(['\r', '\n']) == "---" {
            let header_end = offset;
            offset += line.len();
            return Ok((&source[header_start..header_end], &source[offset..]));
        }
        offset += line.len();
    }
    Err(SiteCompileError::source(
        path,
        "front matter has no closing `---` delimiter",
    ))
}

fn parse_yaml<T: serde::de::DeserializeOwned>(
    path: &Path,
    source: &str,
    origin: (usize, usize),
    spans: Option<&FieldSpanIndex>,
) -> Result<T, SiteCompileError> {
    oxidase_source::parse(path, source)
        .map_err(|error| strict_yaml_error_with_spans(path, source, origin, spans, error))
}

fn strict_yaml_error(
    path: &Path,
    source: &str,
    origin: (usize, usize),
    error: oxidase_source::StrictYamlError,
) -> SiteCompileError {
    strict_yaml_error_with_spans(path, source, origin, None, error)
}

fn strict_yaml_error_with_spans(
    path: &Path,
    source: &str,
    origin: (usize, usize),
    spans: Option<&FieldSpanIndex>,
    error: oxidase_source::StrictYamlError,
) -> SiteCompileError {
    let physical_line = origin.1 + error.line;
    let field_path = spans
        .and_then(|spans| {
            spans
                .iter()
                .filter_map(|(path, field)| {
                    let ranges = [&field.value, &field.key];
                    ranges
                        .into_iter()
                        .find(|range| {
                            range.start_line <= physical_line
                                && physical_line <= range.end_line
                                && (range.start_line != physical_line
                                    || range.start_column <= error.column)
                                && (range.end_line != physical_line
                                    || error.column <= range.end_column)
                        })
                        .map(|range| (path, range.end_byte.saturating_sub(range.start_byte)))
                })
                .min_by_key(|(_, length)| *length)
                .map(|(path, _)| path)
        })
        .unwrap_or("source");
    let span = point_source_span(path, source, origin, error.line, error.column, "source");
    let mut span = span;
    span.field_path = field_path.to_owned();
    let mut diagnostic = Diagnostic::new(error.code, error.message, span);
    if let Some(help) = error.help {
        diagnostic = diagnostic.with_help(help);
    }
    SiteCompileError::from_diagnostic(diagnostic)
}

fn point_source_span(
    path: &Path,
    source: &str,
    origin: (usize, usize),
    line: usize,
    column: usize,
    field_path: &str,
) -> SourceSpan {
    let line_start = source
        .split_inclusive('\n')
        .take(line.saturating_sub(1))
        .map(str::len)
        .sum::<usize>();
    let line_end = source[line_start..]
        .find('\n')
        .map_or(source.len(), |length| line_start + length);
    let line_text = &source[line_start..line_end];
    let column_byte = line_text
        .char_indices()
        .nth(column.saturating_sub(1))
        .map_or(line_text.len(), |(offset, _)| offset);
    let start = line_start + column_byte;
    let end = source[start..line_end]
        .chars()
        .next()
        .map_or(start, |character| start + character.len_utf8());
    SourceSpan {
        file: path.to_path_buf(),
        start_byte: origin.0 + start,
        end_byte: origin.0 + end,
        line: origin.1 + line,
        column,
        end_line: origin.1 + line,
        end_column: column + usize::from(end > start),
        field_path: field_path.to_owned(),
    }
}

fn parse_duration(source: &str) -> Result<Duration, String> {
    let (value, multiplier) = source
        .strip_suffix("ms")
        .map(|value| (value, 1u64))
        .or_else(|| source.strip_suffix('s').map(|value| (value, 1_000)))
        .ok_or_else(|| format!("invalid duration `{source}`; use `ms` or `s`"))?;
    let value = value
        .parse::<u64>()
        .map_err(|_| format!("invalid duration `{source}`"))?;
    Ok(Duration::from_millis(value.saturating_mul(multiplier)))
}

fn parse_size(source: &str) -> Result<usize, String> {
    let (value, multiplier) = source
        .strip_suffix("MiB")
        .map(|value| (value, 1024usize * 1024))
        .or_else(|| source.strip_suffix("KiB").map(|value| (value, 1024)))
        .or_else(|| source.strip_suffix('B').map(|value| (value, 1)))
        .ok_or_else(|| format!("invalid size `{source}`; use B, KiB, or MiB"))?;
    value
        .parse::<usize>()
        .ok()
        .and_then(|value| value.checked_mul(multiplier))
        .ok_or_else(|| format!("invalid or excessive size `{source}`"))
}

fn parse_seconds(source: &str) -> Result<u64, String> {
    let (value, multiplier) = source
        .strip_suffix('s')
        .map(|value| (value, 1u64))
        .or_else(|| source.strip_suffix('m').map(|value| (value, 60)))
        .or_else(|| source.strip_suffix('h').map(|value| (value, 3_600)))
        .or_else(|| source.strip_suffix('d').map(|value| (value, 86_400)))
        .ok_or_else(|| format!("invalid cache duration `{source}`"))?;
    value
        .parse::<u64>()
        .ok()
        .and_then(|value| value.checked_mul(multiplier))
        .ok_or_else(|| format!("invalid cache duration `{source}`"))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use http::{HeaderMap, Method, StatusCode};
    use oxidase_core::{RequestFrame, RequestMetadata, ResourceId, Value};
    use tempfile::tempdir;

    use super::{SiteCompiler, SiteSourceKind, compile_deny_pattern};
    use crate::{PreparedSiteBody, SiteError, TemplateArgumentError};

    fn write_site() -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempdir().expect("temporary site directory is available");
        let root = directory.path().join("site");
        fs::create_dir_all(root.join("_templates")).expect("template directory can be created");
        fs::write(
            root.join("site.oxsite"),
            r#"oxista: site/v1
paths:
  missing: decline
visibility:
  dotfiles: deny
  underscore_directories: private
  symlinks: within_root
templates:
  roots:
    - _templates
inputs:
  canonical_origin:
    type: url
    required: true
data:
  title: Example
"#,
        )
        .expect("manifest can be written");
        fs::write(root.join("about.html"), "about asset").expect("asset can be written");
        fs::write(
            root.join("about.html.oxr"),
            r#"---
oxista: response/v1
response:
  headers:
    set:
      X-Page-Version: "2"
  body:
    asset: sibling
---
"#,
        )
        .expect("OXR can be written");
        fs::write(
            root.join("feed.json.oxr"),
            r#"---
oxista: response/v1
response:
  body:
    json:
      ok: true
      path: "{{ request.path }}"
---
"#,
        )
        .expect("JSON OXR can be written");
        fs::write(
            root.join("_templates/home.oxt"),
            r#"---
oxista: template/v1
output: html
autoescape: html
params:
  greeting: string
---
<h1>{{ greeting }} {{ site.title }}</h1>
"#,
        )
        .expect("OXT can be written");
        fs::write(
            root.join("index.html.oxr"),
            r#"---
oxista: response/v1
response:
  body:
    template:
      source: _templates/home.oxt
      with:
        greeting: "<Hello>"
---
"#,
        )
        .expect("index OXR can be written");
        fs::write(root.join("secret.key"), "private").expect("private fixture can be written");
        (directory, root)
    }

    fn request(path: &str) -> RequestFrame {
        RequestFrame::new(
            RequestMetadata::try_new(Method::GET, "http", "example.com", path, HeaderMap::new())
                .expect("valid fixture request metadata"),
        )
    }

    #[test]
    fn compiles_assets_oxr_templates_and_private_boundaries() {
        let (_directory, root) = write_site();
        let snapshot = SiteCompiler::compile(
            ResourceId::new("site:web"),
            &root,
            root.join("site.oxsite"),
            BTreeMap::from([(
                "canonical_origin".to_owned(),
                Value::from("https://example.com"),
            )]),
        )
        .expect("site compiles");
        let paths = snapshot.public_paths().collect::<Vec<_>>();
        assert!(paths.contains(&"/"));
        assert!(paths.contains(&"/about.html"));
        assert!(!paths.contains(&"/about.html.oxr"));
        assert!(!paths.contains(&"/secret.key"));
        assert!(!paths.iter().any(|path| path.contains("_templates")));

        let about = snapshot
            .execute(&request("/about.html"))
            .expect("site executes")
            .expect("about is handled");
        assert_eq!(about.headers["x-page-version"], "2");
        assert!(matches!(about.body, PreparedSiteBody::Asset(_)));

        let home = snapshot
            .execute(&request("/"))
            .expect("site executes")
            .expect("home is handled");
        let PreparedSiteBody::Bytes(home) = home.body else {
            panic!("home is rendered bytes");
        };
        assert_eq!(
            String::from_utf8_lossy(&home).trim(),
            "<h1>&lt;Hello&gt; Example</h1>"
        );
    }

    #[test]
    fn missing_declines_and_json_is_structured() {
        let (_directory, root) = write_site();
        let snapshot = SiteCompiler::compile(
            ResourceId::new("site:web"),
            &root,
            root.join("site.oxsite"),
            BTreeMap::from([(
                "canonical_origin".to_owned(),
                Value::from("https://example.com"),
            )]),
        )
        .expect("site compiles");
        assert!(
            snapshot
                .execute(&request("/missing"))
                .expect("lookup succeeds")
                .is_none()
        );
        let feed = snapshot
            .execute(&request("/feed.json"))
            .expect("site executes")
            .expect("feed is handled");
        assert_eq!(feed.status, StatusCode::OK);
        let PreparedSiteBody::Bytes(body) = feed.body else {
            panic!("JSON is rendered bytes");
        };
        let json: serde_json::Value = serde_json::from_slice(&body).expect("valid JSON");
        assert_eq!(json["path"], "/feed.json");
    }

    #[test]
    fn failed_compilation_retains_scanned_and_missing_dependencies() {
        let directory = tempdir().expect("temporary site directory is available");
        let root = directory.path().join("site");
        let templates = root.join("_templates");
        fs::create_dir_all(&templates).expect("template directory can be created");
        let manifest = root.join("site.oxsite");
        fs::write(
            &manifest,
            "oxista: site/v1\ntemplates:\n  roots: [_templates]\n",
        )
        .expect("manifest can be written");
        let invalid_template = templates.join("invalid.oxt");
        fs::write(&invalid_template, "not front matter").expect("invalid OXT can be written");
        let canonical_root = root.canonicalize().expect("site root canonicalizes");
        let canonical_templates = canonical_root.join("_templates");

        let failure = SiteCompiler::compile(
            ResourceId::new("site:web"),
            &root,
            &manifest,
            BTreeMap::new(),
        )
        .expect_err("invalid OXT rejects the candidate");
        assert!(
            failure
                .discovered_dependencies
                .contains(&invalid_template.canonicalize().expect("OXT canonicalizes"))
        );
        assert!(
            failure
                .discovered_dependencies
                .contains(&canonical_templates)
        );

        fs::remove_file(&invalid_template).expect("invalid OXT can be removed");
        let oxr = root.join("index.html.oxr");
        fs::write(
            &oxr,
            r#"---
oxista: response/v1
response:
  body:
    template:
      source: _templates/missing.oxt
---
"#,
        )
        .expect("OXR can be written");
        let missing = canonical_templates.join("missing.oxt");
        let failure = SiteCompiler::compile(
            ResourceId::new("site:web"),
            &root,
            &manifest,
            BTreeMap::new(),
        )
        .expect_err("missing external template rejects the candidate");
        assert!(
            failure
                .discovered_dependencies
                .contains(&oxr.canonicalize().expect("OXR canonicalizes"))
        );
        assert!(failure.discovered_dependencies.contains(&missing));
        assert!(
            failure
                .discovered_dependencies
                .contains(&canonical_templates)
        );
    }

    #[test]
    fn preserves_header_layers_and_applies_logical_extension_defaults() {
        let directory = tempdir().expect("temporary site directory is available");
        let root = directory.path().join("site");
        fs::create_dir(&root).expect("site directory can be created");
        fs::write(
            root.join("site.oxsite"),
            r#"oxista: site/v1
assets:
  precompressed:
    brotli: .br
    gzip: .gz
defaults:
  response:
    headers:
      set:
        X-Policy: global
        X-Override: global
  by_extension:
    ".css":
      cache:
        visibility: public
        max_age: 1h
      headers:
        set:
          X-Asset: css
          X-Override: extension
    ".html":
      headers:
        set:
          X-Html: applied
    ".txt":
      headers:
        set:
          X-Extension: present
          X-Override: extension
profiles:
  remove_policy:
    headers:
      remove: [X-Policy]
      add:
        Set-Cookie: profile=one
  first:
    headers:
      set:
        X-Profile: first
  second:
    headers:
      set:
        X-Profile: second
"#,
        )
        .expect("manifest can be written");
        fs::write(root.join("style.css"), "identity").expect("CSS can be written");
        fs::write(root.join("style.css.br"), "brotli").expect("Brotli can be written");
        fs::write(root.join("style.css.gz"), "gzip").expect("gzip can be written");
        fs::write(root.join("page.html"), "html").expect("HTML can be written");
        fs::write(root.join("plain.bin"), "bin").expect("binary can be written");
        fs::write(root.join("theme.css"), "theme").expect("sibling CSS can be written");
        fs::write(
            root.join("theme.css.oxr"),
            r#"---
oxista: response/v1
response:
  headers:
    set:
      X-Asset: local
  body:
    asset: sibling
---
"#,
        )
        .expect("CSS OXR can be written");
        fs::write(
            root.join("policy.txt.oxr"),
            r#"---
oxista: response/v1
apply: [remove_policy, first, second]
response:
  headers:
    remove: [X-Extension]
    set:
      X-Combined: base
    add:
      X-Combined: extra
      Set-Cookie: local=two
  body:
    text: policy
---
"#,
        )
        .expect("policy OXR can be written");

        let snapshot = SiteCompiler::compile(
            ResourceId::new("site:web"),
            &root,
            root.join("site.oxsite"),
            BTreeMap::new(),
        )
        .expect("site compiles");

        let css = snapshot
            .execute(&request("/style.css"))
            .expect("CSS executes")
            .expect("CSS is handled");
        assert_eq!(css.headers["cache-control"], "public, max-age=3600");
        assert_eq!(css.headers["x-asset"], "css");
        assert_eq!(css.headers["x-override"], "extension");
        let PreparedSiteBody::Asset(asset) = css.body else {
            panic!("CSS uses the asset fast path");
        };
        assert!(asset.brotli.is_some());
        assert!(asset.gzip.is_some());

        let html = snapshot
            .execute(&request("/page.html"))
            .expect("HTML executes")
            .expect("HTML is handled");
        assert_eq!(html.headers["x-html"], "applied");
        let plain = snapshot
            .execute(&request("/plain.bin"))
            .expect("binary executes")
            .expect("binary is handled");
        assert!(!plain.headers.contains_key("cache-control"));
        assert!(!plain.headers.contains_key("x-asset"));

        let theme = snapshot
            .execute(&request("/theme.css"))
            .expect("OXR CSS executes")
            .expect("OXR CSS is handled");
        assert_eq!(theme.headers["cache-control"], "public, max-age=3600");
        assert_eq!(theme.headers["x-asset"], "local");

        let policy = snapshot
            .execute(&request("/policy.txt"))
            .expect("policy executes")
            .expect("policy is handled");
        assert!(!policy.headers.contains_key("x-policy"));
        assert!(!policy.headers.contains_key("x-extension"));
        assert_eq!(policy.headers["x-override"], "extension");
        assert_eq!(policy.headers["x-profile"], "second");
        assert_eq!(
            policy
                .headers
                .get_all("x-combined")
                .iter()
                .map(|value| value.to_str().expect("header is text"))
                .collect::<Vec<_>>(),
            ["base", "extra"]
        );
        assert_eq!(
            policy
                .headers
                .get_all("set-cookie")
                .iter()
                .map(|value| value.to_str().expect("cookie is text"))
                .collect::<Vec<_>>(),
            ["profile=one", "local=two"]
        );
    }

    #[test]
    fn visibility_deny_matches_exact_components_extensions_and_subtrees() {
        let directory = tempdir().expect("temporary site directory is available");
        let root = directory.path().join("site");
        for directory in ["foo/secret", "a/b", "private-dir"] {
            fs::create_dir_all(root.join(directory)).expect("fixture directory can be created");
        }
        fs::write(
            root.join("site.oxsite"),
            r#"oxista: site/v1
visibility:
  deny:
    - "**/secret"
    - "**/*.pem"
    - exact-file.txt
    - private-dir
"#,
        )
        .expect("manifest can be written");
        for path in [
            "foo/mysecret",
            "foo/secret/key.txt",
            "secret",
            "foo/secret.txt",
            "key.pem",
            "a/b/key.pem",
            "key.pem.bak",
            "notpem",
            "exact-file.txt",
            "private-dir/child.txt",
        ] {
            fs::write(root.join(path), path).expect("fixture file can be written");
        }
        let snapshot = SiteCompiler::compile(
            ResourceId::new("site:web"),
            &root,
            root.join("site.oxsite"),
            BTreeMap::new(),
        )
        .expect("site compiles");
        let paths = snapshot.public_paths().collect::<Vec<_>>();
        for allowed in [
            "/foo/mysecret",
            "/foo/secret.txt",
            "/key.pem.bak",
            "/notpem",
        ] {
            assert!(paths.contains(&allowed), "{allowed} should remain public");
        }
        for denied in [
            "/foo/secret/key.txt",
            "/secret",
            "/key.pem",
            "/a/b/key.pem",
            "/exact-file.txt",
            "/private-dir/child.txt",
        ] {
            assert!(!paths.contains(&denied), "{denied} should be denied");
        }
        let component = compile_deny_pattern("**/secret").expect("pattern compiles");
        assert!(component.matches(std::path::Path::new("foo/secret/key")));
        assert!(!component.matches(std::path::Path::new("foo/Secret/key")));

        for pattern in [
            "/absolute",
            "../escape",
            "empty//component",
            "back\\slash",
            "**/nested/name",
            "assets/*.pem",
        ] {
            fs::write(
                root.join("site.oxsite"),
                format!("oxista: site/v1\nvisibility:\n  deny:\n    - '{pattern}'\n"),
            )
            .expect("invalid manifest can be written");
            let failure = SiteCompiler::compile(
                ResourceId::new("site:web"),
                &root,
                root.join("site.oxsite"),
                BTreeMap::new(),
            )
            .expect_err("invalid deny pattern must fail");
            assert!(
                failure.to_string().contains("visibility.deny[0]"),
                "{failure}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn pruned_private_directories_still_validate_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().expect("temporary site directory is available");
        let root = directory.path().join("site");
        fs::create_dir_all(root.join("private")).expect("private directory can be created");
        fs::write(
            root.join("site.oxsite"),
            "oxista: site/v1\nvisibility:\n  deny: [private]\n",
        )
        .expect("manifest can be written");
        symlink("/etc/passwd", root.join("private/escape"))
            .expect("escaping symlink can be created");
        let failure = SiteCompiler::compile(
            ResourceId::new("site:web"),
            &root,
            root.join("site.oxsite"),
            BTreeMap::new(),
        )
        .expect_err("private subtree symlink escape must still fail");
        assert!(failure.to_string().contains("symlink"), "{failure}");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let (_directory, root) = write_site();
        symlink("/etc/passwd", root.join("escape.txt")).expect("symlink can be created");
        let result = SiteCompiler::compile(
            ResourceId::new("site:web"),
            &root,
            root.join("site.oxsite"),
            BTreeMap::from([(
                "canonical_origin".to_owned(),
                Value::from("https://example.com"),
            )]),
        );
        assert!(result.is_err());
    }

    #[test]
    fn rejects_managed_headers_in_oxista_policies_and_oxr() {
        let cases = [
            (
                r#"oxista: site/v1
defaults:
  response:
    headers:
      set:
        Connection: close
"#,
                None,
                "defaults.response.headers.set.Connection",
            ),
            (
                r#"oxista: site/v1
profiles:
  cached:
    headers:
      add:
        Transfer-Encoding: chunked
"#,
                Some(
                    r#"---
oxista: response/v1
apply: [cached]
response:
  body:
    text: body
---
"#,
                ),
                "profiles.cached.headers.add[\"Transfer-Encoding\"]",
            ),
            (
                "oxista: site/v1\n",
                Some(
                    r#"---
oxista: response/v1
response:
  headers:
    remove:
      - Content-Length
  body:
    text: body
---
"#,
                ),
                "response.headers.remove[0]",
            ),
            (
                r#"oxista: site/v1
defaults:
  by_extension:
    ".css":
      headers:
        set:
          Upgrade: websocket
"#,
                None,
                "defaults.by_extension[\".css\"].headers.set.Upgrade",
            ),
        ];

        for (manifest, oxr, expected_path) in cases {
            let directory = tempdir().expect("temporary site directory is available");
            let root = directory.path().join("site");
            fs::create_dir(&root).expect("site directory can be created");
            fs::write(root.join("site.oxsite"), manifest).expect("manifest can be written");
            if let Some(oxr) = oxr {
                fs::write(root.join("index.html.oxr"), oxr).expect("OXR can be written");
            } else {
                fs::write(root.join("index.html"), "asset").expect("asset can be written");
            }

            let error = SiteCompiler::compile(
                ResourceId::new("site:web"),
                &root,
                root.join("site.oxsite"),
                BTreeMap::new(),
            )
            .expect_err("managed header must be rejected");
            let message = error.to_string();
            assert!(message.contains(expected_path), "{message}");
            assert!(message.contains("response finalizer"), "{message}");
        }
    }

    #[test]
    fn reports_oxr_header_errors_at_the_front_matter_field() {
        let directory = tempdir().expect("temporary site directory is available");
        let root = directory.path().join("site");
        fs::create_dir(&root).expect("site directory can be created");
        fs::write(root.join("site.oxsite"), "oxista: site/v1\n").expect("manifest can be written");
        fs::write(
            root.join("index.html.oxr"),
            r#"---
oxista: response/v1
response:
  headers:
    set:
      Connection: close
  body:
    text: body
---
"#,
        )
        .expect("OXR can be written");

        let error = SiteCompiler::compile(
            ResourceId::new("site:web"),
            &root,
            root.join("site.oxsite"),
            BTreeMap::new(),
        )
        .expect_err("managed header must be rejected");
        let diagnostic = &error.diagnostics[0];
        assert_eq!(diagnostic.code, "site.forbidden_header");
        assert_eq!((diagnostic.primary.line, diagnostic.primary.column), (6, 7));
        assert_eq!(
            diagnostic.primary.field_path,
            "response.headers.set.Connection"
        );
        assert!(diagnostic.primary.end_byte > diagnostic.primary.start_byte);
    }

    #[test]
    fn rejects_inert_or_unsupported_oxista_v1_fields() {
        let manifest_cases = [
            (
                "oxista: site/v1\npaths:\n  trailing_slash: preserve\n",
                "paths.trailing_slash",
            ),
            (
                "oxista: site/v1\ntemplates:\n  default_output: json\n",
                "templates.default_output",
            ),
            (
                "oxista: site/v1\nerrors:\n  500:\n    template: error.oxt\n",
                "errors.500",
            ),
            (
                "oxista: site/v1\nvisibility:\n  deny:\n    - assets/*.pem\n",
                "visibility.deny[0]",
            ),
        ];
        for (manifest, expected) in manifest_cases {
            let directory = tempdir().expect("temporary site directory is available");
            let root = directory.path().join("site");
            fs::create_dir(&root).expect("site directory can be created");
            fs::write(root.join("site.oxsite"), manifest).expect("manifest can be written");
            fs::write(root.join("index.html"), "asset").expect("asset can be written");
            let error = SiteCompiler::compile(
                ResourceId::new("site:web"),
                &root,
                root.join("site.oxsite"),
                BTreeMap::new(),
            )
            .expect_err("unsupported field value must fail");
            assert!(error.to_string().contains(expected), "{error}");
        }

        let directory = tempdir().expect("temporary site directory is available");
        let root = directory.path().join("site");
        fs::create_dir(&root).expect("site directory can be created");
        fs::write(root.join("site.oxsite"), "oxista: site/v1\n").expect("manifest can be written");
        fs::write(
            root.join("redirect.oxr"),
            r#"---
oxista: response/v1
response:
  redirect:
    status: 308
    location: /target
    query: replace
---
"#,
        )
        .expect("OXR can be written");
        let error = SiteCompiler::compile(
            ResourceId::new("site:web"),
            &root,
            root.join("site.oxsite"),
            BTreeMap::new(),
        )
        .expect_err("query replacement without a value must fail");
        assert!(error.to_string().contains("response.redirect.query"));
        assert!(error.to_string().contains("drop"));
    }

    #[test]
    fn template_output_controls_content_type_and_default_autoescape() {
        let directory = tempdir().expect("temporary site directory is available");
        let root = directory.path().join("site");
        fs::create_dir_all(root.join("_templates")).expect("template directory can be created");
        fs::write(
            root.join("site.oxsite"),
            r#"oxista: site/v1
templates:
  roots: [_templates]
  default_output: text
  default_autoescape: none
"#,
        )
        .expect("manifest can be written");
        fs::write(
            root.join("_templates/plain.oxt"),
            r#"---
oxista: template/v1
params:
  value: string
---
{{ value }}
"#,
        )
        .expect("text template can be written");
        fs::write(
            root.join("_templates/page.oxt"),
            r#"---
oxista: template/v1
output: html
autoescape: html
params:
  value: string
---
{{ value }}
"#,
        )
        .expect("HTML template can be written");
        for (name, template) in [("plain.txt", "plain.oxt"), ("page.html", "page.oxt")] {
            fs::write(
                root.join(format!("{name}.oxr")),
                format!(
                    r#"---
oxista: response/v1
response:
  body:
    template:
      source: _templates/{template}
      with:
        value: "<value>"
---
"#
                ),
            )
            .expect("OXR can be written");
        }
        fs::write(
            root.join("inline.txt.oxr"),
            r#"---
oxista: response/v1
page:
  value: "<inline>"
response:
  body:
    template: inline
---
{{ page.value }}
"#,
        )
        .expect("inline OXR can be written");

        let snapshot = SiteCompiler::compile(
            ResourceId::new("site:web"),
            &root,
            root.join("site.oxsite"),
            BTreeMap::new(),
        )
        .expect("site compiles");
        for (path, content_type, expected) in [
            ("/plain.txt", "text/plain; charset=utf-8", "<value>\n"),
            ("/page.html", "text/html; charset=utf-8", "&lt;value&gt;\n"),
            ("/inline.txt", "text/plain; charset=utf-8", "<inline>\n"),
        ] {
            let response = snapshot
                .execute(&request(path))
                .expect("site executes")
                .expect("path is handled");
            assert_eq!(response.headers["content-type"], content_type);
            let PreparedSiteBody::Bytes(body) = response.body else {
                panic!("template response is rendered bytes");
            };
            assert_eq!(String::from_utf8_lossy(&body), expected);
        }
    }

    #[test]
    fn custom_404_uses_effective_template_settings_and_default_headers() {
        for (output, autoescape, expected_content_type, expected_body) in [
            (
                "text",
                "none",
                "text/plain; charset=utf-8",
                "missing <value>\n",
            ),
            (
                "html",
                "html",
                "text/html; charset=utf-8",
                "missing &lt;value&gt;\n",
            ),
        ] {
            let directory = tempdir().expect("temporary site directory is available");
            let root = directory.path().join("site");
            fs::create_dir_all(root.join("_templates")).expect("template directory can be created");
            fs::write(
                root.join("site.oxsite"),
                format!(
                    r#"oxista: site/v1
paths:
  missing: respond
templates:
  roots: [_templates]
  default_output: {output}
  default_autoescape: {autoescape}
data:
  marker: "<value>"
defaults:
  response:
    headers:
      set:
        X-Error-Policy: applied
errors:
  404:
    template: _templates/404.oxt
"#
                ),
            )
            .expect("manifest can be written");
            fs::write(
                root.join("_templates/404.oxt"),
                r#"---
oxista: template/v1
---
missing {{ site.marker }}
"#,
            )
            .expect("404 template can be written");
            let snapshot = SiteCompiler::compile(
                ResourceId::new("site:web"),
                &root,
                root.join("site.oxsite"),
                BTreeMap::new(),
            )
            .expect("site compiles");
            let response = snapshot
                .execute(&request("/missing"))
                .expect("404 executes")
                .expect("404 is handled");
            assert_eq!(response.status, StatusCode::NOT_FOUND);
            assert_eq!(response.headers["content-type"], expected_content_type);
            assert_eq!(response.headers["x-error-policy"], "applied");
            let PreparedSiteBody::Bytes(body) = response.body else {
                panic!("404 template renders bytes");
            };
            assert_eq!(String::from_utf8_lossy(&body), expected_body);
        }

        let directory = tempdir().expect("temporary site directory is available");
        let root = directory.path().join("site");
        fs::create_dir_all(root.join("_templates")).expect("template directory can be created");
        fs::write(
            root.join("site.oxsite"),
            r#"oxista: site/v1
paths:
  missing: respond
errors:
  404:
    template: _templates/404.oxt
"#,
        )
        .expect("manifest can be written");
        fs::write(
            root.join("_templates/404.oxt"),
            r#"---
oxista: template/v1
params:
  reason: string
---
{{ reason }}
"#,
        )
        .expect("parameterized 404 template can be written");
        let failure = SiteCompiler::compile(
            ResourceId::new("site:web"),
            &root,
            root.join("site.oxsite"),
            BTreeMap::new(),
        )
        .expect_err("404 with a required parameter is not callable");
        let diagnostic = &failure.diagnostics[0];
        assert_eq!(diagnostic.code, "template.argument_missing");
        assert_eq!(diagnostic.primary.field_path, "errors[\"404\"].template");
        assert_eq!(diagnostic.related.len(), 1);
        assert!(
            diagnostic.related[0]
                .span
                .file
                .ends_with("_templates/404.oxt")
        );
        assert_eq!(diagnostic.related[0].span.field_path, "params.reason");
    }

    #[test]
    fn rejects_json_oxt_output_with_structured_json_migration() {
        let directory = tempdir().expect("temporary site directory is available");
        let root = directory.path().join("site");
        fs::create_dir_all(root.join("_templates")).expect("template directory can be created");
        fs::write(
            root.join("site.oxsite"),
            "oxista: site/v1\ntemplates:\n  roots: [_templates]\n",
        )
        .expect("manifest can be written");
        fs::write(
            root.join("_templates/data.oxt"),
            r#"---
oxista: template/v1
output: json
---
{"ok": true}
"#,
        )
        .expect("template can be written");
        let error = SiteCompiler::compile(
            ResourceId::new("site:web"),
            &root,
            root.join("site.oxsite"),
            BTreeMap::new(),
        )
        .expect_err("JSON OXT must be rejected");
        assert!(error.to_string().contains("output: json"));
        assert!(error.to_string().contains("structured JSON"));
    }

    #[test]
    fn every_oxista_yaml_entrypoint_uses_the_shared_strict_subset() {
        for kind in ["oxsite", "oxr", "oxt"] {
            let directory = tempdir().expect("temporary site directory is available");
            let root = directory.path().join("site");
            fs::create_dir_all(root.join("_templates")).expect("template directory can be created");
            let manifest = if kind == "oxsite" {
                "oxista: site/v1\noxista: site/v1\n"
            } else {
                "oxista: site/v1\ntemplates:\n  roots: [_templates]\n"
            };
            fs::write(root.join("site.oxsite"), manifest).expect("manifest can be written");
            if kind == "oxr" {
                fs::write(
                    root.join("page.oxr"),
                    r#"---
oxista: response/v1
response:
  body:
    text: first
response:
  body:
    text: second
---
"#,
                )
                .expect("OXR can be written");
            } else if kind == "oxt" {
                fs::write(
                    root.join("_templates/page.oxt"),
                    r#"---
oxista: template/v1
output: html
output: text
---
body
"#,
                )
                .expect("OXT can be written");
            }
            let error = SiteCompiler::compile(
                ResourceId::new("site:web"),
                &root,
                root.join("site.oxsite"),
                BTreeMap::new(),
            )
            .expect_err("duplicate key must fail in every Oxista source");
            assert!(
                error.to_string().contains("source.duplicate_key"),
                "{error}"
            );
        }
    }

    #[test]
    fn validates_dynamic_template_arguments_before_rendering() {
        let directory = tempdir().expect("temporary site directory is available");
        let root = directory.path().join("site");
        fs::create_dir_all(root.join("_templates")).expect("template directory can be created");
        fs::write(
            root.join("site.oxsite"),
            "oxista: site/v1\ntemplates:\n  roots: [_templates]\n",
        )
        .expect("manifest can be written");
        fs::write(
            root.join("_templates/card.oxt"),
            r#"---
oxista: template/v1
output: text
params:
  count: int
  target: url
---
{{ count }} {{ target }}
"#,
        )
        .expect("template can be written");
        for (name, count, target) in [
            ("bad-count", "wrong", "https://example.test/"),
            ("bad-url", "7", "/local-only"),
            ("good", "7", "https://example.test/path"),
        ] {
            fs::write(
                root.join(format!("{name}.oxr")),
                format!(
                    r#"---
oxista: response/v1
page:
  count: {count}
  target: {target}
response:
  body:
    template:
      source: _templates/card.oxt
      with:
        count:
          $expr: page.count
        target:
          $expr: page.target
---
"#
                ),
            )
            .expect("OXR can be written");
        }
        let snapshot = SiteCompiler::compile(
            ResourceId::new("site:web"),
            &root,
            root.join("site.oxsite"),
            BTreeMap::new(),
        )
        .expect("dynamic arguments compile");

        let error = snapshot
            .execute(&request("/bad-count"))
            .expect_err("wrong dynamic integer must fail at runtime");
        let SiteError::TemplateArgument(TemplateArgumentError::Type {
            template,
            parameter,
            expected,
            actual,
        }) = error
        else {
            panic!("wrong type must be a template argument error");
        };
        assert_eq!(template, "_templates/card.oxt");
        assert_eq!(parameter, "count");
        assert_eq!(expected, "int");
        assert_eq!(actual, "string");

        let error = snapshot
            .execute(&request("/bad-url"))
            .expect_err("relative URL must fail at runtime");
        let SiteError::TemplateArgument(TemplateArgumentError::Type {
            parameter,
            expected,
            actual,
            ..
        }) = error
        else {
            panic!("wrong URL must be a template argument error");
        };
        assert_eq!(parameter, "target");
        assert_eq!(expected, "url");
        assert_eq!(actual, "string (not an absolute URL)");

        let response = snapshot
            .execute(&request("/good"))
            .expect("valid dynamic values render")
            .expect("path is handled");
        let PreparedSiteBody::Bytes(body) = response.body else {
            panic!("template response is rendered bytes");
        };
        assert_eq!(
            String::from_utf8_lossy(&body).trim(),
            "7 https://example.test/path"
        );
    }

    #[test]
    fn rejects_safe_html_without_provenance_and_checks_constants_early() {
        for parameter in ["safe_html", "int"] {
            let directory = tempdir().expect("temporary site directory is available");
            let root = directory.path().join("site");
            fs::create_dir_all(root.join("_templates")).expect("template directory can be created");
            fs::write(
                root.join("site.oxsite"),
                "oxista: site/v1\ntemplates:\n  roots: [_templates]\n",
            )
            .expect("manifest can be written");
            fs::write(
                root.join("_templates/card.oxt"),
                format!(
                    r#"---
oxista: template/v1
params:
  value: {parameter}
---
{{{{ value }}}}
"#
                ),
            )
            .expect("template can be written");
            if parameter == "int" {
                fs::write(
                    root.join("page.oxr"),
                    r#"---
oxista: response/v1
response:
  body:
    template:
      source: _templates/card.oxt
      with:
        value: wrong
---
"#,
                )
                .expect("OXR can be written");
            }
            let error = SiteCompiler::compile(
                ResourceId::new("site:web"),
                &root,
                root.join("site.oxsite"),
                BTreeMap::new(),
            )
            .expect_err("invalid parameter contract must fail during compilation");
            let message = error.to_string();
            if parameter == "safe_html" {
                assert!(message.contains("trusted HTML provenance"));
                assert!(message.contains("use `string`"));
            } else {
                assert!(message.contains("expects int, received string"));
            }
        }
    }

    #[test]
    fn typed_include_contracts_flow_through_site_compilation() {
        let directory = tempdir().expect("temporary site directory is available");
        let root = directory.path().join("site");
        fs::create_dir_all(root.join("_templates")).expect("template directory can be created");
        fs::write(
            root.join("site.oxsite"),
            "oxista: site/v1\ntemplates:\n  roots: [_templates]\n  default_output: text\n",
        )
        .expect("manifest can be written");
        fs::write(
            root.join("_templates/child.oxt"),
            r#"---
oxista: template/v1
params:
  item: string
---
C{{ item }}
"#,
        )
        .expect("child template can be written");
        let parent_path = root.join("_templates/parent.oxt");
        fs::write(
            &parent_path,
            r#"---
oxista: template/v1
params:
  value: string
---
P{% include "_templates/child.oxt" with item=value only %}Z{{ item ?? "clean" }}
"#,
        )
        .expect("parent template can be written");
        fs::write(
            root.join("page.oxr"),
            r#"---
oxista: response/v1
response:
  body:
    template:
      source: _templates/parent.oxt
      with:
        value: hello
---
"#,
        )
        .expect("response source can be written");

        let snapshot = SiteCompiler::compile(
            ResourceId::new("site:web"),
            &root,
            root.join("site.oxsite"),
            BTreeMap::new(),
        )
        .expect("valid typed include site compiles");
        let response = snapshot
            .execute(&request("/page"))
            .expect("site execution succeeds")
            .expect("page is handled");
        let PreparedSiteBody::Bytes(body) = response.body else {
            panic!("template response is rendered bytes");
        };
        assert_eq!(String::from_utf8_lossy(&body).trim(), "PChello\nZclean");

        fs::write(
            &parent_path,
            r#"---
oxista: template/v1
params:
  value: string
---
{% include "_templates/child.oxt" %}
"#,
        )
        .expect("invalid parent can be written");
        let failure = SiteCompiler::compile(
            ResourceId::new("site:web"),
            &root,
            root.join("site.oxsite"),
            BTreeMap::new(),
        )
        .expect_err("missing include argument must fail preparation");
        let diagnostic = &failure.diagnostics[0];
        assert_eq!(diagnostic.code, "template.include_argument_missing");
        assert!(
            diagnostic
                .message
                .contains("missing required parameter `item`")
        );
        assert_eq!(diagnostic.primary.field_path, "template.include.target");
        assert_eq!(diagnostic.related.len(), 1);
        assert_eq!(diagnostic.related[0].span.field_path, "params.item");

        fs::write(
            &parent_path,
            r#"---
oxista: template/v1
params:
  value: string
---
{% include "_templates/child.oxt" with item=value %}
"#,
        )
        .expect("valid parent can be restored");
        for (name, body) in [
            ("a.oxt", "{% include \"_templates/b.oxt\" %}"),
            ("b.oxt", "{% include \"_templates/a.oxt\" %}"),
        ] {
            fs::write(
                root.join("_templates").join(name),
                format!("---\noxista: template/v1\n---\n{body}\n"),
            )
            .expect("cycle fixture can be written");
        }
        let failure = SiteCompiler::compile(
            ResourceId::new("site:web"),
            &root,
            root.join("site.oxsite"),
            BTreeMap::new(),
        )
        .expect_err("include cycle must fail preparation");
        let diagnostic = &failure.diagnostics[0];
        assert_eq!(diagnostic.code, "template.include_cycle");
        assert!(diagnostic.message.contains("template dependency cycle"));
        assert!(diagnostic.message.contains("a.oxt"));
        assert!(diagnostic.message.contains("b.oxt"));
        assert_eq!(diagnostic.primary.field_path, "template.include.target");
        assert_eq!(diagnostic.related.len(), 1);
        assert_eq!(diagnostic.reference_chain.len(), 2);
        assert!(
            diagnostic
                .reference_chain
                .iter()
                .all(|edge| edge.span.as_ref().is_some_and(|span| {
                    span.field_path == "template.include.target" && span.end_byte > span.start_byte
                }))
        );
    }

    #[test]
    fn source_index_reads_each_representation_once_and_keeps_large_assets_bounded() {
        let directory = tempdir().expect("temporary site directory is available");
        let root = directory.path().join("site");
        fs::create_dir_all(root.join("_templates")).expect("template directory can be created");
        let manifest = root.join("site.oxsite");
        fs::write(
            &manifest,
            r#"oxista: site/v1
assets:
  precompressed:
    brotli: .br
    gzip: .gz
templates:
  roots: [_templates]
"#,
        )
        .expect("manifest can be written");
        let asset = root.join("large.bin");
        let brotli = root.join("large.bin.br");
        let gzip = root.join("large.bin.gz");
        let template = root.join("_templates/page.oxt");
        fs::write(&asset, vec![0x5a; 2 * 1024 * 1024]).expect("large asset can be written");
        fs::write(&brotli, b"brotli").expect("Brotli representation can be written");
        fs::write(&gzip, b"gzip").expect("gzip representation can be written");
        fs::write(
            &template,
            "---\noxista: template/v1\n---\n{{ request.path }}\n",
        )
        .expect("template can be written");

        let index = SiteCompiler::scan(&root, &manifest).expect("site source scan succeeds");
        for path in [&manifest, &asset, &brotli, &gzip, &template] {
            assert_eq!(index.file_read_count(path), 1, "{}", path.display());
        }
        let large = index.entry(&asset).expect("large asset is indexed");
        assert_eq!(large.kind, SiteSourceKind::Asset);
        assert_eq!(large.length, 2 * 1024 * 1024);
        assert!(
            large.text.is_none(),
            "large asset bytes must not be retained"
        );
        assert!(
            index
                .entry(&template)
                .expect("template is indexed")
                .text
                .is_some(),
            "small Oxista source text is retained for compilation"
        );

        SiteCompiler::compile_indexed(ResourceId::new("site:web"), &index, BTreeMap::new())
            .expect("snapshot compiles from the existing index");
        for path in [&manifest, &asset, &brotli, &gzip, &template] {
            assert_eq!(
                index.file_read_count(path),
                1,
                "compilation re-read {}",
                path.display()
            );
        }
    }

    #[test]
    fn source_index_digest_tracks_source_compressed_and_path_changes() {
        let directory = tempdir().expect("temporary site directory is available");
        let root = directory.path().join("site");
        fs::create_dir_all(root.join("_templates")).expect("template directory can be created");
        let manifest = root.join("site.oxsite");
        fs::write(
            &manifest,
            "oxista: site/v1\ntemplates:\n  roots: [_templates]\n",
        )
        .expect("manifest can be written");
        let asset = root.join("asset.txt");
        let compressed = root.join("asset.txt.br");
        let template = root.join("_templates/page.oxt");
        fs::write(&asset, "asset").expect("asset can be written");
        fs::write(&compressed, "compressed-v1").expect("compressed asset can be written");
        fs::write(&template, "---\noxista: template/v1\n---\nversion one\n")
            .expect("template can be written");
        let initial = SiteCompiler::scan(&root, &manifest)
            .expect("initial scan succeeds")
            .source_digest();
        assert_eq!(
            initial,
            SiteCompiler::scan(&root, &manifest)
                .expect("repeat scan succeeds")
                .source_digest()
        );

        fs::write(&template, "---\noxista: template/v1\n---\nversion two\n")
            .expect("template can change");
        let template_changed = SiteCompiler::scan(&root, &manifest)
            .expect("changed template scan succeeds")
            .source_digest();
        assert_ne!(initial, template_changed);

        fs::write(&compressed, "compressed-v2").expect("compressed asset can change");
        let compressed_changed = SiteCompiler::scan(&root, &manifest)
            .expect("changed compressed scan succeeds")
            .source_digest();
        assert_ne!(template_changed, compressed_changed);

        let added = root.join("added.txt");
        fs::write(&added, "added").expect("asset can be added");
        let added_digest = SiteCompiler::scan(&root, &manifest)
            .expect("added file scan succeeds")
            .source_digest();
        assert_ne!(compressed_changed, added_digest);
        let renamed = root.join("renamed.txt");
        fs::rename(&added, &renamed).expect("asset can be renamed");
        let renamed_digest = SiteCompiler::scan(&root, &manifest)
            .expect("renamed file scan succeeds")
            .source_digest();
        assert_ne!(added_digest, renamed_digest);
        fs::remove_file(&renamed).expect("asset can be removed");
        let removed_digest = SiteCompiler::scan(&root, &manifest)
            .expect("removed file scan succeeds")
            .source_digest();
        assert_eq!(compressed_changed, removed_digest);
    }

    #[test]
    fn source_index_digest_tracks_exposed_last_modified_metadata() {
        fn set_modified(path: &std::path::Path, seconds: u64) {
            let file = fs::OpenOptions::new()
                .write(true)
                .open(path)
                .expect("asset opens for timestamp update");
            file.set_times(
                fs::FileTimes::new()
                    .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(seconds)),
            )
            .expect("asset timestamp can be set");
        }

        let directory = tempdir().expect("temporary site directory is available");
        let root = directory.path().join("site");
        fs::create_dir(&root).expect("site directory can be created");
        let manifest = root.join("site.oxsite");
        let asset = root.join("asset.txt");
        fs::write(&manifest, "oxista: site/v1\n").expect("manifest can be written");
        fs::write(&asset, "same bytes").expect("asset can be written");

        set_modified(&asset, 1_700_000_000);
        let first = SiteCompiler::scan(&root, &manifest)
            .expect("first scan succeeds")
            .source_digest();
        set_modified(&asset, 1_700_000_001);
        let second = SiteCompiler::scan(&root, &manifest)
            .expect("second scan succeeds")
            .source_digest();
        assert_ne!(first, second, "published Last-Modified is snapshot input");

        fs::write(
            &manifest,
            "oxista: site/v1\nassets:\n  last_modified: false\n",
        )
        .expect("manifest can disable Last-Modified");
        set_modified(&asset, 1_700_000_002);
        let disabled_first = SiteCompiler::scan(&root, &manifest)
            .expect("disabled scan succeeds")
            .source_digest();
        set_modified(&asset, 1_700_000_003);
        let disabled_second = SiteCompiler::scan(&root, &manifest)
            .expect("repeat disabled scan succeeds")
            .source_digest();
        assert_eq!(
            disabled_first, disabled_second,
            "mtime is irrelevant when Last-Modified is disabled"
        );
    }

    #[cfg(unix)]
    #[test]
    fn source_index_digest_tracks_symlink_target_identity() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().expect("temporary site directory is available");
        let root = directory.path().join("site");
        fs::create_dir(&root).expect("site directory can be created");
        let manifest = root.join("site.oxsite");
        fs::write(&manifest, "oxista: site/v1\n").expect("manifest can be written");
        fs::write(root.join("a.txt"), "same bytes").expect("first target can be written");
        fs::write(root.join("b.txt"), "same bytes").expect("second target can be written");
        let link = root.join("alias.txt");
        symlink("a.txt", &link).expect("first symlink can be created");
        let first = SiteCompiler::scan(&root, &manifest)
            .expect("first symlink scan succeeds")
            .source_digest();
        fs::remove_file(&link).expect("first symlink can be removed");
        symlink("b.txt", &link).expect("second symlink can be created");
        let second = SiteCompiler::scan(&root, &manifest)
            .expect("second symlink scan succeeds")
            .source_digest();
        assert_ne!(first, second);
    }

    #[test]
    fn oxt_expression_and_include_contract_errors_report_template_spans() {
        let directory = tempdir().expect("temporary site directory is available");
        let root = directory.path().join("site");
        fs::create_dir_all(root.join("_templates")).expect("template directory can be created");
        let manifest = root.join("site.oxsite");
        fs::write(
            &manifest,
            "oxista: site/v1\ntemplates:\n  roots: [_templates]\n",
        )
        .expect("manifest can be written");
        let page = root.join("_templates/page.oxt");
        fs::write(&page, "---\noxista: template/v1\n---\n雪 {{ page. }}\n")
            .expect("invalid expression template can be written");
        let failure = SiteCompiler::compile(
            ResourceId::new("site:web"),
            &root,
            &manifest,
            BTreeMap::new(),
        )
        .expect_err("invalid interpolation must fail");
        let diagnostic = &failure.diagnostics[0];
        assert_eq!(diagnostic.code, "template.expression");
        assert!(diagnostic.primary.file.ends_with("_templates/page.oxt"));
        assert_eq!((diagnostic.primary.line, diagnostic.primary.column), (4, 6));
        assert_eq!(diagnostic.primary.field_path, "template");

        fs::write(
            root.join("_templates/child.oxt"),
            "---\noxista: template/v1\nparams:\n  value: string\n---\n{{ value }}\n",
        )
        .expect("typed child can be written");
        fs::write(
            &page,
            "---\noxista: template/v1\n---\n雪 {% include \"_templates/child.oxt\" with extra=1 %}\n",
        )
        .expect("invalid include caller can be written");
        let failure = SiteCompiler::compile(
            ResourceId::new("site:web"),
            &root,
            &manifest,
            BTreeMap::new(),
        )
        .expect_err("unknown include argument must fail");
        let diagnostic = &failure.diagnostics[0];
        assert_eq!(diagnostic.code, "template.include_argument_unknown");
        assert!(diagnostic.message.contains("unknown parameter `extra`"));
        assert_eq!(
            (diagnostic.primary.line, diagnostic.primary.column),
            (4, 42)
        );
        assert_eq!(
            diagnostic.primary.field_path,
            "template.include.arguments.extra"
        );
    }

    #[test]
    fn manifest_semantic_diagnostics_retain_exact_field_spans() {
        let cases = [
            (
                "oxista: site/v1\ninputs:\n  unsafe:\n    type: safe_html\n",
                "site.input_type",
                "inputs.unsafe.type",
            ),
            (
                "oxista: site/v1\ndefaults:\n  response:\n    cache:\n      visibility: shared\n",
                "site.cache_visibility",
                "defaults.response.cache.visibility",
            ),
            (
                "oxista: site/v1\nprofiles:\n  public:\n    cache:\n      max_age: soon\n",
                "site.cache_max_age",
                "profiles.public.cache.max_age",
            ),
            (
                "oxista: site/v1\nerrors:\n  500:\n    template: _templates/error.oxt\n",
                "site.unsupported_error_status",
                "errors[\"500\"]",
            ),
            (
                "oxista: site/v1\nvisibility:\n  deny:\n    - ../private\n",
                "site.visibility_pattern",
                "visibility.deny[0]",
            ),
            (
                "oxista: site/v1\ntemplates:\n  limits:\n    render_time: eventually\n",
                "template.limit",
                "templates.limits.render_time",
            ),
        ];

        for (manifest_source, code, field_path) in cases {
            let directory = tempdir().expect("temporary site directory is available");
            let root = directory.path().join("site");
            fs::create_dir(&root).expect("site directory can be created");
            let manifest = root.join("site.oxsite");
            fs::write(&manifest, manifest_source).expect("manifest can be written");
            let failure = SiteCompiler::compile(
                ResourceId::new("site:web"),
                &root,
                &manifest,
                BTreeMap::new(),
            )
            .expect_err("invalid manifest field must fail");
            let diagnostic = &failure.diagnostics[0];
            assert_eq!(diagnostic.code, code, "{diagnostic}");
            assert_eq!(diagnostic.primary.field_path, field_path, "{diagnostic}");
            assert!(diagnostic.primary.file.ends_with("site.oxsite"));
            assert!(diagnostic.primary.end_byte > diagnostic.primary.start_byte);
        }

        let directory = tempdir().expect("temporary site directory is available");
        let root = directory.path().join("site");
        fs::create_dir(&root).expect("site directory can be created");
        let manifest = root.join("site.oxsite");
        fs::write(
            &manifest,
            concat!(
                "oxista: site/v1\r\n",
                "data:\r\n",
                "  note: |\r\n",
                "    雪: literal content\r\n",
                "assets:\r\n",
                "  mime_overrides:\r\n",
                "    \".txt\": \"bad\\nvalue\"\r\n",
            ),
        )
        .expect("CRLF manifest can be written");
        let failure = SiteCompiler::compile(
            ResourceId::new("site:web"),
            &root,
            &manifest,
            BTreeMap::new(),
        )
        .expect_err("invalid MIME override must fail");
        let diagnostic = &failure.diagnostics[0];
        assert_eq!(diagnostic.code, "site.asset_content_type");
        assert_eq!(
            diagnostic.primary.field_path,
            "assets.mime_overrides[\".txt\"]"
        );
        assert_eq!(
            (diagnostic.primary.line, diagnostic.primary.column),
            (7, 13)
        );
    }

    #[test]
    fn oxr_semantic_diagnostics_retain_nested_field_spans() {
        let cases = [
            (
                "apply: [missing]\nresponse:\n  body:\n    empty: true\n",
                "site.profile_reference",
                "apply[0]",
            ),
            (
                "page:\n  value:\n    $expr: \"page.\"\nresponse:\n  body:\n    empty: true\n",
                "site.expression",
                "page.value.$expr",
            ),
            (
                "response:\n  status: 99\n  body:\n    empty: true\n",
                "site.response_status",
                "response.status",
            ),
            (
                "response:\n  content_type: \"bad\\nvalue\"\n  body:\n    empty: true\n",
                "site.response_content_type",
                "response.content_type",
            ),
            (
                "response:\n  redirect:\n    status: 200\n    location: /next\n",
                "site.redirect_status",
                "response.redirect.status",
            ),
            (
                "response:\n  status: 308\n  redirect:\n    status: 308\n    location: /next\n",
                "site.redirect_status_ambiguity",
                "response.status",
            ),
            (
                "response:\n  body:\n    asset: sibling\n    text: duplicate\n",
                "site.response_body_shape",
                "response.body",
            ),
            (
                "response:\n  body:\n    template:\n      source: _templates/missing.oxt\n",
                "template.missing",
                "response.body.template.source",
            ),
            (
                "response:\n  body:\n    asset: /absolute.txt\n",
                "site.asset_path",
                "response.body.asset",
            ),
            (
                "response:\n  body:\n    json:\n      nested:\n        $expr: \"page.\"\n",
                "site.expression",
                "response.body.json.nested.$expr",
            ),
        ];

        for (front_matter, code, field_path) in cases {
            let directory = tempdir().expect("temporary site directory is available");
            let root = directory.path().join("site");
            fs::create_dir(&root).expect("site directory can be created");
            let manifest = root.join("site.oxsite");
            fs::write(&manifest, "oxista: site/v1\n").expect("manifest can be written");
            let oxr = root.join("page.oxr");
            fs::write(
                &oxr,
                format!("---\noxista: response/v1\n{front_matter}---\n"),
            )
            .expect("OXR can be written");
            let failure = SiteCompiler::compile(
                ResourceId::new("site:web"),
                &root,
                &manifest,
                BTreeMap::new(),
            )
            .expect_err("invalid OXR field must fail");
            let diagnostic = &failure.diagnostics[0];
            assert_eq!(diagnostic.code, code, "{diagnostic}");
            assert_eq!(diagnostic.primary.field_path, field_path, "{diagnostic}");
            assert!(diagnostic.primary.file.ends_with("page.oxr"));
            assert!(diagnostic.primary.end_byte > diagnostic.primary.start_byte);
        }
    }

    #[test]
    fn oxt_metadata_and_inline_body_diagnostics_use_physical_sources() {
        for (metadata, code, field_path) in [
            ("output: json\n", "template.output", "output"),
            (
                "params:\n  item: unknown\n",
                "template.parameter_type",
                "params.item",
            ),
            ("autoescape: invalid\n", "source.parse", "autoescape"),
        ] {
            let directory = tempdir().expect("temporary site directory is available");
            let root = directory.path().join("site");
            fs::create_dir_all(root.join("_templates")).expect("template directory can be created");
            let manifest = root.join("site.oxsite");
            fs::write(
                &manifest,
                "oxista: site/v1\ntemplates:\n  roots: [_templates]\n",
            )
            .expect("manifest can be written");
            fs::write(
                root.join("_templates/page.oxt"),
                format!("---\noxista: template/v1\n{metadata}---\nbody\n"),
            )
            .expect("OXT can be written");
            let failure = SiteCompiler::compile(
                ResourceId::new("site:web"),
                &root,
                &manifest,
                BTreeMap::new(),
            )
            .expect_err("invalid OXT metadata must fail");
            let diagnostic = &failure.diagnostics[0];
            assert_eq!(diagnostic.code, code, "{diagnostic}");
            assert_eq!(diagnostic.primary.field_path, field_path, "{diagnostic}");
            assert!(diagnostic.primary.file.ends_with("_templates/page.oxt"));
            assert!(diagnostic.primary.line >= 3);
        }

        let directory = tempdir().expect("temporary site directory is available");
        let root = directory.path().join("site");
        fs::create_dir(&root).expect("site directory can be created");
        let manifest = root.join("site.oxsite");
        fs::write(&manifest, "oxista: site/v1\n").expect("manifest can be written");
        let oxr = root.join("inline.oxr");
        fs::write(
            &oxr,
            "---\noxista: response/v1\nresponse:\n  body:\n    template: inline\n---\n雪 {{ page. }}\n",
        )
        .expect("inline OXR can be written");
        let failure = SiteCompiler::compile(
            ResourceId::new("site:web"),
            &root,
            &manifest,
            BTreeMap::new(),
        )
        .expect_err("invalid inline expression must fail");
        let diagnostic = &failure.diagnostics[0];
        assert_eq!(diagnostic.code, "template.expression");
        assert!(diagnostic.primary.file.ends_with("inline.oxr"));
        assert_eq!((diagnostic.primary.line, diagnostic.primary.column), (7, 6));
    }

    #[test]
    #[ignore = "manual filesystem benchmark; run with --release --ignored --nocapture"]
    fn synthetic_site_preparation_smoke_benchmark() {
        for file_count in [1_000usize, 10_000] {
            let directory = tempdir().expect("temporary site directory is available");
            let root = directory.path().join("site");
            fs::create_dir(&root).expect("site directory can be created");
            let manifest = root.join("site.oxsite");
            fs::write(&manifest, "oxista: site/v1\n").expect("manifest can be written");
            for index in 0..file_count {
                fs::write(
                    root.join(format!("asset-{index:05}.txt")),
                    format!("asset {index}\n"),
                )
                .expect("synthetic asset can be written");
            }

            let scan_started = std::time::Instant::now();
            let index = SiteCompiler::scan(&root, &manifest).expect("synthetic scan succeeds");
            let scan_elapsed = scan_started.elapsed();
            assert_eq!(index.entries().count(), file_count + 1);
            let compile_started = std::time::Instant::now();
            let snapshot = SiteCompiler::compile_indexed(
                ResourceId::new(format!("site:bench-{file_count}")),
                &index,
                BTreeMap::new(),
            )
            .expect("synthetic snapshot compiles");
            let compile_elapsed = compile_started.elapsed();
            std::hint::black_box(snapshot.public_paths().count());
            eprintln!(
                "site preparation ({file_count} assets): scan {scan_elapsed:?}, compile {compile_elapsed:?}"
            );
        }
    }
}
