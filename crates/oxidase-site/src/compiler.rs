use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use http::{HeaderName, HeaderValue, StatusCode};
use oxidase_core::{CompiledTemplate, Expression, ResourceId, Value, is_forbidden_user_header};
use walkdir::WalkDir;

use crate::error::{SiteCompileError, SiteCompileFailure};
use crate::runtime::{
    AssetPlan, AssetRepresentation, ContentEncoding, EntityTag, HeaderPlan, HeaderPolicyLayer,
    RedirectQuery, SiteMissing, SiteResponseKind, SiteResponsePlan, SiteSnapshot, path_is_within,
};
use crate::source::{
    EtagSource, HeadersSource, IndexCanonicalSource, ManifestSource, MissingSource, OutputSource,
    OxrBodySource, OxrSource, RedirectQuerySource, ResponsePolicySource, SymlinkModeSource,
    TemplateReferenceSource, TrailingSlashSource, VisibilityModeSource,
};
use crate::template::{CompiledOxt, CompiledValue, TemplateLimits, normalize_template_name};
use crate::{RESPONSE_API_VERSION, SITE_API_VERSION, TEMPLATE_API_VERSION};

#[derive(Debug, Default)]
pub struct SiteCompiler;

impl SiteCompiler {
    pub fn compile(
        id: ResourceId,
        root: impl AsRef<Path>,
        manifest: impl AsRef<Path>,
        inputs: BTreeMap<String, Value>,
    ) -> Result<SiteSnapshot, SiteCompileFailure> {
        let root = root.as_ref().to_path_buf();
        let manifest = manifest.as_ref().to_path_buf();
        let mut dependencies = Vec::new();
        track_candidate(&mut dependencies, &root);
        track_candidate(&mut dependencies, &manifest);
        Self::compile_inner(id, &root, &manifest, inputs, &mut dependencies).map_err(|error| {
            dependencies.sort();
            dependencies.dedup();
            SiteCompileFailure {
                error,
                discovered_dependencies: dependencies,
            }
        })
    }

    fn compile_inner(
        id: ResourceId,
        root: &Path,
        manifest: &Path,
        inputs: BTreeMap<String, Value>,
        dependencies: &mut Vec<PathBuf>,
    ) -> Result<SiteSnapshot, SiteCompileError> {
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
        let manifest_text = read_text(&manifest)?;
        let source: ManifestSource = parse_yaml(&manifest, &manifest_text)?;
        if source.oxista != SITE_API_VERSION {
            return Err(SiteCompileError::source(
                &manifest,
                format!(
                    "unsupported Oxista version `{}`; expected `{SITE_API_VERSION}`",
                    source.oxista
                ),
            ));
        }
        validate_manifest(&manifest, &source, &inputs)?;
        let deny_patterns = compile_deny_patterns(&manifest, &source.visibility.deny)?;
        let limits = compile_limits(&manifest, &source)?;
        let mut data = source
            .data
            .iter()
            .map(|(name, value)| Ok((name.clone(), compile_constant(value)?)))
            .collect::<Result<BTreeMap<_, _>, SiteCompileError>>()?;
        for (name, value) in &inputs {
            if data.insert(name.clone(), value.clone()).is_some() {
                return Err(SiteCompileError::Input {
                    name: name.clone(),
                    message: "conflicts with a site `data` key".to_owned(),
                });
            }
        }

        let template_roots = template_roots(&root, &source)?;
        let mut files = collect_files(&root, &source, &template_roots, &deny_patterns)?;
        files.sort();
        for path in &files {
            track_site_dependency(dependencies, path, &root);
        }
        for path in &template_roots {
            track_site_dependency(dependencies, path, &root);
        }
        track_precompressed_candidates(&files, &source, &root, dependencies);
        let mut templates = compile_templates(
            &root,
            &files,
            &template_roots,
            source.templates.default_output,
            source.templates.default_autoescape,
            dependencies,
        )?;
        track_template_dependencies(&root, &templates, dependencies);
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
                .strip_prefix(&root)
                .map_err(|_| SiteCompileError::UnsafePath {
                    path: oxr.clone(),
                    message: "OXR escapes the site root".to_owned(),
                })?;
            if is_private(relative, &source, &template_roots, &root, &deny_patterns) {
                continue;
            }
            dependencies.push(oxr.clone());
            let (logical_path, plan, backing) =
                compile_oxr(&root, oxr, &source, &mut templates, dependencies)?;
            if let Some(backing) = backing {
                backing_assets.insert(backing);
            }
            insert_with_index_aliases(&mut entries, logical_path, plan, &source)?;
        }

        let precompressed = precompressed_paths(&files, &source);
        for asset in files.iter().filter(|path| {
            !has_source_extension(path)
                && !backing_assets.contains(*path)
                && !precompressed.contains(*path)
        }) {
            let relative = asset
                .strip_prefix(&root)
                .map_err(|_| SiteCompileError::UnsafePath {
                    path: asset.clone(),
                    message: "asset is outside the canonical site root".to_owned(),
                })?;
            if is_private(relative, &source, &template_roots, &root, &deny_patterns) {
                continue;
            }
            let headers = compile_resource_base_policy(relative, &source, asset)?;
            let logical_path = logical_path(relative);
            let plan = SiteResponsePlan {
                status: StatusCode::OK,
                headers,
                content_type: None,
                page: BTreeMap::new(),
                kind: SiteResponseKind::Asset(Box::new(compile_asset(asset, &source)?)),
                source: asset.clone(),
            };
            insert_with_index_aliases(&mut entries, logical_path, plan, &source)?;
            track_site_dependency(dependencies, asset, &root);
        }
        validate_template_graph(&templates)?;

        let error_404 = source
            .errors
            .get(&404)
            .map(|error| {
                let name = normalize_template_name(&error.template)?;
                track_site_dependency(dependencies, &root.join(&name), &root);
                let template = templates.get(&name).ok_or_else(|| {
                    SiteCompileError::source(
                        &manifest,
                        format!("404 error template `{name}` does not exist"),
                    )
                })?;
                template.validate_arguments(&BTreeMap::new())?;
                Ok(crate::runtime::ErrorPagePlan {
                    template: name,
                    headers: compile_response_policy(
                        &source.defaults.response,
                        &manifest,
                        "defaults.response",
                    )?,
                })
            })
            .transpose()?;

        dependencies.sort();
        dependencies.dedup();
        Ok(SiteSnapshot {
            id,
            root,
            manifest,
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
    path: &Path,
    source: &ManifestSource,
    inputs: &BTreeMap<String, Value>,
) -> Result<(), SiteCompileError> {
    if !matches!(source.paths.trailing_slash, TrailingSlashSource::Canonical) {
        return Err(SiteCompileError::source(
            path,
            "paths.trailing_slash only supports `canonical` in Oxista v1; remove the field or set it to `canonical`",
        ));
    }
    if source.paths.directory_listing {
        return Err(SiteCompileError::source(
            path,
            "directory_listing is intentionally unavailable in Oxista v1",
        ));
    }
    if source.paths.clean_html_urls {
        return Err(SiteCompileError::source(
            path,
            "clean_html_urls is not implemented in this release",
        ));
    }
    if matches!(source.templates.default_output, OutputSource::Json) {
        return Err(SiteCompileError::source(
            path,
            "templates.default_output `json` is not supported; use an OXR structured JSON body",
        ));
    }
    if let Some(status) = source.errors.keys().find(|status| **status != 404) {
        return Err(SiteCompileError::source(
            path,
            format!(
                "errors.{status} is not supported in Oxista v1 alpha; only a 404 template is implemented"
            ),
        ));
    }
    for (name, contract) in &source.inputs {
        validate_input_kind(path, name, &contract.kind)?;
        match inputs.get(name) {
            None if contract.required => {
                return Err(SiteCompileError::Input {
                    name: name.clone(),
                    message: "is required but was not injected".to_owned(),
                });
            }
            Some(value) if !input_accepts(&contract.kind, value) => {
                return Err(SiteCompileError::Input {
                    name: name.clone(),
                    message: format!(
                        "expects type `{}`, received {}",
                        contract.kind,
                        value.type_name()
                    ),
                });
            }
            _ => {}
        }
    }
    for name in inputs.keys() {
        if !source.inputs.contains_key(name) {
            return Err(SiteCompileError::Input {
                name: name.clone(),
                message: "is not declared by the site manifest".to_owned(),
            });
        }
    }
    for index in &source.paths.indexes {
        if index.contains('/') || index.contains('\\') || index.is_empty() {
            return Err(SiteCompileError::source(
                path,
                format!("index name `{index}` must be one file name"),
            ));
        }
    }
    for policy in source
        .profiles
        .values()
        .chain(std::iter::once(&source.defaults.response))
        .chain(source.defaults.by_extension.values())
    {
        validate_cache_policy(path, policy)?;
    }
    compile_response_policy(&source.defaults.response, path, "defaults.response")?;
    for (extension, policy) in &source.defaults.by_extension {
        compile_response_policy(
            policy,
            path,
            &format!("defaults.by_extension[\"{extension}\"]"),
        )?;
    }
    for (name, policy) in &source.profiles {
        compile_response_policy(policy, path, &format!("profiles.{name}"))?;
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
    path: &Path,
    patterns: &[String],
) -> Result<Vec<DenyPattern>, SiteCompileError> {
    patterns
        .iter()
        .enumerate()
        .map(|(index, pattern)| {
            compile_deny_pattern(pattern).map_err(|message| {
                SiteCompileError::source(
                    path,
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

fn validate_input_kind(path: &Path, name: &str, kind: &str) -> Result<(), SiteCompileError> {
    let base = kind.strip_suffix('?').unwrap_or(kind);
    if base == "safe_html" {
        return Err(SiteCompileError::source(
            path,
            format!(
                "inputs.{name}.type `safe_html` is unavailable because runtime values do not carry trusted HTML provenance; use `string`"
            ),
        ));
    }
    if !matches!(
        base,
        "any" | "null" | "bool" | "int" | "float" | "string" | "url"
    ) {
        return Err(SiteCompileError::source(
            path,
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
    path: &Path,
    policy: &ResponsePolicySource,
) -> Result<(), SiteCompileError> {
    if let Some(cache) = &policy.cache {
        if let Some(visibility) = &cache.visibility
            && !matches!(visibility.as_str(), "public" | "private" | "no_store")
        {
            return Err(SiteCompileError::source(
                path,
                format!("invalid cache visibility `{visibility}`"),
            ));
        }
        if let Some(max_age) = &cache.max_age {
            parse_seconds(max_age).map_err(|message| SiteCompileError::source(path, message))?;
        }
    }
    Ok(())
}

fn compile_limits(
    path: &Path,
    source: &ManifestSource,
) -> Result<TemplateLimits, SiteCompileError> {
    Ok(TemplateLimits {
        render_time: parse_duration(&source.templates.limits.render_time)
            .map_err(|message| SiteCompileError::source(path, message))?,
        output_size: parse_size(&source.templates.limits.output_size)
            .map_err(|message| SiteCompileError::source(path, message))?,
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
) -> Result<Vec<PathBuf>, SiteCompileError> {
    let mut files = Vec::new();
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
        let relative =
            entry
                .path()
                .strip_prefix(root)
                .map_err(|_| SiteCompileError::UnsafePath {
                    path: entry.path().to_path_buf(),
                    message: "site scan escaped the canonical root".to_owned(),
                })?;
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
            files.push(canonical);
        } else if entry.file_type().is_file() {
            files.push(entry.path().to_path_buf());
        }
    }
    Ok(files)
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

fn template_roots(root: &Path, source: &ManifestSource) -> Result<Vec<PathBuf>, SiteCompileError> {
    source
        .templates
        .roots
        .iter()
        .map(|template_root| {
            let relative = Path::new(template_root);
            if relative.is_absolute()
                || relative.components().any(|component| {
                    matches!(component, Component::ParentDir | Component::Prefix(_))
                })
            {
                return Err(SiteCompileError::UnsafePath {
                    path: relative.to_path_buf(),
                    message: "template root must be relative and cannot contain `..`".to_owned(),
                });
            }
            Ok(root.join(relative))
        })
        .collect()
}

fn compile_templates(
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
        let text = read_text(path)?;
        let (front_matter, body) = split_front_matter(path, &text)?;
        let metadata: crate::source::OxtMetadataSource = parse_yaml(path, front_matter)?;
        if metadata.oxista != TEMPLATE_API_VERSION {
            return Err(SiteCompileError::source(
                path,
                format!("expected `oxista: {TEMPLATE_API_VERSION}`"),
            ));
        }
        let template = CompiledOxt::compile(
            name.clone(),
            &metadata,
            body,
            default_output,
            default_autoescape,
        )?;
        if templates.insert(name.clone(), template).is_some() {
            return Err(SiteCompileError::source(
                path,
                format!("duplicate template name `{name}`"),
            ));
        }
        dependencies.push(path.clone());
    }
    Ok(templates)
}

fn validate_template_graph(
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
            return Err(SiteCompileError::TemplateCycle(cycle.join(" -> ")));
        }
        let template = templates.get(name).ok_or_else(|| {
            SiteCompileError::source(name, format!("included template `{name}` does not exist"))
        })?;
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
    root: &Path,
    path: &Path,
    manifest: &ManifestSource,
    templates: &mut BTreeMap<String, CompiledOxt>,
    dependencies: &mut Vec<PathBuf>,
) -> Result<(String, SiteResponsePlan, Option<PathBuf>), SiteCompileError> {
    let text = read_text(path)?;
    let (front_matter, inline_body) = split_front_matter(path, &text)?;
    let source: OxrSource = parse_yaml(path, front_matter)?;
    if source.oxista != RESPONSE_API_VERSION {
        return Err(SiteCompileError::source(
            path,
            format!("expected `oxista: {RESPONSE_API_VERSION}`"),
        ));
    }
    if source.response.redirect.is_some() && source.response.body.is_some() {
        return Err(SiteCompileError::source(
            path,
            "OXR response cannot contain both `redirect` and `body`",
        ));
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
    let mut headers = compile_resource_base_policy(&relative_without_oxr, manifest, path)?;
    for profile in &source.apply {
        let policy = manifest.profiles.get(profile).ok_or_else(|| {
            SiteCompileError::source(path, format!("unknown response profile `{profile}`"))
        })?;
        headers.merge(compile_response_policy(
            policy,
            path,
            &format!("profiles.{profile}"),
        )?);
    }
    headers.merge(compile_headers(
        &source.response.headers,
        path,
        "response.headers",
    )?);
    let page = source
        .page
        .iter()
        .map(|(name, value)| Ok((name.clone(), compile_value(value, path)?)))
        .collect::<Result<_, SiteCompileError>>()?;

    let status = StatusCode::from_u16(source.response.status.unwrap_or(200))
        .map_err(|error| SiteCompileError::source(path, error.to_string()))?;
    let (kind, backing) = if let Some(redirect) = &source.response.redirect {
        let status = StatusCode::from_u16(redirect.status)
            .map_err(|error| SiteCompileError::source(path, error.to_string()))?;
        if !status.is_redirection() {
            return Err(SiteCompileError::source(
                path,
                "redirect status must be 3xx",
            ));
        }
        if !redirect.location.contains("{{")
            && (!redirect.location.starts_with('/')
                || redirect.location.starts_with("//")
                || redirect.location.contains('\\'))
        {
            return Err(SiteCompileError::source(
                path,
                "redirect Location must be a local absolute path",
            ));
        }
        let query = match redirect.query {
            RedirectQuerySource::Drop => RedirectQuery::Drop,
            RedirectQuerySource::Preserve => RedirectQuery::Preserve,
            RedirectQuerySource::Replace => {
                return Err(SiteCompileError::source(
                    path,
                    "response.redirect.query `replace` is not supported because Oxista v1 has no replacement query field; use `drop`, `preserve`, or include a fixed query in `location`",
                ));
            }
        };
        (
            SiteResponseKind::Redirect {
                status,
                location: CompiledTemplate::compile(&redirect.location)
                    .map_err(|error| SiteCompileError::source(path, error.to_string()))?,
                query,
            },
            None,
        )
    } else {
        let body = source.response.body.as_ref().ok_or_else(|| {
            SiteCompileError::source(path, "OXR response requires `redirect` or `body`")
        })?;
        compile_oxr_body(
            root,
            path,
            body,
            inline_body,
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

fn compile_oxr_body(
    root: &Path,
    oxr: &Path,
    body: &OxrBodySource,
    inline_body: &str,
    manifest: &ManifestSource,
    templates: &mut BTreeMap<String, CompiledOxt>,
    dependencies: &mut Vec<PathBuf>,
) -> Result<(SiteResponseKind, Option<PathBuf>), SiteCompileError> {
    let selected = usize::from(body.asset.is_some())
        + usize::from(body.template.is_some())
        + usize::from(body.json.is_some())
        + usize::from(body.empty)
        + usize::from(body.text.is_some());
    if selected != 1 {
        return Err(SiteCompileError::source(
            oxr,
            "OXR body must select exactly one of asset, template, json, empty, or text",
        ));
    }
    if let Some(asset) = &body.asset {
        let asset = if asset == "sibling" {
            PathBuf::from(
                oxr.to_string_lossy()
                    .strip_suffix(".oxr")
                    .ok_or_else(|| SiteCompileError::source(oxr, "invalid sibling OXR path"))?,
            )
        } else {
            let relative = Path::new(asset);
            if relative.is_absolute() {
                return Err(SiteCompileError::UnsafePath {
                    path: relative.to_path_buf(),
                    message: "OXR asset path must be relative".to_owned(),
                });
            }
            oxr.parent().unwrap_or(root).join(relative)
        };
        track_site_dependency(dependencies, &asset, root);
        let asset = asset
            .canonicalize()
            .map_err(|error| SiteCompileError::io(&asset, error))?;
        if !path_is_within(&asset, root) || has_source_extension(&asset) {
            return Err(SiteCompileError::UnsafePath {
                path: asset,
                message: "OXR backing asset escapes the root or references source".to_owned(),
            });
        }
        dependencies.push(asset.clone());
        return Ok((
            SiteResponseKind::Asset(Box::new(compile_asset(&asset, manifest)?)),
            Some(asset),
        ));
    }
    if let Some(template) = &body.template {
        return match template {
            TemplateReferenceSource::Inline(kind) if kind == "inline" => {
                if inline_body.is_empty() {
                    return Err(SiteCompileError::source(
                        oxr,
                        "inline template body is empty",
                    ));
                }
                let name = format!(
                    "@inline/{}",
                    oxr.strip_prefix(root).unwrap_or(oxr).to_string_lossy()
                );
                let template = CompiledOxt::inline_with_output(
                    name.clone(),
                    inline_body,
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
            TemplateReferenceSource::Inline(kind) => Err(SiteCompileError::source(
                oxr,
                format!("unknown template mode `{kind}`"),
            )),
            TemplateReferenceSource::External(external) => {
                let name = normalize_template_name(&external.source)?;
                track_site_dependency(dependencies, &root.join(&name), root);
                let template = templates.get(&name).ok_or_else(|| {
                    SiteCompileError::source(oxr, format!("template `{name}` does not exist"))
                })?;
                let arguments = external
                    .arguments
                    .iter()
                    .map(|(name, value)| Ok((name.clone(), compile_value(value, oxr)?)))
                    .collect::<Result<BTreeMap<_, _>, SiteCompileError>>()?;
                template.validate_arguments(&arguments)?;
                Ok((SiteResponseKind::Template { name, arguments }, None))
            }
        };
    }
    if let Some(json) = &body.json {
        return Ok((SiteResponseKind::Json(compile_value(json, oxr)?), None));
    }
    if let Some(text) = &body.text {
        return Ok((
            SiteResponseKind::Text(
                CompiledTemplate::compile(text)
                    .map_err(|error| SiteCompileError::source(oxr, error.to_string()))?,
            ),
            None,
        ));
    }
    Ok((SiteResponseKind::Empty, None))
}

fn compile_value(
    source: &serde_yaml_ng::Value,
    path: &Path,
) -> Result<CompiledValue, SiteCompileError> {
    match source {
        serde_yaml_ng::Value::Mapping(values) if values.len() == 1 => {
            let expression_key = serde_yaml_ng::Value::String("$expr".to_owned());
            if let Some(serde_yaml_ng::Value::String(expression)) = values.get(&expression_key) {
                return Expression::compile(expression)
                    .map(CompiledValue::Expression)
                    .map_err(|error| SiteCompileError::source(path, error.to_string()));
            }
            compile_value_mapping(values, path)
        }
        serde_yaml_ng::Value::Mapping(values) => compile_value_mapping(values, path),
        serde_yaml_ng::Value::Sequence(values) => values
            .iter()
            .map(|value| compile_value(value, path))
            .collect::<Result<Vec<_>, _>>()
            .map(CompiledValue::List),
        serde_yaml_ng::Value::String(value) if value.contains("{{") => {
            CompiledTemplate::compile(value)
                .map(CompiledValue::Template)
                .map_err(|error| SiteCompileError::source(path, error.to_string()))
        }
        value => compile_constant(value).map(CompiledValue::Constant),
    }
}

fn compile_value_mapping(
    values: &serde_yaml_ng::Mapping,
    path: &Path,
) -> Result<CompiledValue, SiteCompileError> {
    values
        .iter()
        .map(|(key, value)| {
            let serde_yaml_ng::Value::String(key) = key else {
                return Err(SiteCompileError::source(path, "map keys must be strings"));
            };
            Ok((key.clone(), compile_value(value, path)?))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()
        .map(CompiledValue::Map)
}

fn compile_constant(source: &serde_yaml_ng::Value) -> Result<Value, SiteCompileError> {
    match source {
        serde_yaml_ng::Value::Null => Ok(Value::Null),
        serde_yaml_ng::Value::Bool(value) => Ok(Value::Bool(*value)),
        serde_yaml_ng::Value::Number(value) => value
            .as_i64()
            .map(Value::Integer)
            .or_else(|| value.as_f64().map(Value::Float))
            .ok_or_else(|| {
                SiteCompileError::source("<value>", "number is outside the supported range")
            }),
        serde_yaml_ng::Value::String(value) => Ok(Value::String(value.clone())),
        serde_yaml_ng::Value::Sequence(values) => values
            .iter()
            .map(compile_constant)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::List),
        serde_yaml_ng::Value::Mapping(values) => values
            .iter()
            .map(|(key, value)| {
                let serde_yaml_ng::Value::String(key) = key else {
                    return Err(SiteCompileError::source(
                        "<value>",
                        "map keys must be strings",
                    ));
                };
                Ok((key.clone(), compile_constant(value)?))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()
            .map(Value::Map),
        serde_yaml_ng::Value::Tagged(_) => Err(SiteCompileError::source(
            "<value>",
            "YAML tags are not supported",
        )),
    }
}

fn compile_response_policy(
    source: &ResponsePolicySource,
    path: &Path,
    field_path: &str,
) -> Result<HeaderPlan, SiteCompileError> {
    let mut headers = compile_headers(&source.headers, path, &format!("{field_path}.headers"))?;
    if let Some(cache) = &source.cache {
        let mut directives = Vec::new();
        if let Some(visibility) = &cache.visibility {
            directives.push(visibility.replace('_', "-"));
        }
        if let Some(max_age) = &cache.max_age {
            directives.push(format!(
                "max-age={}",
                parse_seconds(max_age)
                    .map_err(|message| SiteCompileError::source(path, message))?
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
                CompiledTemplate::compile(directives.join(", "))
                    .map_err(|error| SiteCompileError::source(path, error.to_string()))?,
            ));
        }
    }
    Ok(headers)
}

fn compile_headers(
    source: &HeadersSource,
    path: &Path,
    field_path: &str,
) -> Result<HeaderPlan, SiteCompileError> {
    Ok(HeaderPlan {
        layers: vec![HeaderPolicyLayer {
            set: compile_header_map(&source.set, path, &format!("{field_path}.set"))?,
            add: compile_header_map(&source.add, path, &format!("{field_path}.add"))?,
            remove: source
                .remove
                .iter()
                .enumerate()
                .map(|(index, name)| {
                    compile_user_header_name(name, path, &format!("{field_path}.remove[{index}]"))
                })
                .collect::<Result<Vec<_>, _>>()?,
        }],
    })
}

fn compile_resource_base_policy(
    logical_relative_path: &Path,
    manifest: &ManifestSource,
    source_path: &Path,
) -> Result<HeaderPlan, SiteCompileError> {
    let mut headers = compile_response_policy(
        &manifest.defaults.response,
        source_path,
        "defaults.response",
    )?;
    if let Some(extension) = logical_relative_path
        .extension()
        .map(|extension| format!(".{}", extension.to_string_lossy()))
        && let Some(policy) = manifest.defaults.by_extension.get(&extension)
    {
        headers.merge(compile_response_policy(
            policy,
            source_path,
            &format!("defaults.by_extension[\"{extension}\"]"),
        )?);
    }
    Ok(headers)
}

fn compile_header_map(
    source: &BTreeMap<String, String>,
    path: &Path,
    field_path: &str,
) -> Result<Vec<(HeaderName, CompiledTemplate)>, SiteCompileError> {
    source
        .iter()
        .map(|(name, value)| {
            let header_path = format!("{field_path}.{name}");
            let name = compile_user_header_name(name, path, &header_path)?;
            let template = CompiledTemplate::compile(value).map_err(|error| {
                SiteCompileError::source(path, format!("{header_path}: {error}"))
            })?;
            if template.is_constant() {
                let rendered = template
                    .render(&oxidase_core::EvalContext::default())
                    .map_err(|error| SiteCompileError::source(path, error.to_string()))?;
                HeaderValue::from_str(&rendered).map_err(|_| {
                    SiteCompileError::source(
                        path,
                        format!("{header_path}: header `{name}` has an invalid constant value"),
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
) -> Result<HeaderName, SiteCompileError> {
    let name = HeaderName::from_str(source).map_err(|error| {
        SiteCompileError::source(
            path,
            format!("{field_path}: invalid header name `{source}`: {error}"),
        )
    })?;
    if is_forbidden_user_header(&name) {
        return Err(SiteCompileError::source(
            path,
            format!("{field_path}: header `{name}` is managed by the HTTP response finalizer"),
        ));
    }
    Ok(name)
}

fn compile_asset(path: &Path, source: &ManifestSource) -> Result<AssetPlan, SiteCompileError> {
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
        identity: compile_representation(path, None, source)?,
        brotli: compressed_representation(
            path,
            source.assets.precompressed.brotli.as_deref(),
            ContentEncoding::Brotli,
            source,
        )?,
        gzip: compressed_representation(
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
    path: &Path,
    encoding: Option<ContentEncoding>,
    source: &ManifestSource,
) -> Result<AssetRepresentation, SiteCompileError> {
    let metadata = path
        .metadata()
        .map_err(|error| SiteCompileError::io(path, error))?;
    if !metadata.is_file() {
        return Err(SiteCompileError::source(
            path,
            "asset representation is not a regular file",
        ));
    }
    let etag = match source.assets.etag {
        EtagSource::None => None,
        EtagSource::Weak | EtagSource::Strong => Some(EntityTag::new(
            matches!(source.assets.etag, EtagSource::Weak),
            format!("{:016x}", hash_file(path)?),
        )),
    };
    Ok(AssetRepresentation {
        encoding,
        path: path.to_path_buf(),
        length: metadata.len(),
        etag,
        modified: source
            .assets
            .last_modified
            .then(|| metadata.modified().ok())
            .flatten(),
    })
}

fn compressed_representation(
    path: &Path,
    suffix: Option<&str>,
    encoding: ContentEncoding,
    source: &ManifestSource,
) -> Result<Option<AssetRepresentation>, SiteCompileError> {
    let Some(suffix) = suffix else {
        return Ok(None);
    };
    let candidate = PathBuf::from(format!("{}{}", path.to_string_lossy(), suffix));
    match candidate.metadata() {
        Ok(metadata) if metadata.is_file() => {
            compile_representation(&candidate, Some(encoding), source).map(Some)
        }
        Ok(_) => Err(SiteCompileError::source(
            candidate,
            "precompressed asset is not a regular file",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(SiteCompileError::io(candidate, error)),
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

fn hash_file(path: &Path) -> Result<u64, SiteCompileError> {
    let mut file = fs::File::open(path).map_err(|error| SiteCompileError::io(path, error))?;
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| SiteCompileError::io(path, error))?;
        if read == 0 {
            break;
        }
        for byte in &buffer[..read] {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    Ok(hash)
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

fn read_text(path: &Path) -> Result<String, SiteCompileError> {
    fs::read_to_string(path).map_err(|error| SiteCompileError::io(path, error))
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
) -> Result<T, SiteCompileError> {
    oxidase_source::parse(path, source).map_err(|error| {
        SiteCompileError::source(
            error.path,
            format!(
                "error[{}] at {}:{}: {}",
                error.code, error.line, error.column, error.message
            ),
        )
    })
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

    use super::{SiteCompiler, compile_deny_pattern};
    use crate::{PreparedSiteBody, SiteError};

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
                "profiles.cached.headers.add.Transfer-Encoding",
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
        let message = failure.to_string();
        assert!(message.contains("_templates/404.oxt"), "{message}");
        assert!(message.contains("reason"), "{message}");
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
        let SiteError::TemplateArgument(message) = error else {
            panic!("wrong type must be a template argument error");
        };
        assert!(message.contains("_templates/card.oxt"));
        assert!(message.contains("parameter `count`"));
        assert!(message.contains("expects int, received string"));

        let error = snapshot
            .execute(&request("/bad-url"))
            .expect_err("relative URL must fail at runtime");
        let SiteError::TemplateArgument(message) = error else {
            panic!("wrong URL must be a template argument error");
        };
        assert!(message.contains("parameter `target`"));
        assert!(message.contains("expects url"));
        assert!(message.contains("not an absolute URL"));

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
}
