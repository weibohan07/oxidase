use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, UNIX_EPOCH};

use http::{HeaderName, HeaderValue, StatusCode};
use oxidase_core::{CompiledTemplate, Expression, ResourceId, Value, is_forbidden_user_header};
use walkdir::WalkDir;

use crate::error::SiteCompileError;
use crate::runtime::{
    AssetPlan, CompressedAsset, HeaderPlan, RedirectQuery, SiteMissing, SiteResponseKind,
    SiteResponsePlan, SiteSnapshot, path_is_within,
};
use crate::source::{
    AutoescapeSource, EtagSource, HeadersSource, IndexCanonicalSource, ManifestSource,
    MissingSource, OxrBodySource, OxrSource, RedirectQuerySource, ResponsePolicySource,
    SymlinkModeSource, TemplateReferenceSource, VisibilityModeSource,
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
    ) -> Result<SiteSnapshot, SiteCompileError> {
        let root = root
            .as_ref()
            .canonicalize()
            .map_err(|error| SiteCompileError::io(root.as_ref(), error))?;
        let manifest = manifest
            .as_ref()
            .canonicalize()
            .map_err(|error| SiteCompileError::io(manifest.as_ref(), error))?;
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

        let mut files = collect_files(&root, &source)?;
        files.sort();
        let template_roots = template_roots(&root, &source)?;
        let mut dependencies = vec![manifest.clone()];
        let mut templates = compile_templates(&root, &files, &template_roots, &mut dependencies)?;
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
            if is_private(relative, &source, &template_roots, &root) {
                continue;
            }
            dependencies.push(oxr.clone());
            let (logical_path, plan, backing) =
                compile_oxr(&root, oxr, &source, &mut templates, &mut dependencies)?;
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
            if is_private(relative, &source, &template_roots, &root) {
                continue;
            }
            let logical_path = logical_path(relative);
            let plan = SiteResponsePlan {
                status: StatusCode::OK,
                headers: compile_response_policy(
                    &source.defaults.response,
                    &manifest,
                    "defaults.response",
                )?,
                content_type: None,
                page: BTreeMap::new(),
                kind: SiteResponseKind::Asset(compile_asset(asset, &source)?),
                source: asset.clone(),
            };
            insert_with_index_aliases(&mut entries, logical_path, plan, &source)?;
            dependencies.push(asset.clone());
        }
        validate_template_graph(&templates)?;

        let error_404_template = source
            .errors
            .get(&404)
            .map(|error| normalize_template_name(&error.template))
            .transpose()?;
        if let Some(name) = &error_404_template
            && !templates.contains_key(name)
        {
            return Err(SiteCompileError::source(
                &manifest,
                format!("404 error template `{name}` does not exist"),
            ));
        }

        dependencies.sort();
        dependencies.dedup();
        Ok(SiteSnapshot {
            id,
            root,
            manifest,
            dependencies,
            missing: match source.paths.missing {
                MissingSource::Decline => SiteMissing::Decline,
                MissingSource::Respond => SiteMissing::Respond,
            },
            data,
            limits,
            templates,
            entries,
            error_404_template,
        })
    }
}

fn validate_manifest(
    path: &Path,
    source: &ManifestSource,
    inputs: &BTreeMap<String, Value>,
) -> Result<(), SiteCompileError> {
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
    for (name, contract) in &source.inputs {
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
    Ok(())
}

fn input_accepts(kind: &str, value: &Value) -> bool {
    match kind {
        "any" => true,
        "null" => value.is_null(),
        "bool" => matches!(value, Value::Bool(_)),
        "int" => matches!(value, Value::Integer(_)),
        "float" => matches!(value, Value::Integer(_) | Value::Float(_)),
        "string" | "safe_html" => matches!(value, Value::String(_)),
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

fn collect_files(root: &Path, source: &ManifestSource) -> Result<Vec<PathBuf>, SiteCompileError> {
    let mut files = Vec::new();
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.map_err(|error| {
            let path = error
                .path()
                .map_or_else(|| root.to_path_buf(), Path::to_path_buf);
            SiteCompileError::source(path, error.to_string())
        })?;
        if entry.path() == root {
            continue;
        }
        if entry.file_type().is_symlink() {
            let canonical = entry
                .path()
                .canonicalize()
                .map_err(|error| SiteCompileError::io(entry.path(), error))?;
            if source.visibility.symlinks == SymlinkModeSource::Deny
                || !path_is_within(&canonical, root)
            {
                return Err(SiteCompileError::UnsafePath {
                    path: entry.path().to_path_buf(),
                    message: "symlink is denied or escapes the site root".to_owned(),
                });
            }
            if canonical.is_dir() {
                return Err(SiteCompileError::UnsafePath {
                    path: entry.path().to_path_buf(),
                    message: "directory symlinks are not traversed in Oxista v1".to_owned(),
                });
            }
            files.push(canonical);
        } else if entry.file_type().is_file() {
            files.push(entry.path().to_path_buf());
        }
    }
    Ok(files)
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
        let template = CompiledOxt::compile(name.clone(), &metadata, body)?;
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
    let extension = relative_without_oxr
        .extension()
        .map(|extension| format!(".{}", extension.to_string_lossy()));
    let mut headers =
        compile_response_policy(&manifest.defaults.response, path, "defaults.response")?;
    if let Some(extension) = extension.as_ref()
        && let Some(policy) = manifest.defaults.by_extension.get(extension)
    {
        headers.merge(compile_response_policy(
            policy,
            path,
            &format!("defaults.by_extension.{extension}"),
        )?);
    }
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
        (
            SiteResponseKind::Redirect {
                status,
                location: CompiledTemplate::compile(&redirect.location)
                    .map_err(|error| SiteCompileError::source(path, error.to_string()))?,
                query: match redirect.query {
                    RedirectQuerySource::Drop => RedirectQuery::Drop,
                    RedirectQuerySource::Preserve => RedirectQuery::Preserve,
                    RedirectQuerySource::Replace => RedirectQuery::Replace,
                },
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
            SiteResponseKind::Asset(compile_asset(&asset, manifest)?),
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
                let template = CompiledOxt::inline(
                    name.clone(),
                    inline_body,
                    matches!(
                        manifest.templates.default_autoescape,
                        AutoescapeSource::Html
                    ),
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
            headers.set.push((
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
    })
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
    let metadata = path
        .metadata()
        .map_err(|error| SiteCompileError::io(path, error))?;
    if !metadata.is_file() {
        return Err(SiteCompileError::source(
            path,
            "asset is not a regular file",
        ));
    }
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
    let modified = if source.assets.last_modified {
        metadata.modified().ok()
    } else {
        None
    };
    let etag = match source.assets.etag {
        EtagSource::None => None,
        EtagSource::Weak => Some(format!(
            "W/\"{:x}-{:x}\"",
            metadata.len(),
            modified
                .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
                .map_or(0, |value| value.as_secs())
        )),
        EtagSource::Strong => Some(format!("\"{:016x}\"", hash_file(path)?)),
    };
    Ok(AssetPlan {
        path: path.to_path_buf(),
        length: metadata.len(),
        modified,
        etag,
        content_type,
        range_requests: source.assets.range_requests,
        brotli: compressed_asset(path, source.assets.precompressed.brotli.as_deref())?,
        gzip: compressed_asset(path, source.assets.precompressed.gzip.as_deref())?,
    })
}

fn compressed_asset(
    path: &Path,
    suffix: Option<&str>,
) -> Result<Option<CompressedAsset>, SiteCompileError> {
    let Some(suffix) = suffix else {
        return Ok(None);
    };
    let candidate = PathBuf::from(format!("{}{}", path.to_string_lossy(), suffix));
    match candidate.metadata() {
        Ok(metadata) if metadata.is_file() => Ok(Some(CompressedAsset {
            path: candidate,
            length: metadata.len(),
        })),
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
) -> bool {
    if template_roots
        .iter()
        .filter_map(|root| root.strip_prefix(site_root).ok())
        .any(|root| relative.starts_with(root))
    {
        return true;
    }
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
            .take(components.len().saturating_sub(1))
            .any(|component| component.starts_with('_'))
    {
        return true;
    }
    let value = relative.to_string_lossy().replace('\\', "/");
    source.visibility.deny.iter().any(|pattern| {
        pattern
            .strip_prefix("**/*")
            .is_some_and(|suffix| value.ends_with(suffix))
            || pattern
                .strip_prefix("**/")
                .is_some_and(|suffix| value.ends_with(suffix))
            || value == *pattern
    })
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
    reject_duplicate_keys(path, source)?;
    serde_yaml_ng::from_str(source)
        .map_err(|error| SiteCompileError::source(path, error.to_string()))
}

fn reject_duplicate_keys(path: &Path, source: &str) -> Result<(), SiteCompileError> {
    let mut frames = Vec::<(usize, BTreeSet<String>)>::new();
    for (line_number, raw) in source.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim_end();
        if line.trim().is_empty() {
            continue;
        }
        let indent = raw.len() - raw.trim_start_matches(' ').len();
        let trimmed = line.trim_start();
        let (indent, content, sequence) = trimmed
            .strip_prefix("- ")
            .map_or((indent, trimmed, false), |content| {
                (indent + 2, content, true)
            });
        if sequence {
            while frames.last().is_some_and(|frame| frame.0 >= indent) {
                frames.pop();
            }
        } else {
            while frames.last().is_some_and(|frame| frame.0 > indent) {
                frames.pop();
            }
        }
        let Some((key, _)) = content.split_once(':') else {
            continue;
        };
        let key = key.trim().trim_matches(['\'', '"']).to_owned();
        if frames.last().is_none_or(|frame| frame.0 < indent) {
            frames.push((indent, BTreeSet::new()));
        }
        if !frames
            .last_mut()
            .expect("mapping frame exists")
            .1
            .insert(key.clone())
        {
            return Err(SiteCompileError::source(
                path,
                format!("duplicate key `{key}` on line {}", line_number + 1),
            ));
        }
    }
    Ok(())
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

    use super::SiteCompiler;
    use crate::PreparedSiteBody;

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
        RequestFrame::new(RequestMetadata::new(
            Method::GET,
            "http",
            "example.com",
            path,
            HeaderMap::new(),
        ))
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
}
