use std::collections::BTreeMap;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManifestSource {
    pub oxista: String,
    #[serde(default)]
    pub paths: PathsSource,
    #[serde(default)]
    pub visibility: VisibilitySource,
    #[serde(default)]
    pub assets: AssetsSource,
    #[serde(default)]
    pub templates: TemplatesSource,
    #[serde(default)]
    pub inputs: BTreeMap<String, InputSource>,
    #[serde(default)]
    pub data: BTreeMap<String, serde_yaml_ng::Value>,
    #[serde(default)]
    pub defaults: DefaultsSource,
    #[serde(default)]
    pub profiles: BTreeMap<String, ResponsePolicySource>,
    #[serde(default)]
    pub errors: BTreeMap<u16, ErrorPageSource>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct PathsSource {
    pub indexes: Vec<String>,
    pub index_canonical: IndexCanonicalSource,
    pub clean_html_urls: bool,
    pub trailing_slash: TrailingSlashSource,
    pub directory_listing: bool,
    pub missing: MissingSource,
}

impl Default for PathsSource {
    fn default() -> Self {
        Self {
            indexes: vec!["index.html".to_owned(), "index.htm".to_owned()],
            index_canonical: IndexCanonicalSource::Directory,
            clean_html_urls: false,
            trailing_slash: TrailingSlashSource::Canonical,
            directory_listing: false,
            missing: MissingSource::Decline,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum IndexCanonicalSource {
    #[default]
    Directory,
    File,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TrailingSlashSource {
    #[default]
    Canonical,
    Preserve,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MissingSource {
    #[default]
    Decline,
    Respond,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct VisibilitySource {
    pub dotfiles: VisibilityModeSource,
    pub underscore_directories: VisibilityModeSource,
    pub symlinks: SymlinkModeSource,
    pub deny: Vec<String>,
}

impl Default for VisibilitySource {
    fn default() -> Self {
        Self {
            dotfiles: VisibilityModeSource::Deny,
            underscore_directories: VisibilityModeSource::Private,
            symlinks: SymlinkModeSource::WithinRoot,
            deny: vec![
                "**/*.pem".to_owned(),
                "**/*.key".to_owned(),
                "**/*.secret".to_owned(),
            ],
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VisibilityModeSource {
    Allow,
    #[default]
    Deny,
    Private,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SymlinkModeSource {
    Deny,
    #[default]
    WithinRoot,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct AssetsSource {
    pub range_requests: bool,
    pub etag: EtagSource,
    pub last_modified: bool,
    pub precompressed: PrecompressedSource,
    pub mime_overrides: BTreeMap<String, String>,
}

impl Default for AssetsSource {
    fn default() -> Self {
        Self {
            range_requests: true,
            etag: EtagSource::Strong,
            last_modified: true,
            precompressed: PrecompressedSource::default(),
            mime_overrides: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EtagSource {
    None,
    Weak,
    #[default]
    Strong,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct PrecompressedSource {
    pub brotli: Option<String>,
    pub gzip: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct TemplatesSource {
    pub roots: Vec<String>,
    pub strict_undefined: bool,
    pub default_output: OutputSource,
    pub default_autoescape: AutoescapeSource,
    pub limits: LimitsSource,
}

impl Default for TemplatesSource {
    fn default() -> Self {
        Self {
            roots: vec!["_templates".to_owned()],
            strict_undefined: true,
            default_output: OutputSource::Html,
            default_autoescape: AutoescapeSource::Html,
            limits: LimitsSource::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OutputSource {
    #[default]
    Html,
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AutoescapeSource {
    #[default]
    Html,
    None,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct LimitsSource {
    pub render_time: String,
    pub output_size: String,
    pub loop_iterations: usize,
    pub include_depth: usize,
    pub expression_steps: usize,
}

impl Default for LimitsSource {
    fn default() -> Self {
        Self {
            render_time: "25ms".to_owned(),
            output_size: "2MiB".to_owned(),
            loop_iterations: 10_000,
            include_depth: 32,
            expression_steps: 100_000,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InputSource {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DefaultsSource {
    #[serde(default)]
    pub response: ResponsePolicySource,
    #[serde(default)]
    pub by_extension: BTreeMap<String, ResponsePolicySource>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResponsePolicySource {
    #[serde(default)]
    pub headers: HeadersSource,
    pub cache: Option<CacheSource>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CacheSource {
    pub visibility: Option<String>,
    pub max_age: Option<String>,
    #[serde(default)]
    pub immutable: bool,
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ErrorPageSource {
    pub template: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OxrSource {
    pub oxista: String,
    #[serde(default)]
    pub apply: Vec<String>,
    #[serde(default)]
    pub page: BTreeMap<String, serde_yaml_ng::Value>,
    pub response: OxrResponseSource,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OxrResponseSource {
    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub redirect: Option<RedirectSource>,
    #[serde(default)]
    pub headers: HeadersSource,
    pub body: Option<OxrBodySource>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RedirectSource {
    pub status: u16,
    pub location: String,
    #[serde(default)]
    pub query: RedirectQuerySource,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RedirectQuerySource {
    Drop,
    #[default]
    Preserve,
    Replace,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OxrBodySource {
    pub asset: Option<String>,
    pub template: Option<TemplateReferenceSource>,
    pub json: Option<serde_yaml_ng::Value>,
    #[serde(default)]
    pub empty: bool,
    pub text: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum TemplateReferenceSource {
    Inline(String),
    External(ExternalTemplateSource),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExternalTemplateSource {
    pub source: String,
    #[serde(default, rename = "with")]
    pub arguments: BTreeMap<String, serde_yaml_ng::Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OxtMetadataSource {
    pub oxista: String,
    #[serde(default)]
    pub output: OutputSource,
    #[serde(default)]
    pub autoescape: AutoescapeSource,
    #[serde(default)]
    pub params: BTreeMap<String, String>,
}
