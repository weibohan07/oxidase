use super::placeholder::TypeSpec;
use super::PatternError;

/// What a context must provide: how to expand a placeholder type into regex,
/// and whether that expansion is tail-only (i.e., nothing may follow).
pub trait PatternContext {
    fn expand(&self, ty: &TypeSpec, is_last_after: bool) -> Result<Expand, PatternError>;
    fn default_type(&self) -> TypeSpec;
    fn asterisk_type(&self) -> TypeSpec;
}

#[derive(Debug, Clone)]
pub struct Expand {
    pub src: String,
    pub tail_only: bool,
}

#[derive(Debug, Clone, Copy)] pub struct PathCtx;
#[derive(Debug, Clone, Copy)] pub struct HostCtx;
#[derive(Debug, Clone, Copy)] pub struct ValueCtx;

const RE_SLUG: &str = "[A-Za-z0-9_-]+";
const RE_INT: &str = "\\d+";
const RE_HEX: &str = "[0-9a-fA-F]+";
const RE_ALNUM: &str = "[A-Za-z0-9]+";
const RE_UUID: &str = "[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}";

impl PatternContext for PathCtx {
    fn expand(&self, ty: &TypeSpec, _is_last_after: bool) -> Result<Expand, PatternError> {
        use TypeSpec::*;
        Ok(match ty {
            Segment => re("[^/]+"),
            Slug    => re(RE_SLUG),
            Int     => re(RE_INT),
            Hex     => re(RE_HEX),
            Alnum   => re(RE_ALNUM),
            Uuid    => re(RE_UUID),
            Path    => re_tail(".+"),
            Regex(s) => re_group(s),
            RegexPath(s) => re_tail_group(s),
            _ => return Err(PatternError::BadTypeForCtx(name_of(ty))),
        })
    }
    fn default_type(&self) -> TypeSpec { TypeSpec::Segment }
    fn asterisk_type(&self) -> TypeSpec { TypeSpec::Path }
}

impl PatternContext for HostCtx {
    fn expand(&self, ty: &TypeSpec, _is_last_after: bool) -> Result<Expand, PatternError> {
        use TypeSpec::*;
        Ok(match ty {
            Segment => re("[^.]+"),
            Slug    => re(RE_SLUG),
            Int     => re(RE_INT),
            Hex     => re(RE_HEX),
            Alnum   => re(RE_ALNUM),
            Uuid    => re(RE_UUID),
            Label   => re("[a-z0-9-]+"),
            Labels  => re("(?:[a-z0-9-]+(?:\\.[a-z0-9-]+)*)"),
            Regex(s) => re_group(s),
            RegexLabels(s) => re_group(s),
            _ => return Err(PatternError::BadTypeForCtx(name_of(ty))),
        })
    }
    fn default_type(&self) -> TypeSpec { TypeSpec::Segment }
    fn asterisk_type(&self) -> TypeSpec { TypeSpec::Labels }
}

impl PatternContext for ValueCtx {
    fn expand(&self, ty: &TypeSpec, is_last_after: bool) -> Result<Expand, PatternError> {
        use TypeSpec::*;
        Ok(match ty {
            Segment => re(if is_last_after { ".+" } else { ".+?" }),
            Any     => re(if is_last_after { ".*" } else { ".*?" }),
            Slug    => re(RE_SLUG),
            Int     => re(RE_INT),
            Hex     => re(RE_HEX),
            Alnum   => re(RE_ALNUM),
            Uuid    => re(RE_UUID),
            Regex(s) => re_group(s),
            _ => return Err(PatternError::BadTypeForCtx(name_of(ty))),
        })
    }
    fn default_type(&self) -> TypeSpec { TypeSpec::Segment }
    fn asterisk_type(&self) -> TypeSpec { TypeSpec::Any }
}

fn re(s: &str) -> Expand { Expand { src: s.to_string(), tail_only: false } }
fn re_group(s: &str) -> Expand { Expand { src: format!("(?:{})", s), tail_only: false } }
fn re_tail(s: &str) -> Expand { Expand { src: s.to_string(), tail_only: true } }
fn re_tail_group(s: &str) -> Expand { Expand { src: format!("(?:{})", s), tail_only: true } }

fn name_of(ty: &TypeSpec) -> &'static str {
    use TypeSpec::*;
    match ty {
        Segment => "segment",
        Slug => "slug",
        Int => "int",
        Hex => "hex",
        Alnum => "alnum",
        Uuid => "uuid",
        Path => "path",
        Label => "label",
        Labels => "labels",
        Any => "any",
        Regex(_) => "regex",
        RegexPath(_) => "regex_path",
        RegexLabels(_) => "regex_labels",
    }
}
