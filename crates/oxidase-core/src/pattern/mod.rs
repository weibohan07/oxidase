mod error;

use std::collections::{BTreeMap, HashSet};

pub use error::PatternError;
use regex::Regex;

const RE_SLUG: &str = "[A-Za-z0-9_-]+";
const RE_UINT: &str = "[0-9]+";
const RE_INT: &str = "-?[0-9]+";
const RE_HEX: &str = "[0-9A-Fa-f]+";
const RE_ALNUM: &str = "[A-Za-z0-9]+";
const RE_UUID: &str = "[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}";
const RE_LABEL: &str = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternContext {
    Host,
    Path,
    Value,
}

impl PatternContext {
    const fn name(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Path => "path",
            Self::Value => "value",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompiledPattern {
    raw: String,
    context: PatternContext,
    regex: Regex,
    capture_names: Vec<String>,
}

impl CompiledPattern {
    pub fn compile(raw: impl Into<String>, context: PatternContext) -> Result<Self, PatternError> {
        let raw = raw.into();
        let (source, capture_names) = compile_source(&raw, context)?;
        let regex = Regex::new(&source).map_err(|error| PatternError::Regex(error.to_string()))?;
        Ok(Self {
            raw,
            context,
            regex,
            capture_names,
        })
    }

    #[must_use]
    pub fn raw(&self) -> &str {
        &self.raw
    }

    #[must_use]
    pub const fn context(&self) -> PatternContext {
        self.context
    }

    #[must_use]
    pub fn is_match(&self, value: &str) -> bool {
        self.regex.is_match(value)
    }

    #[must_use]
    pub fn captures(&self, value: &str) -> Option<BTreeMap<String, String>> {
        let captures = self.regex.captures(value)?;
        let mut result = BTreeMap::new();
        for name in &self.capture_names {
            if let Some(value) = captures.name(name) {
                result.insert(name.clone(), value.as_str().to_owned());
            }
        }
        Some(result)
    }
}

fn compile_source(
    input: &str,
    context: PatternContext,
) -> Result<(String, Vec<String>), PatternError> {
    let mut output = String::from("^");
    let mut names = Vec::new();
    let mut seen = HashSet::new();
    let mut chars = input.chars().peekable();
    let mut tail_only = false;

    while let Some(character) = chars.next() {
        match character {
            '\\' => {
                let escaped = chars.next().ok_or(PatternError::Unclosed)?;
                output.push_str(&regex::escape(&escaped.to_string()));
            }
            '<' => {
                if tail_only {
                    return Err(PatternError::TailOnlyMustBeLast);
                }
                let mut placeholder = String::new();
                let mut escaped = false;
                let mut closed = false;
                for next in chars.by_ref() {
                    if escaped {
                        placeholder.push(next);
                        escaped = false;
                    } else if next == '\\' {
                        escaped = true;
                    } else if next == '>' {
                        closed = true;
                        break;
                    } else {
                        placeholder.push(next);
                    }
                }
                if !closed || escaped {
                    return Err(PatternError::Unclosed);
                }
                if placeholder.is_empty() {
                    return Err(PatternError::Empty);
                }

                let parsed = Placeholder::parse(&placeholder, context)?;
                let expansion = parsed.kind.expand(context, chars.peek().is_none())?;
                tail_only = expansion.tail_only;
                if let Some(name) = parsed.name {
                    if !seen.insert(name.clone()) {
                        return Err(PatternError::DuplicateCapture(name));
                    }
                    output.push_str("(?P<");
                    output.push_str(&name);
                    output.push('>');
                    output.push_str(&expansion.source);
                    output.push(')');
                    names.push(name);
                } else {
                    output.push_str("(?:");
                    output.push_str(&expansion.source);
                    output.push(')');
                }
            }
            literal => {
                if tail_only {
                    return Err(PatternError::TailOnlyMustBeLast);
                }
                output.push_str(&regex::escape(&literal.to_string()));
            }
        }
    }
    output.push('$');
    Ok((output, names))
}

#[derive(Debug)]
struct Placeholder {
    name: Option<String>,
    kind: PlaceholderKind,
}

impl Placeholder {
    fn parse(source: &str, context: PatternContext) -> Result<Self, PatternError> {
        let (name, kind) = source
            .split_once(':')
            .map_or((source, None), |(name, kind)| (name, Some(kind)));
        let name = if name.is_empty() {
            None
        } else {
            if !is_identifier(name) {
                return Err(PatternError::InvalidCaptureName(name.to_owned()));
            }
            Some(name.to_owned())
        };
        let kind = match kind {
            None | Some("") => PlaceholderKind::default_for(context),
            Some("*") => PlaceholderKind::wildcard_for(context),
            Some(kind) => PlaceholderKind::parse(kind)?,
        };
        Ok(Self { name, kind })
    }
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some('_' | 'a'..='z' | 'A'..='Z'))
        && chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

#[derive(Debug)]
enum PlaceholderKind {
    Segment,
    Path,
    Label,
    Labels,
    Slug,
    Uint,
    Int,
    Hex,
    Alnum,
    Uuid,
    Any,
    Regex(String),
}

impl PlaceholderKind {
    const fn default_for(context: PatternContext) -> Self {
        match context {
            PatternContext::Host => Self::Label,
            PatternContext::Path | PatternContext::Value => Self::Segment,
        }
    }

    const fn wildcard_for(context: PatternContext) -> Self {
        match context {
            PatternContext::Host => Self::Labels,
            PatternContext::Path => Self::Path,
            PatternContext::Value => Self::Any,
        }
    }

    fn parse(source: &str) -> Result<Self, PatternError> {
        match source.trim() {
            "segment" => Ok(Self::Segment),
            "path" => Ok(Self::Path),
            "label" => Ok(Self::Label),
            "labels" => Ok(Self::Labels),
            "slug" => Ok(Self::Slug),
            "uint" => Ok(Self::Uint),
            "int" => Ok(Self::Int),
            "hex" => Ok(Self::Hex),
            "alnum" => Ok(Self::Alnum),
            "uuid" => Ok(Self::Uuid),
            "any" => Ok(Self::Any),
            source if source.starts_with("regex(") && source.ends_with(')') => {
                let argument = &source[6..source.len() - 1];
                let argument = argument
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                    .ok_or_else(|| PatternError::InvalidPlaceholder(source.to_owned()))?;
                validate_restricted_regex(argument)?;
                Ok(Self::Regex(argument.replace("\\\\", "\\")))
            }
            _ => Err(PatternError::InvalidPlaceholder(source.to_owned())),
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Segment => "segment",
            Self::Path => "path",
            Self::Label => "label",
            Self::Labels => "labels",
            Self::Slug => "slug",
            Self::Uint => "uint",
            Self::Int => "int",
            Self::Hex => "hex",
            Self::Alnum => "alnum",
            Self::Uuid => "uuid",
            Self::Any => "any",
            Self::Regex(_) => "regex",
        }
    }

    fn expand(&self, context: PatternContext, is_last: bool) -> Result<Expansion, PatternError> {
        let (source, tail_only) = match (context, self) {
            (PatternContext::Path, Self::Segment) => ("[^/]+".to_owned(), false),
            (PatternContext::Path, Self::Path) => (".+".to_owned(), true),
            (PatternContext::Host, Self::Segment | Self::Label) => (RE_LABEL.to_owned(), false),
            (PatternContext::Host, Self::Labels) => {
                (format!("(?:{RE_LABEL})(?:\\.(?:{RE_LABEL}))*"), false)
            }
            (PatternContext::Value, Self::Segment) => {
                ((if is_last { ".+" } else { ".+?" }).to_owned(), false)
            }
            (PatternContext::Value, Self::Any) => {
                ((if is_last { ".*" } else { ".*?" }).to_owned(), false)
            }
            (_, Self::Slug) => (RE_SLUG.to_owned(), false),
            (_, Self::Uint) => (RE_UINT.to_owned(), false),
            (_, Self::Int) => (RE_INT.to_owned(), false),
            (_, Self::Hex) => (RE_HEX.to_owned(), false),
            (_, Self::Alnum) => (RE_ALNUM.to_owned(), false),
            (_, Self::Uuid) => (RE_UUID.to_owned(), false),
            (_, Self::Regex(source)) => (format!("(?:{source})"), false),
            _ => {
                return Err(PatternError::InvalidTypeForContext {
                    kind: self.name(),
                    context: context.name(),
                });
            }
        };
        Ok(Expansion { source, tail_only })
    }
}

fn validate_restricted_regex(source: &str) -> Result<(), PatternError> {
    // Reject constructs that add captures, assertions, backreferences, or unbounded
    // repetition. Regex still supplies linear-time execution; this subset keeps
    // capture numbering and diagnostics predictable.
    let forbidden = ["(?", "\\k", "\\1", "\\2", "*", "+", "{,"];
    if source.is_empty() || forbidden.iter().any(|needle| source.contains(needle)) {
        return Err(PatternError::UnsafeRegex(source.to_owned()));
    }
    Ok(())
}

struct Expansion {
    source: String,
    tail_only: bool,
}

#[cfg(test)]
mod tests {
    use super::{CompiledPattern, PatternContext, PatternError};

    #[test]
    fn preserves_v01_path_and_capture_semantics() {
        let pattern = CompiledPattern::compile("/post/<slug:slug>", PatternContext::Path)
            .expect("valid path pattern");
        assert!(pattern.is_match("/post/hello-world"));
        assert_eq!(
            pattern
                .captures("/post/hello-world")
                .expect("matching path has captures")
                .get("slug"),
            Some(&"hello-world".to_owned())
        );
        assert!(!pattern.is_match("/post/"));
    }

    #[test]
    fn preserves_v01_host_label_semantics() {
        let pattern = CompiledPattern::compile("<sub:labels>.example.com", PatternContext::Host)
            .expect("valid host pattern");
        assert!(pattern.is_match("x.example.com"));
        assert!(pattern.is_match("a.b.c.example.com"));
        assert_eq!(
            pattern
                .captures("x.example.com")
                .expect("matching host has captures")
                .get("sub"),
            Some(&"x".to_owned())
        );
    }

    #[test]
    fn value_wildcards_are_lazy_until_the_tail() {
        let pattern = CompiledPattern::compile("<:any>bot<:any>", PatternContext::Value)
            .expect("valid wildcard pattern");
        assert!(pattern.is_match("xxbotyy"));
        let suffix = CompiledPattern::compile("<:any>\\.json", PatternContext::Value)
            .expect("valid suffix pattern");
        assert!(suffix.is_match("report.json"));
        assert!(!suffix.is_match("report.json.bak"));
    }

    #[test]
    fn supports_restricted_custom_regex() {
        let pattern =
            CompiledPattern::compile("/u/<id:regex(\"[1-9][0-9]{0,8}\")>", PatternContext::Path)
                .expect("valid restricted regex pattern");
        assert!(pattern.is_match("/u/42"));
        assert!(!pattern.is_match("/u/0"));
    }

    #[test]
    fn path_capture_must_be_last() {
        let error = CompiledPattern::compile("/docs/<rest:path>.html", PatternContext::Path)
            .expect_err("path placeholder before suffix must fail");
        assert_eq!(error, PatternError::TailOnlyMustBeLast);
    }

    #[test]
    fn rejects_duplicate_or_invalid_capture_names() {
        let duplicate =
            CompiledPattern::compile("/<part:segment>/<part:segment>", PatternContext::Path)
                .expect_err("duplicate captures must fail");
        assert_eq!(duplicate, PatternError::DuplicateCapture("part".to_owned()));

        let invalid = CompiledPattern::compile("/<bad-name:segment>", PatternContext::Path)
            .expect_err("invalid identifiers must fail");
        assert_eq!(
            invalid,
            PatternError::InvalidCaptureName("bad-name".to_owned())
        );
    }
}
