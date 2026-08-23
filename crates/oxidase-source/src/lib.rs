//! Shared strict source parsing for Gateway and Oxista YAML documents.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::de::DeserializeOwned;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("error[{code}]: {message} at {path}:{line}:{column}")]
pub struct StrictYamlError {
    pub code: &'static str,
    pub message: String,
    pub path: PathBuf,
    pub line: usize,
    pub column: usize,
    pub help: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRange {
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSpan {
    pub field_path: String,
    pub key: SourceRange,
    pub value: SourceRange,
}

#[derive(Debug, Clone, Default)]
pub struct FieldSpanIndex {
    spans: BTreeMap<String, FieldSpan>,
}

impl FieldSpanIndex {
    #[must_use]
    pub fn get(&self, field_path: &str) -> Option<&FieldSpan> {
        self.spans.get(field_path)
    }

    /// Resolves an exact field first, then its nearest indexed parent.
    #[must_use]
    pub fn nearest(&self, field_path: &str) -> Option<&FieldSpan> {
        let mut candidate = field_path;
        loop {
            if let Some(span) = self.get(candidate) {
                return Some(span);
            }
            let dot = candidate.rfind('.');
            let bracket = candidate.rfind('[');
            let boundary = dot.into_iter().chain(bracket).max()?;
            candidate = &candidate[..boundary];
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &FieldSpan)> {
        self.spans.iter().map(|(path, span)| (path.as_str(), span))
    }
}

#[derive(Debug, Clone)]
pub struct SourceDocument<T> {
    pub value: T,
    pub path: PathBuf,
    pub text: Arc<str>,
    pub spans: FieldSpanIndex,
}

/// Parses the deliberately small YAML subset shared by every Oxidase source
/// format. Flow sequences are allowed; flow mappings and YAML graph features
/// are not.
pub fn parse<T: DeserializeOwned>(path: &Path, source: &str) -> Result<T, StrictYamlError> {
    parse_document(path, source).map(|document| document.value)
}

/// Parses a strict YAML document while retaining its original text and a
/// lightweight field-path span index for semantic diagnostics.
pub fn parse_document<T: DeserializeOwned>(
    path: &Path,
    source: &str,
) -> Result<SourceDocument<T>, StrictYamlError> {
    validate_subset(path, source)?;
    let value = serde_yaml_ng::from_str(source).map_err(|error| {
        let location = error.location();
        let (line, column) = location
            .map(|location| (location.line(), location.column()))
            .unwrap_or((1, 1));
        StrictYamlError {
            code: "source.parse",
            message: error.to_string(),
            path: path.to_path_buf(),
            line,
            column,
            help: Some("remove unknown fields and ensure every value has the documented type"),
        }
    })?;
    Ok(SourceDocument {
        value,
        path: path.to_path_buf(),
        text: Arc::from(source),
        spans: build_field_span_index(source),
    })
}

#[derive(Debug)]
struct SpanFrame {
    indent: usize,
    path: String,
    next_sequence_index: usize,
}

fn build_field_span_index(source: &str) -> FieldSpanIndex {
    let mut spans = BTreeMap::new();
    let mut frames = Vec::<SpanFrame>::new();
    let mut root_sequence_index = 0usize;
    let mut block_scalar = None::<BlockScalarState>;
    let mut byte_offset = 0usize;

    for (line_index, physical_line) in source.split_inclusive('\n').enumerate() {
        let line_with_cr = physical_line.strip_suffix('\n').unwrap_or(physical_line);
        let raw_line = line_with_cr.strip_suffix('\r').unwrap_or(line_with_cr);
        let indent = raw_line.len() - raw_line.trim_start_matches(' ').len();
        if let Some(state) = block_scalar.as_mut() {
            if raw_line.trim().is_empty() {
                byte_offset += physical_line.len();
                continue;
            }
            if indent > state.base_indent {
                let required_indent = state
                    .explicit_indent
                    .map(|explicit| state.base_indent + explicit)
                    .unwrap_or(indent);
                state.content_indent.get_or_insert(required_indent);
                byte_offset += physical_line.len();
                continue;
            }
            block_scalar = None;
        }

        let structural_line = strip_comment(raw_line);
        let trimmed = structural_line.trim();
        if trimmed.is_empty() || matches!(trimmed, "---" | "...") {
            byte_offset += physical_line.len();
            continue;
        }
        let trimmed_start = structural_line.find(trimmed).unwrap_or(indent);
        let starts_sequence_item = trimmed == "-" || trimmed.starts_with("- ");
        let (content, content_start, mapping_indent, item_path) =
            if let Some(rest) = trimmed.strip_prefix("- ") {
                while frames.last().is_some_and(|frame| indent <= frame.indent) {
                    frames.pop();
                }
                let parent_path = frames
                    .last()
                    .map(|frame| frame.path.clone())
                    .unwrap_or_default();
                let index = if let Some(parent) = frames.last_mut() {
                    let index = parent.next_sequence_index;
                    parent.next_sequence_index += 1;
                    index
                } else {
                    let index = root_sequence_index;
                    root_sequence_index += 1;
                    index
                };
                let item_path = format!("{parent_path}[{index}]");
                frames.push(SpanFrame {
                    indent,
                    path: item_path.clone(),
                    next_sequence_index: 0,
                });
                let rest = rest.trim_start();
                let rest_offset = trimmed.len() - rest.len();
                (rest, trimmed_start + rest_offset, indent + 2, item_path)
            } else if trimmed == "-" {
                while frames.last().is_some_and(|frame| indent <= frame.indent) {
                    frames.pop();
                }
                let parent_path = frames
                    .last()
                    .map(|frame| frame.path.clone())
                    .unwrap_or_default();
                let index = if let Some(parent) = frames.last_mut() {
                    let index = parent.next_sequence_index;
                    parent.next_sequence_index += 1;
                    index
                } else {
                    let index = root_sequence_index;
                    root_sequence_index += 1;
                    index
                };
                let item_path = format!("{parent_path}[{index}]");
                frames.push(SpanFrame {
                    indent,
                    path: item_path.clone(),
                    next_sequence_index: 0,
                });
                ("", trimmed_start + 1, indent + 2, item_path)
            } else {
                while frames.last().is_some_and(|frame| indent <= frame.indent) {
                    frames.pop();
                }
                let parent = frames
                    .last()
                    .map(|frame| frame.path.clone())
                    .unwrap_or_default();
                (trimmed, trimmed_start, indent, parent)
            };

        if let Some(entry) = mapping_entry_detail(content) {
            let field_path = append_field_path(&item_path, &entry.key);
            let key_start = content_start + entry.key_column;
            let key_end = key_start + entry.raw_key_len;
            let key = source_range(raw_line, byte_offset, line_index, key_start, key_end);
            let value = if entry.value.is_empty() {
                key.clone()
            } else {
                let value_start = content_start + entry.value_column;
                source_range(
                    raw_line,
                    byte_offset,
                    line_index,
                    value_start,
                    value_start + entry.value.len(),
                )
            };
            let field_span = FieldSpan {
                field_path: field_path.clone(),
                key,
                value,
            };
            spans.insert(field_path.clone(), field_span.clone());
            if !valid_field_component(&entry.key) {
                let legacy_path = if item_path.is_empty() {
                    entry.key.clone()
                } else {
                    format!("{item_path}.{}", entry.key)
                };
                spans.entry(legacy_path).or_insert(field_span);
            }
            if entry.value.is_empty() {
                frames.push(SpanFrame {
                    indent: mapping_indent,
                    path: field_path,
                    next_sequence_index: 0,
                });
            }
        } else if starts_sequence_item && !content.is_empty() {
            let value = source_range(
                raw_line,
                byte_offset,
                line_index,
                content_start,
                content_start + content.len(),
            );
            spans.insert(
                item_path.clone(),
                FieldSpan {
                    field_path: item_path.clone(),
                    key: value.clone(),
                    value,
                },
            );
        }
        if let Some(explicit_indent) = block_scalar_indicator(content, starts_sequence_item) {
            block_scalar = Some(BlockScalarState {
                base_indent: mapping_indent,
                explicit_indent,
                content_indent: None,
            });
        }
        byte_offset += physical_line.len();
    }
    FieldSpanIndex { spans }
}

fn append_field_path(parent: &str, key: &str) -> String {
    if valid_field_component(key) {
        if parent.is_empty() {
            key.to_owned()
        } else {
            format!("{parent}.{key}")
        }
    } else {
        let escaped = key.replace('\\', "\\\\").replace('"', "\\\"");
        format!("{parent}[\"{escaped}\"]")
    }
}

fn valid_field_component(value: &str) -> bool {
    let mut characters = value.chars();
    matches!(characters.next(), Some('_' | 'a'..='z' | 'A'..='Z'))
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn source_range(
    raw_line: &str,
    byte_offset: usize,
    zero_based_line: usize,
    start: usize,
    end: usize,
) -> SourceRange {
    SourceRange {
        start_byte: byte_offset + start,
        end_byte: byte_offset + end,
        start_line: zero_based_line + 1,
        start_column: raw_line[..start].chars().count() + 1,
        end_line: zero_based_line + 1,
        end_column: raw_line[..end].chars().count() + 1,
    }
}

fn validate_subset(path: &Path, source: &str) -> Result<(), StrictYamlError> {
    let mut mappings = Vec::<MappingFrame>::new();
    let mut block_scalar = None::<BlockScalarState>;
    for (line_index, raw_line) in source.lines().enumerate() {
        let indent = raw_line.len() - raw_line.trim_start_matches(' ').len();
        if let Some(state) = block_scalar.as_mut() {
            if raw_line.trim().is_empty() {
                continue;
            }
            if indent > state.base_indent {
                let required_indent = state
                    .explicit_indent
                    .map(|explicit| state.base_indent + explicit)
                    .unwrap_or(indent);
                state.content_indent.get_or_insert(required_indent);
                continue;
            }
            block_scalar = None;
        }
        if let Some(column) = indentation_tab(raw_line) {
            return Err(error(
                path,
                line_index,
                column,
                "source.tabs",
                "tabs are not allowed for YAML indentation",
                None,
            ));
        }
        let line = strip_comment(raw_line);
        let trimmed = line.trim();
        if trimmed.is_empty() || matches!(trimmed, "---" | "...") {
            continue;
        }
        if let Some(column) = find_unquoted(trimmed, '{') {
            return Err(error(
                path,
                line_index,
                raw_line.find(trimmed).unwrap_or(0) + column + 1,
                "source.flow_mapping",
                "flow-style mappings are not supported in strict source YAML",
                Some("write this mapping in indented block style"),
            ));
        }
        let structural_content = trimmed.strip_prefix("- ").unwrap_or(trimmed).trim_start();
        if let Some((key, key_column)) = mapping_key(structural_content)
            && key == "<<"
        {
            return Err(error(
                path,
                line_index,
                raw_line.find(structural_content).unwrap_or(0) + key_column + 1,
                "source.merge_key",
                "YAML merge keys are not supported in Oxidase source",
                Some("write each mapping key explicitly"),
            ));
        }
        for (indicator, code, message) in [
            (
                '&',
                "source.anchor",
                "YAML anchors are not supported in Oxidase source",
            ),
            (
                '*',
                "source.alias",
                "YAML aliases are not supported in Oxidase source",
            ),
            (
                '!',
                "source.tag",
                "custom YAML tags are not supported in Oxidase source",
            ),
        ] {
            if let Some(column) = find_indicator_token(trimmed, indicator) {
                return Err(error(
                    path,
                    line_index,
                    raw_line.find(trimmed).unwrap_or(0) + column + 1,
                    code,
                    message,
                    Some("use plain YAML values and Oxidase imports instead"),
                ));
            }
        }

        let (mapping_indent, content, starts_sequence_item) =
            if let Some(rest) = trimmed.strip_prefix("- ") {
                (indent + 2, rest, true)
            } else if trimmed == "-" {
                (indent + 2, "", true)
            } else {
                (indent, trimmed, false)
            };

        if starts_sequence_item {
            while mappings
                .last()
                .is_some_and(|frame| frame.indent >= mapping_indent)
            {
                mappings.pop();
            }
        } else {
            while mappings
                .last()
                .is_some_and(|frame| frame.indent > mapping_indent)
            {
                mappings.pop();
            }
        }

        let scalar_indicator = block_scalar_indicator(content, starts_sequence_item);
        let Some((key, key_column)) = mapping_key(content) else {
            if let Some(explicit_indent) = scalar_indicator {
                block_scalar = Some(BlockScalarState {
                    base_indent: indent,
                    explicit_indent,
                    content_indent: None,
                });
            }
            continue;
        };
        if key == "<<" {
            return Err(error(
                path,
                line_index,
                indent + key_column + 1,
                "source.merge_key",
                "YAML merge keys are not supported in Oxidase source",
                Some("write each mapping key explicitly"),
            ));
        }
        if mappings
            .last()
            .is_none_or(|frame| frame.indent < mapping_indent)
        {
            mappings.push(MappingFrame {
                indent: mapping_indent,
                keys: BTreeSet::new(),
            });
        }
        let frame = mappings.last_mut().expect("mapping frame was just created");
        if !frame.keys.insert(key.clone()) {
            return Err(error(
                path,
                line_index,
                indent + key_column + 1,
                "source.duplicate_key",
                format!("duplicate mapping key `{key}`"),
                None,
            ));
        }
        if let Some(explicit_indent) = scalar_indicator {
            block_scalar = Some(BlockScalarState {
                base_indent: mapping_indent,
                explicit_indent,
                content_indent: None,
            });
        }
    }
    Ok(())
}

struct BlockScalarState {
    base_indent: usize,
    explicit_indent: Option<usize>,
    content_indent: Option<usize>,
}

struct MappingFrame {
    indent: usize,
    keys: BTreeSet<String>,
}

fn error(
    path: &Path,
    zero_based_line: usize,
    column: usize,
    code: &'static str,
    message: impl Into<String>,
    help: Option<&'static str>,
) -> StrictYamlError {
    StrictYamlError {
        code,
        message: message.into(),
        path: path.to_path_buf(),
        line: zero_based_line + 1,
        column,
        help,
    }
}

fn indentation_tab(line: &str) -> Option<usize> {
    for (index, byte) in line.bytes().enumerate() {
        match byte {
            b' ' => {}
            b'\t' => return Some(index + 1),
            _ => return None,
        }
    }
    None
}

fn strip_comment(line: &str) -> &str {
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' && quote == Some('"') {
            escaped = true;
        } else if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            }
        } else if character == '#' && quote.is_none() {
            return &line[..index];
        }
    }
    line
}

fn find_unquoted(value: &str, needle: char) -> Option<usize> {
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' && quote == Some('"') {
            escaped = true;
        } else if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            }
        } else if quote.is_none() && character == needle {
            return Some(index);
        }
    }
    None
}

fn find_indicator_token(value: &str, indicator: char) -> Option<usize> {
    let mut quote = None;
    let mut escaped = false;
    let mut previous = None;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' && quote == Some('"') {
            escaped = true;
        } else if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            }
        } else if quote.is_none()
            && character == indicator
            && previous.is_none_or(|previous: char| {
                previous.is_whitespace() || matches!(previous, ':' | '-' | '[' | ',' | '?')
            })
        {
            return Some(index);
        }
        previous = Some(character);
    }
    None
}

fn mapping_key(content: &str) -> Option<(String, usize)> {
    mapping_entry_detail(content).map(|entry| (entry.key, entry.key_column))
}

struct MappingEntry<'a> {
    key: String,
    key_column: usize,
    raw_key_len: usize,
    value: &'a str,
    value_column: usize,
}

fn mapping_entry_detail(content: &str) -> Option<MappingEntry<'_>> {
    let mut quote = None;
    let mut escaped = false;
    let mut bracket_depth = 0usize;
    for (index, character) in content.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' && quote == Some('"') {
            escaped = true;
        } else if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            }
        } else if quote.is_none() {
            match character {
                '[' => bracket_depth += 1,
                ']' => bracket_depth = bracket_depth.saturating_sub(1),
                ':' if bracket_depth == 0 => {
                    let raw_key = content[..index].trim();
                    if raw_key.is_empty() {
                        return None;
                    }
                    let column = content[..index].find(raw_key).unwrap_or(0);
                    let key = raw_key
                        .strip_prefix('"')
                        .and_then(|key| key.strip_suffix('"'))
                        .or_else(|| {
                            raw_key
                                .strip_prefix('\'')
                                .and_then(|key| key.strip_suffix('\''))
                        })
                        .unwrap_or(raw_key)
                        .to_owned();
                    let after_colon = &content[index + 1..];
                    let value = after_colon.trim();
                    let value_column =
                        index + 1 + after_colon.find(value).unwrap_or(after_colon.len());
                    return Some(MappingEntry {
                        key,
                        key_column: column,
                        raw_key_len: raw_key.len(),
                        value,
                        value_column,
                    });
                }
                _ => {}
            }
        }
    }
    None
}

fn block_scalar_indicator(content: &str, starts_sequence_item: bool) -> Option<Option<usize>> {
    let value = mapping_entry_detail(content)
        .map(|entry| entry.value)
        .or_else(|| starts_sequence_item.then_some(content.trim()))?;
    parse_block_scalar_indicator(value)
}

fn parse_block_scalar_indicator(value: &str) -> Option<Option<usize>> {
    let mut characters = value.chars();
    if !matches!(characters.next(), Some('|' | '>')) {
        return None;
    }
    let mut chomping = false;
    let mut indentation = None;
    for character in characters {
        match character {
            '+' | '-' if !chomping => chomping = true,
            '1'..='9' if indentation.is_none() => {
                indentation = character.to_digit(10).map(|value| value as usize);
            }
            _ => return None,
        }
    }
    Some(indentation)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde::Deserialize;

    use super::{parse, parse_document};

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Fixture {
        value: String,
        #[serde(default)]
        items: Vec<Item>,
        #[serde(default)]
        names: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Item {
        name: String,
        value: String,
    }

    #[test]
    fn accepts_the_shared_yaml_corpus() {
        let source = concat!(
            "value: \"quoted # and : plus {{ request.path }}\" # comment\r\n",
            "items:\r\n",
            "  - name: first\r\n",
            "    value: one\r\n",
            "  - name: second\r\n",
            "    value: two\r\n",
            "names: [alpha, beta]\r\n",
        );
        let fixture = parse::<Fixture>(Path::new("fixture.yaml"), source)
            .expect("shared strict corpus is valid");
        assert_eq!(fixture.value, "quoted # and : plus {{ request.path }}");
        assert_eq!(fixture.items.len(), 2);
        assert_eq!(fixture.items[0].name, "first");
        assert_eq!(fixture.items[1].value, "two");
        assert_eq!(fixture.names, ["alpha", "beta"]);
    }

    #[test]
    fn rejects_duplicate_keys_with_location() {
        let error = parse::<Fixture>(Path::new("fixture.yaml"), "value: first\nvalue: second\n")
            .expect_err("duplicate keys must fail");
        assert_eq!(error.code, "source.duplicate_key");
        assert_eq!((error.line, error.column), (2, 1));
    }

    #[test]
    fn rejects_yaml_graph_features_tags_tabs_and_flow_mappings() {
        for (source, code) in [
            ("value: &base text\n", "source.anchor"),
            ("value: *base\n", "source.alias"),
            ("value: text\nother:\n  <<: *base\n", "source.merge_key"),
            ("value: !custom text\n", "source.tag"),
            ("\tvalue: text\n", "source.tabs"),
            ("value: { nested: true }\n", "source.flow_mapping"),
        ] {
            let error = parse::<Fixture>(Path::new("fixture.yaml"), source)
                .expect_err("unsupported YAML feature must fail");
            assert_eq!(error.code, code, "{source}");
        }
    }

    #[test]
    fn rejects_unknown_fields_through_serde() {
        let error = parse::<Fixture>(Path::new("fixture.yaml"), "value: ok\nextra: true\n")
            .expect_err("unknown field must fail");
        assert_eq!(error.code, "source.parse");
        assert_eq!(error.line, 2);
    }

    #[test]
    fn block_scalar_contents_are_opaque_to_the_strict_prescan() {
        let source = concat!(
            "value: |-\r\n",
            "  key: first\r\n",
            "  key: second\r\n",
            "  literal # &anchor *alias !tag { mapping } {{ template }}\r\n",
            "items:\r\n",
            "  - name: folded\r\n",
            "    value: >+\r\n",
            "      colon: remains text\r\n",
            "\r\n",
            "      hash # remains text\r\n",
            "names:\r\n",
            "  - |-\r\n",
            "    direct: sequence scalar\r\n",
            "    direct: duplicate-looking text\r\n",
        );
        let fixture = parse::<Fixture>(Path::new("fixture.yaml"), source)
            .expect("block scalar content is not YAML structure");
        assert!(fixture.value.contains("key: first"));
        assert!(fixture.value.contains("# &anchor *alias !tag { mapping }"));
        assert!(fixture.items[0].value.contains("colon:"));
        assert!(fixture.items[0].value.contains("hash # remains text"));
        assert!(fixture.names[0].contains("direct: duplicate-looking text"));
    }

    #[test]
    fn accepts_block_scalar_chomping_and_indentation_indicators() {
        for indicator in [
            "|", "|-", "|+", ">", ">-", ">+", "|2", "|2-", "|-2", ">2+", ">+2",
        ] {
            let source = format!("value: {indicator}\n  scalar: text\n");
            let fixture = parse::<Fixture>(Path::new("fixture.yaml"), &source)
                .unwrap_or_else(|error| panic!("{indicator} should parse: {error}"));
            assert!(fixture.value.contains("scalar: text"), "{indicator}");
        }
    }

    #[test]
    fn resumes_structural_checks_after_block_scalars() {
        let duplicate = "value: |\n  key: first\n  key: second\nvalue: real duplicate\n";
        let error = parse::<Fixture>(Path::new("fixture.yaml"), duplicate)
            .expect_err("real duplicate after scalar must fail");
        assert_eq!(error.code, "source.duplicate_key");
        assert_eq!(error.line, 4);

        let anchor = "value: >\n  & text inside scalar\nitems: &outside\n";
        let error = parse::<Fixture>(Path::new("fixture.yaml"), anchor)
            .expect_err("anchor after scalar must fail");
        assert_eq!(error.code, "source.anchor");
        assert_eq!(error.line, 3);

        let quoted_indicator = "value: \"|\"\nvalue: duplicate\n";
        let error = parse::<Fixture>(Path::new("fixture.yaml"), quoted_indicator)
            .expect_err("quoted pipe must not enter block scalar mode");
        assert_eq!(error.code, "source.duplicate_key");
        assert_eq!(error.line, 2);
    }

    #[test]
    fn indexes_nested_sequence_quoted_and_post_scalar_field_spans() {
        let source = concat!(
            "listeners:\r\n",
            "  - name: public\r\n",
            "    bind: 127.0.0.1:8080\r\n",
            "defaults:\r\n",
            "  by_extension:\r\n",
            "    \".css\":\r\n",
            "      value: 雪\r\n",
            "body: |-\r\n",
            "  duplicate: text\r\n",
            "  duplicate: remains scalar\r\n",
            "after: final\r\n",
        );
        let document = parse_document::<serde_yaml_ng::Value>(Path::new("fixture.yaml"), source)
            .expect("span fixture parses");
        let bind = document
            .spans
            .get("listeners[0].bind")
            .expect("listener bind is indexed");
        assert_eq!((bind.value.start_line, bind.value.start_column), (3, 11));
        assert_eq!(
            &document.text[bind.value.start_byte..bind.value.end_byte],
            "127.0.0.1:8080"
        );
        let extension = document
            .spans
            .get("defaults.by_extension[\".css\"].value")
            .expect("quoted extension path is indexed");
        assert_eq!(
            (extension.value.start_line, extension.value.start_column),
            (7, 14)
        );
        assert_eq!(
            &document.text[extension.value.start_byte..extension.value.end_byte],
            "雪"
        );
        let after = document
            .spans
            .get("after")
            .expect("field after block scalar is indexed");
        assert_eq!((after.key.start_line, after.key.start_column), (11, 1));
    }
}
