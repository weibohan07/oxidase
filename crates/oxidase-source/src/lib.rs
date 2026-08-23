//! Shared strict source parsing for Gateway and Oxista YAML documents.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

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

/// Parses the deliberately small YAML subset shared by every Oxidase source
/// format. Flow sequences are allowed; flow mappings and YAML graph features
/// are not.
pub fn parse<T: DeserializeOwned>(path: &Path, source: &str) -> Result<T, StrictYamlError> {
    validate_subset(path, source)?;
    serde_yaml_ng::from_str(source).map_err(|error| {
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
    })
}

fn validate_subset(path: &Path, source: &str) -> Result<(), StrictYamlError> {
    let mut mappings = Vec::<MappingFrame>::new();
    for (line_index, raw_line) in source.lines().enumerate() {
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

        let indent = raw_line.len() - raw_line.trim_start_matches(' ').len();
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

        let Some((key, key_column)) = mapping_key(content) else {
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
    }
    Ok(())
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
                    return Some((key, column));
                }
                _ => {}
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde::Deserialize;

    use super::parse;

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
}
