use std::collections::BTreeSet;
use std::path::Path;

use oxidase_core::SourceSpan;
use serde::de::DeserializeOwned;

use crate::Diagnostic;

pub(crate) fn parse<T: DeserializeOwned>(
    path: &Path,
    source: &str,
    field_path: &str,
) -> Result<T, Box<Diagnostic>> {
    validate_yaml_subset(path, source)?;
    serde_yaml_ng::from_str(source).map_err(|error| {
        let location = error.location();
        let (line, column) = location
            .map(|location| (location.line(), location.column()))
            .unwrap_or((1, 1));
        Box::new(
            Diagnostic::new(
                "config.parse",
                error.to_string(),
                SourceSpan {
                    file: path.to_path_buf(),
                    line,
                    column,
                    field_path: field_path.to_owned(),
                },
            )
            .with_help("remove unknown fields and ensure every value has the documented type"),
        )
    })
}

fn validate_yaml_subset(path: &Path, source: &str) -> Result<(), Box<Diagnostic>> {
    let mut mappings = Vec::<MappingFrame>::new();
    for (line_index, raw_line) in source.lines().enumerate() {
        if raw_line.contains('\t')
            && raw_line.starts_with(|character: char| character.is_whitespace())
        {
            return Err(Box::new(diagnostic(
                path,
                line_index,
                1,
                "config.tabs",
                "tabs are not allowed for YAML indentation",
            )));
        }
        let line = strip_comment(raw_line);
        let trimmed = line.trim();
        if trimmed.is_empty() || matches!(trimmed, "---" | "...") {
            continue;
        }
        if contains_unquoted(trimmed, '{') {
            return Err(Box::new(
                diagnostic(
                    path,
                    line_index,
                    raw_line.find('{').unwrap_or(0) + 1,
                    "config.flow_mapping",
                    "flow-style mappings are not supported in strict configuration",
                )
                .with_help("write this mapping in indented block style"),
            ));
        }
        if contains_unquoted(trimmed, '&') || starts_with_unquoted_alias(trimmed) {
            return Err(Box::new(
                diagnostic(
                    path,
                    line_index,
                    1,
                    "config.yaml_alias",
                    "YAML anchors, aliases, and merge keys are not supported",
                )
                .with_help("use Oxidase imports and named Service references instead"),
            ));
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
            return Err(Box::new(diagnostic(
                path,
                line_index,
                indent + key_column + 1,
                "config.yaml_merge",
                "YAML merge keys are not supported",
            )));
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
            return Err(Box::new(diagnostic(
                path,
                line_index,
                indent + key_column + 1,
                "config.duplicate_key",
                format!("duplicate mapping key `{key}`"),
            )));
        }
    }
    Ok(())
}

struct MappingFrame {
    indent: usize,
    keys: BTreeSet<String>,
}

fn diagnostic(
    path: &Path,
    zero_based_line: usize,
    column: usize,
    code: &'static str,
    message: impl Into<String>,
) -> Diagnostic {
    Diagnostic::new(
        code,
        message,
        SourceSpan {
            file: path.to_path_buf(),
            line: zero_based_line + 1,
            column,
            field_path: String::new(),
        },
    )
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

fn contains_unquoted(value: &str, needle: char) -> bool {
    let mut quote = None;
    let mut escaped = false;
    for character in value.chars() {
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
        } else if character == needle && quote.is_none() {
            return true;
        }
    }
    false
}

fn starts_with_unquoted_alias(value: &str) -> bool {
    value.starts_with('*') || value.contains(": *")
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
    }

    #[test]
    fn rejects_duplicate_block_keys() {
        let error = parse::<Fixture>(
            Path::new("config.yaml"),
            "value: first\nvalue: second\n",
            "",
        )
        .expect_err("duplicate keys must fail");
        assert_eq!(error.code, "config.duplicate_key");
        assert_eq!(error.source.line, 2);
    }

    #[test]
    fn rejects_unknown_fields() {
        let error = parse::<Fixture>(Path::new("config.yaml"), "value: first\nextra: true\n", "")
            .expect_err("unknown fields must fail");
        assert_eq!(error.code, "config.parse");
    }

    #[test]
    fn accepts_braces_inside_quoted_values() {
        let fixture = parse::<Fixture>(
            Path::new("config.yaml"),
            "value: \"{{ request.path }}\"\n",
            "",
        )
        .expect("quoted template is valid");
        assert_eq!(fixture.value, "{{ request.path }}");
    }
}
