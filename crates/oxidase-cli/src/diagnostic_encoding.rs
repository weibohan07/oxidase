use std::borrow::Cow;
use std::io;
use std::path::{Path, PathBuf};

use oxidase_core::{
    DIAGNOSTIC_SCHEMA_VERSION, Diagnostic, DiagnosticReference, DiagnosticSeverity,
    RelatedDiagnostic, SourceSpan,
};
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct DiagnosticRoot(PathBuf);

impl DiagnosticRoot {
    #[must_use]
    pub fn for_config(config: &Path) -> Self {
        let parent = config.parent().filter(|path| !path.as_os_str().is_empty());
        let root = parent.unwrap_or_else(|| Path::new("."));
        Self(root.canonicalize().unwrap_or_else(|_| root.to_path_buf()))
    }

    #[must_use]
    pub fn new(root: &Path) -> Self {
        Self(root.to_path_buf())
    }

    fn display_path<'a>(&self, path: &'a Path) -> Cow<'a, Path> {
        if is_virtual_path(path) {
            return Cow::Borrowed(path);
        }
        if let Ok(relative) = path.strip_prefix(&self.0) {
            return Cow::Owned(relative.to_path_buf());
        }
        Cow::Borrowed(path)
    }
}

fn is_virtual_path(path: &Path) -> bool {
    path.to_string_lossy().starts_with('<') && path.to_string_lossy().ends_with('>')
}

pub fn encode_json_diagnostics(
    root: &DiagnosticRoot,
    mut diagnostics: Vec<Diagnostic>,
) -> io::Result<Vec<u8>> {
    sort_diagnostics(root, &mut diagnostics);
    let envelope = JsonDiagnosticEnvelope::new(root, &diagnostics);
    let mut encoded = serde_json::to_vec_pretty(&envelope)
        .map_err(|error| io::Error::other(error.to_string()))?;
    encoded.push(b'\n');
    Ok(encoded)
}

pub fn sort_diagnostics(root: &DiagnosticRoot, diagnostics: &mut [Diagnostic]) {
    diagnostics.sort_by(|left, right| {
        diagnostic_sort_key(root, left).cmp(&diagnostic_sort_key(root, right))
    });
}

fn diagnostic_sort_key(
    root: &DiagnosticRoot,
    diagnostic: &Diagnostic,
) -> (String, usize, usize, &'static str, String) {
    (
        encoded_path(root, &diagnostic.primary.file).value,
        diagnostic.primary.start_byte,
        diagnostic.primary.end_byte,
        diagnostic.code,
        diagnostic.message.clone(),
    )
}

#[derive(Serialize)]
struct JsonDiagnosticEnvelope<'a> {
    schema_version: &'static str,
    diagnostics: Vec<JsonDiagnostic<'a>>,
}

impl<'a> JsonDiagnosticEnvelope<'a> {
    fn new(root: &DiagnosticRoot, diagnostics: &'a [Diagnostic]) -> Self {
        Self {
            schema_version: DIAGNOSTIC_SCHEMA_VERSION,
            diagnostics: diagnostics
                .iter()
                .map(|diagnostic| JsonDiagnostic::new(root, diagnostic))
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct JsonDiagnostic<'a> {
    code: &'static str,
    severity: DiagnosticSeverity,
    message: &'a str,
    primary: JsonSourceSpan,
    labels: Vec<JsonLabel<'a>>,
    related: Vec<JsonRelated<'a>>,
    notes: &'a [String],
    help: Option<&'a str>,
    reference_chain: Vec<JsonReference<'a>>,
}

impl<'a> JsonDiagnostic<'a> {
    fn new(root: &DiagnosticRoot, diagnostic: &'a Diagnostic) -> Self {
        Self {
            code: diagnostic.code,
            severity: diagnostic.severity,
            message: &diagnostic.message,
            primary: JsonSourceSpan::new(root, &diagnostic.primary),
            labels: diagnostic
                .labels
                .iter()
                .map(|label| JsonLabel {
                    message: &label.message,
                    span: JsonSourceSpan::new(root, &label.span),
                })
                .collect(),
            related: diagnostic
                .related
                .iter()
                .map(|related| JsonRelated::new(root, related))
                .collect(),
            notes: &diagnostic.notes,
            help: diagnostic.help.as_deref(),
            reference_chain: diagnostic
                .reference_chain
                .iter()
                .map(|reference| JsonReference::new(root, reference))
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct JsonLabel<'a> {
    message: &'a str,
    span: JsonSourceSpan,
}

#[derive(Serialize)]
struct JsonRelated<'a> {
    message: &'a str,
    span: JsonSourceSpan,
}

impl<'a> JsonRelated<'a> {
    fn new(root: &DiagnosticRoot, related: &'a RelatedDiagnostic) -> Self {
        Self {
            message: &related.message,
            span: JsonSourceSpan::new(root, &related.span),
        }
    }
}

#[derive(Serialize)]
struct JsonReference<'a> {
    message: &'a str,
    span: Option<JsonSourceSpan>,
}

impl<'a> JsonReference<'a> {
    fn new(root: &DiagnosticRoot, reference: &'a DiagnosticReference) -> Self {
        Self {
            message: &reference.message,
            span: reference
                .span
                .as_ref()
                .map(|span| JsonSourceSpan::new(root, span)),
        }
    }
}

#[derive(Serialize)]
struct JsonSourceSpan {
    file: String,
    file_encoding: &'static str,
    field_path: String,
    start: JsonPosition,
    end: JsonPosition,
}

impl JsonSourceSpan {
    fn new(root: &DiagnosticRoot, span: &SourceSpan) -> Self {
        let path = encoded_path(root, &span.file);
        Self {
            file: path.value,
            file_encoding: path.encoding,
            field_path: span.field_path.clone(),
            start: JsonPosition {
                byte: span.start_byte,
                line: span.line,
                column: span.column,
            },
            end: JsonPosition {
                byte: span.end_byte,
                line: span.end_line,
                column: span.end_column,
            },
        }
    }
}

#[derive(Serialize)]
struct JsonPosition {
    byte: usize,
    line: usize,
    column: usize,
}

struct EncodedPath {
    value: String,
    encoding: &'static str,
}

fn encoded_path(root: &DiagnosticRoot, path: &Path) -> EncodedPath {
    let path = root.display_path(path);
    let encoded = path.to_string_lossy();
    let encoding = if matches!(encoded, Cow::Borrowed(_)) {
        "utf-8"
    } else {
        "utf-8-lossy"
    };
    EncodedPath {
        value: encoded.replace('\\', "/"),
        encoding,
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use oxidase_core::{Diagnostic, DiagnosticSeverity, SourceSpan};

    use super::{DiagnosticRoot, encode_json_diagnostics, sort_diagnostics};

    fn diagnostic(path: &str, byte: usize, code: &'static str) -> Diagnostic {
        Diagnostic::new(
            code,
            "message",
            SourceSpan {
                file: PathBuf::from(path),
                start_byte: byte,
                end_byte: byte + 1,
                line: 1,
                column: byte + 1,
                end_line: 1,
                end_column: byte + 2,
                field_path: "value".to_owned(),
            },
        )
    }

    #[test]
    fn diagnostics_have_a_stable_source_order() {
        let root = DiagnosticRoot(PathBuf::from("/workspace"));
        let mut diagnostics = vec![
            diagnostic("/workspace/b.yaml", 1, "b"),
            diagnostic("/workspace/a.yaml", 2, "c"),
            diagnostic("/workspace/a.yaml", 1, "a"),
        ];
        sort_diagnostics(&root, &mut diagnostics);
        assert_eq!(
            diagnostics.iter().map(|item| item.code).collect::<Vec<_>>(),
            ["a", "c", "b"]
        );
    }

    #[test]
    fn encoded_json_keeps_the_existing_schema_and_field_order() {
        let root = DiagnosticRoot(PathBuf::from("/workspace"));
        let encoded = encode_json_diagnostics(
            &root,
            vec![diagnostic("/workspace/oxidase.yaml", 0, "source.invalid")],
        )
        .expect("diagnostic envelope serializes");
        let expected = concat!(
            "{\n",
            "  \"schema_version\": \"oxidase.diagnostics/v1\",\n",
            "  \"diagnostics\": [\n",
            "    {\n",
            "      \"code\": \"source.invalid\",\n",
            "      \"severity\": \"error\",\n",
            "      \"message\": \"message\",\n",
            "      \"primary\": {\n",
            "        \"file\": \"oxidase.yaml\",\n",
            "        \"file_encoding\": \"utf-8\",\n",
            "        \"field_path\": \"value\",\n",
            "        \"start\": {\n",
            "          \"byte\": 0,\n",
            "          \"line\": 1,\n",
            "          \"column\": 1\n",
            "        },\n",
            "        \"end\": {\n",
            "          \"byte\": 1,\n",
            "          \"line\": 1,\n",
            "          \"column\": 2\n",
            "        }\n",
            "      },\n",
            "      \"labels\": [],\n",
            "      \"related\": [],\n",
            "      \"notes\": [],\n",
            "      \"help\": null,\n",
            "      \"reference_chain\": []\n",
            "    }\n",
            "  ]\n",
            "}\n"
        );
        assert_eq!(encoded, expected.as_bytes());
    }

    #[test]
    fn json_paths_are_relative_and_declare_their_encoding() {
        let root = DiagnosticRoot(PathBuf::from("/workspace"));
        let encoded = encode_json_diagnostics(
            &root,
            vec![diagnostic("/workspace/imports/a.yaml", 1, "code")],
        )
        .expect("diagnostic envelope serializes");
        let json: serde_json::Value =
            serde_json::from_slice(&encoded).expect("encoded diagnostics are JSON");
        assert_eq!(json["diagnostics"][0]["primary"]["file"], "imports/a.yaml");
        assert_eq!(json["diagnostics"][0]["primary"]["file_encoding"], "utf-8");
    }

    #[test]
    fn json_diagnostics_preserve_non_fatal_warning_severity() {
        let root = DiagnosticRoot(PathBuf::from("/workspace"));
        let warning = Diagnostic::warning(
            "resource.cluster_retry_post",
            "retrying POST requires an explicit idempotency decision",
            SourceSpan {
                file: PathBuf::from("/workspace/oxidase.yaml"),
                start_byte: 12,
                end_byte: 16,
                line: 3,
                column: 5,
                end_line: 3,
                end_column: 9,
                field_path: "resources.clusters.api.retry.methods[0]".to_owned(),
            },
        );
        let encoded =
            encode_json_diagnostics(&root, vec![warning]).expect("warning envelope serializes");
        let json: serde_json::Value =
            serde_json::from_slice(&encoded).expect("encoded diagnostics are JSON");
        assert_eq!(
            json["schema_version"],
            oxidase_core::DIAGNOSTIC_SCHEMA_VERSION
        );
        assert_eq!(
            json["diagnostics"][0]["severity"],
            serde_json::to_value(DiagnosticSeverity::Warning).expect("severity serializes")
        );
        assert_eq!(
            json["diagnostics"][0]["code"],
            "resource.cluster_retry_post"
        );
    }

    #[test]
    fn virtual_paths_are_not_resolved_against_the_config_root() {
        let root = DiagnosticRoot::for_config(Path::new("config.yaml"));
        let encoded = encode_json_diagnostics(&root, vec![diagnostic("<generated>", 0, "code")])
            .expect("diagnostic envelope serializes");
        let json: serde_json::Value =
            serde_json::from_slice(&encoded).expect("encoded diagnostics are JSON");
        assert_eq!(json["diagnostics"][0]["primary"]["file"], "<generated>");
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_paths_are_explicitly_marked_as_lossy() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let root = DiagnosticRoot(PathBuf::from("/workspace"));
        let invalid = PathBuf::from(OsString::from_vec(b"/workspace/bad-\xff.yaml".to_vec()));
        let diagnostic = Diagnostic::new(
            "code",
            "message",
            SourceSpan {
                file: invalid,
                start_byte: 0,
                end_byte: 0,
                line: 1,
                column: 1,
                end_line: 1,
                end_column: 1,
                field_path: "value".to_owned(),
            },
        );
        let encoded =
            encode_json_diagnostics(&root, vec![diagnostic]).expect("diagnostics serialize");
        let json: serde_json::Value =
            serde_json::from_slice(&encoded).expect("encoded diagnostics are JSON");
        assert_eq!(
            json["diagnostics"][0]["primary"]["file_encoding"],
            "utf-8-lossy"
        );
    }
}
