use std::borrow::Cow;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::ValueEnum;
use oxidase_core::{
    DIAGNOSTIC_SCHEMA_VERSION, Diagnostic, DiagnosticReference, DiagnosticSeverity,
    RelatedDiagnostic, SourceSpan,
};
use serde::Serialize;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub(crate) enum DiagnosticFormat {
    #[default]
    Human,
    Json,
}

#[derive(Debug, Clone)]
pub(crate) struct DiagnosticRoot(PathBuf);

impl DiagnosticRoot {
    pub(crate) fn for_config(config: &Path) -> Self {
        let parent = config.parent().filter(|path| !path.as_os_str().is_empty());
        let root = parent.unwrap_or_else(|| Path::new("."));
        Self(root.canonicalize().unwrap_or_else(|_| root.to_path_buf()))
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

pub(crate) struct Reporter {
    format: DiagnosticFormat,
}

impl Reporter {
    pub(crate) fn new(format: DiagnosticFormat) -> Self {
        Self { format }
    }

    pub(crate) fn human_stdout(&self, message: impl AsRef<str>) {
        if self.format == DiagnosticFormat::Human {
            println!("{}", message.as_ref());
        }
    }
}

pub(crate) fn render(
    format: DiagnosticFormat,
    root: &DiagnosticRoot,
    diagnostics: Vec<Diagnostic>,
) -> io::Result<()> {
    let diagnostics = sorted_diagnostics(root, diagnostics);
    match format {
        DiagnosticFormat::Human => {
            let mut stderr = io::stderr().lock();
            for (index, diagnostic) in diagnostics.iter().enumerate() {
                if index > 0 {
                    writeln!(stderr)?;
                }
                writeln!(stderr, "{diagnostic}")?;
            }
            stderr.flush()
        }
        DiagnosticFormat::Json => {
            let envelope = JsonDiagnosticEnvelope::new(root, &diagnostics);
            let mut encoded = serde_json::to_vec_pretty(&envelope)
                .map_err(|error| io::Error::other(error.to_string()))?;
            encoded.push(b'\n');
            let mut stdout = io::stdout().lock();
            stdout.write_all(&encoded)?;
            stdout.flush()
        }
    }
}

fn sorted_diagnostics(root: &DiagnosticRoot, mut diagnostics: Vec<Diagnostic>) -> Vec<Diagnostic> {
    diagnostics.sort_by(|left, right| {
        diagnostic_sort_key(root, left).cmp(&diagnostic_sort_key(root, right))
    });
    diagnostics
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

    use super::{DiagnosticRoot, JsonDiagnosticEnvelope, sorted_diagnostics};

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
        let sorted = sorted_diagnostics(
            &root,
            vec![
                diagnostic("/workspace/b.yaml", 1, "b"),
                diagnostic("/workspace/a.yaml", 2, "c"),
                diagnostic("/workspace/a.yaml", 1, "a"),
            ],
        );
        assert_eq!(
            sorted.iter().map(|item| item.code).collect::<Vec<_>>(),
            ["a", "c", "b"]
        );
    }

    #[test]
    fn json_paths_are_relative_and_declare_their_encoding() {
        let root = DiagnosticRoot(PathBuf::from("/workspace"));
        let diagnostics = [diagnostic("/workspace/imports/a.yaml", 1, "code")];
        let json = serde_json::to_value(JsonDiagnosticEnvelope::new(&root, &diagnostics))
            .expect("diagnostic envelope serializes");
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

        let json = serde_json::to_value(JsonDiagnosticEnvelope::new(&root, &[warning]))
            .expect("warning envelope serializes");
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
        let diagnostics = [diagnostic("<generated>", 0, "code")];
        let json = serde_json::to_value(JsonDiagnosticEnvelope::new(&root, &diagnostics))
            .expect("diagnostic envelope serializes");
        assert_eq!(json["diagnostics"][0]["primary"]["file"], "<generated>");
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_paths_are_explicitly_marked_as_lossy() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let root = DiagnosticRoot(PathBuf::from("/workspace"));
        let invalid = PathBuf::from(OsString::from_vec(b"/workspace/bad-\xff.yaml".to_vec()));
        let diagnostics = [Diagnostic::new(
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
        )];
        let json = serde_json::to_value(JsonDiagnosticEnvelope::new(&root, &diagnostics))
            .expect("diagnostic envelope serializes");
        assert_eq!(
            json["diagnostics"][0]["primary"]["file_encoding"],
            "utf-8-lossy"
        );
    }
}
