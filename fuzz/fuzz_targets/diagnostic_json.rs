#![no_main]

use std::path::{Path, PathBuf};

use libfuzzer_sys::fuzz_target;
use oxidase_cli::fuzzing::encode_diagnostics;
use oxidase_core::{Diagnostic, DiagnosticReference, SourceSpan};

const CODES: [&str; 5] = [
    "source.parse",
    "listener.sni",
    "resource.cluster_endpoint",
    "protocol.upgrade",
    "template.include",
];

fuzz_target!(|data: &[u8]| {
    let mut diagnostics = Vec::new();
    for (index, chunk) in data.chunks(24).take(16).enumerate() {
        let selector = chunk.first().copied().unwrap_or_default();
        let primary_span = span(chunk, index);
        let message = String::from_utf8_lossy(chunk.get(8..).unwrap_or_default()).into_owned();
        let mut diagnostic = if selector & 1 == 0 {
            Diagnostic::new(CODES[index % CODES.len()], message, primary_span.clone())
        } else {
            Diagnostic::warning(CODES[index % CODES.len()], message, primary_span.clone())
        };
        if selector & 2 != 0 {
            diagnostic = diagnostic.with_label("secondary", span(chunk, index + 1));
        }
        if selector & 4 != 0 {
            diagnostic = diagnostic.with_related("related", span(chunk, index + 2));
        }
        if selector & 8 != 0 {
            diagnostic = diagnostic.with_note(String::from_utf8_lossy(chunk).into_owned());
        }
        if selector & 16 != 0 {
            diagnostic = diagnostic.with_help("bounded fuzz help");
        }
        if selector & 32 != 0 {
            diagnostic = diagnostic.with_reference_chain([
                DiagnosticReference::new("import", span(chunk, index + 3)),
                DiagnosticReference::message("generated reference"),
            ]);
        }
        diagnostics.push(diagnostic);
    }

    let Ok(first) = encode_diagnostics(Path::new("/workspace"), diagnostics.clone()) else {
        return;
    };
    let second = encode_diagnostics(Path::new("/workspace"), diagnostics)
        .expect("the same diagnostics remain encodable");
    assert_eq!(first, second, "diagnostic JSON must be deterministic");
    let decoded: serde_json::Value =
        serde_json::from_slice(&first).expect("diagnostic encoder must emit valid JSON");
    assert_eq!(
        decoded["schema_version"],
        oxidase_core::DIAGNOSTIC_SCHEMA_VERSION
    );
    assert!(decoded["diagnostics"].is_array());
});

fn span(chunk: &[u8], salt: usize) -> SourceSpan {
    let start = usize::from(chunk.get(1).copied().unwrap_or_default());
    let width = usize::from(chunk.get(2).copied().unwrap_or_default());
    let line = usize::from(chunk.get(3).copied().unwrap_or_default()) + 1;
    let column = usize::from(chunk.get(4).copied().unwrap_or_default()) + 1;
    let path_fragment = String::from_utf8_lossy(chunk.get(5..8).unwrap_or_default());
    SourceSpan {
        file: PathBuf::from(format!("/workspace/{salt}-{path_fragment}.yaml")),
        start_byte: start,
        end_byte: start.saturating_add(width),
        line,
        column,
        end_line: line.saturating_add(usize::from(width > 0)),
        end_column: column.saturating_add(width),
        field_path: format!("fuzz.items[{salt}]"),
    }
}
