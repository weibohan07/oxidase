//! Shared CLI output primitives.

mod diagnostic_encoding;

#[doc(hidden)]
pub use diagnostic_encoding::{DiagnosticRoot, encode_json_diagnostics, sort_diagnostics};

/// Narrow facade used only by the out-of-workspace fuzz harness.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing {
    use std::path::Path;

    use oxidase_core::Diagnostic;

    /// Encodes diagnostics with the exact deterministic JSON path used by the
    /// CLI, without writing to process stdout.
    pub fn encode_diagnostics(
        root: &Path,
        diagnostics: Vec<Diagnostic>,
    ) -> Result<Vec<u8>, String> {
        super::encode_json_diagnostics(&super::DiagnosticRoot::new(root), diagnostics)
            .map_err(|error| error.to_string())
    }
}
