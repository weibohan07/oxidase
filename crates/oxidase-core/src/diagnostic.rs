use std::fmt;

use serde::Serialize;

use crate::SourceSpan;

pub const DIAGNOSTIC_SCHEMA_VERSION: &str = "oxidase.diagnostics/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticSeverity {
    Error,
    Warning,
}

impl fmt::Display for DiagnosticSeverity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Error => "error",
            Self::Warning => "warning",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticLabel {
    pub message: String,
    pub span: SourceSpan,
}

impl DiagnosticLabel {
    #[must_use]
    pub fn new(message: impl Into<String>, span: SourceSpan) -> Self {
        Self {
            message: message.into(),
            span,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelatedDiagnostic {
    pub message: String,
    pub span: SourceSpan,
}

impl RelatedDiagnostic {
    #[must_use]
    pub fn new(message: impl Into<String>, span: SourceSpan) -> Self {
        Self {
            message: message.into(),
            span,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticReference {
    pub message: String,
    pub span: Option<SourceSpan>,
}

impl DiagnosticReference {
    #[must_use]
    pub fn new(message: impl Into<String>, span: SourceSpan) -> Self {
        Self {
            message: message.into(),
            span: Some(span),
        }
    }

    #[must_use]
    pub fn message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            span: None,
        }
    }
}

impl From<String> for DiagnosticReference {
    fn from(message: String) -> Self {
        Self::message(message)
    }
}

impl From<&str> for DiagnosticReference {
    fn from(message: &str) -> Self {
        Self::message(message)
    }
}

impl From<SourceSpan> for DiagnosticReference {
    fn from(span: SourceSpan) -> Self {
        Self::new("reference", span)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub code: &'static str,
    pub severity: DiagnosticSeverity,
    pub message: String,
    pub primary: SourceSpan,
    pub labels: Vec<DiagnosticLabel>,
    pub related: Vec<RelatedDiagnostic>,
    pub notes: Vec<String>,
    pub help: Option<String>,
    pub reference_chain: Vec<DiagnosticReference>,
}

impl Diagnostic {
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>, primary: SourceSpan) -> Self {
        Self {
            code,
            severity: DiagnosticSeverity::Error,
            message: message.into(),
            primary,
            labels: Vec::new(),
            related: Vec::new(),
            notes: Vec::new(),
            help: None,
            reference_chain: Vec::new(),
        }
    }

    #[must_use]
    pub fn warning(code: &'static str, message: impl Into<String>, primary: SourceSpan) -> Self {
        Self {
            severity: DiagnosticSeverity::Warning,
            ..Self::new(code, message, primary)
        }
    }

    #[must_use]
    pub fn with_label(mut self, message: impl Into<String>, span: SourceSpan) -> Self {
        self.labels.push(DiagnosticLabel::new(message, span));
        self
    }

    #[must_use]
    pub fn with_related(mut self, message: impl Into<String>, span: SourceSpan) -> Self {
        self.related.push(RelatedDiagnostic::new(message, span));
        self
    }

    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }

    #[must_use]
    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    #[must_use]
    pub fn with_reference_chain<I, Reference>(mut self, chain: I) -> Self
    where
        I: IntoIterator<Item = Reference>,
        Reference: Into<DiagnosticReference>,
    {
        self.reference_chain
            .extend(chain.into_iter().map(Into::into));
        self
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}[{}]: {}\n  --> {}",
            self.severity, self.code, self.message, self.primary
        )?;
        for label in &self.labels {
            write!(formatter, "\n  = {}: {}", label.message, label.span)?;
        }
        for related in &self.related {
            write!(
                formatter,
                "\n  = related {}: {}",
                related.message, related.span
            )?;
        }
        if !self.reference_chain.is_empty() {
            formatter.write_str("\n  reference chain:")?;
            for reference in &self.reference_chain {
                if let Some(span) = &reference.span {
                    write!(formatter, "\n    {}: {span}", reference.message)?;
                } else {
                    write!(formatter, "\n    {}", reference.message)?;
                }
            }
        }
        for note in &self.notes {
            write!(formatter, "\n  note: {note}")?;
        }
        if let Some(help) = &self.help {
            write!(formatter, "\n  help: {help}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::SourceSpan;

    use super::{Diagnostic, DiagnosticReference, DiagnosticSeverity};

    fn span(path: &str, field_path: &str, line: usize) -> SourceSpan {
        SourceSpan {
            file: PathBuf::from(path),
            start_byte: line * 10,
            end_byte: line * 10 + 4,
            line,
            column: 3,
            end_line: line,
            end_column: 7,
            field_path: field_path.to_owned(),
        }
    }

    #[test]
    fn preserves_structured_primary_secondary_and_reference_locations() {
        let diagnostic = Diagnostic::new("config.duplicate", "duplicate value", span("b", "b", 2))
            .with_label("first definition", span("a", "a", 1))
            .with_related("imported definition", span("a", "a", 1))
            .with_note("definitions are merged deterministically")
            .with_help("remove one definition")
            .with_reference_chain([DiagnosticReference::new(
                "imported from",
                span("root", "imports[0]", 3),
            )]);

        assert_eq!(diagnostic.severity, DiagnosticSeverity::Error);
        assert_eq!(diagnostic.primary.file, PathBuf::from("b"));
        assert_eq!(diagnostic.labels[0].span.file, PathBuf::from("a"));
        assert_eq!(
            diagnostic.reference_chain[0]
                .span
                .as_ref()
                .expect("reference has an exact span")
                .field_path,
            "imports[0]"
        );
    }
}
