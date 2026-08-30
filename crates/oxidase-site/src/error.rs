use std::path::PathBuf;

use oxidase_core::{Diagnostic, SourceSpan};
use thiserror::Error;

#[derive(Debug)]
pub struct SiteCompileFailure {
    pub error: Box<SiteCompileError>,
    pub diagnostics: Vec<Diagnostic>,
    pub discovered_dependencies: Vec<PathBuf>,
}

impl SiteCompileFailure {
    pub(crate) fn new(error: SiteCompileError, discovered_dependencies: Vec<PathBuf>) -> Self {
        let diagnostics = vec![error.diagnostic()];
        Self {
            error: Box::new(error),
            diagnostics,
            discovered_dependencies,
        }
    }
}

impl std::fmt::Display for SiteCompileFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for SiteCompileFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

#[derive(Debug, Error)]
pub enum SiteCompileError {
    #[error("cannot access `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{0}")]
    Diagnostic(Box<Diagnostic>),
    #[error("invalid Oxista source `{path}` at {line}:{column}-{end_line}:{end_column}: {message}")]
    Source {
        path: PathBuf,
        line: usize,
        column: usize,
        end_line: usize,
        end_column: usize,
        message: String,
    },
    #[error("unsafe site path `{path}`: {message}")]
    UnsafePath { path: PathBuf, message: String },
    #[error("duplicate public site path `{logical_path}` from `{first}` and `{second}`")]
    DuplicatePath {
        logical_path: String,
        first: PathBuf,
        second: PathBuf,
    },
    #[error("template dependency cycle: {0}")]
    TemplateCycle(String),
    #[error("site input `{name}` {message}")]
    Input { name: String, message: String },
}

impl SiteCompileError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    pub(crate) fn source(path: impl Into<PathBuf>, message: impl Into<String>) -> Self {
        let path = path.into();
        Self::at(
            "site.source",
            SourceSpan {
                file: path,
                start_byte: 0,
                end_byte: 0,
                line: 1,
                column: 1,
                end_line: 1,
                end_column: 1,
                field_path: "source".to_owned(),
            },
            message,
        )
    }

    pub(crate) fn at(code: &'static str, source: SourceSpan, message: impl Into<String>) -> Self {
        Self::Diagnostic(Box::new(Diagnostic::new(code, message, source)))
    }

    pub(crate) fn from_diagnostic(diagnostic: Diagnostic) -> Self {
        Self::Diagnostic(Box::new(diagnostic))
    }

    #[must_use]
    pub fn diagnostic(&self) -> Diagnostic {
        match self {
            Self::Diagnostic(diagnostic) => diagnostic.as_ref().clone(),
            Self::Io { path, source } => Diagnostic::new(
                "site.io",
                format!("cannot access `{}`: {source}", path.display()),
                point_span(path, "source"),
            ),
            Self::Source {
                path,
                line,
                column,
                end_line,
                end_column,
                message,
            } => Diagnostic::new(
                "site.source",
                message.clone(),
                SourceSpan {
                    file: path.clone(),
                    start_byte: 0,
                    end_byte: 0,
                    line: *line,
                    column: *column,
                    end_line: *end_line,
                    end_column: *end_column,
                    field_path: "source".to_owned(),
                },
            ),
            Self::UnsafePath { path, message } => Diagnostic::new(
                "site.unsafe_path",
                message.clone(),
                point_span(path, "source"),
            ),
            Self::DuplicatePath {
                logical_path,
                first,
                second,
            } => Diagnostic::new(
                "site.duplicate_path",
                format!("duplicate public site path `{logical_path}`"),
                point_span(second, "source"),
            )
            .with_related("first public path", point_span(first, "source")),
            Self::TemplateCycle(message) => Diagnostic::new(
                "template.include_cycle",
                message.clone(),
                SourceSpan::synthetic("template.include"),
            ),
            Self::Input { name, message } => Diagnostic::new(
                "site.input",
                format!("site input `{name}` {message}"),
                SourceSpan::synthetic(format!("inputs.{name}")),
            ),
        }
    }
}

fn point_span(path: &std::path::Path, field_path: &str) -> SourceSpan {
    SourceSpan {
        file: path.to_path_buf(),
        start_byte: 0,
        end_byte: 0,
        line: 1,
        column: 1,
        end_line: 1,
        end_column: 1,
        field_path: field_path.to_owned(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateLimitKind {
    OutputSize,
    LoopIterations,
    IncludeDepth,
    ExpressionSteps,
    RenderTime,
}

impl std::fmt::Display for TemplateLimitKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::OutputSize => "output size",
            Self::LoopIterations => "loop iteration",
            Self::IncludeDepth => "include depth",
            Self::ExpressionSteps => "expression step",
            Self::RenderTime => "render time",
        })
    }
}

#[derive(Debug, Error)]
pub enum TemplateRenderError {
    #[error("template `{template}` exceeded its {kind} limit")]
    Limit {
        template: String,
        kind: TemplateLimitKind,
    },
    #[error("template `{template}` could not evaluate `{expression}`: {message}")]
    Evaluation {
        template: String,
        expression: String,
        message: String,
    },
    #[error("template `{template}` has no value for `{expression}`")]
    MissingValue {
        template: String,
        expression: String,
    },
    #[error(transparent)]
    Argument(#[from] TemplateArgumentError),
}

#[derive(Debug, Error)]
pub enum TemplateArgumentError {
    #[error("template `{template}` is missing required parameter `{parameter}` ({expected})")]
    Missing {
        template: String,
        parameter: String,
        expected: String,
    },
    #[error("template `{template}` parameter `{parameter}` evaluation failed: {message}")]
    Evaluation {
        template: String,
        parameter: String,
        message: String,
    },
    #[error("template `{template}` parameter `{parameter}` expects {expected}, received {actual}")]
    Type {
        template: String,
        parameter: String,
        expected: String,
        actual: String,
    },
    #[error("template `{template}` received unknown parameter `{parameter}`")]
    Unknown { template: String, parameter: String },
}

#[derive(Debug, Error)]
pub enum SiteError {
    #[error("request path is invalid: {0}")]
    InvalidRequestPath(String),
    #[error("site template `{template}` exceeded its {kind} limit")]
    TemplateLimit {
        template: String,
        kind: TemplateLimitKind,
    },
    #[error("site template failed: {0}")]
    TemplateRender(#[source] TemplateRenderError),
    #[error("site template argument is invalid: {0}")]
    TemplateArgument(#[source] TemplateArgumentError),
    #[error("site response metadata is invalid: {0}")]
    Response(String),
}

impl SiteError {
    pub(crate) fn from_template_render(error: TemplateRenderError) -> Self {
        match error {
            TemplateRenderError::Limit { template, kind } => Self::TemplateLimit { template, kind },
            TemplateRenderError::Argument(error) => Self::TemplateArgument(error),
            error => Self::TemplateRender(error),
        }
    }
}
