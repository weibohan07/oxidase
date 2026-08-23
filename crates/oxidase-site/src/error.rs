use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug)]
pub struct SiteCompileFailure {
    pub error: SiteCompileError,
    pub discovered_dependencies: Vec<PathBuf>,
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
    #[error("invalid Oxista source `{path}`: {message}")]
    Source { path: PathBuf, message: String },
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
        Self::Source {
            path: path.into(),
            message: message.into(),
        }
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
            error => Self::TemplateRender(error),
        }
    }
}
