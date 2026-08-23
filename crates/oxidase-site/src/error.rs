use std::path::PathBuf;

use thiserror::Error;

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

#[derive(Debug, Error)]
pub enum SiteError {
    #[error("request path is invalid: {0}")]
    InvalidRequestPath(String),
    #[error("site template failed: {0}")]
    Template(String),
    #[error("site response metadata is invalid: {0}")]
    Response(String),
}
