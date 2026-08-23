use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PatternError {
    #[error("unclosed placeholder `<...>`")]
    Unclosed,
    #[error("empty placeholder")]
    Empty,
    #[error("invalid placeholder syntax `{0}`")]
    InvalidPlaceholder(String),
    #[error("invalid capture name `{0}`")]
    InvalidCaptureName(String),
    #[error("duplicate capture name `{0}`")]
    DuplicateCapture(String),
    #[error("placeholder type `{kind}` is not allowed in {context} patterns")]
    InvalidTypeForContext {
        kind: &'static str,
        context: &'static str,
    },
    #[error("a tail-only placeholder must be the final pattern component")]
    TailOnlyMustBeLast,
    #[error("custom regex is outside the restricted subset: {0}")]
    UnsafeRegex(String),
    #[error("regex compilation failed: {0}")]
    Regex(String),
}
