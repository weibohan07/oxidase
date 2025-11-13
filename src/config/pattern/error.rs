use thiserror::Error;

#[derive(Error, Debug)]
pub enum PatternError {
    #[error("unclosed placeholder <...>")] Unclosed,
    #[error("empty placeholder")] Empty,
    #[error("invalid placeholder syntax: {0}")] BadPlaceholder(String),
    #[error("duplicate capture name: {0}")] DupName(String),
    #[error("type `{0}` not allowed in this context")] BadTypeForCtx(&'static str),
    #[error("a tail-only placeholder must be the last component")] TailOnlyMustBeLast,
    #[error("regex compile error: {0}")] Regex(#[from] regex::Error),
}
