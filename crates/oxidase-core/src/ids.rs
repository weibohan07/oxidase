use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

macro_rules! string_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            #[must_use]
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self::new(value)
            }
        }
    };
}

string_id!(ServiceId);
string_id!(ResourceId);
string_id!(RouteId);
string_id!(ListenerId);
string_id!(ConfigVersion);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSpan {
    pub file: PathBuf,
    pub start_byte: usize,
    pub end_byte: usize,
    pub line: usize,
    pub column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub field_path: String,
}

impl SourceSpan {
    #[must_use]
    pub fn synthetic(field_path: impl Into<String>) -> Self {
        Self {
            file: PathBuf::from("<generated>"),
            start_byte: 0,
            end_byte: 0,
            line: 1,
            column: 1,
            end_line: 1,
            end_column: 1,
            field_path: field_path.into(),
        }
    }

    /// Validates the path/position subset accepted from portable artifacts.
    pub fn validate_portable(&self) -> Result<(), String> {
        let file = self
            .file
            .to_str()
            .ok_or_else(|| "source span file must be portable UTF-8".to_owned())?;
        if file.is_empty()
            || file.len() > 16 * 1024
            || self.file.is_absolute()
            || file.contains(['\\', '\0', '\r', '\n'])
            || file.split('/').any(|component| component == "..")
        {
            return Err(
                "source span file must be bounded, project-relative, and traversal-free".to_owned(),
            );
        }
        if self.start_byte > self.end_byte
            || self.line == 0
            || self.column == 0
            || self.end_line == 0
            || self.end_column == 0
            || (self.end_line, self.end_column) < (self.line, self.column)
        {
            return Err("source span positions are invalid".to_owned());
        }
        if self.field_path.is_empty()
            || self.field_path.len() > 16 * 1024
            || self.field_path.contains(['\0', '\r', '\n'])
        {
            return Err("source span field path is empty, too large, or unsafe".to_owned());
        }
        Ok(())
    }
}

impl fmt::Display for SourceSpan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}:{}-{}:{} ({})",
            self.file.display(),
            self.line,
            self.column,
            self.end_line,
            self.end_column,
            self.field_path
        )
    }
}
