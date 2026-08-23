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
    pub line: usize,
    pub column: usize,
    pub field_path: String,
}

impl SourceSpan {
    #[must_use]
    pub fn synthetic(field_path: impl Into<String>) -> Self {
        Self {
            file: PathBuf::from("<generated>"),
            line: 1,
            column: 1,
            field_path: field_path.into(),
        }
    }
}

impl fmt::Display for SourceSpan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}:{} ({})",
            self.file.display(),
            self.line,
            self.column,
            self.field_path
        )
    }
}
