use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Value {
    Null,
    Bool(bool),
    Integer(i64),
    Float(f64),
    String(String),
    Bytes(#[serde(with = "bytes_serde")] Vec<u8>),
    List(Vec<Value>),
    Map(BTreeMap<String, Value>),
}

impl Value {
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        if let Self::Bool(value) = self {
            Some(*value)
        } else {
            None
        }
    }

    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        if let Self::String(value) = self {
            Some(value)
        } else {
            None
        }
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Map(values) => values.get(key),
            _ => None,
        }
    }

    #[must_use]
    pub fn index(&self, index: usize) -> Option<&Self> {
        match self {
            Self::List(values) => values.get(index),
            _ => None,
        }
    }

    pub fn render(&self) -> Result<String, &'static str> {
        match self {
            Self::Null => Ok(String::new()),
            Self::Bool(value) => Ok(value.to_string()),
            Self::Integer(value) => Ok(value.to_string()),
            Self::Float(value) if value.is_finite() => Ok(value.to_string()),
            Self::Float(_) => Err("non-finite floats cannot be rendered"),
            Self::String(value) => Ok(value.clone()),
            Self::Bytes(value) => String::from_utf8(value.clone())
                .map_err(|_| "bytes are not valid UTF-8 and cannot be rendered"),
            Self::List(_) | Self::Map(_) => {
                serde_json::to_string(self).map_err(|_| "value cannot be serialized")
            }
        }
    }

    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "bool",
            Self::Integer(_) => "integer",
            Self::Float(_) => "float",
            Self::String(_) => "string",
            Self::Bytes(_) => "bytes",
            Self::List(_) => "list",
            Self::Map(_) => "map",
        }
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

mod bytes_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<u8>::deserialize(deserializer)
    }
}
