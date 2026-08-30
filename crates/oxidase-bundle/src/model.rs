use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use oxidase_core::ContentDigest;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{BundleError, BundleErrorKind};

pub const BUNDLE_SCHEMA_VERSION: &str = "oxidase.bundle/v1";
pub const SIGNATURE_SCHEMA_VERSION: &str = "oxidase.bundle.signatures/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BundleDigest(ContentDigest);

impl BundleDigest {
    #[must_use]
    pub fn of_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(ContentDigest::of_bytes(bytes))
    }

    #[must_use]
    pub const fn from_content_digest(digest: ContentDigest) -> Self {
        Self(digest)
    }

    #[must_use]
    pub const fn content_digest(self) -> ContentDigest {
        self.0
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(ContentDigest::of_bytes([])).replace_bytes(bytes)
    }

    fn replace_bytes(self, bytes: [u8; 32]) -> Self {
        // ContentDigest deliberately does not expose unchecked construction.
        // A fixed-size digest read from a verified container is encoded through
        // its stable hexadecimal serde form instead.
        let hex = hex_encode(&bytes);
        parse_digest(&hex).expect("hex generated from 32 bytes is always a digest")
    }
}

impl From<ContentDigest> for BundleDigest {
    fn from(value: ContentDigest) -> Self {
        Self(value)
    }
}

impl From<BundleDigest> for ContentDigest {
    fn from(value: BundleDigest) -> Self {
        value.0
    }
}

impl fmt::Display for BundleDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for BundleDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for BundleDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = String::deserialize(deserializer)?;
        parse_digest(&input).map_err(de::Error::custom)
    }
}

fn parse_digest(input: &str) -> Result<BundleDigest, &'static str> {
    if input.len() != 64 {
        return Err("SHA-256 digest must contain exactly 64 lowercase hexadecimal characters");
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in input.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }

    // ContentDigest has an intentionally opaque representation. Deserialize
    // its stable serde array rather than adding an unchecked public constructor.
    let encoded = serde_json::to_vec(&bytes).map_err(|_| "failed to encode digest")?;
    let digest =
        serde_json::from_slice::<ContentDigest>(&encoded).map_err(|_| "failed to decode digest")?;
    Ok(BundleDigest(digest))
}

fn hex_nibble(byte: u8) -> Result<u8, &'static str> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("SHA-256 digest must use lowercase hexadecimal characters"),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum CanonicalValue {
    Float(CanonicalFloat),
    Bytes(CanonicalBytes),
    Null,
    Bool(bool),
    Integer(i64),
    Unsigned(u64),
    String(String),
    Array(Vec<CanonicalValue>),
    Object(BTreeMap<String, CanonicalValue>),
}

impl CanonicalValue {
    #[must_use]
    pub fn float(value: f64) -> Self {
        Self::Float(CanonicalFloat {
            bits: format!("{:016x}", value.to_bits()),
        })
    }

    #[must_use]
    pub fn bytes(value: impl AsRef<[u8]>) -> Self {
        Self::Bytes(CanonicalBytes {
            hex: hex_encode(value.as_ref()),
        })
    }

    pub fn from_core_value(value: &oxidase_core::Value) -> Self {
        match value {
            oxidase_core::Value::Null => Self::Null,
            oxidase_core::Value::Bool(value) => Self::Bool(*value),
            oxidase_core::Value::Integer(value) => Self::Integer(*value),
            oxidase_core::Value::Float(value) => Self::float(*value),
            oxidase_core::Value::String(value) => Self::String(value.clone()),
            oxidase_core::Value::Bytes(value) => Self::bytes(value),
            oxidase_core::Value::List(values) => {
                Self::Array(values.iter().map(Self::from_core_value).collect())
            }
            oxidase_core::Value::Map(values) => Self::Object(
                values
                    .iter()
                    .map(|(key, value)| (key.clone(), Self::from_core_value(value)))
                    .collect(),
            ),
        }
    }

    pub fn from_json(value: serde_json::Value) -> Result<Self, BundleError> {
        match value {
            serde_json::Value::Null => Ok(Self::Null),
            serde_json::Value::Bool(value) => Ok(Self::Bool(value)),
            serde_json::Value::Number(value) => {
                if let Some(value) = value.as_i64() {
                    Ok(Self::Integer(value))
                } else if let Some(value) = value.as_u64() {
                    Ok(Self::Unsigned(value))
                } else if let Some(value) = value.as_f64() {
                    Ok(Self::float(value))
                } else {
                    Err(BundleError::new(
                        BundleErrorKind::InvalidModel,
                        "JSON number cannot be represented by the stable bundle value model",
                    ))
                }
            }
            serde_json::Value::String(value) => Ok(Self::String(value)),
            serde_json::Value::Array(values) => values
                .into_iter()
                .map(Self::from_json)
                .collect::<Result<Vec<_>, _>>()
                .map(Self::Array),
            serde_json::Value::Object(values) => values
                .into_iter()
                .map(|(key, value)| Ok((key, Self::from_json(value)?)))
                .collect::<Result<BTreeMap<_, _>, BundleError>>()
                .map(Self::Object),
        }
    }

    pub fn to_json(&self) -> Result<serde_json::Value, BundleError> {
        match self {
            Self::Float(value) => serde_json::Number::from_f64(value.value()?)
                .map(serde_json::Value::Number)
                .ok_or_else(|| {
                    BundleError::new(
                        BundleErrorKind::InvalidModel,
                        "non-finite canonical float cannot be decoded through JSON serde",
                    )
                }),
            Self::Bytes(value) => Ok(serde_json::Value::Array(
                value
                    .value()?
                    .into_iter()
                    .map(|byte| serde_json::Value::Number(byte.into()))
                    .collect(),
            )),
            Self::Null => Ok(serde_json::Value::Null),
            Self::Bool(value) => Ok(serde_json::Value::Bool(*value)),
            Self::Integer(value) => Ok(serde_json::Value::Number((*value).into())),
            Self::Unsigned(value) => Ok(serde_json::Value::Number((*value).into())),
            Self::String(value) => Ok(serde_json::Value::String(value.clone())),
            Self::Array(values) => values
                .iter()
                .map(Self::to_json)
                .collect::<Result<Vec<_>, _>>()
                .map(serde_json::Value::Array),
            Self::Object(values) => values
                .iter()
                .map(|(key, value)| Ok((key.clone(), value.to_json()?)))
                .collect::<Result<serde_json::Map<_, _>, BundleError>>()
                .map(serde_json::Value::Object),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalFloat {
    #[serde(rename = "$oxidase_float_bits")]
    bits: String,
}

impl CanonicalFloat {
    pub fn value(&self) -> Result<f64, BundleError> {
        if self.bits.len() != 16
            || !self
                .bits
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(BundleError::new(
                BundleErrorKind::InvalidModel,
                "canonical float must contain exactly 16 lowercase hexadecimal bit digits",
            ));
        }
        let bits = u64::from_str_radix(&self.bits, 16).map_err(|_| {
            BundleError::new(
                BundleErrorKind::InvalidModel,
                "canonical float bit encoding is invalid",
            )
        })?;
        Ok(f64::from_bits(bits))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalBytes {
    #[serde(rename = "$oxidase_bytes_hex")]
    hex: String,
}

impl CanonicalBytes {
    pub fn value(&self) -> Result<Vec<u8>, BundleError> {
        if self.hex.len() & 1 != 0
            || !self
                .hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(BundleError::new(
                BundleErrorKind::InvalidModel,
                "canonical bytes must contain even-length lowercase hexadecimal",
            ));
        }
        self.hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| Ok((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
            .collect::<Result<Vec<_>, &'static str>>()
            .map_err(|message| BundleError::new(BundleErrorKind::InvalidModel, message))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildMetadata {
    pub tool_version: String,
    pub source_commit: Option<String>,
    pub gateway_api: String,
    pub oxista_api: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StableSection {
    pub schema: String,
    pub required: bool,
    pub payload: CanonicalValue,
}

impl StableSection {
    pub fn from_serde<T: Serialize>(
        schema: impl Into<String>,
        required: bool,
        value: &T,
    ) -> Result<Self, BundleError> {
        let value = serde_json::to_value(value).map_err(|error| {
            BundleError::new(
                BundleErrorKind::InvalidModel,
                format!("failed to encode stable section value: {error}"),
            )
        })?;
        Ok(Self {
            schema: schema.into(),
            required,
            payload: CanonicalValue::from_json(value)?,
        })
    }

    pub fn to_serde<T>(&self) -> Result<T, BundleError>
    where
        T: serde::de::DeserializeOwned,
    {
        serde_json::from_value(self.payload.to_json()?).map_err(|error| {
            BundleError::new(
                BundleErrorKind::InvalidModel,
                format!(
                    "stable section `{}` cannot be decoded into the requested type: {error}",
                    self.schema
                ),
            )
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetReferenceBase {
    Absolute,
    DeploymentRoot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum AssetStorage {
    Embedded {
        blob: BundleDigest,
        length: u64,
    },
    Reference {
        base: AssetReferenceBase,
        path: String,
        expected_digest: BundleDigest,
        length: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetDescriptor {
    pub storage: AssetStorage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveReferenceKind {
    Secret,
    PrivateKey,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SensitiveReference {
    pub kind: SensitiveReferenceKind,
    pub base: AssetReferenceBase,
    pub runtime_path: String,
    pub max_bytes: u64,
}

impl fmt::Debug for SensitiveReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitiveReference")
            .field("kind", &self.kind)
            .field("base", &self.base)
            .field("runtime_path", &"[REDACTED]")
            .field("max_bytes", &self.max_bytes)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceOrigin {
    pub display_path: String,
    pub start_byte: u64,
    pub end_byte: u64,
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
    pub field_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    pub schema_version: String,
    pub minimum_runtime_version: String,
    pub build: BuildMetadata,
    pub required_features: BTreeSet<String>,
    pub optional_metadata: BTreeMap<String, CanonicalValue>,
    pub sections: BTreeMap<String, StableSection>,
    pub assets: BTreeMap<String, AssetDescriptor>,
    pub sensitive_references: BTreeMap<String, SensitiveReference>,
    pub origins: BTreeMap<String, SourceOrigin>,
}

impl BundleManifest {
    #[must_use]
    pub fn new(build: BuildMetadata, minimum_runtime_version: impl Into<String>) -> Self {
        Self {
            schema_version: BUNDLE_SCHEMA_VERSION.to_owned(),
            minimum_runtime_version: minimum_runtime_version.into(),
            build,
            required_features: BTreeSet::new(),
            optional_metadata: BTreeMap::new(),
            sections: BTreeMap::new(),
            assets: BTreeMap::new(),
            sensitive_references: BTreeMap::new(),
            origins: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureRecord {
    pub algorithm: String,
    pub key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEnvelope {
    pub schema_version: String,
    pub signatures: Vec<SignatureRecord>,
}

impl Default for SignatureEnvelope {
    fn default() -> Self {
        Self {
            schema_version: SIGNATURE_SCHEMA_VERSION.to_owned(),
            signatures: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleCapabilities {
    pub runtime_version: String,
    pub supported_features: BTreeSet<String>,
    /// Exact executable section names and schemas this runtime consumes.
    pub supported_sections: BTreeMap<String, String>,
}

impl Default for BundleCapabilities {
    fn default() -> Self {
        Self {
            runtime_version: env!("CARGO_PKG_VERSION").to_owned(),
            supported_features: BTreeSet::new(),
            supported_sections: BTreeMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct ExampleSection {
        count: u64,
        ratio: f64,
        bytes: Vec<u8>,
    }

    #[test]
    fn stable_section_helpers_round_trip_without_ad_hoc_json() {
        let source = ExampleSection {
            count: u64::MAX,
            ratio: -0.25,
            bytes: vec![0, 1, 254, 255],
        };
        let section = StableSection::from_serde("example/v1", true, &source).expect("encode");
        let decoded = section.to_serde::<ExampleSection>().expect("decode");
        assert_eq!(decoded, source);
    }

    #[test]
    fn core_value_float_and_bytes_keep_distinct_stable_types() {
        let float = CanonicalValue::from_core_value(&oxidase_core::Value::Float(-0.0));
        let bytes = CanonicalValue::from_core_value(&oxidase_core::Value::Bytes(vec![0, 255]));
        let list = CanonicalValue::from_core_value(&oxidase_core::Value::List(vec![
            oxidase_core::Value::Integer(0),
            oxidase_core::Value::Integer(255),
        ]));
        assert!(matches!(float, CanonicalValue::Float(_)));
        assert!(matches!(bytes, CanonicalValue::Bytes(_)));
        assert!(matches!(list, CanonicalValue::Array(_)));
        if let CanonicalValue::Float(value) = float {
            assert_eq!(
                value.value().expect("float").to_bits(),
                (-0.0_f64).to_bits()
            );
        }
    }
}
