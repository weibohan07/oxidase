use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// A complete SHA-256 content identity owned by Oxidase.
///
/// The concrete hashing implementation is intentionally hidden so IR and
/// runtime APIs do not depend on a third-party hasher type.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct ContentDigest([u8; 32]);

impl ContentDigest {
    /// Computes the digest of exactly the supplied bytes.
    #[must_use]
    pub fn of_bytes(bytes: impl AsRef<[u8]>) -> Self {
        let mut hasher = ContentHasher::new();
        hasher.update(bytes);
        hasher.finish()
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        let mut output = String::with_capacity(64);
        for byte in self.0 {
            use std::fmt::Write as _;
            write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
        }
        output
    }
}

impl fmt::Display for ContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Streaming SHA-256 for byte-for-byte content identities such as asset ETags.
pub struct ContentHasher(Sha256);

impl ContentHasher {
    #[must_use]
    pub fn new() -> Self {
        Self(Sha256::new())
    }

    pub fn update(&mut self, bytes: impl AsRef<[u8]>) {
        self.0.update(bytes);
    }

    #[must_use]
    pub fn finish(self) -> ContentDigest {
        ContentDigest(self.0.finalize().into())
    }
}

impl Default for ContentHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Unambiguous structured digest construction using domain separation and
/// length-prefixed field names and values.
pub struct ContentDigestBuilder {
    hasher: ContentHasher,
}

impl ContentDigestBuilder {
    #[must_use]
    pub fn new(domain: &str) -> Self {
        let mut builder = Self {
            hasher: ContentHasher::new(),
        };
        builder.field_bytes("domain", domain.as_bytes());
        builder
    }

    pub fn field_bytes(&mut self, name: &str, value: impl AsRef<[u8]>) -> &mut Self {
        let value = value.as_ref();
        self.hasher.update((name.len() as u64).to_be_bytes());
        self.hasher.update(name.as_bytes());
        self.hasher.update((value.len() as u64).to_be_bytes());
        self.hasher.update(value);
        self
    }

    pub fn field_u64(&mut self, name: &str, value: u64) -> &mut Self {
        self.field_bytes(name, value.to_be_bytes())
    }

    pub fn field_u128(&mut self, name: &str, value: u128) -> &mut Self {
        self.field_bytes(name, value.to_be_bytes())
    }

    pub fn field_digest(&mut self, name: &str, value: ContentDigest) -> &mut Self {
        self.field_bytes(name, value.as_bytes())
    }

    #[must_use]
    pub fn finish(self) -> ContentDigest {
        self.hasher.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{ContentDigest, ContentDigestBuilder};

    #[test]
    fn matches_the_sha256_known_vector() {
        assert_eq!(
            ContentDigest::of_bytes(b"abc").to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn structured_fields_are_domain_separated_and_boundary_safe() {
        let mut left = ContentDigestBuilder::new("oxidase/test/v1");
        left.field_bytes("first", b"ab").field_bytes("second", b"c");
        let mut right = ContentDigestBuilder::new("oxidase/test/v1");
        right
            .field_bytes("first", b"a")
            .field_bytes("second", b"bc");
        let mut same_fields_other_domain = ContentDigestBuilder::new("oxidase/other/v1");
        same_fields_other_domain
            .field_bytes("first", b"ab")
            .field_bytes("second", b"c");

        assert_ne!(left.finish(), right.finish());
        let mut same_fields = ContentDigestBuilder::new("oxidase/test/v1");
        same_fields
            .field_bytes("first", b"ab")
            .field_bytes("second", b"c");
        assert_ne!(same_fields.finish(), same_fields_other_domain.finish());
        assert_eq!(
            ContentDigest::of_bytes(b"same"),
            ContentDigest::of_bytes(b"same")
        );
        assert_ne!(
            ContentDigest::of_bytes(b"same"),
            ContentDigest::of_bytes(b"different")
        );
    }
}
