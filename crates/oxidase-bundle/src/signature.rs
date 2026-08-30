use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::Read as _;
use std::path::Path;

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use oxidase_core::ContentDigest;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{BundleArchive, BundleDigest, BundleError, BundleErrorKind, SignatureRecord};

const ALGORITHM: &str = "ed25519";
const SIGNING_DOMAIN: &[u8] = b"oxidase.bundle.signature/v1\0";
pub const DEFAULT_KEY_FILE_LIMIT: u64 = 4 * 1024;

pub struct BundleSigningKey {
    key_id: String,
    key: SigningKey,
}

impl BundleSigningKey {
    pub fn from_bytes(key_id: impl Into<String>, bytes: &[u8]) -> Result<Self, BundleError> {
        let key_id = key_id.into();
        validate_key_id(&key_id)?;
        let key = match bytes.len() {
            32 => {
                let mut seed: [u8; 32] = bytes.try_into().map_err(|_| invalid_key_length())?;
                let key = SigningKey::from_bytes(&seed);
                seed.zeroize();
                key
            }
            64 => {
                let mut keypair: [u8; 64] = bytes.try_into().map_err(|_| invalid_key_length())?;
                let result = SigningKey::from_keypair_bytes(&keypair);
                keypair.zeroize();
                result.map_err(|_| {
                    BundleError::new(
                        BundleErrorKind::InvalidSigningKey,
                        "Ed25519 keypair contains an inconsistent public key",
                    )
                })?
            }
            _ => return Err(invalid_key_length()),
        };
        Ok(Self { key_id, key })
    }

    pub fn read_file(path: impl AsRef<Path>) -> Result<Self, BundleError> {
        let bytes = read_bounded_key_file(path.as_ref(), DEFAULT_KEY_FILE_LIMIT)?;
        let key_material = decode_key_material(&bytes, &[32, 64])?;
        let mut key = Self::from_bytes("pending", &key_material)?;
        key.key_id = derived_key_id(key.key.verifying_key().as_bytes());
        Ok(key)
    }

    pub fn read_file_with_id(
        key_id: impl Into<String>,
        path: impl AsRef<Path>,
        max_bytes: u64,
    ) -> Result<Self, BundleError> {
        let bytes = read_bounded_key_file(path.as_ref(), max_bytes)?;
        let key_material = decode_key_material(&bytes, &[32, 64])?;
        Self::from_bytes(key_id, &key_material)
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub fn verification_key(&self) -> BundleVerificationKey {
        BundleVerificationKey {
            key_id: self.key_id.clone(),
            key: self.key.verifying_key(),
        }
    }

    #[must_use]
    pub fn sign_digest(&self, digest: BundleDigest) -> SignatureRecord {
        let message = signing_message(digest);
        let signature = self.key.sign(&message);
        SignatureRecord {
            algorithm: ALGORITHM.to_owned(),
            key_id: self.key_id.clone(),
            signature: hex_encode(&signature.to_bytes()),
        }
    }
}

impl fmt::Debug for BundleSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BundleSigningKey")
            .field("key_id", &self.key_id)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct BundleVerificationKey {
    key_id: String,
    key: VerifyingKey,
}

impl BundleVerificationKey {
    pub fn from_bytes(key_id: impl Into<String>, bytes: &[u8]) -> Result<Self, BundleError> {
        let key_id = key_id.into();
        validate_key_id(&key_id)?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            BundleError::new(
                BundleErrorKind::InvalidSigningKey,
                "Ed25519 verification key must contain exactly 32 bytes",
            )
        })?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| {
            BundleError::new(
                BundleErrorKind::InvalidSigningKey,
                "Ed25519 verification key is not a valid compressed Edwards point",
            )
        })?;
        Ok(Self { key_id, key })
    }

    pub fn read_file(path: impl AsRef<Path>) -> Result<Self, BundleError> {
        let bytes = read_bounded_key_file(path.as_ref(), DEFAULT_KEY_FILE_LIMIT)?;
        let key_material = decode_key_material(&bytes, &[32])?;
        let key_id = derived_key_id(&key_material);
        Self::from_bytes(key_id, &key_material)
    }

    pub fn read_file_with_id(
        key_id: impl Into<String>,
        path: impl AsRef<Path>,
        max_bytes: u64,
    ) -> Result<Self, BundleError> {
        let bytes = read_bounded_key_file(path.as_ref(), max_bytes)?;
        let key_material = decode_key_material(&bytes, &[32])?;
        Self::from_bytes(key_id, &key_material)
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.key.as_bytes()
    }
}

impl fmt::Debug for BundleVerificationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BundleVerificationKey")
            .field("key_id", &self.key_id)
            .field("key", &hex_encode(self.key.as_bytes()))
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureRequirement {
    AllowUnsigned,
    RequireAnyTrusted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureVerification {
    pub verified_key_ids: BTreeSet<String>,
    pub untrusted_signature_count: usize,
}

impl BundleArchive {
    pub fn sign(&self, signing_key: &BundleSigningKey) -> Result<Self, BundleError> {
        let mut signatures = self.signatures().signatures.clone();
        signatures.retain(|record| {
            record.algorithm != ALGORITHM || record.key_id != signing_key.key_id()
        });
        signatures.push(signing_key.sign_digest(self.signing_digest()));
        self.with_signatures(signatures)
    }

    pub fn write_signed_atomic(
        &self,
        path: impl AsRef<Path>,
        signing_keys: &[BundleSigningKey],
    ) -> Result<BundleDigest, BundleError> {
        let mut signatures = self.signatures().signatures.clone();
        for signing_key in signing_keys {
            signatures.retain(|record| {
                record.algorithm != ALGORITHM || record.key_id != signing_key.key_id()
            });
            signatures.push(signing_key.sign_digest(self.signing_digest()));
        }
        self.write_atomic_with_signatures(path, signatures)
    }

    pub fn verify_ed25519(
        &self,
        trusted_keys: &[BundleVerificationKey],
        requirement: SignatureRequirement,
    ) -> Result<SignatureVerification, BundleError> {
        if self.signatures().signatures.is_empty() {
            return match requirement {
                SignatureRequirement::AllowUnsigned => Ok(SignatureVerification {
                    verified_key_ids: BTreeSet::new(),
                    untrusted_signature_count: 0,
                }),
                SignatureRequirement::RequireAnyTrusted => Err(BundleError::new(
                    BundleErrorKind::SignatureRequired,
                    "bundle policy requires a trusted Ed25519 signature",
                )),
            };
        }
        let mut trusted = BTreeMap::new();
        for key in trusted_keys {
            if trusted.insert(key.key_id.as_str(), &key.key).is_some() {
                return Err(BundleError::new(
                    BundleErrorKind::InvalidSigningKey,
                    format!(
                        "trusted Ed25519 key id `{}` is configured more than once",
                        key.key_id
                    ),
                ));
            }
        }
        let message = signing_message(self.signing_digest());
        let mut verified = BTreeSet::new();
        let mut untrusted = 0_usize;
        for record in &self.signatures().signatures {
            if record.algorithm != ALGORITHM {
                untrusted += 1;
                continue;
            }
            let Some(key) = trusted.get(record.key_id.as_str()) else {
                untrusted += 1;
                continue;
            };
            let signature_bytes = decode_fixed::<64>(&record.signature).map_err(|_| {
                BundleError::new(
                    BundleErrorKind::SignatureVerificationFailed,
                    format!(
                        "Ed25519 signature from key `{}` has invalid bytes",
                        record.key_id
                    ),
                )
            })?;
            let signature = Signature::from_bytes(&signature_bytes);
            key.verify_strict(&message, &signature).map_err(|_| {
                BundleError::new(
                    BundleErrorKind::SignatureVerificationFailed,
                    format!(
                        "Ed25519 signature from trusted key `{}` does not verify",
                        record.key_id
                    ),
                )
            })?;
            verified.insert(record.key_id.clone());
        }
        if requirement == SignatureRequirement::RequireAnyTrusted && verified.is_empty() {
            return Err(BundleError::new(
                BundleErrorKind::SignatureVerificationFailed,
                "bundle has signatures but none were produced by a trusted Ed25519 key",
            ));
        }
        Ok(SignatureVerification {
            verified_key_ids: verified,
            untrusted_signature_count: untrusted,
        })
    }
}

fn signing_message(digest: BundleDigest) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNING_DOMAIN.len() + 32);
    message.extend_from_slice(SIGNING_DOMAIN);
    message.extend_from_slice(digest.as_bytes());
    message
}

fn validate_key_id(key_id: &str) -> Result<(), BundleError> {
    if key_id.is_empty()
        || key_id.len() > 256
        || key_id.contains(['\0', '\r', '\n'])
        || !key_id.is_ascii()
    {
        return Err(BundleError::new(
            BundleErrorKind::InvalidSigningKey,
            "signature key id must be non-empty bounded ASCII without control delimiters",
        ));
    }
    Ok(())
}

fn invalid_key_length() -> BundleError {
    BundleError::new(
        BundleErrorKind::InvalidSigningKey,
        "Ed25519 signing key must contain a 32-byte seed or 64-byte keypair",
    )
}

fn read_bounded_key_file(path: &Path, max_bytes: u64) -> Result<Zeroizing<Vec<u8>>, BundleError> {
    if max_bytes == 0 {
        return Err(BundleError::new(
            BundleErrorKind::InvalidSigningKey,
            "key file byte limit must be greater than zero",
        ));
    }
    let before =
        std::fs::metadata(path).map_err(|error| BundleError::io(error, "stat Ed25519 key file"))?;
    if !before.is_file() {
        return Err(BundleError::new(
            BundleErrorKind::InvalidSigningKey,
            "Ed25519 key path is not a regular file",
        ));
    }
    if before.len() > max_bytes {
        return Err(BundleError::new(
            BundleErrorKind::LimitExceeded,
            format!(
                "Ed25519 key file contains {} bytes, exceeding limit {max_bytes}",
                before.len()
            ),
        ));
    }
    #[cfg(unix)]
    let mut file = {
        use rustix::fs::{Mode, OFlags};

        let descriptor = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| {
            BundleError::io(
                std::io::Error::from_raw_os_error(error.raw_os_error()),
                "open Ed25519 key file",
            )
        })?;
        File::from(descriptor)
    };
    #[cfg(not(unix))]
    let mut file =
        File::open(path).map_err(|error| BundleError::io(error, "open Ed25519 key file"))?;
    let metadata = file
        .metadata()
        .map_err(|error| BundleError::io(error, "inspect opened Ed25519 key file"))?;
    if !metadata.is_file() {
        return Err(BundleError::new(
            BundleErrorKind::InvalidSigningKey,
            "opened Ed25519 key is not a regular file",
        ));
    }
    if metadata.len() > max_bytes {
        return Err(BundleError::new(
            BundleErrorKind::LimitExceeded,
            format!(
                "Ed25519 key file contains {} bytes, exceeding limit {max_bytes}",
                metadata.len()
            ),
        ));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(metadata.len()).unwrap_or(0),
    ));
    file.by_ref()
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| BundleError::io(error, "read Ed25519 key file"))?;
    if bytes.len() as u64 > max_bytes {
        return Err(BundleError::new(
            BundleErrorKind::LimitExceeded,
            "Ed25519 key file grew beyond its configured byte limit while reading",
        ));
    }
    Ok(bytes)
}

fn decode_key_material(
    bytes: &[u8],
    accepted_raw_lengths: &[usize],
) -> Result<Zeroizing<Vec<u8>>, BundleError> {
    if accepted_raw_lengths.contains(&bytes.len()) {
        return Ok(Zeroizing::new(bytes.to_vec()));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid_key_encoding())?;
    let trimmed = text.trim_ascii();
    if !accepted_raw_lengths
        .iter()
        .any(|length| trimmed.len() == length * 2)
    {
        return Err(invalid_key_encoding());
    }
    let mut decoded = Zeroizing::new(Vec::with_capacity(trimmed.len() / 2));
    for pair in trimmed.as_bytes().chunks_exact(2) {
        decoded.push(
            (hex_nibble(pair[0]).map_err(|_| invalid_key_encoding())? << 4)
                | hex_nibble(pair[1]).map_err(|_| invalid_key_encoding())?,
        );
    }
    Ok(decoded)
}

fn invalid_key_encoding() -> BundleError {
    BundleError::new(
        BundleErrorKind::InvalidSigningKey,
        "Ed25519 key file must contain raw bytes or lowercase hexadecimal",
    )
}

fn derived_key_id(public_key: &[u8]) -> String {
    let digest = ContentDigest::of_bytes(public_key).to_hex();
    format!("ed25519-{}", &digest[..32])
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

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], ()> {
    if value.len() != N * 2 {
        return Err(());
    }
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> Result<u8, ()> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{BuildMetadata, BundleBuilder, BundleLimits, BundleManifest};

    fn archive() -> BundleArchive {
        let manifest = BundleManifest::new(
            BuildMetadata {
                tool_version: "0.4.0-alpha.1".to_owned(),
                source_commit: None,
                gateway_api: "oxidase.dev/v1alpha1".to_owned(),
                oxista_api: "v1".to_owned(),
            },
            "0.4.0-alpha.1",
        );
        let bytes = BundleBuilder::new(manifest).build().expect("bundle");
        BundleArchive::parse(&bytes, &BundleLimits::default()).expect("archive")
    }

    #[test]
    fn valid_wrong_and_rotated_keys_are_distinguished() {
        let first = BundleSigningKey::from_bytes("first", &[7_u8; 32]).expect("first key");
        let second = BundleSigningKey::from_bytes("second", &[9_u8; 32]).expect("second key");
        let wrong = BundleSigningKey::from_bytes("wrong", &[11_u8; 32]).expect("wrong key");
        let signed = archive()
            .sign(&first)
            .expect("first signature")
            .sign(&second)
            .expect("second signature");

        let rotation = signed
            .verify_ed25519(
                &[first.verification_key(), second.verification_key()],
                SignatureRequirement::RequireAnyTrusted,
            )
            .expect("rotated keys verify");
        assert_eq!(
            rotation.verified_key_ids,
            BTreeSet::from(["first".to_owned(), "second".to_owned()])
        );
        assert_eq!(rotation.untrusted_signature_count, 0);
        let duplicate = first.verification_key();
        assert_eq!(
            signed
                .verify_ed25519(
                    &[duplicate.clone(), duplicate],
                    SignatureRequirement::RequireAnyTrusted,
                )
                .expect_err("duplicate trusted key identities are ambiguous")
                .kind(),
            BundleErrorKind::InvalidSigningKey
        );
        assert_eq!(
            signed
                .verify_ed25519(
                    &[wrong.verification_key()],
                    SignatureRequirement::RequireAnyTrusted,
                )
                .expect_err("wrong trust set")
                .kind(),
            BundleErrorKind::SignatureVerificationFailed
        );
    }

    #[test]
    fn signature_corruption_is_rejected() {
        let key = BundleSigningKey::from_bytes("release", &[3_u8; 32]).expect("key");
        let signed = archive().sign(&key).expect("signed");
        let mut records = signed.signatures().signatures.clone();
        records[0].signature = "00".repeat(64);
        let corrupt = signed.with_signatures(records).expect("valid envelope");
        assert_eq!(
            corrupt
                .verify_ed25519(
                    &[key.verification_key()],
                    SignatureRequirement::RequireAnyTrusted,
                )
                .expect_err("corrupt signature")
                .kind(),
            BundleErrorKind::SignatureVerificationFailed
        );
    }

    #[test]
    fn unsigned_policy_and_private_key_redaction_are_explicit() {
        let unsigned = archive();
        unsigned
            .verify_ed25519(&[], SignatureRequirement::AllowUnsigned)
            .expect("unsigned allowed");
        assert_eq!(
            unsigned
                .verify_ed25519(&[], SignatureRequirement::RequireAnyTrusted)
                .expect_err("signature required")
                .kind(),
            BundleErrorKind::SignatureRequired
        );
        let seed = [0x42_u8; 32];
        let key = BundleSigningKey::from_bytes("release", &seed).expect("key");
        assert!(!format!("{key:?}").contains("42424242"));
        let encoded = unsigned.sign(&key).expect("sign").encode().expect("encode");
        assert!(!encoded.windows(seed.len()).any(|window| window == seed));
    }

    #[test]
    fn verification_key_round_trips_public_bytes() {
        let signing = BundleSigningKey::from_bytes("release", &[1_u8; 32]).expect("key");
        let public = signing.verification_key();
        let rebuilt = BundleVerificationKey::from_bytes("release", public.as_bytes())
            .expect("verification key");
        assert_eq!(public, rebuilt);
        let debug = format!("{rebuilt:?}");
        assert!(debug.contains("release"));
    }

    #[test]
    fn signing_does_not_change_content_digest() {
        let key = BundleSigningKey::from_bytes("release", &[5_u8; 32]).expect("key");
        let unsigned = archive();
        let signed = unsigned.sign(&key).expect("signed");
        assert_eq!(unsigned.content_digest(), signed.content_digest());
        assert_ne!(unsigned.file_digest(), signed.file_digest());
        assert_eq!(
            serde_json::to_value(BTreeMap::from([("digest", signed.signing_digest())]))
                .expect("digest JSON")["digest"]
                .as_str()
                .map(str::len),
            Some(64)
        );
    }

    #[test]
    fn bounded_key_files_support_raw_and_hex_with_derived_rotation_ids() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let signing_path = directory.path().join("signing.key");
        let public_path = directory.path().join("verify.key");
        std::fs::write(&signing_path, format!("{}\n", "17".repeat(32))).expect("write signing key");
        let signing = BundleSigningKey::read_file(&signing_path).expect("read signing key");
        std::fs::write(&public_path, signing.verification_key().as_bytes())
            .expect("write public key");
        let verification = BundleVerificationKey::read_file(&public_path).expect("read public key");
        assert_eq!(signing.key_id(), verification.key_id());
        archive()
            .sign(&signing)
            .expect("sign")
            .verify_ed25519(&[verification], SignatureRequirement::RequireAnyTrusted)
            .expect("verify");

        assert_eq!(
            BundleSigningKey::read_file_with_id("too-large", &signing_path, 8)
                .expect_err("bounded read")
                .kind(),
            BundleErrorKind::LimitExceeded
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn non_regular_key_input_is_rejected_without_blocking() {
        use rustix::fs::{CWD, Mode, mkfifoat};

        let directory = tempfile::tempdir().expect("temporary directory");
        let fifo = directory.path().join("signing.fifo");
        mkfifoat(CWD, &fifo, Mode::RUSR | Mode::WUSR).expect("test FIFO is created");
        assert_eq!(
            BundleSigningKey::read_file(&fifo)
                .expect_err("FIFO is not a key file")
                .kind(),
            BundleErrorKind::InvalidSigningKey
        );
    }

    #[test]
    fn path_archive_signing_rewrites_streamingly_and_verifies() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let unsigned_path = directory.path().join("unsigned.oxb");
        let signed_path = directory.path().join("signed.oxb");
        let source = archive();
        source.write_atomic(&unsigned_path).expect("write unsigned");
        let indexed = BundleArchive::read_path(&unsigned_path, &BundleLimits::default())
            .expect("index unsigned");
        let key = BundleSigningKey::from_bytes("release", &[23_u8; 32]).expect("key");
        indexed
            .write_signed_atomic(&signed_path, &[key])
            .expect("write signed");
        let signed =
            BundleArchive::read_path(&signed_path, &BundleLimits::default()).expect("index signed");
        let trusted = BundleSigningKey::from_bytes("release", &[23_u8; 32])
            .expect("rebuild key")
            .verification_key();
        signed
            .verify_ed25519(&[trusted], SignatureRequirement::RequireAnyTrusted)
            .expect("verify signed path archive");
        assert_eq!(indexed.content_digest(), signed.content_digest());
    }
}
