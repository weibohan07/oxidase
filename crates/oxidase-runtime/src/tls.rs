use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use oxidase_config::{
    CertificateSpec, CompiledListener, HttpListenerSpec, HttpVersion, ListenerProtocol, SniPattern,
    TlsListenerSpec,
};
use oxidase_core::{
    ContentDigest, ContentDigestBuilder, Diagnostic, ListenerId, ResourceId, ServiceId, SourceSpan,
};
use rustls::crypto::ring::default_provider;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{Error as RustlsError, InconsistentKeys, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};

/// One validated certificate chain and signing key prepared before publication.
///
/// The custom `Debug` implementation deliberately omits the signing key and all
/// certificate bytes. Callers can clone the opaque rustls key for a resolver,
/// but cannot inspect private-key material through this API.
#[derive(Clone)]
pub struct PreparedCertificate {
    pub id: ResourceId,
    pub digest: ContentDigest,
    certified_key: Arc<CertifiedKey>,
    cert_chain_source: SourceSpan,
}

impl PreparedCertificate {
    pub(crate) fn prepare(source: &CertificateSpec) -> Result<Self, CertificatePreparationFailure> {
        let certificate_pem = read_regular_file(
            &source.cert_chain,
            &source.cert_chain_source,
            CertificateFileKind::Chain,
        )?;
        let private_key_pem = read_regular_file(
            &source.private_key,
            &source.private_key_source,
            CertificateFileKind::PrivateKey,
        )?;

        let certificates = CertificateDer::pem_slice_iter(&certificate_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                CertificatePreparationFailure::new(
                    CertificatePreparationErrorKind::CertificatePem,
                    "tls.certificate_pem",
                    format!("certificate chain is not valid PEM: {error}"),
                    source.cert_chain_source.clone(),
                )
            })?;
        if certificates.is_empty() {
            return Err(CertificatePreparationFailure::new(
                CertificatePreparationErrorKind::CertificateChainEmpty,
                "tls.certificate_chain_empty",
                "certificate chain must contain at least one CERTIFICATE section",
                source.cert_chain_source.clone(),
            ));
        }
        for (index, certificate) in certificates.iter().enumerate() {
            webpki::EndEntityCert::try_from(certificate).map_err(|error| {
                CertificatePreparationFailure::new(
                    CertificatePreparationErrorKind::CertificateX509,
                    "tls.certificate_x509",
                    format!(
                        "certificate chain entry {} is not valid X.509: {error}",
                        index + 1
                    ),
                    source.cert_chain_source.clone(),
                )
            })?;
        }

        if appears_to_be_encrypted_private_key(&private_key_pem) {
            return Err(CertificatePreparationFailure::new(
                CertificatePreparationErrorKind::PrivateKeyEncrypted,
                "tls.private_key_encrypted",
                "encrypted private keys are not supported",
                source.private_key_source.clone(),
            )
            .with_help("decrypt the key into a PKCS#8, PKCS#1, or SEC1 PEM file"));
        }
        let mut private_keys = PrivateKeyDer::pem_slice_iter(&private_key_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                CertificatePreparationFailure::new(
                    CertificatePreparationErrorKind::PrivateKeyPem,
                    "tls.private_key_pem",
                    format!("private key is not valid PEM: {error}"),
                    source.private_key_source.clone(),
                )
            })?;
        let private_key = match private_keys.len() {
            0 => {
                return Err(CertificatePreparationFailure::new(
                    CertificatePreparationErrorKind::PrivateKeyMissing,
                    "tls.private_key_missing",
                    "private key file must contain exactly one PKCS#8, PKCS#1, or SEC1 key",
                    source.private_key_source.clone(),
                ));
            }
            1 => private_keys
                .pop()
                .expect("the private-key count was checked immediately above"),
            count => {
                return Err(CertificatePreparationFailure::new(
                    CertificatePreparationErrorKind::PrivateKeyMultiple,
                    "tls.private_key_multiple",
                    format!("private key file contains {count} keys; exactly one is required"),
                    source.private_key_source.clone(),
                ));
            }
        };

        let provider = default_provider();
        let certified_key = CertifiedKey::from_der(certificates, private_key, &provider)
            .map_err(|error| certified_key_error(source, error))?;
        // `from_der` deliberately accepts providers that cannot expose their
        // public key. Oxidase's preparation contract is stricter: consistency
        // must be positively established before publication.
        certified_key
            .keys_match()
            .map_err(|error| certified_key_error(source, error))?;

        let mut digest = ContentDigestBuilder::new("oxidase/certificate-chain/v1");
        digest.field_u64("certificate_count", certified_key.cert.len() as u64);
        for certificate in &certified_key.cert {
            digest.field_bytes("certificate_der", certificate.as_ref());
        }

        Ok(Self {
            id: source.id.clone(),
            digest: digest.finish(),
            certified_key: Arc::new(certified_key),
            cert_chain_source: source.cert_chain_source.clone(),
        })
    }

    /// Returns the public certificate chain length without exposing its bytes.
    #[must_use]
    pub fn certificate_count(&self) -> usize {
        self.certified_key.cert.len()
    }

    /// Clones the opaque rustls signing material for use by a TLS resolver.
    #[must_use]
    pub fn certified_key(&self) -> Arc<CertifiedKey> {
        Arc::clone(&self.certified_key)
    }

    fn matches_server_name(&self, server_name: &str) -> Result<(), webpki::Error> {
        let leaf = self
            .certified_key
            .cert
            .first()
            .expect("prepared certificate chains are non-empty");
        let certificate = webpki::EndEntityCert::try_from(leaf)
            .expect("prepared leaf certificates were parsed during preparation");
        let server_name = ServerName::try_from(server_name.to_owned())
            .expect("compiled SNI names and generated probes are valid DNS names");
        certificate.verify_is_valid_for_subject_name(&server_name)
    }

    fn has_dns_subject_alt_name(&self, expected: &str) -> bool {
        let leaf = self
            .certified_key
            .cert
            .first()
            .expect("prepared certificate chains are non-empty");
        let certificate = webpki::EndEntityCert::try_from(leaf)
            .expect("prepared leaf certificates were parsed during preparation");
        certificate
            .valid_dns_names()
            .any(|name| name.eq_ignore_ascii_case(expected))
    }
}

impl fmt::Debug for PreparedCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedCertificate")
            .field("id", &self.id)
            .field("certificate_count", &self.certificate_count())
            .finish_non_exhaustive()
    }
}

/// Exact/wildcard/default SNI resolver shared by one prepared ServerConfig.
pub struct PreparedCertificateResolver {
    default: Arc<PreparedCertificate>,
    exact: BTreeMap<String, Arc<PreparedCertificate>>,
    wildcards: Vec<(String, Arc<PreparedCertificate>)>,
}

impl PreparedCertificateResolver {
    fn prepare(
        source: &TlsListenerSpec,
        certificates: &BTreeMap<ResourceId, Arc<PreparedCertificate>>,
    ) -> Result<Self, TlsListenerPreparationFailure> {
        let default = certificates
            .get(&source.default_certificate)
            .cloned()
            .ok_or_else(|| {
                TlsListenerPreparationFailure::new(
                    TlsListenerPreparationErrorKind::CertificateUnavailable,
                    "tls.certificate_unavailable",
                    format!(
                        "prepared default certificate `{}` is unavailable",
                        source.default_certificate
                    ),
                    source.default_certificate_source.clone(),
                )
            })?;
        let mut exact = BTreeMap::new();
        let mut wildcards = Vec::new();
        for rule in &source.sni {
            let certificate = certificates
                .get(&rule.certificate)
                .cloned()
                .ok_or_else(|| {
                    TlsListenerPreparationFailure::new(
                        TlsListenerPreparationErrorKind::CertificateUnavailable,
                        "tls.certificate_unavailable",
                        format!("prepared certificate `{}` is unavailable", rule.certificate),
                        rule.certificate_source.clone(),
                    )
                })?;
            let compatibility: Result<(), String> = match &rule.pattern {
                SniPattern::Exact(name) => certificate
                    .matches_server_name(name)
                    .map_err(|error| error.to_string()),
                SniPattern::Wildcard(suffix) => {
                    let declared = format!("*.{suffix}");
                    if !certificate.has_dns_subject_alt_name(&declared) {
                        Err(format!("leaf subjectAltName does not contain `{declared}`"))
                    } else {
                        // Also ask webpki to exercise its wildcard matching rules
                        // against a representative single-label reference name.
                        certificate
                            .matches_server_name(&format!("oxidase-sni-probe.{suffix}"))
                            .map_err(|error| error.to_string())
                    }
                }
            };
            compatibility.map_err(|error| {
                TlsListenerPreparationFailure::new(
                    TlsListenerPreparationErrorKind::SniCertificateName,
                    "tls.sni_certificate_name",
                    format!(
                        "certificate `{}` is not valid for declared SNI rule `{}`: {error}",
                        certificate.id,
                        rule.pattern.normalized_rule()
                    ),
                    rule.source.clone(),
                )
                .with_label("certificate resource", rule.certificate_source.clone())
                .with_related("certificate chain", certificate.cert_chain_source.clone())
                .with_help("use a certificate whose subjectAltName covers this SNI rule")
            })?;
            match &rule.pattern {
                SniPattern::Exact(name) => {
                    exact.insert(name.clone(), certificate);
                }
                SniPattern::Wildcard(suffix) => {
                    wildcards.push((suffix.clone(), certificate));
                }
            }
        }
        wildcards.sort_by(|left, right| {
            right
                .0
                .len()
                .cmp(&left.0.len())
                .then_with(|| left.0.cmp(&right.0))
        });
        Ok(Self {
            default,
            exact,
            wildcards,
        })
    }

    /// Selects exact SNI first, then a single-label wildcard, then default.
    #[must_use]
    pub fn resolve_prepared(&self, server_name: Option<&str>) -> Arc<PreparedCertificate> {
        let Some(server_name) = server_name else {
            return Arc::clone(&self.default);
        };
        let server_name = server_name.to_ascii_lowercase();
        if let Some(certificate) = self.exact.get(&server_name) {
            return Arc::clone(certificate);
        }
        self.wildcards
            .iter()
            .find(|(suffix, _)| wildcard_matches(suffix, &server_name))
            .map_or_else(
                || Arc::clone(&self.default),
                |(_, certificate)| Arc::clone(certificate),
            )
    }
}

impl fmt::Debug for PreparedCertificateResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedCertificateResolver")
            .field("default", &self.default.id)
            .field("exact_rule_count", &self.exact.len())
            .field("wildcard_rule_count", &self.wildcards.len())
            .finish()
    }
}

impl ResolvesServerCert for PreparedCertificateResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(
            self.resolve_prepared(client_hello.server_name())
                .certified_key(),
        )
    }
}

/// Prepared HTTPS transport state. Existing connections retain this Arc while
/// a reload can publish a new one for future accepts.
#[derive(Clone)]
pub struct PreparedTlsListener {
    pub server_config: Arc<ServerConfig>,
    pub handshake_timeout: Duration,
    pub resolver: Arc<PreparedCertificateResolver>,
}

impl fmt::Debug for PreparedTlsListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedTlsListener")
            .field("handshake_timeout", &self.handshake_timeout)
            .field("alpn_protocols", &self.server_config.alpn_protocols)
            .field("resolver", &self.resolver)
            .finish_non_exhaustive()
    }
}

/// Immutable connection plan installed for new accepts on one listener.
#[derive(Clone)]
pub struct PreparedListenerPlan {
    pub id: ListenerId,
    pub name: String,
    pub bind: SocketAddr,
    pub protocol: ListenerProtocol,
    pub http: HttpListenerSpec,
    pub service: ServiceId,
    pub source: SourceSpan,
    pub tls: Option<PreparedTlsListener>,
    pub digest: ContentDigest,
}

impl PreparedListenerPlan {
    pub(crate) fn prepare(
        source: &CompiledListener,
        certificates: &BTreeMap<ResourceId, Arc<PreparedCertificate>>,
    ) -> Result<Self, TlsListenerPreparationFailure> {
        let tls = match &source.tls {
            Some(tls) => {
                let resolver = Arc::new(PreparedCertificateResolver::prepare(tls, certificates)?);
                let provider = Arc::new(default_provider());
                let mut server_config = ServerConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()
                    .map_err(|error| {
                        TlsListenerPreparationFailure::new(
                            TlsListenerPreparationErrorKind::ServerConfig,
                            "tls.server_config",
                            format!("cannot enable the safe TLS 1.2/1.3 defaults: {error}"),
                            tls.source.clone(),
                        )
                    })?
                    .with_no_client_auth()
                    .with_cert_resolver(resolver.clone());
                server_config.alpn_protocols = source
                    .http
                    .versions
                    .iter()
                    .map(|version| match version {
                        HttpVersion::H2 => b"h2".to_vec(),
                        HttpVersion::Http1 => b"http/1.1".to_vec(),
                    })
                    .collect();
                Some(PreparedTlsListener {
                    server_config: Arc::new(server_config),
                    handshake_timeout: tls.handshake_timeout,
                    resolver,
                })
            }
            None => None,
        };

        let mut digest = ContentDigestBuilder::new("oxidase/listener-plan/v1");
        digest
            .field_bytes("id", source.id.as_str().as_bytes())
            .field_bytes("name", source.name.as_bytes())
            .field_bytes("bind", source.bind.to_string().as_bytes())
            .field_bytes(
                "protocol",
                match source.protocol {
                    ListenerProtocol::Http => b"http".as_slice(),
                    ListenerProtocol::Https => b"https".as_slice(),
                },
            )
            .field_bytes("service", source.service.as_str().as_bytes())
            .field_u64("http_version_count", source.http.versions.len() as u64);
        for version in &source.http.versions {
            digest.field_bytes(
                "http_version",
                match version {
                    HttpVersion::Http1 => b"http1".as_slice(),
                    HttpVersion::H2 => b"h2".as_slice(),
                },
            );
        }
        if let Some(settings) = &source.http.http1 {
            digest.field_u128(
                "http1_header_read_timeout_ns",
                settings.header_read_timeout.as_nanos(),
            );
        }
        if let Some(settings) = &source.http.http2 {
            digest
                .field_u64(
                    "http2_max_concurrent_streams",
                    u64::from(settings.max_concurrent_streams),
                )
                .field_u64(
                    "http2_max_header_list_size",
                    u64::from(settings.max_header_list_size),
                )
                .field_u128(
                    "http2_keep_alive_interval_ns",
                    settings.keep_alive_interval.as_nanos(),
                )
                .field_u128(
                    "http2_keep_alive_timeout_ns",
                    settings.keep_alive_timeout.as_nanos(),
                );
        }
        if let Some(tls_source) = &source.tls {
            digest
                .field_u128(
                    "tls_handshake_timeout_ns",
                    tls_source.handshake_timeout.as_nanos(),
                )
                .field_digest(
                    "tls_default_certificate",
                    certificates[&tls_source.default_certificate].digest,
                )
                .field_u64("tls_sni_rule_count", tls_source.sni.len() as u64);
            for rule in &tls_source.sni {
                digest
                    .field_bytes("tls_sni_rule", rule.pattern.normalized_rule().as_bytes())
                    .field_digest(
                        "tls_sni_certificate",
                        certificates[&rule.certificate].digest,
                    );
            }
        }

        Ok(Self {
            id: source.id.clone(),
            name: source.name.clone(),
            bind: source.bind,
            protocol: source.protocol,
            http: source.http.clone(),
            service: source.service.clone(),
            source: source.source.clone(),
            tls,
            digest: digest.finish(),
        })
    }

    /// A listener socket can remain bound when only transport, protocol, or
    /// Service state changes. New accepts receive the newly published plan.
    #[must_use]
    pub fn can_reuse_socket_from(&self, previous: &Self) -> bool {
        self.id == previous.id && self.bind == previous.bind
    }
}

impl fmt::Debug for PreparedListenerPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedListenerPlan")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("bind", &self.bind)
            .field("protocol", &self.protocol)
            .field("http", &self.http)
            .field("service", &self.service)
            .field("source", &self.source)
            .field("tls", &self.tls)
            .field("digest", &self.digest)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificatePreparationErrorKind {
    CertificateMissing,
    CertificateNotFile,
    CertificateRead,
    CertificatePem,
    CertificateChainEmpty,
    CertificateX509,
    PrivateKeyMissingFile,
    PrivateKeyNotFile,
    PrivateKeyRead,
    PrivateKeyEncrypted,
    PrivateKeyPem,
    PrivateKeyMissing,
    PrivateKeyMultiple,
    PrivateKeyUnsupported,
    KeyMismatch,
    KeyMatchUnavailable,
}

impl fmt::Display for CertificatePreparationErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CertificateMissing => "certificate chain file does not exist",
            Self::CertificateNotFile => "certificate chain path is not a regular file",
            Self::CertificateRead => "certificate chain file cannot be read",
            Self::CertificatePem => "certificate chain PEM is invalid",
            Self::CertificateChainEmpty => "certificate chain is empty",
            Self::CertificateX509 => "certificate chain contains invalid X.509",
            Self::PrivateKeyMissingFile => "private key file does not exist",
            Self::PrivateKeyNotFile => "private key path is not a regular file",
            Self::PrivateKeyRead => "private key file cannot be read",
            Self::PrivateKeyEncrypted => "private key is encrypted",
            Self::PrivateKeyPem => "private key PEM is invalid",
            Self::PrivateKeyMissing => "private key is missing",
            Self::PrivateKeyMultiple => "multiple private keys were supplied",
            Self::PrivateKeyUnsupported => "private key is unsupported",
            Self::KeyMismatch => "private key does not match the leaf certificate",
            Self::KeyMatchUnavailable => "private-key consistency cannot be established",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsListenerPreparationErrorKind {
    CertificateUnavailable,
    SniCertificateName,
    ServerConfig,
}

impl fmt::Display for TlsListenerPreparationErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CertificateUnavailable => "listener certificate is unavailable",
            Self::SniCertificateName => "certificate does not cover its SNI rule",
            Self::ServerConfig => "TLS server configuration is invalid",
        })
    }
}

#[derive(Debug)]
pub(crate) struct CertificatePreparationFailure {
    pub kind: CertificatePreparationErrorKind,
    pub diagnostic: Box<Diagnostic>,
}

impl CertificatePreparationFailure {
    fn new(
        kind: CertificatePreparationErrorKind,
        code: &'static str,
        message: impl Into<String>,
        primary: SourceSpan,
    ) -> Self {
        Self {
            kind,
            diagnostic: Box::new(Diagnostic::new(code, message, primary)),
        }
    }

    fn with_help(mut self, help: impl Into<String>) -> Self {
        self.diagnostic = Box::new((*self.diagnostic).with_help(help));
        self
    }
}

#[derive(Debug)]
pub(crate) struct TlsListenerPreparationFailure {
    pub kind: TlsListenerPreparationErrorKind,
    pub diagnostic: Box<Diagnostic>,
}

impl TlsListenerPreparationFailure {
    fn new(
        kind: TlsListenerPreparationErrorKind,
        code: &'static str,
        message: impl Into<String>,
        primary: SourceSpan,
    ) -> Self {
        Self {
            kind,
            diagnostic: Box::new(Diagnostic::new(code, message, primary)),
        }
    }

    fn with_label(mut self, message: impl Into<String>, span: SourceSpan) -> Self {
        self.diagnostic = Box::new((*self.diagnostic).with_label(message, span));
        self
    }

    fn with_related(mut self, message: impl Into<String>, span: SourceSpan) -> Self {
        self.diagnostic = Box::new((*self.diagnostic).with_related(message, span));
        self
    }

    fn with_help(mut self, help: impl Into<String>) -> Self {
        self.diagnostic = Box::new((*self.diagnostic).with_help(help));
        self
    }
}

#[derive(Clone, Copy)]
enum CertificateFileKind {
    Chain,
    PrivateKey,
}

fn read_regular_file(
    path: &Path,
    source: &SourceSpan,
    kind: CertificateFileKind,
) -> Result<Vec<u8>, CertificatePreparationFailure> {
    let metadata = fs::metadata(path).map_err(|error| {
        let missing = error.kind() == std::io::ErrorKind::NotFound;
        let (kind, code, message) = match (kind, missing) {
            (CertificateFileKind::Chain, true) => (
                CertificatePreparationErrorKind::CertificateMissing,
                "tls.certificate_missing",
                "certificate chain file does not exist".to_owned(),
            ),
            (CertificateFileKind::Chain, false) => (
                CertificatePreparationErrorKind::CertificateRead,
                "tls.certificate_read",
                format!("cannot inspect certificate chain file: {error}"),
            ),
            (CertificateFileKind::PrivateKey, true) => (
                CertificatePreparationErrorKind::PrivateKeyMissingFile,
                "tls.private_key_missing_file",
                "private key file does not exist".to_owned(),
            ),
            (CertificateFileKind::PrivateKey, false) => (
                CertificatePreparationErrorKind::PrivateKeyRead,
                "tls.private_key_read",
                format!("cannot inspect private key file: {error}"),
            ),
        };
        CertificatePreparationFailure::new(kind, code, message, source.clone())
    })?;
    if !metadata.is_file() {
        let (kind, code, message) = match kind {
            CertificateFileKind::Chain => (
                CertificatePreparationErrorKind::CertificateNotFile,
                "tls.certificate_not_file",
                "certificate chain path must name a regular file",
            ),
            CertificateFileKind::PrivateKey => (
                CertificatePreparationErrorKind::PrivateKeyNotFile,
                "tls.private_key_not_file",
                "private key path must name a regular file",
            ),
        };
        return Err(CertificatePreparationFailure::new(
            kind,
            code,
            message,
            source.clone(),
        ));
    }
    fs::read(path).map_err(|error| {
        let (kind, code, message) = match kind {
            CertificateFileKind::Chain => (
                CertificatePreparationErrorKind::CertificateRead,
                "tls.certificate_read",
                format!("cannot read certificate chain file: {error}"),
            ),
            CertificateFileKind::PrivateKey => (
                CertificatePreparationErrorKind::PrivateKeyRead,
                "tls.private_key_read",
                format!("cannot read private key file: {error}"),
            ),
        };
        CertificatePreparationFailure::new(kind, code, message, source.clone())
    })
}

fn certified_key_error(
    source: &CertificateSpec,
    error: RustlsError,
) -> CertificatePreparationFailure {
    match error {
        RustlsError::InconsistentKeys(InconsistentKeys::KeyMismatch) => {
            CertificatePreparationFailure::new(
                CertificatePreparationErrorKind::KeyMismatch,
                "tls.key_mismatch",
                "private key does not match the leaf certificate",
                source.private_key_source.clone(),
            )
            .with_help("select the private key corresponding to the first certificate in the chain")
        }
        RustlsError::InconsistentKeys(InconsistentKeys::Unknown) => {
            CertificatePreparationFailure::new(
                CertificatePreparationErrorKind::KeyMatchUnavailable,
                "tls.key_match_unavailable",
                "the private key provider cannot prove that the key matches the leaf certificate",
                source.private_key_source.clone(),
            )
        }
        error => CertificatePreparationFailure::new(
            CertificatePreparationErrorKind::PrivateKeyUnsupported,
            "tls.private_key_unsupported",
            format!("private key is not supported by the configured ring provider: {error}"),
            source.private_key_source.clone(),
        ),
    }
}

fn appears_to_be_encrypted_private_key(pem: &[u8]) -> bool {
    ascii_contains_ignore_case(pem, b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
        || (ascii_contains_ignore_case(pem, b"PROC-TYPE:")
            && ascii_contains_ignore_case(pem, b"ENCRYPTED"))
        || ascii_contains_ignore_case(pem, b"DEK-INFO:")
}

fn ascii_contains_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn wildcard_matches(suffix: &str, server_name: &str) -> bool {
    server_name
        .strip_suffix(suffix)
        .and_then(|prefix| prefix.strip_suffix('.'))
        .is_some_and(|label| !label.is_empty() && !label.contains('.'))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;

    use oxidase_config::{CertificateSpec, SniCertificateSpec, SniPattern, TlsListenerSpec};
    use oxidase_core::{ResourceId, SourceSpan};
    use rcgen::{CertifiedKey as GeneratedCertificate, generate_simple_self_signed};
    use tempfile::tempdir;

    use super::{
        CertificatePreparationErrorKind, PreparedCertificate, PreparedCertificateResolver,
    };

    struct TestIdentity {
        certificate_pem: String,
        private_key_pem: String,
    }

    fn identity(names: &[&str]) -> TestIdentity {
        let GeneratedCertificate { cert, signing_key } = generate_simple_self_signed(
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )
        .expect("test-only certificate can be generated");
        TestIdentity {
            certificate_pem: cert.pem(),
            private_key_pem: signing_key.serialize_pem(),
        }
    }

    fn certificate_spec(
        directory: &Path,
        name: &str,
        certificate_pem: &str,
        private_key_pem: &str,
    ) -> CertificateSpec {
        let certificate = directory.join(format!("{name}.pem"));
        let private_key = directory.join(format!("{name}-key.pem"));
        fs::write(&certificate, certificate_pem).expect("test certificate can be written");
        fs::write(&private_key, private_key_pem).expect("test private key can be written");
        CertificateSpec {
            id: ResourceId::new(format!("certificate:{name}")),
            cert_chain: certificate,
            private_key,
            cert_chain_source: SourceSpan::synthetic(format!(
                "resources.certificates.{name}.cert_chain"
            )),
            private_key_source: SourceSpan::synthetic(format!(
                "resources.certificates.{name}.private_key"
            )),
            source: SourceSpan::synthetic(format!("resources.certificates.{name}")),
        }
    }

    #[test]
    fn rejects_empty_certificate_chain() {
        let directory = tempdir().expect("temporary directory is available");
        let generated = identity(&["default.example.test"]);
        let source = certificate_spec(directory.path(), "empty", "", &generated.private_key_pem);

        let failure = PreparedCertificate::prepare(&source)
            .expect_err("an empty certificate chain must fail preparation");
        assert_eq!(
            failure.kind,
            CertificatePreparationErrorKind::CertificateChainEmpty
        );
        assert_eq!(failure.diagnostic.code, "tls.certificate_chain_empty");
    }

    #[test]
    fn rejects_multiple_private_keys_without_exposing_them() {
        let directory = tempdir().expect("temporary directory is available");
        let generated = identity(&["default.example.test"]);
        let private_keys = format!("{}{}", generated.private_key_pem, generated.private_key_pem);
        let source = certificate_spec(
            directory.path(),
            "multiple",
            &generated.certificate_pem,
            &private_keys,
        );

        let failure = PreparedCertificate::prepare(&source)
            .expect_err("multiple private keys must fail preparation");
        assert_eq!(
            failure.kind,
            CertificatePreparationErrorKind::PrivateKeyMultiple
        );
        assert_eq!(failure.diagnostic.code, "tls.private_key_multiple");
        assert!(!failure.diagnostic.message.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn rejects_encrypted_private_key_armor_before_generic_pem_errors() {
        let directory = tempdir().expect("temporary directory is available");
        let generated = identity(&["default.example.test"]);
        let source = certificate_spec(
            directory.path(),
            "encrypted",
            &generated.certificate_pem,
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n-----END ENCRYPTED PRIVATE KEY-----\n",
        );

        let failure = PreparedCertificate::prepare(&source)
            .expect_err("encrypted private keys must fail with a specific diagnostic");
        assert_eq!(
            failure.kind,
            CertificatePreparationErrorKind::PrivateKeyEncrypted
        );
        assert_eq!(failure.diagnostic.code, "tls.private_key_encrypted");
    }

    #[test]
    fn rejects_certificate_private_key_mismatch() {
        let directory = tempdir().expect("temporary directory is available");
        let certificate = identity(&["default.example.test"]);
        let other_key = identity(&["other.example.test"]);
        let source = certificate_spec(
            directory.path(),
            "mismatch",
            &certificate.certificate_pem,
            &other_key.private_key_pem,
        );

        let failure = PreparedCertificate::prepare(&source)
            .expect_err("a mismatched private key must fail preparation");
        assert_eq!(failure.kind, CertificatePreparationErrorKind::KeyMismatch);
        assert_eq!(failure.diagnostic.code, "tls.key_mismatch");
    }

    #[test]
    fn accepts_common_rsa_pkcs1_private_keys() {
        let directory = tempdir().expect("temporary directory is available");
        let certificate_path = directory.path().join("rsa-cert.pem");
        let private_key_path = directory.path().join("rsa-key.pem");
        fs::write(
            &certificate_path,
            include_bytes!("../tests/fixtures/test-only-rsa-cert.pem"),
        )
        .expect("test-only RSA certificate can be written");
        fs::write(
            &private_key_path,
            include_bytes!("../tests/fixtures/test-only-rsa-key.pem"),
        )
        .expect("test-only RSA private key can be written");

        let prepared = PreparedCertificate::prepare(&CertificateSpec {
            id: ResourceId::new("certificate:rsa"),
            cert_chain: certificate_path,
            private_key: private_key_path,
            cert_chain_source: SourceSpan::synthetic("resources.certificates.rsa.cert_chain"),
            private_key_source: SourceSpan::synthetic("resources.certificates.rsa.private_key"),
            source: SourceSpan::synthetic("resources.certificates.rsa"),
        })
        .expect("a matching PKCS#1 RSA identity is supported");
        assert_eq!(prepared.certificate_count(), 1);
        prepared
            .matches_server_name("rsa.example.test")
            .expect("test-only certificate covers its DNS name");
    }

    #[test]
    fn resolves_exact_then_single_label_wildcard_then_default() {
        let directory = tempdir().expect("temporary directory is available");
        let inputs = [
            ("default", identity(&["default.example.test"])),
            ("api", identity(&["api.example.test"])),
            ("internal", identity(&["*.internal.example.test"])),
        ];
        let mut certificates = BTreeMap::new();
        let mut paths = BTreeMap::<&str, PathBuf>::new();
        for (name, generated) in &inputs {
            let source = certificate_spec(
                directory.path(),
                name,
                &generated.certificate_pem,
                &generated.private_key_pem,
            );
            paths.insert(name, source.cert_chain.clone());
            certificates.insert(
                source.id.clone(),
                Arc::new(
                    PreparedCertificate::prepare(&source).expect("test-only certificate prepares"),
                ),
            );
        }
        let source = TlsListenerSpec {
            default_certificate: ResourceId::new("certificate:default"),
            default_certificate_source: SourceSpan::synthetic(
                "listeners[0].tls.default_certificate",
            ),
            sni: vec![
                SniCertificateSpec {
                    pattern: SniPattern::Exact("api.example.test".to_owned()),
                    certificate: ResourceId::new("certificate:api"),
                    source: SourceSpan::synthetic("listeners[0].tls.sni.api.example.test"),
                    certificate_source: SourceSpan::synthetic(
                        "listeners[0].tls.sni.api.example.test",
                    ),
                },
                SniCertificateSpec {
                    pattern: SniPattern::Wildcard("internal.example.test".to_owned()),
                    certificate: ResourceId::new("certificate:internal"),
                    source: SourceSpan::synthetic("listeners[0].tls.sni[*.internal.example.test]"),
                    certificate_source: SourceSpan::synthetic(
                        "listeners[0].tls.sni[*.internal.example.test]",
                    ),
                },
            ],
            handshake_timeout: Duration::from_secs(5),
            source: SourceSpan::synthetic("listeners[0].tls"),
        };
        let resolver = PreparedCertificateResolver::prepare(&source, &certificates)
            .expect("compatible SNI certificates prepare");

        assert_eq!(
            resolver
                .resolve_prepared(Some("API.EXAMPLE.TEST"))
                .id
                .as_str(),
            "certificate:api"
        );
        assert_eq!(
            resolver
                .resolve_prepared(Some("one.internal.example.test"))
                .id
                .as_str(),
            "certificate:internal"
        );
        assert_eq!(
            resolver
                .resolve_prepared(Some("two.one.internal.example.test"))
                .id
                .as_str(),
            "certificate:default"
        );
        assert_eq!(
            resolver.resolve_prepared(None).id.as_str(),
            "certificate:default"
        );
        assert_eq!(paths.len(), 3);
    }

    #[test]
    fn rejects_sni_rule_not_covered_by_certificate_san() {
        let directory = tempdir().expect("temporary directory is available");
        let generated = identity(&["different.example.test"]);
        let certificate_source = certificate_spec(
            directory.path(),
            "wrong",
            &generated.certificate_pem,
            &generated.private_key_pem,
        );
        let certificate = Arc::new(
            PreparedCertificate::prepare(&certificate_source)
                .expect("test-only certificate prepares"),
        );
        let certificates = BTreeMap::from([(certificate.id.clone(), certificate)]);
        let source = TlsListenerSpec {
            default_certificate: ResourceId::new("certificate:wrong"),
            default_certificate_source: SourceSpan::synthetic(
                "listeners[0].tls.default_certificate",
            ),
            sni: vec![SniCertificateSpec {
                pattern: SniPattern::Exact("api.example.test".to_owned()),
                certificate: ResourceId::new("certificate:wrong"),
                source: SourceSpan::synthetic("listeners[0].tls.sni.api.example.test"),
                certificate_source: SourceSpan::synthetic("listeners[0].tls.sni.api.example.test"),
            }],
            handshake_timeout: Duration::from_secs(5),
            source: SourceSpan::synthetic("listeners[0].tls"),
        };

        let failure = PreparedCertificateResolver::prepare(&source, &certificates)
            .expect_err("an incompatible certificate SAN must fail preparation");
        assert_eq!(failure.diagnostic.code, "tls.sni_certificate_name");
    }
}
