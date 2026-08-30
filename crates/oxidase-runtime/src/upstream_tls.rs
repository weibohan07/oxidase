//! Prepared upstream TLS policy shared by Proxy and active health checks.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use oxidase_config::ClusterSpec;
use oxidase_core::{ContentDigest, ContentDigestBuilder, Diagnostic, ResourceId, SourceSpan};
use rustls::ClientConfig;
use rustls::crypto::ring::default_provider;
use rustls::sign::SingleCertAndKey;
use rustls::{RootCertStore, pki_types::ServerName};

use crate::{PreparedCertificate, PreparedTrustStore};

/// Fully validated upstream TLS state. Hyper connector types remain at the
/// server boundary; this object contains only rustls policy and stable identity.
#[derive(Clone)]
pub struct PreparedUpstreamTls {
    digest: ContentDigest,
    client_config: Arc<ClientConfig>,
    server_name: Option<ServerName<'static>>,
    root_count: usize,
    has_client_certificate: bool,
}

impl PreparedUpstreamTls {
    pub(crate) fn prepare(
        cluster: &ClusterSpec,
        trust_stores: &BTreeMap<ResourceId, Arc<PreparedTrustStore>>,
        certificates: &BTreeMap<ResourceId, Arc<PreparedCertificate>>,
    ) -> Result<Option<Self>, UpstreamTlsPreparationFailure> {
        if !cluster
            .endpoints
            .iter()
            .any(|endpoint| endpoint.url.scheme() == "https")
        {
            return Ok(None);
        }

        let source = cluster.tls.as_ref();
        let system_roots = source.is_none_or(|source| source.trust.system_roots);
        let mut roots = RootCertStore::empty();
        let mut digest = ContentDigestBuilder::new("oxidase/upstream-tls/v1");
        digest.field_bytes("cluster", cluster.id.as_str().as_bytes());
        digest.field_u64("system_roots", u64::from(system_roots));

        if system_roots {
            let loaded = rustls_native_certs::load_native_certs();
            let mut certificates = loaded.certs;
            certificates.sort_by(|left, right| left.as_ref().cmp(right.as_ref()));
            certificates.dedup_by(|left, right| left.as_ref() == right.as_ref());
            let (accepted, _) = roots.add_parsable_certificates(certificates.iter().cloned());
            digest.field_u64("system_root_count", accepted as u64);
            for certificate in &certificates {
                digest.field_bytes("system_root_der", certificate.as_ref());
            }
            if accepted == 0 && source.is_none_or(|source| source.trust.trust_store.is_none()) {
                return Err(UpstreamTlsPreparationFailure::new(
                    UpstreamTlsPreparationErrorKind::NativeRoots,
                    "upstream_tls.system_roots",
                    format!(
                        "native TLS trust store contains no usable certificates ({} load errors)",
                        loaded.errors.len()
                    ),
                    source.map_or_else(
                        || cluster.source.clone(),
                        |source| source.trust.system_roots_source.clone(),
                    ),
                ));
            }
        }

        if let Some(trust_store_id) = source.and_then(|source| source.trust.trust_store.as_ref()) {
            let trust_store = trust_stores.get(trust_store_id).ok_or_else(|| {
                UpstreamTlsPreparationFailure::new(
                    UpstreamTlsPreparationErrorKind::TrustStoreUnavailable,
                    "upstream_tls.trust_store_unavailable",
                    format!("prepared trust store `{trust_store_id}` is unavailable"),
                    source
                        .and_then(|source| source.trust.trust_store_source.clone())
                        .unwrap_or_else(|| cluster.source.clone()),
                )
            })?;
            roots
                .roots
                .extend(trust_store.roots().roots.iter().cloned());
            digest.field_digest("custom_trust_store", trust_store.digest());
        }
        if roots.is_empty() {
            return Err(UpstreamTlsPreparationFailure::new(
                UpstreamTlsPreparationErrorKind::TrustStoreEmpty,
                "upstream_tls.trust_empty",
                "upstream TLS policy has no trust anchors",
                source.map_or_else(
                    || cluster.source.clone(),
                    |source| source.trust.source.clone(),
                ),
            ));
        }

        let provider = Arc::new(default_provider());
        let builder = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| {
                UpstreamTlsPreparationFailure::new(
                    UpstreamTlsPreparationErrorKind::ClientConfig,
                    "upstream_tls.client_config",
                    format!("cannot enable safe upstream TLS versions: {error}"),
                    source.map_or_else(|| cluster.source.clone(), |source| source.source.clone()),
                )
            })?
            .with_root_certificates(roots.clone());

        let client_certificate = source.and_then(|source| source.client_certificate.as_ref());
        let client_config = if let Some(certificate_id) = client_certificate {
            let certificate = certificates.get(certificate_id).ok_or_else(|| {
                UpstreamTlsPreparationFailure::new(
                    UpstreamTlsPreparationErrorKind::ClientCertificateUnavailable,
                    "upstream_tls.client_certificate_unavailable",
                    format!("prepared client certificate `{certificate_id}` is unavailable"),
                    source
                        .and_then(|source| source.client_certificate_source.clone())
                        .unwrap_or_else(|| cluster.source.clone()),
                )
            })?;
            digest.field_digest("client_certificate", certificate.digest);
            builder.with_client_cert_resolver(Arc::new(SingleCertAndKey::from(
                certificate.certified_key(),
            )))
        } else {
            builder.with_no_client_auth()
        };

        let server_name = source
            .and_then(|source| source.server_name.as_ref())
            .map(|name| {
                ServerName::try_from(name.clone()).map_err(|_| {
                    UpstreamTlsPreparationFailure::new(
                        UpstreamTlsPreparationErrorKind::ServerName,
                        "upstream_tls.server_name",
                        "compiled upstream TLS server name is invalid",
                        source
                            .and_then(|source| source.server_name_source.clone())
                            .unwrap_or_else(|| cluster.source.clone()),
                    )
                })
            })
            .transpose()?;
        if let Some(server_name) = &server_name {
            digest.field_bytes("server_name", server_name.to_str().as_bytes());
        }

        Ok(Some(Self {
            digest: digest.finish(),
            client_config: Arc::new(client_config),
            server_name,
            root_count: roots.len(),
            has_client_certificate: client_certificate.is_some(),
        }))
    }

    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }

    #[must_use]
    pub fn client_config(&self) -> Arc<ClientConfig> {
        Arc::clone(&self.client_config)
    }

    #[must_use]
    pub fn server_name(&self) -> Option<ServerName<'static>> {
        self.server_name.clone()
    }
}

impl fmt::Debug for PreparedUpstreamTls {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedUpstreamTls")
            .field("digest", &self.digest)
            .field("root_count", &self.root_count)
            .field("has_fixed_server_name", &self.server_name.is_some())
            .field("has_client_certificate", &self.has_client_certificate)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamTlsPreparationErrorKind {
    NativeRoots,
    TrustStoreUnavailable,
    TrustStoreEmpty,
    ClientCertificateUnavailable,
    ClientConfig,
    ServerName,
}

impl fmt::Display for UpstreamTlsPreparationErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NativeRoots => "native upstream TLS roots are unavailable",
            Self::TrustStoreUnavailable => "prepared upstream trust store is unavailable",
            Self::TrustStoreEmpty => "upstream TLS trust policy is empty",
            Self::ClientCertificateUnavailable => {
                "prepared upstream client certificate is unavailable"
            }
            Self::ClientConfig => "upstream rustls client configuration failed",
            Self::ServerName => "upstream TLS server name is invalid",
        })
    }
}

#[derive(Debug)]
pub(crate) struct UpstreamTlsPreparationFailure {
    pub kind: UpstreamTlsPreparationErrorKind,
    pub diagnostic: Box<Diagnostic>,
}

impl UpstreamTlsPreparationFailure {
    fn new(
        kind: UpstreamTlsPreparationErrorKind,
        code: &'static str,
        message: impl Into<String>,
        source: SourceSpan,
    ) -> Self {
        Self {
            kind,
            diagnostic: Box::new(Diagnostic::new(code, message, source)),
        }
    }
}
