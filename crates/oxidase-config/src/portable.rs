//! Stable, runtime-independent Gateway transport and Resource plans for Bundles.
//!
//! This module deliberately excludes the Service graph and Site snapshots. Those
//! are separately versioned Bundle sections. Importing this DTO rebuilds only
//! compiler-owned configuration types and reparses every textual protocol value.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr as _;
use std::time::Duration;

use http::uri::PathAndQuery;
use http::{Method, StatusCode};
use oxidase_core::{ListenerId, ResourceId, ServiceId, SourceSpan};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::compiler::{
    ActiveHealthSpec, CertificateSpec, ClientAuthMode, ClientAuthSpec, ClusterEndpointSpec,
    ClusterHealthSpec, ClusterLimits, ClusterProtocol, ClusterSpec, ClusterTlsSpec,
    ClusterTlsTrustSpec, CompiledGateway, CompiledListener, CompiledResources, Http1Settings,
    Http2Settings, HttpListenerSpec, HttpVersion, ListenerLimits, ListenerProtocol,
    LoadBalancePolicy, PassiveHealthSpec, RetryBodyMode, RetryCause, RetryRequestBodySpec,
    RetrySpec, SecretSpec, SniCertificateSpec, SniPattern, StatusRange, TlsListenerSpec,
    TrustStoreSpec,
};

pub const PORTABLE_GATEWAY_CONFIG_SCHEMA_V1: &str = "oxidase.gateway-config/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableGatewayConfigV1 {
    pub schema_version: String,
    pub listeners: BTreeMap<String, PortableListenerV1>,
    pub certificates: BTreeMap<String, PortableCertificateV1>,
    pub secrets: BTreeMap<String, PortableSecretV1>,
    pub trust_stores: BTreeMap<String, PortableTrustStoreV1>,
    pub clusters: BTreeMap<String, PortableClusterV1>,
    pub site_ids: Vec<String>,
}

impl PortableGatewayConfigV1 {
    pub fn from_compiled(gateway: &CompiledGateway) -> Result<Self, PortableConfigError> {
        let source_root = gateway
            .source
            .parent()
            .ok_or_else(|| invalid("source", "Gateway source has no parent directory"))?;
        Self::from_compiled_with_root(gateway, source_root)
    }

    pub fn from_compiled_with_root(
        gateway: &CompiledGateway,
        source_root: &Path,
    ) -> Result<Self, PortableConfigError> {
        if !source_root.is_absolute() {
            return Err(invalid("source_root", "source root must be absolute"));
        }
        let listeners = gateway
            .listeners
            .iter()
            .map(|listener| {
                Ok((
                    listener.id.to_string(),
                    PortableListenerV1::from_compiled(listener),
                ))
            })
            .collect::<Result<BTreeMap<_, _>, PortableConfigError>>()?;
        let certificates = gateway
            .resources
            .certificates
            .iter()
            .map(|(id, certificate)| {
                Ok((
                    id.to_string(),
                    PortableCertificateV1::from_compiled(certificate, source_root)?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, PortableConfigError>>()?;
        let secrets = gateway
            .resources
            .secrets
            .iter()
            .map(|(id, secret)| {
                Ok((
                    id.to_string(),
                    PortableSecretV1::from_compiled(secret, source_root)?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, PortableConfigError>>()?;
        let trust_stores = gateway
            .resources
            .trust_stores
            .iter()
            .map(|(id, trust)| (id.to_string(), PortableTrustStoreV1::from_compiled(trust)))
            .collect();
        let clusters = gateway
            .resources
            .clusters
            .iter()
            .map(|(id, cluster)| Ok((id.to_string(), PortableClusterV1::from_compiled(cluster))))
            .collect::<Result<BTreeMap<_, _>, PortableConfigError>>()?;
        let site_ids = gateway
            .resources
            .sites
            .keys()
            .map(ToString::to_string)
            .collect();

        let mut portable = Self {
            schema_version: PORTABLE_GATEWAY_CONFIG_SCHEMA_V1.to_owned(),
            listeners,
            certificates,
            secrets,
            trust_stores,
            clusters,
            site_ids,
        };
        portable.normalize_source_spans(source_root)?;
        Ok(portable)
    }

    fn normalize_source_spans(&mut self, source_root: &Path) -> Result<(), PortableConfigError> {
        for certificate in self.certificates.values_mut() {
            normalize_span(&mut certificate.cert_chain_source, source_root)?;
            normalize_span(&mut certificate.private_key_source, source_root)?;
            normalize_span(&mut certificate.source, source_root)?;
        }
        for secret in self.secrets.values_mut() {
            normalize_span(&mut secret.file_source, source_root)?;
            normalize_span(&mut secret.max_bytes_source, source_root)?;
            normalize_span(&mut secret.source, source_root)?;
        }
        for trust in self.trust_stores.values_mut() {
            normalize_span(&mut trust.ca_bundle_source, source_root)?;
            normalize_span(&mut trust.source, source_root)?;
        }
        for cluster in self.clusters.values_mut() {
            normalize_span(&mut cluster.protocol_source, source_root)?;
            normalize_span(&mut cluster.source, source_root)?;
            for endpoint in &mut cluster.endpoints {
                normalize_span(&mut endpoint.name_source, source_root)?;
                normalize_span(&mut endpoint.url_source, source_root)?;
                normalize_span(&mut endpoint.weight_source, source_root)?;
                normalize_span(&mut endpoint.source, source_root)?;
            }
            if let Some(active) = cluster.health.active.as_mut() {
                normalize_span(&mut active.source, source_root)?;
            }
            if let Some(passive) = cluster.health.passive.as_mut() {
                normalize_span(&mut passive.source, source_root)?;
            }
            normalize_span(&mut cluster.retry.request_body.source, source_root)?;
            normalize_span(&mut cluster.retry.source, source_root)?;
            normalize_span(&mut cluster.limits.source, source_root)?;
            if let Some(tls) = cluster.tls.as_mut() {
                normalize_optional_span(&mut tls.server_name_source, source_root)?;
                normalize_optional_span(&mut tls.client_certificate_source, source_root)?;
                normalize_span(&mut tls.trust.system_roots_source, source_root)?;
                normalize_optional_span(&mut tls.trust.trust_store_source, source_root)?;
                normalize_span(&mut tls.trust.source, source_root)?;
                normalize_span(&mut tls.source, source_root)?;
            }
        }
        for listener in self.listeners.values_mut() {
            normalize_span(&mut listener.source, source_root)?;
            normalize_span(&mut listener.http.source, source_root)?;
            if let Some(http1) = listener.http.http1.as_mut() {
                normalize_span(&mut http1.source, source_root)?;
            }
            if let Some(http2) = listener.http.http2.as_mut() {
                normalize_span(&mut http2.source, source_root)?;
            }
            normalize_span(&mut listener.limits.source, source_root)?;
            if let Some(tls) = listener.tls.as_mut() {
                normalize_span(&mut tls.default_certificate_source, source_root)?;
                for sni in &mut tls.sni {
                    normalize_span(&mut sni.source, source_root)?;
                    normalize_span(&mut sni.certificate_source, source_root)?;
                }
                normalize_span(&mut tls.client_auth.mode_source, source_root)?;
                normalize_optional_span(&mut tls.client_auth.trust_store_source, source_root)?;
                normalize_span(&mut tls.client_auth.source, source_root)?;
                normalize_span(&mut tls.source, source_root)?;
            }
        }
        Ok(())
    }

    pub fn compile_at(
        &self,
        deployment_root: &Path,
    ) -> Result<PortableGatewayPlanV1, PortableConfigError> {
        if !deployment_root.is_absolute() {
            return Err(invalid(
                "deployment_root",
                "deployment root must be absolute",
            ));
        }
        if self.schema_version != PORTABLE_GATEWAY_CONFIG_SCHEMA_V1 {
            return Err(PortableConfigError::UnsupportedSchema(
                self.schema_version.clone(),
            ));
        }
        self.validate_source_spans()?;

        let mut resources = CompiledResources::default();
        for (id, source) in &self.certificates {
            let id = resource_id(id, "certificate", "certificates")?;
            resources
                .certificates
                .insert(id.clone(), source.compile(id, deployment_root)?);
        }
        for (id, source) in &self.secrets {
            let id = resource_id(id, "secret", "secrets")?;
            resources
                .secrets
                .insert(id.clone(), source.compile(id, deployment_root)?);
        }
        for (id, source) in &self.trust_stores {
            let id = resource_id(id, "trust_store", "trust_stores")?;
            resources
                .trust_stores
                .insert(id.clone(), source.compile(id));
        }
        for (id, source) in &self.clusters {
            let id = resource_id(id, "cluster", "clusters")?;
            let cluster = source.compile(id.clone(), &resources)?;
            resources.clusters.insert(id, cluster);
        }

        let mut site_ids = Vec::with_capacity(self.site_ids.len());
        let mut seen_sites = BTreeSet::new();
        for (index, id) in self.site_ids.iter().enumerate() {
            let id = resource_id(id, "site", &format!("site_ids[{index}]"))?;
            if !seen_sites.insert(id.clone()) {
                return Err(invalid(
                    format!("site_ids[{index}]"),
                    "duplicate Site resource identity",
                ));
            }
            site_ids.push(id);
        }

        let mut listeners = Vec::with_capacity(self.listeners.len());
        let mut listener_names = BTreeSet::new();
        for (id, source) in &self.listeners {
            let id = listener_id(id, "listeners")?;
            let listener = source.compile(id, &resources)?;
            if !listener_names.insert(listener.name.clone()) {
                return Err(invalid(
                    "listeners",
                    format!("duplicate listener name `{}`", listener.name),
                ));
            }
            listeners.push(listener);
        }
        if listeners.is_empty() {
            return Err(invalid("listeners", "at least one listener is required"));
        }

        Ok(PortableGatewayPlanV1 {
            resources,
            listeners,
            site_ids,
        })
    }

    fn validate_source_spans(&self) -> Result<(), PortableConfigError> {
        fn check(span: &SourceSpan, field: &str) -> Result<(), PortableConfigError> {
            span.validate_portable()
                .map_err(|message| invalid(field, message))
        }
        fn check_optional(
            span: Option<&SourceSpan>,
            field: &str,
        ) -> Result<(), PortableConfigError> {
            span.map_or(Ok(()), |span| check(span, field))
        }

        for (id, certificate) in &self.certificates {
            check(
                &certificate.cert_chain_source,
                &format!("certificates.{id}.cert_chain_source"),
            )?;
            check(
                &certificate.private_key_source,
                &format!("certificates.{id}.private_key_source"),
            )?;
            check(&certificate.source, &format!("certificates.{id}.source"))?;
        }
        for (id, secret) in &self.secrets {
            check(&secret.file_source, &format!("secrets.{id}.file_source"))?;
            check(
                &secret.max_bytes_source,
                &format!("secrets.{id}.max_bytes_source"),
            )?;
            check(&secret.source, &format!("secrets.{id}.source"))?;
        }
        for (id, trust) in &self.trust_stores {
            check(
                &trust.ca_bundle_source,
                &format!("trust_stores.{id}.ca_bundle_source"),
            )?;
            check(&trust.source, &format!("trust_stores.{id}.source"))?;
        }
        for (id, cluster) in &self.clusters {
            check(
                &cluster.protocol_source,
                &format!("clusters.{id}.protocol_source"),
            )?;
            check(&cluster.source, &format!("clusters.{id}.source"))?;
            for (index, endpoint) in cluster.endpoints.iter().enumerate() {
                for (name, span) in [
                    ("name", &endpoint.name_source),
                    ("url", &endpoint.url_source),
                    ("weight", &endpoint.weight_source),
                    ("source", &endpoint.source),
                ] {
                    check(span, &format!("clusters.{id}.endpoints[{index}].{name}"))?;
                }
            }
            if let Some(active) = &cluster.health.active {
                check(&active.source, &format!("clusters.{id}.health.active"))?;
            }
            if let Some(passive) = &cluster.health.passive {
                check(&passive.source, &format!("clusters.{id}.health.passive"))?;
            }
            check(
                &cluster.retry.request_body.source,
                &format!("clusters.{id}.retry.request_body"),
            )?;
            check(&cluster.retry.source, &format!("clusters.{id}.retry"))?;
            check(&cluster.limits.source, &format!("clusters.{id}.limits"))?;
            if let Some(tls) = &cluster.tls {
                check_optional(
                    tls.server_name_source.as_ref(),
                    &format!("clusters.{id}.tls.server_name"),
                )?;
                check_optional(
                    tls.client_certificate_source.as_ref(),
                    &format!("clusters.{id}.tls.client_certificate"),
                )?;
                check(
                    &tls.trust.system_roots_source,
                    &format!("clusters.{id}.tls.trust.system_roots"),
                )?;
                check_optional(
                    tls.trust.trust_store_source.as_ref(),
                    &format!("clusters.{id}.tls.trust.trust_store"),
                )?;
                check(&tls.trust.source, &format!("clusters.{id}.tls.trust"))?;
                check(&tls.source, &format!("clusters.{id}.tls"))?;
            }
        }
        for (id, listener) in &self.listeners {
            check(&listener.source, &format!("listeners.{id}.source"))?;
            check(&listener.http.source, &format!("listeners.{id}.http"))?;
            if let Some(http1) = &listener.http.http1 {
                check(&http1.source, &format!("listeners.{id}.http.http1"))?;
            }
            if let Some(http2) = &listener.http.http2 {
                check(&http2.source, &format!("listeners.{id}.http.http2"))?;
            }
            check(&listener.limits.source, &format!("listeners.{id}.limits"))?;
            if let Some(tls) = &listener.tls {
                check(
                    &tls.default_certificate_source,
                    &format!("listeners.{id}.tls.default_certificate"),
                )?;
                for (index, sni) in tls.sni.iter().enumerate() {
                    check(&sni.source, &format!("listeners.{id}.tls.sni[{index}]"))?;
                    check(
                        &sni.certificate_source,
                        &format!("listeners.{id}.tls.sni[{index}].certificate"),
                    )?;
                }
                check(
                    &tls.client_auth.mode_source,
                    &format!("listeners.{id}.tls.client_auth.mode"),
                )?;
                check_optional(
                    tls.client_auth.trust_store_source.as_ref(),
                    &format!("listeners.{id}.tls.client_auth.trust_store"),
                )?;
                check(
                    &tls.client_auth.source,
                    &format!("listeners.{id}.tls.client_auth"),
                )?;
                check(&tls.source, &format!("listeners.{id}.tls"))?;
            }
        }
        Ok(())
    }
}

fn normalize_span(span: &mut SourceSpan, source_root: &Path) -> Result<(), PortableConfigError> {
    span.file = portable_source_display_path(&span.file, source_root)?;
    Ok(())
}

/// Produces a deterministic, non-absolute diagnostic identity for one compiler
/// source file. Sources beneath the deployment root keep their relative path;
/// sibling imports encode the number of parent hops without retaining the
/// machine-specific absolute checkout prefix.
pub fn portable_source_display_path(
    path: &Path,
    source_root: &Path,
) -> Result<PathBuf, PortableConfigError> {
    if !path.is_absolute() || !source_root.is_absolute() {
        return Err(invalid(
            "source_span.file",
            "source paths and the source root must be absolute",
        ));
    }
    if let Ok(relative) = path.strip_prefix(source_root) {
        return Ok(PathBuf::from("source/root")
            .join(normalized_relative_path(relative, "source_span.file")?));
    }

    let root_components = source_root.components().collect::<Vec<_>>();
    let path_components = path.components().collect::<Vec<_>>();
    let common = root_components
        .iter()
        .zip(&path_components)
        .take_while(|(left, right)| left == right)
        .count();
    let parent_hops = root_components[common..]
        .iter()
        .filter(|component| matches!(component, Component::Normal(_)))
        .count();
    let mut logical = PathBuf::from("source/external");
    logical.push(format!("up-{parent_hops}"));
    let mut appended = false;
    for component in &path_components[common..] {
        if let Component::Normal(part) = component {
            let part = part
                .to_str()
                .ok_or_else(|| PortableConfigError::NonUtf8Path {
                    field: "source_span.file".to_owned(),
                })?;
            if part.is_empty() || part.contains(['\\', '\0', '\r', '\n']) {
                return Err(invalid(
                    "source_span.file",
                    "source path contains a non-portable component",
                ));
            }
            logical.push(part);
            appended = true;
        }
    }
    if !appended {
        logical.push("source");
    }
    Ok(logical)
}

fn normalize_optional_span(
    span: &mut Option<SourceSpan>,
    source_root: &Path,
) -> Result<(), PortableConfigError> {
    if let Some(span) = span {
        normalize_span(span, source_root)?;
    }
    Ok(())
}

#[derive(Debug)]
pub struct PortableGatewayPlanV1 {
    pub resources: CompiledResources,
    pub listeners: Vec<CompiledListener>,
    /// Site IDs whose separately decoded Site sections must be supplied.
    pub site_ids: Vec<ResourceId>,
}

impl PortableGatewayPlanV1 {
    /// Verifies the independently decoded Site section set before snapshot
    /// assembly. Missing and unreferenced Site sections are both rejected.
    pub fn validate_site_sections(
        &self,
        provided: &BTreeSet<ResourceId>,
    ) -> Result<(), PortableConfigError> {
        let expected = self.site_ids.iter().cloned().collect::<BTreeSet<_>>();
        if let Some(missing) = expected.difference(provided).next() {
            return Err(invalid(
                "site_ids",
                format!("missing portable Site section `{missing}`"),
            ));
        }
        if let Some(extra) = provided.difference(&expected).next() {
            return Err(invalid(
                "site_ids",
                format!("unreferenced portable Site section `{extra}`"),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PortableConfigError {
    #[error("unsupported portable Gateway config schema `{0}`")]
    UnsupportedSchema(String),
    #[error("portable Gateway config field `{field}` is invalid: {message}")]
    Invalid { field: String, message: String },
    #[error("portable Gateway config path `{field}` is not valid UTF-8")]
    NonUtf8Path { field: String },
}

impl PortableConfigError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedSchema(_) => "bundle.gateway_config_schema",
            Self::Invalid { .. } => "bundle.gateway_config_invalid",
            Self::NonUtf8Path { .. } => "bundle.gateway_config_path_encoding",
        }
    }
}

fn invalid(field: impl Into<String>, message: impl Into<String>) -> PortableConfigError {
    PortableConfigError::Invalid {
        field: field.into(),
        message: message.into(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableDurationV1 {
    pub seconds: u64,
    pub nanoseconds: u32,
}

impl PortableDurationV1 {
    fn from_duration(duration: Duration) -> Self {
        Self {
            seconds: duration.as_secs(),
            nanoseconds: duration.subsec_nanos(),
        }
    }

    fn compile(&self, field: &str, allow_zero: bool) -> Result<Duration, PortableConfigError> {
        if self.nanoseconds >= 1_000_000_000 {
            return Err(invalid(field, "nanoseconds must be less than one billion"));
        }
        let duration = Duration::new(self.seconds, self.nanoseconds);
        if duration.is_zero() && !allow_zero {
            return Err(invalid(field, "duration must be greater than zero"));
        }
        Ok(duration)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortablePathRefV1 {
    pub base: String,
    pub path: String,
}

impl PortablePathRefV1 {
    fn from_path(
        path: &Path,
        source_root: &Path,
        field: &str,
    ) -> Result<Self, PortableConfigError> {
        if let Ok(relative) = path.strip_prefix(source_root) {
            return Ok(Self {
                base: "deployment_root".to_owned(),
                path: normalized_relative_path(relative, field)?,
            });
        }
        if !path.is_absolute() {
            return Err(invalid(
                field,
                "path is neither absolute nor beneath the source root",
            ));
        }
        let path = path
            .to_str()
            .ok_or_else(|| PortableConfigError::NonUtf8Path {
                field: field.to_owned(),
            })?
            .replace('\\', "/");
        if path.contains('\0') {
            return Err(invalid(field, "path must not contain NUL"));
        }
        Ok(Self {
            base: "absolute".to_owned(),
            path,
        })
    }

    fn compile(&self, deployment_root: &Path, field: &str) -> Result<PathBuf, PortableConfigError> {
        if self.path.is_empty() || self.path.contains('\0') || self.path.contains('\\') {
            return Err(invalid(
                field,
                "path must be non-empty, NUL-free, and use `/` separators",
            ));
        }
        match self.base.as_str() {
            "absolute" => {
                let path = PathBuf::from(&self.path);
                if !path.is_absolute() {
                    return Err(invalid(field, "absolute path reference is not absolute"));
                }
                Ok(path)
            }
            "deployment_root" => {
                let relative = normalized_relative_path(Path::new(&self.path), field)?;
                Ok(deployment_root.join(relative))
            }
            _ => Err(invalid(
                field,
                "path base must be `absolute` or `deployment_root`",
            )),
        }
    }
}

fn normalized_relative_path(path: &Path, field: &str) -> Result<String, PortableConfigError> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let part = part
                    .to_str()
                    .ok_or_else(|| PortableConfigError::NonUtf8Path {
                        field: field.to_owned(),
                    })?;
                if part.is_empty() || part.contains('\0') || part.contains('\\') {
                    return Err(invalid(field, "invalid deployment-root path component"));
                }
                parts.push(part);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(invalid(
                    field,
                    "deployment-root path cannot contain root, prefix, or parent components",
                ));
            }
        }
    }
    if parts.is_empty() {
        return Err(invalid(field, "deployment-root path cannot be empty"));
    }
    Ok(parts.join("/"))
}

fn resource_id(source: &str, kind: &str, field: &str) -> Result<ResourceId, PortableConfigError> {
    let prefix = format!("{kind}:");
    if !source.starts_with(&prefix) || source.len() == prefix.len() {
        return Err(invalid(
            field,
            format!("resource identity must start with `{prefix}` and have a name"),
        ));
    }
    Ok(ResourceId::new(source))
}

fn listener_id(source: &str, field: &str) -> Result<ListenerId, PortableConfigError> {
    let Some(name) = source.strip_prefix("listener:") else {
        return Err(invalid(
            field,
            "listener identity must start with `listener:`",
        ));
    };
    if name.trim().is_empty() {
        return Err(invalid(field, "listener identity must have a name"));
    }
    Ok(ListenerId::new(source))
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableCertificateV1 {
    pub private_key: PortablePathRefV1,
    pub cert_chain_source: SourceSpan,
    pub private_key_source: SourceSpan,
    pub source: SourceSpan,
}

impl std::fmt::Debug for PortableCertificateV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PortableCertificateV1")
            .field("private_key", &"<redacted path>")
            .field("cert_chain_source", &self.cert_chain_source)
            .field("private_key_source", &self.private_key_source)
            .field("source", &self.source)
            .finish()
    }
}

impl PortableCertificateV1 {
    fn from_compiled(
        source: &CertificateSpec,
        source_root: &Path,
    ) -> Result<Self, PortableConfigError> {
        Ok(Self {
            private_key: PortablePathRefV1::from_path(
                &source.private_key,
                source_root,
                "certificates.private_key",
            )?,
            cert_chain_source: source.cert_chain_source.clone(),
            private_key_source: source.private_key_source.clone(),
            source: source.source.clone(),
        })
    }

    fn compile(
        &self,
        id: ResourceId,
        deployment_root: &Path,
    ) -> Result<CertificateSpec, PortableConfigError> {
        Ok(CertificateSpec {
            id,
            cert_chain: PathBuf::from("<bundle-public-certificate-chain>"),
            private_key: self
                .private_key
                .compile(deployment_root, "certificates.private_key")?,
            cert_chain_source: self.cert_chain_source.clone(),
            private_key_source: self.private_key_source.clone(),
            source: self.source.clone(),
        })
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableSecretV1 {
    pub file: PortablePathRefV1,
    pub max_bytes: u64,
    pub file_source: SourceSpan,
    pub max_bytes_source: SourceSpan,
    pub source: SourceSpan,
}

impl std::fmt::Debug for PortableSecretV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PortableSecretV1")
            .field("file", &"<redacted path>")
            .field("max_bytes", &self.max_bytes)
            .field("file_source", &self.file_source)
            .field("max_bytes_source", &self.max_bytes_source)
            .field("source", &self.source)
            .finish()
    }
}

impl PortableSecretV1 {
    fn from_compiled(source: &SecretSpec, source_root: &Path) -> Result<Self, PortableConfigError> {
        Ok(Self {
            file: PortablePathRefV1::from_path(&source.file, source_root, "secrets.file")?,
            max_bytes: source.max_bytes,
            file_source: source.file_source.clone(),
            max_bytes_source: source.max_bytes_source.clone(),
            source: source.source.clone(),
        })
    }

    fn compile(
        &self,
        id: ResourceId,
        deployment_root: &Path,
    ) -> Result<SecretSpec, PortableConfigError> {
        if self.max_bytes == 0 {
            return Err(invalid(
                "secrets.max_bytes",
                "limit must be greater than zero",
            ));
        }
        Ok(SecretSpec {
            id,
            file: self.file.compile(deployment_root, "secrets.file")?,
            max_bytes: self.max_bytes,
            file_source: self.file_source.clone(),
            max_bytes_source: self.max_bytes_source.clone(),
            source: self.source.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableTrustStoreV1 {
    pub ca_bundle_source: SourceSpan,
    pub source: SourceSpan,
}

impl PortableTrustStoreV1 {
    fn from_compiled(source: &TrustStoreSpec) -> Self {
        Self {
            ca_bundle_source: source.ca_bundle_source.clone(),
            source: source.source.clone(),
        }
    }

    fn compile(&self, id: ResourceId) -> TrustStoreSpec {
        TrustStoreSpec {
            id,
            ca_bundle: PathBuf::from("<bundle-public-trust-store>"),
            ca_bundle_source: self.ca_bundle_source.clone(),
            source: self.source.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableClusterV1 {
    pub protocol: String,
    pub endpoints: Vec<PortableClusterEndpointV1>,
    pub load_balance: String,
    pub health: PortableClusterHealthV1,
    pub retry: PortableRetryV1,
    pub limits: PortableClusterLimitsV1,
    pub tls: Option<PortableClusterTlsV1>,
    pub connect_timeout: PortableDurationV1,
    pub response_timeout: PortableDurationV1,
    pub protocol_source: SourceSpan,
    pub source: SourceSpan,
}

impl PortableClusterV1 {
    fn from_compiled(source: &ClusterSpec) -> Self {
        Self {
            protocol: source.protocol.as_str().to_owned(),
            endpoints: source
                .endpoints
                .iter()
                .map(PortableClusterEndpointV1::from_compiled)
                .collect(),
            load_balance: source.load_balance.as_str().to_owned(),
            health: PortableClusterHealthV1::from_compiled(&source.health),
            retry: PortableRetryV1::from_compiled(&source.retry),
            limits: PortableClusterLimitsV1::from_compiled(&source.limits),
            tls: source.tls.as_ref().map(PortableClusterTlsV1::from_compiled),
            connect_timeout: PortableDurationV1::from_duration(source.connect_timeout),
            response_timeout: PortableDurationV1::from_duration(source.response_timeout),
            protocol_source: source.protocol_source.clone(),
            source: source.source.clone(),
        }
    }

    fn compile(
        &self,
        id: ResourceId,
        resources: &CompiledResources,
    ) -> Result<ClusterSpec, PortableConfigError> {
        let protocol = match self.protocol.as_str() {
            "auto" => ClusterProtocol::Auto,
            "http1" => ClusterProtocol::Http1,
            "h2" => ClusterProtocol::H2,
            _ => {
                return Err(invalid(
                    "clusters.protocol",
                    "expected `auto`, `http1`, or `h2`",
                ));
            }
        };
        if self.endpoints.is_empty() {
            return Err(invalid(
                "clusters.endpoints",
                "at least one endpoint is required",
            ));
        }
        let mut endpoint_names = BTreeSet::new();
        let endpoints = self
            .endpoints
            .iter()
            .enumerate()
            .map(|(index, endpoint)| {
                let endpoint = endpoint.compile(index)?;
                if !endpoint_names.insert(endpoint.name.clone()) {
                    return Err(invalid(
                        format!("clusters.endpoints[{index}].name"),
                        "endpoint name must be unique",
                    ));
                }
                Ok(endpoint)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let load_balance = match self.load_balance.as_str() {
            "round_robin" => LoadBalancePolicy::RoundRobin,
            "weighted_round_robin" => LoadBalancePolicy::WeightedRoundRobin,
            "least_requests" => LoadBalancePolicy::LeastRequests,
            _ => {
                return Err(invalid(
                    "clusters.load_balance",
                    "expected `round_robin`, `weighted_round_robin`, or `least_requests`",
                ));
            }
        };
        if load_balance == LoadBalancePolicy::RoundRobin
            && endpoints.iter().any(|endpoint| endpoint.weight != 1)
        {
            return Err(invalid(
                "clusters.endpoints.weight",
                "round_robin requires every endpoint weight to be 1",
            ));
        }
        let tls = self
            .tls
            .as_ref()
            .map(|tls| tls.compile(resources, &endpoints))
            .transpose()?;
        Ok(ClusterSpec {
            id,
            protocol,
            endpoints,
            load_balance,
            health: self.health.compile()?,
            retry: self.retry.compile()?,
            limits: self.limits.compile()?,
            tls,
            connect_timeout: self
                .connect_timeout
                .compile("clusters.connect_timeout", false)?,
            response_timeout: self
                .response_timeout
                .compile("clusters.response_timeout", false)?,
            protocol_source: self.protocol_source.clone(),
            source: self.source.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableClusterEndpointV1 {
    pub name: String,
    pub url: String,
    pub weight: u16,
    pub name_source: SourceSpan,
    pub url_source: SourceSpan,
    pub weight_source: SourceSpan,
    pub source: SourceSpan,
}

impl PortableClusterEndpointV1 {
    fn from_compiled(source: &ClusterEndpointSpec) -> Self {
        Self {
            name: source.name.clone(),
            url: source.url.as_str().to_owned(),
            weight: source.weight,
            name_source: source.name_source.clone(),
            url_source: source.url_source.clone(),
            weight_source: source.weight_source.clone(),
            source: source.source.clone(),
        }
    }

    fn compile(&self, index: usize) -> Result<ClusterEndpointSpec, PortableConfigError> {
        let prefix = format!("clusters.endpoints[{index}]");
        if self.name.is_empty()
            || self.name.len() > 128
            || !self
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(invalid(
                format!("{prefix}.name"),
                "expected 1..=128 ASCII letters, digits, dots, underscores, or hyphens",
            ));
        }
        if !(1..=1_000).contains(&self.weight) {
            return Err(invalid(
                format!("{prefix}.weight"),
                "weight must be in 1..=1000",
            ));
        }
        let url = Url::parse(&self.url)
            .map_err(|error| invalid(format!("{prefix}.url"), format!("invalid URL: {error}")))?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid(
                format!("{prefix}.url"),
                "endpoint must be an http(s) origin/path without credentials, query, or fragment",
            ));
        }
        Ok(ClusterEndpointSpec {
            name: self.name.clone(),
            url,
            weight: self.weight,
            name_source: self.name_source.clone(),
            url_source: self.url_source.clone(),
            weight_source: self.weight_source.clone(),
            source: self.source.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableClusterTlsV1 {
    pub server_name: Option<String>,
    pub trust: PortableClusterTlsTrustV1,
    pub client_certificate: Option<String>,
    pub server_name_source: Option<SourceSpan>,
    pub client_certificate_source: Option<SourceSpan>,
    pub source: SourceSpan,
}

impl PortableClusterTlsV1 {
    fn from_compiled(source: &ClusterTlsSpec) -> Self {
        Self {
            server_name: source.server_name.clone(),
            trust: PortableClusterTlsTrustV1::from_compiled(&source.trust),
            client_certificate: source.client_certificate.as_ref().map(ToString::to_string),
            server_name_source: source.server_name_source.clone(),
            client_certificate_source: source.client_certificate_source.clone(),
            source: source.source.clone(),
        }
    }

    fn compile(
        &self,
        resources: &CompiledResources,
        endpoints: &[ClusterEndpointSpec],
    ) -> Result<ClusterTlsSpec, PortableConfigError> {
        if !endpoints
            .iter()
            .any(|endpoint| endpoint.url.scheme() == "https")
        {
            return Err(invalid(
                "clusters.tls",
                "TLS policy is inert when every endpoint uses http",
            ));
        }
        let server_name = self
            .server_name
            .as_deref()
            .map(normalize_server_name)
            .transpose()?;
        let trust = self.trust.compile(resources)?;
        let client_certificate = self
            .client_certificate
            .as_deref()
            .map(|id| {
                let id = resource_id(id, "certificate", "clusters.tls.client_certificate")?;
                if !resources.certificates.contains_key(&id) {
                    return Err(invalid(
                        "clusters.tls.client_certificate",
                        "referenced certificate does not exist",
                    ));
                }
                Ok(id)
            })
            .transpose()?;
        Ok(ClusterTlsSpec {
            server_name,
            trust,
            client_certificate,
            server_name_source: self.server_name_source.clone(),
            client_certificate_source: self.client_certificate_source.clone(),
            source: self.source.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableClusterTlsTrustV1 {
    pub system_roots: bool,
    pub trust_store: Option<String>,
    pub system_roots_source: SourceSpan,
    pub trust_store_source: Option<SourceSpan>,
    pub source: SourceSpan,
}

impl PortableClusterTlsTrustV1 {
    fn from_compiled(source: &ClusterTlsTrustSpec) -> Self {
        Self {
            system_roots: source.system_roots,
            trust_store: source.trust_store.as_ref().map(ToString::to_string),
            system_roots_source: source.system_roots_source.clone(),
            trust_store_source: source.trust_store_source.clone(),
            source: source.source.clone(),
        }
    }

    fn compile(
        &self,
        resources: &CompiledResources,
    ) -> Result<ClusterTlsTrustSpec, PortableConfigError> {
        if !self.system_roots && self.trust_store.is_none() {
            return Err(invalid(
                "clusters.tls.trust",
                "system roots, a trust store, or both are required",
            ));
        }
        let trust_store = self
            .trust_store
            .as_deref()
            .map(|id| {
                let id = resource_id(id, "trust_store", "clusters.tls.trust.trust_store")?;
                if !resources.trust_stores.contains_key(&id) {
                    return Err(invalid(
                        "clusters.tls.trust.trust_store",
                        "referenced Trust Store does not exist",
                    ));
                }
                Ok(id)
            })
            .transpose()?;
        Ok(ClusterTlsTrustSpec {
            system_roots: self.system_roots,
            trust_store,
            system_roots_source: self.system_roots_source.clone(),
            trust_store_source: self.trust_store_source.clone(),
            source: self.source.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableClusterHealthV1 {
    pub active: Option<PortableActiveHealthV1>,
    pub passive: Option<PortablePassiveHealthV1>,
}

impl PortableClusterHealthV1 {
    fn from_compiled(source: &ClusterHealthSpec) -> Self {
        Self {
            active: source
                .active
                .as_ref()
                .map(PortableActiveHealthV1::from_compiled),
            passive: source
                .passive
                .as_ref()
                .map(PortablePassiveHealthV1::from_compiled),
        }
    }

    fn compile(&self) -> Result<ClusterHealthSpec, PortableConfigError> {
        Ok(ClusterHealthSpec {
            active: self
                .active
                .as_ref()
                .map(PortableActiveHealthV1::compile)
                .transpose()?,
            passive: self
                .passive
                .as_ref()
                .map(PortablePassiveHealthV1::compile)
                .transpose()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableActiveHealthV1 {
    pub path: String,
    pub interval: PortableDurationV1,
    pub timeout: PortableDurationV1,
    pub healthy_statuses: Vec<PortableStatusRangeV1>,
    pub healthy_threshold: u32,
    pub unhealthy_threshold: u32,
    pub source: SourceSpan,
}

impl PortableActiveHealthV1 {
    fn from_compiled(source: &ActiveHealthSpec) -> Self {
        Self {
            path: source.path.clone(),
            interval: PortableDurationV1::from_duration(source.interval),
            timeout: PortableDurationV1::from_duration(source.timeout),
            healthy_statuses: source
                .healthy_statuses
                .iter()
                .copied()
                .map(PortableStatusRangeV1::from_compiled)
                .collect(),
            healthy_threshold: source.healthy_threshold,
            unhealthy_threshold: source.unhealthy_threshold,
            source: source.source.clone(),
        }
    }

    fn compile(&self) -> Result<ActiveHealthSpec, PortableConfigError> {
        if !self.path.starts_with('/')
            || self.path.starts_with("//")
            || PathAndQuery::from_str(&self.path).is_err()
        {
            return Err(invalid(
                "clusters.health.active.path",
                "health path must be valid origin-form",
            ));
        }
        if self.healthy_statuses.is_empty() {
            return Err(invalid(
                "clusters.health.active.healthy_statuses",
                "at least one healthy status range is required",
            ));
        }
        if self.healthy_threshold == 0 || self.unhealthy_threshold == 0 {
            return Err(invalid(
                "clusters.health.active.threshold",
                "health thresholds must be greater than zero",
            ));
        }
        Ok(ActiveHealthSpec {
            path: self.path.clone(),
            interval: self
                .interval
                .compile("clusters.health.active.interval", false)?,
            timeout: self
                .timeout
                .compile("clusters.health.active.timeout", false)?,
            healthy_statuses: self
                .healthy_statuses
                .iter()
                .enumerate()
                .map(|(index, range)| {
                    range.compile(&format!("clusters.health.active.healthy_statuses[{index}]"))
                })
                .collect::<Result<_, _>>()?,
            healthy_threshold: self.healthy_threshold,
            unhealthy_threshold: self.unhealthy_threshold,
            source: self.source.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortablePassiveHealthV1 {
    pub consecutive_failures: u32,
    pub eject_for: PortableDurationV1,
    pub source: SourceSpan,
}

impl PortablePassiveHealthV1 {
    fn from_compiled(source: &PassiveHealthSpec) -> Self {
        Self {
            consecutive_failures: source.consecutive_failures,
            eject_for: PortableDurationV1::from_duration(source.eject_for),
            source: source.source.clone(),
        }
    }

    fn compile(&self) -> Result<PassiveHealthSpec, PortableConfigError> {
        if self.consecutive_failures == 0 {
            return Err(invalid(
                "clusters.health.passive.consecutive_failures",
                "threshold must be greater than zero",
            ));
        }
        Ok(PassiveHealthSpec {
            consecutive_failures: self.consecutive_failures,
            eject_for: self
                .eject_for
                .compile("clusters.health.passive.eject_for", false)?,
            source: self.source.clone(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableStatusRangeV1 {
    pub start: u16,
    pub end: u16,
}

impl PortableStatusRangeV1 {
    fn from_compiled(source: StatusRange) -> Self {
        Self {
            start: source.start,
            end: source.end,
        }
    }

    fn compile(&self, field: &str) -> Result<StatusRange, PortableConfigError> {
        if StatusCode::from_u16(self.start).is_err()
            || StatusCode::from_u16(self.end).is_err()
            || self.start > self.end
        {
            return Err(invalid(field, "invalid HTTP status range"));
        }
        Ok(StatusRange {
            start: self.start,
            end: self.end,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableRetryV1 {
    pub max_attempts: u32,
    pub methods: Vec<String>,
    pub retry_on: Vec<String>,
    pub statuses: Vec<PortableStatusRangeV1>,
    pub request_body: PortableRetryRequestBodyV1,
    pub max_concurrent_retries: u32,
    pub source: SourceSpan,
}

impl PortableRetryV1 {
    fn from_compiled(source: &RetrySpec) -> Self {
        Self {
            max_attempts: source.max_attempts,
            methods: source
                .methods
                .iter()
                .map(|method| method.as_str().to_owned())
                .collect(),
            retry_on: source
                .retry_on
                .iter()
                .map(|cause| cause.as_str().to_owned())
                .collect(),
            statuses: source
                .statuses
                .iter()
                .copied()
                .map(PortableStatusRangeV1::from_compiled)
                .collect(),
            request_body: PortableRetryRequestBodyV1::from_compiled(&source.request_body),
            max_concurrent_retries: source.max_concurrent_retries,
            source: source.source.clone(),
        }
    }

    fn compile(&self) -> Result<RetrySpec, PortableConfigError> {
        if self.max_attempts == 0 || self.max_concurrent_retries == 0 {
            return Err(invalid(
                "clusters.retry",
                "max_attempts and max_concurrent_retries must be greater than zero",
            ));
        }
        let mut seen_methods = BTreeSet::new();
        let methods = self
            .methods
            .iter()
            .enumerate()
            .map(|(index, source)| {
                let method = Method::from_bytes(source.as_bytes()).map_err(|error| {
                    invalid(
                        format!("clusters.retry.methods[{index}]"),
                        format!("invalid HTTP method: {error}"),
                    )
                })?;
                if !seen_methods.insert(method.as_str().to_owned()) {
                    return Err(invalid(
                        format!("clusters.retry.methods[{index}]"),
                        "duplicate retry method",
                    ));
                }
                Ok(method)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut seen_causes = BTreeSet::new();
        let retry_on = self
            .retry_on
            .iter()
            .enumerate()
            .map(|(index, source)| {
                let cause = match source.as_str() {
                    "connect_failure" => RetryCause::ConnectFailure,
                    "response_header_timeout" => RetryCause::ResponseHeaderTimeout,
                    "refused_stream" => RetryCause::RefusedStream,
                    "reset" => RetryCause::Reset,
                    _ => {
                        return Err(invalid(
                            format!("clusters.retry.retry_on[{index}]"),
                            "unknown retry cause",
                        ));
                    }
                };
                if !seen_causes.insert(cause) {
                    return Err(invalid(
                        format!("clusters.retry.retry_on[{index}]"),
                        "duplicate retry cause",
                    ));
                }
                Ok(cause)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let statuses = self
            .statuses
            .iter()
            .enumerate()
            .map(|(index, range)| range.compile(&format!("clusters.retry.statuses[{index}]")))
            .collect::<Result<Vec<_>, _>>()?;
        if self.max_attempts > 1 && methods.is_empty() {
            return Err(invalid(
                "clusters.retry.methods",
                "retry requires at least one explicit method",
            ));
        }
        if self.max_attempts > 1 && retry_on.is_empty() && statuses.is_empty() {
            return Err(invalid(
                "clusters.retry",
                "retry requires at least one cause or status",
            ));
        }
        Ok(RetrySpec {
            max_attempts: self.max_attempts,
            methods,
            retry_on,
            statuses,
            request_body: self.request_body.compile()?,
            max_concurrent_retries: self.max_concurrent_retries,
            source: self.source.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableRetryRequestBodyV1 {
    pub mode: String,
    pub max_bytes: u64,
    pub source: SourceSpan,
}

impl PortableRetryRequestBodyV1 {
    fn from_compiled(source: &RetryRequestBodySpec) -> Self {
        Self {
            mode: match source.mode {
                RetryBodyMode::None => "none",
                RetryBodyMode::Buffer => "buffer",
            }
            .to_owned(),
            max_bytes: source.max_bytes,
            source: source.source.clone(),
        }
    }

    fn compile(&self) -> Result<RetryRequestBodySpec, PortableConfigError> {
        let mode = match self.mode.as_str() {
            "none" => RetryBodyMode::None,
            "buffer" => RetryBodyMode::Buffer,
            _ => {
                return Err(invalid(
                    "clusters.retry.request_body.mode",
                    "expected `none` or `buffer`",
                ));
            }
        };
        Ok(RetryRequestBodySpec {
            mode,
            max_bytes: self.max_bytes,
            source: self.source.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableClusterLimitsV1 {
    pub max_in_flight: u32,
    pub max_in_flight_per_endpoint: u32,
    pub queue_timeout: PortableDurationV1,
    pub source: SourceSpan,
}

impl PortableClusterLimitsV1 {
    fn from_compiled(source: &ClusterLimits) -> Self {
        Self {
            max_in_flight: source.max_in_flight,
            max_in_flight_per_endpoint: source.max_in_flight_per_endpoint,
            queue_timeout: PortableDurationV1::from_duration(source.queue_timeout),
            source: source.source.clone(),
        }
    }

    fn compile(&self) -> Result<ClusterLimits, PortableConfigError> {
        if self.max_in_flight == 0 || self.max_in_flight_per_endpoint == 0 {
            return Err(invalid(
                "clusters.limits",
                "in-flight limits must be greater than zero",
            ));
        }
        Ok(ClusterLimits {
            max_in_flight: self.max_in_flight,
            max_in_flight_per_endpoint: self.max_in_flight_per_endpoint,
            queue_timeout: self
                .queue_timeout
                .compile("clusters.limits.queue_timeout", true)?,
            source: self.source.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableListenerV1 {
    pub name: String,
    pub bind: String,
    pub protocol: String,
    pub tls: Option<PortableTlsListenerV1>,
    pub http: PortableHttpListenerV1,
    pub limits: PortableListenerLimitsV1,
    pub service: String,
    pub source: SourceSpan,
}

impl PortableListenerV1 {
    fn from_compiled(source: &CompiledListener) -> Self {
        Self {
            name: source.name.clone(),
            bind: source.bind.to_string(),
            protocol: match source.protocol {
                ListenerProtocol::Http => "http",
                ListenerProtocol::Https => "https",
            }
            .to_owned(),
            tls: source
                .tls
                .as_ref()
                .map(PortableTlsListenerV1::from_compiled),
            http: PortableHttpListenerV1::from_compiled(&source.http),
            limits: PortableListenerLimitsV1::from_compiled(&source.limits),
            service: source.service.to_string(),
            source: source.source.clone(),
        }
    }

    fn compile(
        &self,
        id: ListenerId,
        resources: &CompiledResources,
    ) -> Result<CompiledListener, PortableConfigError> {
        if self.name.trim().is_empty() {
            return Err(invalid("listeners.name", "listener name cannot be empty"));
        }
        if id.as_str() != format!("listener:{}", self.name) {
            return Err(invalid(
                "listeners",
                "listener map identity does not match its name",
            ));
        }
        let bind = self.bind.parse().map_err(|error| {
            invalid("listeners.bind", format!("invalid socket address: {error}"))
        })?;
        let protocol = match self.protocol.as_str() {
            "http" => ListenerProtocol::Http,
            "https" => ListenerProtocol::Https,
            _ => return Err(invalid("listeners.protocol", "expected `http` or `https`")),
        };
        let tls = match (protocol, self.tls.as_ref()) {
            (ListenerProtocol::Http, None) => None,
            (ListenerProtocol::Http, Some(_)) => {
                return Err(invalid(
                    "listeners.tls",
                    "TLS settings are forbidden for an HTTP listener",
                ));
            }
            (ListenerProtocol::Https, None) => {
                return Err(invalid(
                    "listeners.tls",
                    "TLS settings are required for an HTTPS listener",
                ));
            }
            (ListenerProtocol::Https, Some(tls)) => Some(tls.compile(resources)?),
        };
        let http = self.http.compile(protocol)?;
        if self.service.is_empty() {
            return Err(invalid(
                "listeners.service",
                "Service identity cannot be empty",
            ));
        }
        Ok(CompiledListener {
            id,
            name: self.name.clone(),
            bind,
            protocol,
            tls,
            http,
            limits: self.limits.compile()?,
            service: ServiceId::new(&self.service),
            source: self.source.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableListenerLimitsV1 {
    pub max_connections: u32,
    pub max_connections_per_ip: u32,
    pub idle_timeout: PortableDurationV1,
    pub request_body_idle_timeout: PortableDurationV1,
    pub response_body_idle_timeout: PortableDurationV1,
    pub max_header_bytes: u32,
    pub max_headers: u32,
    pub max_requests_per_connection: u32,
    pub source: SourceSpan,
}

impl PortableListenerLimitsV1 {
    fn from_compiled(source: &ListenerLimits) -> Self {
        Self {
            max_connections: source.max_connections,
            max_connections_per_ip: source.max_connections_per_ip,
            idle_timeout: PortableDurationV1::from_duration(source.idle_timeout),
            request_body_idle_timeout: PortableDurationV1::from_duration(
                source.request_body_idle_timeout,
            ),
            response_body_idle_timeout: PortableDurationV1::from_duration(
                source.response_body_idle_timeout,
            ),
            max_header_bytes: source.max_header_bytes,
            max_headers: source.max_headers,
            max_requests_per_connection: source.max_requests_per_connection,
            source: source.source.clone(),
        }
    }

    fn compile(&self) -> Result<ListenerLimits, PortableConfigError> {
        if self.max_connections == 0
            || self.max_connections_per_ip == 0
            || self.max_headers == 0
            || self.max_requests_per_connection == 0
        {
            return Err(invalid(
                "listeners.limits",
                "connection, Header, and request limits must be greater than zero",
            ));
        }
        if self.max_header_bytes < 8 * 1_024 {
            return Err(invalid(
                "listeners.limits.max_header_bytes",
                "decoded Header limit must be at least 8KiB",
            ));
        }
        Ok(ListenerLimits {
            max_connections: self.max_connections,
            max_connections_per_ip: self.max_connections_per_ip,
            idle_timeout: self
                .idle_timeout
                .compile("listeners.limits.idle_timeout", false)?,
            request_body_idle_timeout: self
                .request_body_idle_timeout
                .compile("listeners.limits.request_body_idle_timeout", false)?,
            response_body_idle_timeout: self
                .response_body_idle_timeout
                .compile("listeners.limits.response_body_idle_timeout", false)?,
            max_header_bytes: self.max_header_bytes,
            max_headers: self.max_headers,
            max_requests_per_connection: self.max_requests_per_connection,
            source: self.source.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableHttpListenerV1 {
    pub versions: Vec<String>,
    pub http1: Option<PortableHttp1SettingsV1>,
    pub http2: Option<PortableHttp2SettingsV1>,
    pub source: SourceSpan,
}

impl PortableHttpListenerV1 {
    fn from_compiled(source: &HttpListenerSpec) -> Self {
        Self {
            versions: source
                .versions
                .iter()
                .map(|version| match version {
                    HttpVersion::Http1 => "http1",
                    HttpVersion::H2 => "h2",
                })
                .map(ToOwned::to_owned)
                .collect(),
            http1: source
                .http1
                .as_ref()
                .map(PortableHttp1SettingsV1::from_compiled),
            http2: source
                .http2
                .as_ref()
                .map(PortableHttp2SettingsV1::from_compiled),
            source: source.source.clone(),
        }
    }

    fn compile(&self, protocol: ListenerProtocol) -> Result<HttpListenerSpec, PortableConfigError> {
        if self.versions.is_empty() {
            return Err(invalid(
                "listeners.http.versions",
                "at least one HTTP version is required",
            ));
        }
        let mut seen = BTreeSet::new();
        let versions = self
            .versions
            .iter()
            .enumerate()
            .map(|(index, source)| {
                let version = match source.as_str() {
                    "http1" => HttpVersion::Http1,
                    "h2" => HttpVersion::H2,
                    _ => {
                        return Err(invalid(
                            format!("listeners.http.versions[{index}]"),
                            "expected `http1` or `h2`",
                        ));
                    }
                };
                if protocol == ListenerProtocol::Http && version == HttpVersion::H2 {
                    return Err(invalid(
                        format!("listeners.http.versions[{index}]"),
                        "cleartext HTTP/2 (h2c) is not supported",
                    ));
                }
                if !seen.insert(version) {
                    return Err(invalid(
                        format!("listeners.http.versions[{index}]"),
                        "duplicate HTTP version",
                    ));
                }
                Ok(version)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let has_http1 = seen.contains(&HttpVersion::Http1);
        let has_h2 = seen.contains(&HttpVersion::H2);
        if has_http1 != self.http1.is_some() {
            return Err(invalid(
                "listeners.http.http1",
                "HTTP/1 settings must exist exactly when http1 is enabled",
            ));
        }
        if has_h2 != self.http2.is_some() {
            return Err(invalid(
                "listeners.http.http2",
                "HTTP/2 settings must exist exactly when h2 is enabled",
            ));
        }
        Ok(HttpListenerSpec {
            versions,
            http1: self
                .http1
                .as_ref()
                .map(PortableHttp1SettingsV1::compile)
                .transpose()?,
            http2: self
                .http2
                .as_ref()
                .map(PortableHttp2SettingsV1::compile)
                .transpose()?,
            source: self.source.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableHttp1SettingsV1 {
    pub header_read_timeout: PortableDurationV1,
    pub source: SourceSpan,
}

impl PortableHttp1SettingsV1 {
    fn from_compiled(source: &Http1Settings) -> Self {
        Self {
            header_read_timeout: PortableDurationV1::from_duration(source.header_read_timeout),
            source: source.source.clone(),
        }
    }

    fn compile(&self) -> Result<Http1Settings, PortableConfigError> {
        Ok(Http1Settings {
            header_read_timeout: self
                .header_read_timeout
                .compile("listeners.http.http1.header_read_timeout", false)?,
            source: self.source.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableHttp2SettingsV1 {
    pub max_concurrent_streams: u32,
    pub max_header_list_size: u32,
    pub keep_alive_interval: PortableDurationV1,
    pub keep_alive_timeout: PortableDurationV1,
    pub source: SourceSpan,
}

impl PortableHttp2SettingsV1 {
    fn from_compiled(source: &Http2Settings) -> Self {
        Self {
            max_concurrent_streams: source.max_concurrent_streams,
            max_header_list_size: source.max_header_list_size,
            keep_alive_interval: PortableDurationV1::from_duration(source.keep_alive_interval),
            keep_alive_timeout: PortableDurationV1::from_duration(source.keep_alive_timeout),
            source: source.source.clone(),
        }
    }

    fn compile(&self) -> Result<Http2Settings, PortableConfigError> {
        if self.max_concurrent_streams == 0 {
            return Err(invalid(
                "listeners.http.http2.max_concurrent_streams",
                "stream limit must be greater than zero",
            ));
        }
        Ok(Http2Settings {
            max_concurrent_streams: self.max_concurrent_streams,
            max_header_list_size: self.max_header_list_size,
            keep_alive_interval: self
                .keep_alive_interval
                .compile("listeners.http.http2.keep_alive_interval", false)?,
            keep_alive_timeout: self
                .keep_alive_timeout
                .compile("listeners.http.http2.keep_alive_timeout", false)?,
            source: self.source.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableTlsListenerV1 {
    pub default_certificate: String,
    pub default_certificate_source: SourceSpan,
    pub sni: Vec<PortableSniCertificateV1>,
    pub handshake_timeout: PortableDurationV1,
    pub client_auth: PortableClientAuthV1,
    pub source: SourceSpan,
}

impl PortableTlsListenerV1 {
    fn from_compiled(source: &TlsListenerSpec) -> Self {
        Self {
            default_certificate: source.default_certificate.to_string(),
            default_certificate_source: source.default_certificate_source.clone(),
            sni: source
                .sni
                .iter()
                .map(PortableSniCertificateV1::from_compiled)
                .collect(),
            handshake_timeout: PortableDurationV1::from_duration(source.handshake_timeout),
            client_auth: PortableClientAuthV1::from_compiled(&source.client_auth),
            source: source.source.clone(),
        }
    }

    fn compile(
        &self,
        resources: &CompiledResources,
    ) -> Result<TlsListenerSpec, PortableConfigError> {
        let default_certificate = resource_id(
            &self.default_certificate,
            "certificate",
            "listeners.tls.default_certificate",
        )?;
        if !resources.certificates.contains_key(&default_certificate) {
            return Err(invalid(
                "listeners.tls.default_certificate",
                "referenced certificate does not exist",
            ));
        }
        let mut seen = BTreeSet::new();
        let mut sni = self
            .sni
            .iter()
            .enumerate()
            .map(|(index, source)| {
                let rule = source.compile(resources, index)?;
                if !seen.insert(rule.pattern.clone()) {
                    return Err(invalid(
                        format!("listeners.tls.sni[{index}].pattern"),
                        "duplicate normalized SNI rule",
                    ));
                }
                Ok(rule)
            })
            .collect::<Result<Vec<_>, _>>()?;
        sni.sort_by(|left, right| left.pattern.cmp(&right.pattern));
        Ok(TlsListenerSpec {
            default_certificate,
            default_certificate_source: self.default_certificate_source.clone(),
            sni,
            handshake_timeout: self
                .handshake_timeout
                .compile("listeners.tls.handshake_timeout", false)?,
            client_auth: self.client_auth.compile(resources)?,
            source: self.source.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableSniCertificateV1 {
    pub pattern: String,
    pub certificate: String,
    pub source: SourceSpan,
    pub certificate_source: SourceSpan,
}

impl PortableSniCertificateV1 {
    fn from_compiled(source: &SniCertificateSpec) -> Self {
        Self {
            pattern: source.pattern.normalized_rule(),
            certificate: source.certificate.to_string(),
            source: source.source.clone(),
            certificate_source: source.certificate_source.clone(),
        }
    }

    fn compile(
        &self,
        resources: &CompiledResources,
        index: usize,
    ) -> Result<SniCertificateSpec, PortableConfigError> {
        let pattern = parse_sni_pattern(&self.pattern)
            .map_err(|message| invalid(format!("listeners.tls.sni[{index}].pattern"), message))?;
        let certificate = resource_id(
            &self.certificate,
            "certificate",
            &format!("listeners.tls.sni[{index}].certificate"),
        )?;
        if !resources.certificates.contains_key(&certificate) {
            return Err(invalid(
                format!("listeners.tls.sni[{index}].certificate"),
                "referenced certificate does not exist",
            ));
        }
        Ok(SniCertificateSpec {
            pattern,
            certificate,
            source: self.source.clone(),
            certificate_source: self.certificate_source.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableClientAuthV1 {
    pub mode: String,
    pub trust_store: Option<String>,
    pub mode_source: SourceSpan,
    pub trust_store_source: Option<SourceSpan>,
    pub source: SourceSpan,
}

impl PortableClientAuthV1 {
    fn from_compiled(source: &ClientAuthSpec) -> Self {
        Self {
            mode: match source.mode {
                ClientAuthMode::None => "none",
                ClientAuthMode::Optional => "optional",
                ClientAuthMode::Required => "required",
            }
            .to_owned(),
            trust_store: source.trust_store.as_ref().map(ToString::to_string),
            mode_source: source.mode_source.clone(),
            trust_store_source: source.trust_store_source.clone(),
            source: source.source.clone(),
        }
    }

    fn compile(
        &self,
        resources: &CompiledResources,
    ) -> Result<ClientAuthSpec, PortableConfigError> {
        let mode = match self.mode.as_str() {
            "none" => ClientAuthMode::None,
            "optional" => ClientAuthMode::Optional,
            "required" => ClientAuthMode::Required,
            _ => {
                return Err(invalid(
                    "listeners.tls.client_auth.mode",
                    "expected `none`, `optional`, or `required`",
                ));
            }
        };
        match (mode, self.trust_store.as_deref()) {
            (ClientAuthMode::None, Some(_)) => {
                return Err(invalid(
                    "listeners.tls.client_auth.trust_store",
                    "trust store is forbidden when client-auth mode is none",
                ));
            }
            (ClientAuthMode::Optional | ClientAuthMode::Required, None) => {
                return Err(invalid(
                    "listeners.tls.client_auth.trust_store",
                    "trust store is required for optional or required client authentication",
                ));
            }
            _ => {}
        }
        let trust_store = self
            .trust_store
            .as_deref()
            .map(|id| {
                let id = resource_id(id, "trust_store", "listeners.tls.client_auth.trust_store")?;
                if !resources.trust_stores.contains_key(&id) {
                    return Err(invalid(
                        "listeners.tls.client_auth.trust_store",
                        "referenced Trust Store does not exist",
                    ));
                }
                Ok(id)
            })
            .transpose()?;
        Ok(ClientAuthSpec {
            mode,
            trust_store,
            mode_source: self.mode_source.clone(),
            trust_store_source: self.trust_store_source.clone(),
            source: self.source.clone(),
        })
    }
}

fn normalize_server_name(source: &str) -> Result<String, PortableConfigError> {
    if source.is_empty() || !source.is_ascii() || source.contains('*') {
        return Err(invalid(
            "clusters.tls.server_name",
            "server name must be an exact ASCII DNS name or IP address",
        ));
    }
    if let Ok(address) = source.parse::<std::net::IpAddr>() {
        return Ok(address.to_string());
    }
    let normalized = source.to_ascii_lowercase();
    validate_dns_name(&normalized, false)
        .map_err(|message| invalid("clusters.tls.server_name", message))?;
    Ok(normalized)
}

fn parse_sni_pattern(source: &str) -> Result<SniPattern, String> {
    if !source.is_ascii() {
        return Err("SNI pattern must use ASCII DNS characters".to_owned());
    }
    let normalized = source.to_ascii_lowercase();
    if let Some(suffix) = normalized.strip_prefix("*.") {
        if suffix.contains('*') {
            return Err("SNI pattern may contain only one left-most wildcard".to_owned());
        }
        validate_dns_name(suffix, true)?;
        Ok(SniPattern::Wildcard(suffix.to_owned()))
    } else {
        if normalized.contains('*') {
            return Err("SNI wildcard must be the complete left-most label".to_owned());
        }
        validate_dns_name(&normalized, false)?;
        Ok(SniPattern::Exact(normalized))
    }
}

fn validate_dns_name(name: &str, wildcard_suffix: bool) -> Result<(), String> {
    let max_length = if wildcard_suffix { 251 } else { 253 };
    if name.is_empty() || name.len() > max_length || name.ends_with('.') {
        return Err("invalid DNS name".to_owned());
    }
    if name.parse::<std::net::IpAddr>().is_ok() {
        return Err("SNI rules must use DNS names, not IP addresses".to_owned());
    }
    for label in name.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err("invalid DNS label".to_owned());
        }
    }
    if name
        .rsplit('.')
        .next()
        .is_some_and(|label| label.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err("final DNS label must not be all numeric".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;
    use crate::Compiler;

    fn compiled_gateway() -> (tempfile::TempDir, CompiledGateway) {
        let directory = tempdir().expect("temporary directory is available");
        let path = directory.path().join("oxidase.yaml");
        fs::write(
            &path,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
bundle:
  assets:
    mode: reference
resources:
  certificates:
    gateway:
      cert_chain: public/gateway.pem
      private_key: distinctive-gateway-private-key.pem
    upstream-client:
      cert_chain: public/client.pem
      private_key: distinctive-upstream-private-key.pem
  secrets:
    admin:
      file: distinctive-admin-token
      max_bytes: 32KiB
  trust_stores:
    internal:
      ca_bundle: public/internal-ca.pem
  clusters:
    api:
      protocol: h2
      endpoints:
        - name: api-a
          url: https://127.0.0.1:9443/base
          weight: 1
      load_balance:
        policy: least_requests
      health:
        active:
          path: /healthz?ready=1
          interval: 5s
          timeout: 1s
          healthy_statuses: ["200-299", 304]
          healthy_threshold: 2
          unhealthy_threshold: 3
        passive:
          consecutive_failures: 4
          eject_for: 30s
      retry:
        max_attempts: 2
        methods: [GET]
        retry_on: [connect_failure]
        statuses: [503]
        request_body:
          mode: none
          max_bytes: 64KiB
        max_concurrent_retries: 8
      limits:
        max_in_flight: 100
        max_in_flight_per_endpoint: 50
        queue_timeout: 10ms
      tls:
        server_name: api.internal.example
        trust:
          system_roots: false
          trust_store: internal
        client_certificate: upstream-client
      connect_timeout: 2s
      response_timeout: 10s
  sites:
    web:
      root: site
services:
  root:
    type: respond
    body:
      text: portable
listeners:
  - name: secure
    bind: 127.0.0.1:8443
    protocol: https
    tls:
      default_certificate: gateway
      sni:
        api.example.com: gateway
      handshake_timeout: 4s
      client_auth:
        mode: required
        trust_store: internal
    http:
      versions: [h2, http1]
      http1:
        header_read_timeout: 20s
      http2:
        max_concurrent_streams: 128
        max_header_list_size: 32KiB
        keep_alive_interval: 15s
        keep_alive_timeout: 5s
    limits:
      max_connections: 200
      max_connections_per_ip: 20
      idle_timeout: 1m
      request_body_idle_timeout: 20s
      response_body_idle_timeout: 25s
      max_header_bytes: 32KiB
      max_headers: 64
      max_requests_per_connection: 500
    service:
      ref: root
"#,
        )
        .expect("fixture config is written");
        let gateway = Compiler::compile_path(path).expect("fixture compiles");
        (directory, gateway)
    }

    #[test]
    fn portable_gateway_config_roundtrips_every_transport_and_resource_policy() {
        let (_directory, gateway) = compiled_gateway();
        let portable = PortableGatewayConfigV1::from_compiled(&gateway)
            .expect("compiled paths are portable UTF-8");
        let encoded = serde_json::to_vec(&portable).expect("portable config serializes");
        let decoded: PortableGatewayConfigV1 =
            serde_json::from_slice(&encoded).expect("portable config deserializes");
        assert_eq!(decoded, portable);
        assert_eq!(
            encoded,
            serde_json::to_vec(&decoded).expect("repeat encoding succeeds")
        );

        let plan = decoded
            .compile_at(_directory.path())
            .expect("portable config recompiles");
        assert_eq!(plan.listeners.len(), 1);
        let listener = &plan.listeners[0];
        assert_eq!(listener.bind.to_string(), "127.0.0.1:8443");
        assert_eq!(
            listener.http.versions,
            [HttpVersion::H2, HttpVersion::Http1]
        );
        assert_eq!(
            listener
                .tls
                .as_ref()
                .expect("TLS policy exists")
                .client_auth
                .mode,
            ClientAuthMode::Required
        );
        assert_eq!(plan.resources.certificates.len(), 2);
        assert_eq!(plan.resources.secrets.len(), 1);
        assert_eq!(plan.resources.trust_stores.len(), 1);
        let cluster = &plan.resources.clusters[&ResourceId::new("cluster:api")];
        assert_eq!(cluster.protocol, ClusterProtocol::H2);
        assert_eq!(cluster.load_balance, LoadBalancePolicy::LeastRequests);
        assert_eq!(cluster.retry.methods, [Method::GET]);
        assert_eq!(
            cluster
                .health
                .active
                .as_ref()
                .expect("active health policy exists")
                .healthy_statuses
                .len(),
            2
        );
        assert_eq!(
            cluster
                .tls
                .as_ref()
                .expect("upstream TLS policy exists")
                .server_name
                .as_deref(),
            Some("api.internal.example")
        );
        assert_eq!(plan.site_ids, [ResourceId::new("site:web")]);
        assert_eq!(
            plan.resources.secrets[&ResourceId::new("secret:admin")].file,
            _directory.path().join("distinctive-admin-token")
        );

        let expected = plan.site_ids.iter().cloned().collect::<BTreeSet<_>>();
        plan.validate_site_sections(&expected)
            .expect("matching Site sections validate");
    }

    #[test]
    fn portable_gateway_config_is_independent_of_source_checkout_root() {
        let (_first_directory, first) = compiled_gateway();
        let (_second_directory, second) = compiled_gateway();
        let first =
            PortableGatewayConfigV1::from_compiled(&first).expect("first portable config exports");
        let second = PortableGatewayConfigV1::from_compiled(&second)
            .expect("second portable config exports");

        assert_eq!(
            serde_json::to_vec(&first).expect("first serializes"),
            serde_json::to_vec(&second).expect("second serializes")
        );
        assert_eq!(
            first.secrets["secret:admin"].file,
            PortablePathRefV1 {
                base: "deployment_root".to_owned(),
                path: "distinctive-admin-token".to_owned(),
            }
        );
        assert_eq!(
            first.certificates["certificate:gateway"].private_key,
            PortablePathRefV1 {
                base: "deployment_root".to_owned(),
                path: "distinctive-gateway-private-key.pem".to_owned(),
            }
        );
        assert_eq!(
            first.listeners["listener:secure"].source.file,
            Path::new("source/root/oxidase.yaml")
        );
    }

    #[test]
    fn sibling_import_origins_are_logical_and_checkout_independent() {
        fn compile_tree() -> (tempfile::TempDir, CompiledGateway) {
            let directory = tempdir().expect("temporary directory");
            let gateway_directory = directory.path().join("gateway");
            fs::create_dir(&gateway_directory).expect("Gateway directory is created");
            fs::write(
                directory.path().join("shared.yaml"),
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    api:
      endpoints: [http://127.0.0.1:3000]
services:
  imported:
    type: proxy
    cluster: api
"#,
            )
            .expect("sibling import is written");
            let source = gateway_directory.join("oxidase.yaml");
            fs::write(
                &source,
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
imports: [../shared.yaml]
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      ref: imported
"#,
            )
            .expect("root Gateway is written");
            let gateway = Compiler::compile_path(&source).expect("import tree compiles");
            (directory, gateway)
        }

        let (_first_root, first) = compile_tree();
        let (_second_root, second) = compile_tree();
        let first = PortableGatewayConfigV1::from_compiled(&first).expect("first exports");
        let second = PortableGatewayConfigV1::from_compiled(&second).expect("second exports");
        assert_eq!(
            serde_json::to_vec(&first).expect("first serializes"),
            serde_json::to_vec(&second).expect("second serializes")
        );
        let cluster_source = &first.clusters["cluster:api"].source.file;
        assert_eq!(
            cluster_source,
            Path::new("source/external/up-1/shared.yaml")
        );
        assert!(!cluster_source.is_absolute());
    }

    #[test]
    fn source_root_and_external_origin_namespaces_cannot_collide() {
        let directory = tempdir().expect("temporary directory");
        let source_root = directory.path().join("gateway");
        let inside = source_root.join("source/external/up-1/shared.yaml");
        let outside = directory.path().join("shared.yaml");
        let inside = portable_source_display_path(&inside, &source_root)
            .expect("inside source has a portable name");
        let outside = portable_source_display_path(&outside, &source_root)
            .expect("outside source has a portable name");
        assert_eq!(
            inside,
            Path::new("source/root/source/external/up-1/shared.yaml")
        );
        assert_eq!(outside, Path::new("source/external/up-1/shared.yaml"));
        assert_ne!(inside, outside);
    }

    #[test]
    fn portable_gateway_import_rejects_corrupt_textual_and_numeric_fields() {
        let (_directory, gateway) = compiled_gateway();
        let portable =
            PortableGatewayConfigV1::from_compiled(&gateway).expect("portable config exports");

        let mut bad = portable.clone();
        bad.schema_version = "oxidase.gateway-config/v999".to_owned();
        assert!(matches!(
            bad.compile_at(_directory.path()),
            Err(PortableConfigError::UnsupportedSchema(_))
        ));

        let mut bad = portable.clone();
        bad.listeners
            .values_mut()
            .next()
            .expect("listener exists")
            .source
            .file = PathBuf::from("/absolute/source.yaml");
        assert_invalid_field(
            bad.compile_at(_directory.path()),
            "listeners.listener:secure.source",
        );

        let mut bad = portable.clone();
        bad.listeners
            .values_mut()
            .next()
            .expect("listener exists")
            .bind = "not-a-socket".to_owned();
        assert_invalid_field(bad.compile_at(_directory.path()), "listeners.bind");

        let mut bad = portable.clone();
        bad.clusters
            .values_mut()
            .next()
            .expect("cluster exists")
            .endpoints[0]
            .url = "file:///private/upstream".to_owned();
        assert_invalid_field(
            bad.compile_at(_directory.path()),
            "clusters.endpoints[0].url",
        );

        let mut bad = portable.clone();
        bad.clusters
            .values_mut()
            .next()
            .expect("cluster exists")
            .retry
            .methods[0] = "BAD METHOD".to_owned();
        assert_invalid_field(
            bad.compile_at(_directory.path()),
            "clusters.retry.methods[0]",
        );

        let mut bad = portable.clone();
        bad.clusters
            .values_mut()
            .next()
            .expect("cluster exists")
            .retry
            .statuses[0] = PortableStatusRangeV1 { start: 99, end: 99 };
        assert_invalid_field(
            bad.compile_at(_directory.path()),
            "clusters.retry.statuses[0]",
        );

        let mut bad = portable.clone();
        bad.listeners
            .values_mut()
            .next()
            .expect("listener exists")
            .limits
            .idle_timeout
            .nanoseconds = 1_000_000_000;
        assert_invalid_field(
            bad.compile_at(_directory.path()),
            "listeners.limits.idle_timeout",
        );

        let mut bad = portable.clone();
        bad.secrets
            .get_mut("secret:admin")
            .expect("Secret exists")
            .file
            .base = "cwd".to_owned();
        assert_invalid_field(bad.compile_at(_directory.path()), "secrets.file");

        let mut bad = portable;
        bad.secrets
            .get_mut("secret:admin")
            .expect("Secret exists")
            .file
            .path = "../escape".to_owned();
        assert_invalid_field(bad.compile_at(_directory.path()), "secrets.file");
    }

    #[test]
    fn portable_gateway_import_rejects_broken_references_and_site_section_sets() {
        let (_directory, gateway) = compiled_gateway();
        let portable =
            PortableGatewayConfigV1::from_compiled(&gateway).expect("portable config exports");

        let mut bad = portable.clone();
        bad.certificates.remove("certificate:gateway");
        assert_invalid_field(
            bad.compile_at(_directory.path()),
            "listeners.tls.default_certificate",
        );

        let mut bad = portable.clone();
        bad.trust_stores.remove("trust_store:internal");
        assert_invalid_field(
            bad.compile_at(_directory.path()),
            "clusters.tls.trust.trust_store",
        );

        let mut bad = portable.clone();
        bad.site_ids.push("site:web".to_owned());
        assert_invalid_field(bad.compile_at(_directory.path()), "site_ids[1]");

        let plan = portable
            .compile_at(_directory.path())
            .expect("portable config imports");
        assert_invalid_field(plan.validate_site_sections(&BTreeSet::new()), "site_ids");
        let mut extra = plan.site_ids.iter().cloned().collect::<BTreeSet<_>>();
        extra.insert(ResourceId::new("site:extra"));
        assert_invalid_field(plan.validate_site_sections(&extra), "site_ids");
    }

    #[test]
    fn portable_gateway_json_is_strict_and_debug_redacts_sensitive_paths() {
        let (_directory, gateway) = compiled_gateway();
        let portable =
            PortableGatewayConfigV1::from_compiled(&gateway).expect("portable config exports");
        let debug = format!("{portable:?}");
        assert!(!debug.contains("distinctive-admin-token"));
        assert!(!debug.contains("distinctive-gateway-private-key.pem"));
        assert!(!debug.contains("distinctive-upstream-private-key.pem"));
        let encoded = serde_json::to_string(&portable).expect("portable config serializes");
        assert!(
            !encoded.contains("public/gateway.pem") && !encoded.contains("public/internal-ca.pem"),
            "public material is embedded separately, so its source path must not become inert IR"
        );

        let mut document = serde_json::to_value(&portable).expect("portable config serializes");
        document
            .as_object_mut()
            .expect("top-level portable config is an object")
            .insert(
                "accepted_but_inert".to_owned(),
                serde_json::Value::Bool(true),
            );
        let error = serde_json::from_value::<PortableGatewayConfigV1>(document)
            .expect_err("unknown fields must fail");
        assert!(error.to_string().contains("accepted_but_inert"));
    }

    fn assert_invalid_field<T: std::fmt::Debug>(
        result: Result<T, PortableConfigError>,
        expected: &str,
    ) {
        let PortableConfigError::Invalid { field, .. } = result.expect_err("input must fail")
        else {
            panic!("expected Invalid portable config error");
        };
        assert_eq!(field, expected);
    }
}
