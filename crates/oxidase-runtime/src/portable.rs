//! Stable, source-free runtime plans used by portable Oxidase Bundles.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use oxidase_config::{
    BundleAssetMode, BundleAssetsSpec, BundleSpec, CompiledGateway, PortableConfigError,
    PortableGatewayConfigV1, PortableGatewayPlanV1, portable_source_display_path,
};
use oxidase_core::{
    ConfigVersion, ContentDigest, ContentDigestBuilder, PortableIrError, PortableServiceGraphV1,
    ResourceId, ServiceGraph, ServiceKind, ServiceProgram, ServiceProgramError, SourceSpan,
};
use oxidase_site::{AssetSource, PortableAssetInputV1, PortableSiteError, PortableSiteSnapshotV1};
use serde::{Deserialize, Serialize};

use crate::snapshot::{PortablePreparedResources, PortablePreparedSite};
use crate::{
    PreparationError, PreparedCertificate, PreparedTrustStore, ResourceReuse, RuntimeSnapshot,
};

/// Stable schema for the runtime-independent portion of an Oxidase snapshot.
pub const PORTABLE_RUNTIME_PLAN_SCHEMA_V1: &str = "oxidase.runtime-plan/v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableRuntimePlanV1 {
    pub schema_version: String,
    pub gateway: PortableGatewayConfigV1,
    pub graph: PortableServiceGraphV1,
    pub sites: BTreeMap<String, PortableSiteSnapshotV1>,
    pub certificate_chains: BTreeMap<String, PortablePublicCertificateV1>,
    pub trust_stores: BTreeMap<String, PortablePublicTrustStoreV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortablePublicCertificateV1 {
    /// Leaf-first public DER chain. Private signing material is never present.
    pub certificates_der: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortablePublicTrustStoreV1 {
    /// Sorted and deduplicated public DER trust anchors.
    pub certificates_der: Vec<Vec<u8>>,
}

/// Non-serializable build output. Asset bytes remain behind streaming file or
/// Bundle-slice sources until the archive writer consumes them.
#[derive(Debug, Clone)]
pub struct PortableRuntimeExportV1 {
    pub plan: PortableRuntimePlanV1,
    pub assets: BTreeMap<String, PortableAssetInputV1>,
}

struct DecodedPortablePlan {
    gateway: PortableGatewayPlanV1,
    graph: Arc<ServiceGraph>,
    sites: BTreeMap<ResourceId, PortablePreparedSite>,
}

impl RuntimeSnapshot {
    /// Exports one prepared snapshot and its compiler-owned stable plans.
    ///
    /// The supplied `CompiledGateway` must be the source used to prepare this
    /// snapshot. The method rejects resource/graph mismatches instead of
    /// emitting a self-inconsistent archive.
    pub fn export_portable(
        &self,
        gateway: &CompiledGateway,
    ) -> Result<PortableRuntimeExportV1, PortableRuntimeError> {
        let source_root = gateway.source.parent().ok_or_else(|| {
            PortableRuntimeError::Invalid("Gateway source has no parent directory".to_owned())
        })?;
        self.export_portable_at(gateway, source_root)
    }

    /// Exports using an explicit deployment root for all relative runtime
    /// references and logical diagnostic paths.
    pub fn export_portable_at(
        &self,
        gateway: &CompiledGateway,
        source_root: &Path,
    ) -> Result<PortableRuntimeExportV1, PortableRuntimeError> {
        if self.graph.len() != gateway.graph.len() || !self.graph.keys().eq(gateway.graph.keys()) {
            return Err(PortableRuntimeError::Invalid(
                "prepared Service graph does not match the compiled Gateway".to_owned(),
            ));
        }

        let gateway_plan = PortableGatewayConfigV1::from_compiled_with_root(gateway, source_root)
            .map_err(PortableRuntimeError::Config)?;
        let mut graph = PortableServiceGraphV1::from_graph(&gateway.graph);
        // Match the normalized file identity used by the Gateway DTO. Cross-
        // section diagnostics can then label one definition/reference pair as
        // belonging to the same logical source document.
        for node in &mut graph.nodes {
            node.source.file = portable_source_display_path(&node.source.file, source_root)
                .map_err(PortableRuntimeError::Config)?;
            if let oxidase_core::portable::PortableServiceKindV1::Route { cases, .. } =
                &mut node.kind
            {
                for case in cases {
                    case.source.file = portable_source_display_path(&case.source.file, source_root)
                        .map_err(PortableRuntimeError::Config)?;
                }
            }
        }

        let expected_site_ids = gateway_plan
            .site_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let actual_site_ids = self
            .resources
            .sites
            .keys()
            .map(ResourceId::as_str)
            .collect::<BTreeSet<_>>();
        if expected_site_ids != actual_site_ids {
            return Err(PortableRuntimeError::Invalid(
                "prepared Site resources do not match the compiled Gateway".to_owned(),
            ));
        }

        let mut sites = BTreeMap::new();
        let mut assets = BTreeMap::<String, PortableAssetInputV1>::new();
        for (id, site) in &self.resources.sites {
            let exported = site
                .export_portable()
                .map_err(|error| PortableRuntimeError::Site {
                    site: id.to_string(),
                    code: error.code(),
                    message: error.message().to_owned(),
                })?;
            for (key, asset) in exported.assets {
                if let Some(existing) = assets.get(&key) {
                    if existing.digest != asset.digest || existing.length != asset.length {
                        return Err(PortableRuntimeError::Invalid(format!(
                            "content key `{key}` has inconsistent Asset metadata"
                        )));
                    }
                } else {
                    assets.insert(key, asset);
                }
            }
            sites.insert(id.to_string(), exported.snapshot);
        }

        let certificate_chains = self
            .resources
            .certificates
            .iter()
            .map(|(id, certificate)| {
                (
                    id.to_string(),
                    PortablePublicCertificateV1 {
                        certificates_der: certificate.public_chain_der(),
                    },
                )
            })
            .collect();
        let trust_stores = self
            .resources
            .trust_stores
            .iter()
            .map(|(id, trust_store)| {
                (
                    id.to_string(),
                    PortablePublicTrustStoreV1 {
                        certificates_der: trust_store.public_roots_der(),
                    },
                )
            })
            .collect();

        Ok(PortableRuntimeExportV1 {
            plan: PortableRuntimePlanV1 {
                schema_version: PORTABLE_RUNTIME_PLAN_SCHEMA_V1.to_owned(),
                gateway: gateway_plan,
                graph,
                sites,
                certificate_chains,
                trust_stores,
            },
            assets,
        })
    }
}

impl PortableRuntimePlanV1 {
    /// Returns the exact content-key set consumed by compiled Site plans.
    #[must_use]
    pub fn asset_keys(&self) -> BTreeSet<String> {
        let mut keys = BTreeSet::new();
        for site in self.sites.values() {
            for response in site.entries.values() {
                if let oxidase_site::PortableSiteResponseKindV1::Asset { plan } = &response.kind {
                    keys.insert(plan.identity.asset_key.clone());
                    if let Some(representation) = &plan.brotli {
                        keys.insert(representation.asset_key.clone());
                    }
                    if let Some(representation) = &plan.gzip {
                        keys.insert(representation.asset_key.clone());
                    }
                }
            }
        }
        keys
    }

    /// Validates every source-free executable semantic without opening Secret
    /// or private-key references and without publishing a snapshot.
    pub fn validate_with_assets<F>(
        &self,
        artifact_identity: ContentDigest,
        deployment_root: &Path,
        resolve_asset: F,
    ) -> Result<(), PortableRuntimeError>
    where
        F: FnMut(&str, ContentDigest, u64) -> Result<AssetSource, PortableSiteError>,
    {
        self.decode_with_assets(artifact_identity, deployment_root, resolve_asset)
            .map(|_| ())
    }

    fn decode_with_assets<F>(
        &self,
        artifact_identity: ContentDigest,
        deployment_root: &Path,
        mut resolve_asset: F,
    ) -> Result<DecodedPortablePlan, PortableRuntimeError>
    where
        F: FnMut(&str, ContentDigest, u64) -> Result<AssetSource, PortableSiteError>,
    {
        if self.schema_version != PORTABLE_RUNTIME_PLAN_SCHEMA_V1 {
            return Err(PortableRuntimeError::UnsupportedSchema(
                self.schema_version.clone(),
            ));
        }
        let gateway = self
            .gateway
            .compile_at(deployment_root)
            .map_err(PortableRuntimeError::Config)?;
        let graph = Arc::new(self.graph.compile().map_err(PortableRuntimeError::Ir)?);
        let first_listener = gateway
            .listeners
            .first()
            .expect("portable Gateway validation requires at least one listener");
        ServiceProgram::new(first_listener.service.clone(), Arc::clone(&graph))
            .validate()
            .map_err(PortableRuntimeError::Program)?;
        for listener in gateway.listeners.iter().skip(1) {
            if graph.get(&listener.service).is_none() {
                return Err(PortableRuntimeError::Program(
                    ServiceProgramError::MissingService(listener.service.clone()),
                ));
            }
        }

        let expected_sites = gateway
            .site_ids
            .iter()
            .map(ResourceId::as_str)
            .collect::<BTreeSet<_>>();
        let actual_sites = self
            .sites
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if expected_sites != actual_sites {
            return Err(PortableRuntimeError::Invalid(
                "portable Site sections do not exactly match Gateway site_ids".to_owned(),
            ));
        }

        for (_, node) in graph.iter() {
            match &node.kind {
                ServiceKind::Site { resource } if !gateway.site_ids.contains(resource) => {
                    return Err(PortableRuntimeError::Invalid(format!(
                        "Service `{}` references missing portable Site `{resource}`",
                        node.id
                    )));
                }
                ServiceKind::Proxy { cluster }
                    if !gateway.resources.clusters.contains_key(cluster) =>
                {
                    return Err(PortableRuntimeError::Invalid(format!(
                        "Service `{}` references missing portable Cluster `{cluster}`",
                        node.id
                    )));
                }
                _ => {}
            }
        }

        validate_public_resource_keys(
            "certificate",
            gateway.resources.certificates.keys(),
            self.certificate_chains.keys(),
        )?;
        validate_public_resource_keys(
            "trust store",
            gateway.resources.trust_stores.keys(),
            self.trust_stores.keys(),
        )?;
        for (id, source) in &gateway.resources.certificates {
            let public = &self.certificate_chains[id.as_str()];
            PreparedCertificate::validate_public_chain(source, &public.certificates_der).map_err(
                |failure| PortableRuntimeError::PublicResource {
                    kind: "certificate",
                    resource: id.to_string(),
                    code: failure.diagnostic.code,
                    message: failure.diagnostic.message.clone(),
                },
            )?;
        }
        for (id, source) in &gateway.resources.trust_stores {
            let public = &self.trust_stores[id.as_str()];
            if public
                .certificates_der
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            {
                return Err(PortableRuntimeError::PublicResource {
                    kind: "trust store",
                    resource: id.to_string(),
                    code: "bundle.trust_store_noncanonical",
                    message: "public trust anchors must be strictly sorted and free of duplicates"
                        .to_owned(),
                });
            }
            PreparedTrustStore::prepare_with_public_roots(source, &public.certificates_der)
                .map_err(|failure| PortableRuntimeError::PublicResource {
                    kind: "trust store",
                    resource: id.to_string(),
                    code: failure.diagnostic.code,
                    message: failure.diagnostic.message.clone(),
                })?;
        }

        let mut sites = BTreeMap::new();
        for (id, site) in &self.sites {
            let resource_id = ResourceId::new(id.clone());
            let snapshot = site
                .compile_with_assets(&mut resolve_asset)
                .map_err(|error| PortableRuntimeError::Site {
                    site: id.clone(),
                    code: error.code(),
                    message: error.message().to_owned(),
                })?;
            if snapshot.id != resource_id {
                return Err(PortableRuntimeError::Invalid(format!(
                    "Site map key `{id}` does not match embedded identity `{}`",
                    snapshot.id
                )));
            }
            let encoded = serde_json::to_vec(site).map_err(|error| {
                PortableRuntimeError::Invalid(format!(
                    "cannot encode Site `{id}` for its stable fingerprint: {error}"
                ))
            })?;
            let mut fingerprint = ContentDigestBuilder::new("oxidase/portable-site/v1");
            fingerprint
                .field_digest("bundle", artifact_identity)
                .field_bytes("site", encoded);
            sites.insert(
                resource_id,
                PortablePreparedSite {
                    snapshot: Arc::new(snapshot),
                    fingerprint: fingerprint.finish(),
                },
            );
        }

        Ok(DecodedPortablePlan {
            gateway,
            graph,
            sites,
        })
    }

    /// Rebuilds and prepares a runtime snapshot without reading Gateway YAML,
    /// Oxista source, public certificate chains, or trust-store PEM files.
    ///
    /// `resolve_asset` must return either a verified external file or a byte
    /// range in the already-verified Bundle archive. Secret/private-key
    /// references are still validated by the ordinary preparation boundary.
    pub fn prepare_with_assets<F>(
        &self,
        activation_identity: ContentDigest,
        deployment_root: &Path,
        dependencies: Vec<PathBuf>,
        resolve_asset: F,
        previous: Option<&RuntimeSnapshot>,
    ) -> Result<(RuntimeSnapshot, ResourceReuse), PortableRuntimeError>
    where
        F: FnMut(&str, ContentDigest, u64) -> Result<AssetSource, PortableSiteError>,
    {
        let DecodedPortablePlan {
            gateway: gateway_plan,
            graph,
            sites: prepared_sites,
        } = self.decode_with_assets(activation_identity, deployment_root, resolve_asset)?;

        let certificate_chains = self
            .certificate_chains
            .iter()
            .map(|(id, chain)| (ResourceId::new(id.clone()), chain.certificates_der.clone()))
            .collect();
        let trust_store_roots = self
            .trust_stores
            .iter()
            .map(|(id, trust_store)| {
                (
                    ResourceId::new(id.clone()),
                    trust_store.certificates_der.clone(),
                )
            })
            .collect();

        let mut resources = gateway_plan.resources;
        resources.sites.clear();
        let bundle_source = SourceSpan::synthetic("bundle");
        let gateway = CompiledGateway {
            source: PathBuf::from("<bundle>"),
            config_version: ConfigVersion::new(format!("bundle-sha256-{activation_identity}")),
            bundle: BundleSpec {
                assets: BundleAssetsSpec {
                    mode: BundleAssetMode::Embed,
                    mode_source: bundle_source.clone(),
                    source: bundle_source.clone(),
                },
                source: bundle_source,
            },
            dependencies: dependencies.clone(),
            summary_dependencies: Vec::new(),
            graph,
            resources,
            listeners: gateway_plan.listeners,
            tests: Vec::new(),
            warnings: Vec::new(),
        };
        let prepared = PortablePreparedResources {
            dependencies,
            sites: prepared_sites,
            certificate_chains,
            trust_store_roots,
        };
        RuntimeSnapshot::prepare_reusing_with_resources(gateway, previous, Some(&prepared))
            .map_err(PortableRuntimeError::Preparation)
    }
}

fn validate_public_resource_keys<'a>(
    kind: &str,
    expected: impl Iterator<Item = &'a ResourceId>,
    actual: impl Iterator<Item = &'a String>,
) -> Result<(), PortableRuntimeError> {
    let expected = expected.map(ResourceId::as_str).collect::<BTreeSet<_>>();
    let actual = actual.map(String::as_str).collect::<BTreeSet<_>>();
    if expected == actual {
        Ok(())
    } else {
        Err(PortableRuntimeError::Invalid(format!(
            "portable public {kind} sections do not exactly match Gateway resources"
        )))
    }
}

#[derive(Debug)]
pub enum PortableRuntimeError {
    UnsupportedSchema(String),
    Config(PortableConfigError),
    Ir(PortableIrError),
    Program(ServiceProgramError),
    Site {
        site: String,
        code: &'static str,
        message: String,
    },
    PublicResource {
        kind: &'static str,
        resource: String,
        code: &'static str,
        message: String,
    },
    Invalid(String),
    Preparation(PreparationError),
}

impl PortableRuntimeError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedSchema(_) => "bundle.runtime_schema",
            Self::Config(error) => error.code(),
            Self::Ir(_) => "bundle.service_graph",
            Self::Program(_) => "bundle.service_program",
            Self::Site { code, .. } => code,
            Self::PublicResource { code, .. } => code,
            Self::Invalid(_) => "bundle.runtime_plan",
            Self::Preparation(_) => "bundle.prepare",
        }
    }
}

impl fmt::Display for PortableRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchema(schema) => {
                write!(formatter, "unsupported portable runtime schema `{schema}`")
            }
            Self::Config(error) => error.fmt(formatter),
            Self::Ir(error) => error.fmt(formatter),
            Self::Program(error) => error.fmt(formatter),
            Self::Site {
                site,
                code,
                message,
            } => write!(formatter, "Site `{site}` failed [{code}]: {message}"),
            Self::PublicResource {
                kind,
                resource,
                code,
                message,
            } => write!(
                formatter,
                "public {kind} `{resource}` failed [{code}]: {message}"
            ),
            Self::Invalid(message) => formatter.write_str(message),
            Self::Preparation(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PortableRuntimeError {}

#[cfg(test)]
mod tests {
    use std::fs;

    use oxidase_config::Compiler;
    use rcgen::{CertifiedKey as GeneratedCertificate, generate_simple_self_signed};
    use tempfile::tempdir;

    use super::*;

    const GATEWAY: &str = r#"api_version: oxidase.dev/v1alpha1
kind: gateway
services:
  root:
    type: respond
    status: 200
    body:
      text: portable
listeners:
  - name: public
    bind: 127.0.0.1:0
    protocol: http
    service:
      ref: root
"#;

    #[test]
    fn source_free_runtime_plan_round_trips_deterministically() {
        let directory = tempdir().expect("temporary directory");
        let source = directory.path().join("oxidase.yaml");
        fs::write(&source, GATEWAY).expect("write Gateway source");
        let gateway = Compiler::compile_path(&source).expect("compile Gateway");
        let snapshot = RuntimeSnapshot::prepare(gateway.clone()).expect("prepare snapshot");
        let exported = snapshot
            .export_portable(&gateway)
            .expect("export portable runtime");
        assert!(exported.assets.is_empty());

        let first = serde_json::to_vec(&exported.plan).expect("encode portable runtime");
        let decoded: PortableRuntimePlanV1 =
            serde_json::from_slice(&first).expect("decode portable runtime");
        let second = serde_json::to_vec(&decoded).expect("re-encode portable runtime");
        assert_eq!(first, second);
        assert!(
            !String::from_utf8_lossy(&first).contains(directory.path().to_string_lossy().as_ref())
        );

        let relocated = tempdir().expect("second temporary directory");
        let relocated_source = relocated.path().join("oxidase.yaml");
        fs::write(&relocated_source, GATEWAY).expect("write relocated Gateway source");
        let relocated_gateway =
            Compiler::compile_path(&relocated_source).expect("compile relocated Gateway");
        let relocated_snapshot = RuntimeSnapshot::prepare(relocated_gateway.clone())
            .expect("prepare relocated snapshot");
        let relocated_bytes = serde_json::to_vec(
            &relocated_snapshot
                .export_portable(&relocated_gateway)
                .expect("export relocated runtime")
                .plan,
        )
        .expect("encode relocated runtime");
        assert_eq!(
            first, relocated_bytes,
            "portable runtime identity must not depend on the checkout root"
        );

        let (rebuilt, _) = decoded
            .prepare_with_assets(
                ContentDigest::of_bytes(b"test-bundle"),
                directory.path(),
                Vec::new(),
                |_, _, _| {
                    Ok(AssetSource::File(
                        directory.path().join("unreachable-asset"),
                    ))
                },
                None,
            )
            .expect("prepare source-free runtime");
        assert_eq!(rebuilt.graph.len(), snapshot.graph.len());
        assert_eq!(rebuilt.listeners.len(), snapshot.listeners.len());
        assert!(rebuilt.program_for("public").is_some());
    }

    #[test]
    fn runtime_plan_normalizes_sibling_import_service_origins() {
        fn export_tree() -> PortableRuntimePlanV1 {
            let directory = tempdir().expect("temporary directory");
            let gateway_directory = directory.path().join("gateway");
            fs::create_dir(&gateway_directory).expect("Gateway directory is created");
            fs::write(
                directory.path().join("shared.yaml"),
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
services:
  imported:
    type: respond
    body:
      text: imported
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
            let gateway = Compiler::compile_path(source).expect("import tree compiles");
            let snapshot = RuntimeSnapshot::prepare(gateway.clone()).expect("snapshot prepares");
            snapshot
                .export_portable(&gateway)
                .expect("runtime plan exports")
                .plan
        }

        let first = export_tree();
        let second = export_tree();
        assert_eq!(
            serde_json::to_vec(&first).expect("first serializes"),
            serde_json::to_vec(&second).expect("second serializes")
        );
        assert!(
            first
                .graph
                .nodes
                .iter()
                .any(|node| { node.source.file == Path::new("source/external/up-1/shared.yaml") })
        );
    }

    #[test]
    fn rejects_unknown_runtime_schema_and_unknown_fields() {
        let directory = tempdir().expect("temporary directory");
        let source = directory.path().join("oxidase.yaml");
        fs::write(&source, GATEWAY).expect("write Gateway source");
        let gateway = Compiler::compile_path(&source).expect("compile Gateway");
        let snapshot = RuntimeSnapshot::prepare(gateway.clone()).expect("prepare snapshot");
        let mut plan = snapshot
            .export_portable(&gateway)
            .expect("export portable runtime")
            .plan;
        plan.schema_version = "oxidase.runtime-plan/v999".to_owned();
        let error = plan
            .prepare_with_assets(
                ContentDigest::of_bytes(b"test-bundle"),
                directory.path(),
                Vec::new(),
                |_, _, _| unreachable!("the invalid schema fails before asset resolution"),
                None,
            )
            .expect_err("unknown schema is rejected");
        assert_eq!(error.code(), "bundle.runtime_schema");

        let mut value = serde_json::to_value(&plan).expect("portable runtime is JSON");
        value
            .as_object_mut()
            .expect("runtime plan is an object")
            .insert("future_required".to_owned(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<PortableRuntimePlanV1>(value).is_err());
    }

    #[test]
    fn rejects_invalid_service_programs_and_missing_resources_before_prepare() {
        let directory = tempdir().expect("temporary directory");
        let source = directory.path().join("oxidase.yaml");
        fs::write(&source, GATEWAY).expect("write Gateway source");
        let gateway = Compiler::compile_path(&source).expect("compile Gateway");
        let snapshot = RuntimeSnapshot::prepare(gateway.clone()).expect("prepare snapshot");
        let plan = snapshot
            .export_portable(&gateway)
            .expect("export portable runtime")
            .plan;

        let mut invalid_limit = plan.clone();
        let service = invalid_limit.graph.nodes[0].id.clone();
        invalid_limit.graph.nodes[0].kind =
            oxidase_core::portable::PortableServiceKindV1::RequestBodyLimit {
                max_bytes: 0,
                service,
            };
        let error = invalid_limit
            .prepare_with_assets(
                ContentDigest::of_bytes(b"invalid-limit"),
                directory.path(),
                Vec::new(),
                |_, _, _| unreachable!("fixture has no assets"),
                None,
            )
            .expect_err("zero limits fail before governance preparation");
        assert_eq!(error.code(), "bundle.service_program");

        let mut no_listeners = plan.clone();
        no_listeners.gateway.listeners.clear();
        let error = no_listeners
            .validate_with_assets(
                ContentDigest::of_bytes(b"no-listeners"),
                directory.path(),
                |_, _, _| unreachable!("fixture has no assets"),
            )
            .expect_err("source-impossible empty listener sets are rejected");
        assert_eq!(error.code(), "bundle.gateway_config_invalid");

        let mut missing_entry = plan.clone();
        missing_entry
            .gateway
            .listeners
            .values_mut()
            .next()
            .expect("fixture listener")
            .service = "service:missing".to_owned();
        let error = missing_entry
            .prepare_with_assets(
                ContentDigest::of_bytes(b"missing-entry"),
                directory.path(),
                Vec::new(),
                |_, _, _| unreachable!("fixture has no assets"),
                None,
            )
            .expect_err("missing listener entry fails before publication");
        assert_eq!(error.code(), "bundle.service_program");

        let mut missing_site = plan;
        missing_site.graph.nodes[0].kind = oxidase_core::portable::PortableServiceKindV1::Site {
            resource: ResourceId::new("site:missing"),
        };
        let error = missing_site
            .prepare_with_assets(
                ContentDigest::of_bytes(b"missing-site"),
                directory.path(),
                Vec::new(),
                |_, _, _| unreachable!("fixture has no assets"),
                None,
            )
            .expect_err("missing Site resource fails before publication");
        assert_eq!(error.code(), "bundle.runtime_plan");
    }

    #[test]
    fn embeds_public_tls_material_but_keeps_private_key_external() {
        let directory = tempdir().expect("temporary directory");
        let GeneratedCertificate { cert, signing_key } =
            generate_simple_self_signed(vec!["bundle.example.test".to_owned()])
                .expect("test-only certificate");
        fs::write(directory.path().join("cert.pem"), cert.pem()).expect("write public chain");
        fs::write(
            directory.path().join("key.pem"),
            signing_key.serialize_pem(),
        )
        .expect("write test-only private key");
        fs::write(directory.path().join("ca.pem"), cert.pem()).expect("write trust anchor");
        let source = directory.path().join("oxidase.yaml");
        fs::write(
            &source,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    public:
      cert_chain: cert.pem
      private_key: key.pem
  trust_stores:
    internal:
      ca_bundle: ca.pem
listeners:
  - name: secure
    bind: 127.0.0.1:0
    protocol: https
    tls:
      default_certificate: public
    service:
      type: respond
      status: 200
"#,
        )
        .expect("write Gateway source");
        let gateway = Compiler::compile_path(&source).expect("compile Gateway");
        let snapshot = RuntimeSnapshot::prepare(gateway.clone()).expect("prepare snapshot");
        let exported = snapshot
            .export_portable(&gateway)
            .expect("export portable runtime");
        assert_eq!(exported.plan.certificate_chains.len(), 1);
        assert_eq!(exported.plan.trust_stores.len(), 1);
        let encoded = serde_json::to_vec(&exported.plan).expect("encode runtime plan");
        assert!(
            !encoded
                .windows(signing_key.serialize_der().len())
                .any(|window| window == signing_key.serialize_der().as_slice())
        );

        let mut invalid_chain = exported.plan.clone();
        invalid_chain
            .certificate_chains
            .get_mut("certificate:public")
            .expect("public chain")
            .certificates_der[0] = vec![0, 1, 2];
        let error = invalid_chain
            .validate_with_assets(
                ContentDigest::of_bytes(b"invalid-public-chain"),
                directory.path(),
                |_, _, _| unreachable!("fixture has no assets"),
            )
            .expect_err("invalid embedded public certificate is rejected by verification");
        assert_eq!(error.code(), "tls.certificate_x509");

        let mut invalid_trust = exported.plan.clone();
        invalid_trust
            .trust_stores
            .get_mut("trust_store:internal")
            .expect("public trust store")
            .certificates_der[0] = vec![0, 1, 2];
        let error = invalid_trust
            .validate_with_assets(
                ContentDigest::of_bytes(b"invalid-public-trust"),
                directory.path(),
                |_, _, _| unreachable!("fixture has no assets"),
            )
            .expect_err("invalid embedded trust root is rejected by verification");
        assert_eq!(error.code(), "trust_store.certificate");

        let mut duplicate_trust = exported.plan.clone();
        let roots = &mut duplicate_trust
            .trust_stores
            .get_mut("trust_store:internal")
            .expect("public trust store")
            .certificates_der;
        roots.push(roots[0].clone());
        let error = duplicate_trust
            .validate_with_assets(
                ContentDigest::of_bytes(b"duplicate-public-trust"),
                directory.path(),
                |_, _, _| unreachable!("fixture has no assets"),
            )
            .expect_err("duplicate embedded trust roots are not canonical");
        assert_eq!(error.code(), "bundle.trust_store_noncanonical");

        fs::remove_file(directory.path().join("cert.pem")).expect("remove source chain");
        fs::remove_file(directory.path().join("ca.pem")).expect("remove source trust store");
        let (rebuilt, _) = exported
            .plan
            .prepare_with_assets(
                ContentDigest::of_bytes(b"tls-bundle"),
                directory.path(),
                Vec::new(),
                |_, _, _| unreachable!("fixture has no assets"),
                None,
            )
            .expect("embedded public material prepares without source PEM");
        assert_eq!(rebuilt.resources.certificates.len(), 1);
        assert_eq!(rebuilt.resources.trust_stores.len(), 1);

        fs::remove_file(directory.path().join("key.pem")).expect("remove private key reference");
        assert!(
            exported
                .plan
                .prepare_with_assets(
                    ContentDigest::of_bytes(b"tls-bundle"),
                    directory.path(),
                    Vec::new(),
                    |_, _, _| unreachable!("fixture has no assets"),
                    None,
                )
                .is_err()
        );
    }
}
