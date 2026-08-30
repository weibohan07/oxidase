use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use bytes::Bytes;
use clap::{Parser, Subcommand};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use oxidase_config::{
    Compiler, ExplainRequestSource, HttpVersion, ListenerProtocol, TestExpectationSource,
};
use oxidase_core::{
    ContentDigest, ContentDigestBuilder, Diagnostic, RequestFrame, RequestMetadata, ResourceId,
    ResponseHead, ServiceOutcome, SourceSpan,
};
use oxidase_runtime::{
    BoxLeafFuture, ExecutionReport, Executor, GovernanceRegistry, LeafExecutor, RuntimeSnapshot,
};
use oxidase_site::PreparedSiteBody;
use serde::Serialize;

mod bundle_support;
mod diagnostic_output;

use diagnostic_output::{DiagnosticFormat, DiagnosticRoot, Reporter};

#[derive(Debug, Parser)]
#[command(
    name = "oxidase",
    version,
    about = "Declarative HTTP Service compiler and runtime"
)]
struct Cli {
    /// Selects human-readable or machine-readable diagnostics.
    #[arg(long, value_enum, global = true, default_value = "human")]
    diagnostic_format: DiagnosticFormat,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Compile and prepare-check a configuration without publishing it.
    Check { config: PathBuf },
    /// Execute a request symbolically and print the complete Service trace.
    Explain {
        config: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        listener: Option<String>,
    },
    /// Write a deterministic, portable compilation manifest.
    Compile {
        config: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Execute declarative tests embedded in the gateway source.
    Test { config: PathBuf },
    /// Build, inspect, verify, compare, or sign a portable Oxidase Bundle.
    Bundle {
        #[command(subcommand)]
        command: BundleCommand,
    },
    /// Serve a compiled gateway (enabled by the data-plane phase).
    Serve {
        #[arg(
            value_name = "CONFIG",
            required_unless_present = "bundle",
            conflicts_with = "bundle"
        )]
        config: Option<PathBuf>,
        /// Serve a verified portable Bundle instead of Gateway source.
        #[arg(
            long,
            value_name = "OXB",
            required_unless_present = "config",
            conflicts_with = "config"
        )]
        bundle: Option<PathBuf>,
        #[arg(long, requires = "config", conflicts_with = "bundle")]
        watch: bool,
        /// Trusted Ed25519 public key used to verify --bundle; repeat for rotation.
        #[arg(long = "bundle-key", value_name = "PUBLIC_KEY", requires = "bundle")]
        bundle_keys: Vec<PathBuf>,
        /// Explicitly allow an unsigned Bundle for standalone development use.
        #[arg(long, requires = "bundle", conflicts_with = "bundle_keys")]
        allow_unsigned_bundle: bool,
        /// Root for deployment-relative Bundle Asset and sensitive references.
        #[arg(long, value_name = "DIR", requires = "bundle")]
        deployment_root: Option<PathBuf>,
        /// Explicit bind for the separate health/metrics listener.
        #[arg(long)]
        admin_bind: Option<SocketAddr>,
    },
}

#[derive(Debug, Subcommand)]
enum BundleCommand {
    /// Compile source into a deterministic `.oxb` archive.
    Build {
        config: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Root used to encode deployment-relative runtime references.
        #[arg(long, value_name = "DIR")]
        deployment_root: Option<PathBuf>,
    },
    /// Print a safe structural inspection; --verbose includes external Asset paths.
    Inspect {
        bundle: PathBuf,
        #[arg(long)]
        verbose: bool,
    },
    /// Verify structure, digests, and optionally a trusted Ed25519 signature.
    Verify {
        bundle: PathBuf,
        #[arg(long = "key", value_name = "PUBLIC_KEY")]
        keys: Vec<PathBuf>,
        /// Root used to resolve deployment-relative external Assets.
        #[arg(long, value_name = "DIR")]
        deployment_root: Option<PathBuf>,
    },
    /// Compare two Bundle manifests and content identities.
    Diff { old: PathBuf, new: PathBuf },
    /// Add or replace one Ed25519 signature using an offline key file.
    Sign {
        bundle: PathBuf,
        #[arg(long, value_name = "PRIVATE_KEY")]
        key: PathBuf,
        /// Output path; omitted means an atomic in-place replacement.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let format = cli.diagnostic_format;
    let root = DiagnosticRoot::for_config(cli.config_path());
    let reporter = Reporter::new(format);
    let (diagnostics, failed, stdout_payload) = match run(cli, &reporter).await {
        Ok(success) => (success.diagnostics, false, success.stdout_payload),
        Err(failure) => (failure.diagnostics, true, false),
    };
    if !(format == DiagnosticFormat::Json && stdout_payload)
        && let Err(error) = diagnostic_output::render(format, &root, diagnostics)
    {
        eprintln!("cannot render diagnostics: {error}");
        std::process::exit(1);
    }
    if failed {
        std::process::exit(1);
    }
}

impl Cli {
    fn config_path(&self) -> &Path {
        match &self.command {
            Command::Check { config }
            | Command::Compile { config, .. }
            | Command::Test { config }
            | Command::Explain { config, .. } => config,
            Command::Serve { config, bundle, .. } => config
                .as_deref()
                .or(bundle.as_deref())
                .expect("clap requires one serve input"),
            Command::Bundle { command } => match command {
                BundleCommand::Build { config, .. } => config,
                BundleCommand::Inspect { bundle, .. }
                | BundleCommand::Verify { bundle, .. }
                | BundleCommand::Sign { bundle, .. } => bundle,
                BundleCommand::Diff { old, .. } => old,
            },
        }
    }
}

#[derive(Debug, Default)]
struct RunSuccess {
    stdout_payload: bool,
    diagnostics: Vec<Diagnostic>,
}

impl RunSuccess {
    fn with_diagnostics(diagnostics: Vec<Diagnostic>) -> Self {
        Self {
            stdout_payload: false,
            diagnostics,
        }
    }
}

fn bundle_payload_success(
    reporter: &Reporter,
    payload: &impl Serialize,
    human_message: impl AsRef<str>,
    diagnostics: Vec<Diagnostic>,
    source: &Path,
) -> Result<RunSuccess, CliFailure> {
    if reporter.is_json() {
        if !diagnostics.is_empty() {
            return Ok(RunSuccess::with_diagnostics(diagnostics));
        }
        let encoded =
            bundle_support::json_payload(payload).map_err(|error| bundle_failure(error, source))?;
        println!("{encoded}");
        Ok(RunSuccess {
            stdout_payload: true,
            diagnostics,
        })
    } else {
        reporter.human_stdout(human_message);
        Ok(RunSuccess::with_diagnostics(diagnostics))
    }
}

#[derive(Debug)]
struct CliFailure {
    diagnostics: Vec<Diagnostic>,
}

impl CliFailure {
    fn one(diagnostic: Diagnostic) -> Self {
        Self {
            diagnostics: vec![diagnostic],
        }
    }

    fn with_prior(mut self, prior: &[Diagnostic]) -> Self {
        if prior.is_empty() {
            return self;
        }
        let mut diagnostics = prior.to_vec();
        diagnostics.append(&mut self.diagnostics);
        self.diagnostics = diagnostics;
        self
    }
}

impl From<oxidase_config::CompileError> for CliFailure {
    fn from(error: oxidase_config::CompileError) -> Self {
        Self {
            diagnostics: error.diagnostics,
        }
    }
}

fn bundle_failure(error: bundle_support::BundleCliError, source: &Path) -> CliFailure {
    if let Some(diagnostics) = error.structured_diagnostics() {
        return CliFailure { diagnostics };
    }
    let offset = error
        .offset()
        .and_then(|offset| usize::try_from(offset).ok())
        .unwrap_or(0);
    CliFailure::one(Diagnostic::new(
        error.code(),
        error.message(),
        SourceSpan {
            file: source.to_path_buf(),
            start_byte: offset,
            end_byte: offset,
            line: 1,
            column: offset.saturating_add(1),
            end_line: 1,
            end_column: offset.saturating_add(1),
            field_path: "bundle".to_owned(),
        },
    ))
}

async fn run(cli: Cli, reporter: &Reporter) -> Result<RunSuccess, CliFailure> {
    match cli.command {
        Command::Check { config } => {
            let PreparedSnapshot {
                snapshot: gateway,
                warnings,
            } = prepare_snapshot(&config)?;
            reporter.human_stdout(format!(
                "configuration {} is valid: {} listener(s), {} service node(s), {} resource(s)",
                gateway.config_version,
                gateway.listeners.len(),
                gateway.graph.len(),
                snapshot_resource_count(&gateway)
            ));
            Ok(RunSuccess::with_diagnostics(warnings))
        }
        Command::Explain {
            config,
            request,
            listener,
        } => {
            let PreparedSnapshot {
                snapshot: gateway, ..
            } = prepare_snapshot(&config)?;
            let request_source =
                Compiler::parse_request_file(&request).map_err(CliFailure::from)?;
            let output = explain(&gateway, listener.as_deref(), &request_source, &request).await?;
            let output = serde_json::to_string_pretty(&output).map_err(|error| {
                CliFailure::one(diagnostic_at(
                    "explain.output_encode",
                    format!("cannot encode explain output: {error}"),
                    &request,
                    "explain.output",
                ))
            })?;
            println!("{output}");
            Ok(RunSuccess {
                stdout_payload: true,
                diagnostics: Vec::new(),
            })
        }
        Command::Compile { config, output } => {
            let PreparedSnapshot {
                snapshot: gateway,
                warnings,
            } = prepare_snapshot(&config)?;
            let manifest = CompilationManifest {
                format: "oxidase.snapshot-manifest/v1",
                summary: gateway.summary().clone(),
            };
            let manifest = serde_json::to_vec_pretty(&manifest).map_err(|error| {
                CliFailure::one(diagnostic_at(
                    "compile.manifest_encode",
                    format!("cannot encode compilation manifest: {error}"),
                    &config,
                    "compile.output",
                ))
                .with_prior(&warnings)
            })?;
            std::fs::write(&output, manifest).map_err(|error| {
                CliFailure::one(diagnostic_at(
                    "compile.output_write",
                    format!(
                        "cannot write compilation manifest `{}`: {error}",
                        output.display()
                    ),
                    &output,
                    "compile.output",
                ))
                .with_prior(&warnings)
            })?;
            Ok(RunSuccess::with_diagnostics(warnings))
        }
        Command::Test { config } => {
            let PreparedSnapshot {
                snapshot: gateway,
                warnings,
            } = prepare_snapshot(&config)?;
            run_config_tests(&gateway, &config, reporter)
                .await
                .map_err(|failure| failure.with_prior(&warnings))?;
            Ok(RunSuccess::with_diagnostics(warnings))
        }
        Command::Bundle { command } => match command {
            BundleCommand::Build {
                config,
                output,
                deployment_root,
            } => {
                let PreparedBundleSource {
                    gateway,
                    snapshot,
                    warnings,
                } = prepare_bundle_source(&config)?;
                let deployment_root =
                    bundle_support::resolve_deployment_root(deployment_root.as_deref(), &config)
                        .map_err(|error| bundle_failure(error, &config).with_prior(&warnings))?;
                let built =
                    bundle_support::build_bundle(&gateway, &snapshot, &output, &deployment_root)
                        .map_err(|error| bundle_failure(error, &config).with_prior(&warnings))?;
                bundle_payload_success(
                    reporter,
                    &built,
                    format!(
                        "built Bundle {} (content {}, {} Asset(s), {} embedded blob(s))",
                        built.output, built.content_digest, built.assets, built.embedded_blobs
                    ),
                    warnings,
                    &output,
                )
            }
            BundleCommand::Inspect { bundle, verbose } => {
                let inspection = bundle_support::inspect_bundle(&bundle, verbose)
                    .map_err(|error| bundle_failure(error, &bundle))?;
                let mut human_message = format!(
                    "Bundle {}: content {}, {} Asset(s), {} signature(s)",
                    bundle.display(),
                    inspection.content_digest,
                    inspection.assets,
                    inspection.signatures
                );
                if verbose && !inspection.reference_assets.is_empty() {
                    human_message.push_str("\nreference Assets:");
                    for (asset, path) in &inspection.reference_assets {
                        human_message.push_str(&format!("\n  {asset}: {path}"));
                    }
                }
                bundle_payload_success(reporter, &inspection, human_message, Vec::new(), &bundle)
            }
            BundleCommand::Verify {
                bundle,
                keys,
                deployment_root,
            } => {
                let verification =
                    bundle_support::verify_bundle(&bundle, &keys, deployment_root.as_deref())
                        .map_err(|error| bundle_failure(error, &bundle))?;
                bundle_payload_success(
                    reporter,
                    &verification,
                    format!(
                        "verified Bundle {}: {} blob(s), {} trusted signature(s)",
                        bundle.display(),
                        verification.structural.blob_count,
                        verification.verified_key_ids.len()
                    ),
                    Vec::new(),
                    &bundle,
                )
            }
            BundleCommand::Diff { old, new } => {
                let diff = bundle_support::diff_bundles(&old, &new)
                    .map_err(|error| bundle_failure(error, &old))?;
                bundle_payload_success(
                    reporter,
                    &diff,
                    if diff.identical_content {
                        "Bundles have identical canonical content".to_owned()
                    } else {
                        format!(
                            "Bundles differ: runtime_requirement={}, features=+{}/-{}, sections=+{}/-{}/~{}, assets=+{}/-{}/~{}, origins=+{}/-{}/~{}, sensitive_refs=+{}/-{}/~{}",
                            diff.minimum_runtime_version_changed,
                            diff.required_features_added.len(),
                            diff.required_features_removed.len(),
                            diff.sections_added.len(),
                            diff.sections_removed.len(),
                            diff.sections_changed.len(),
                            diff.assets_added.len(),
                            diff.assets_removed.len(),
                            diff.assets_changed.len(),
                            diff.origins_added.len(),
                            diff.origins_removed.len(),
                            diff.origins_changed.len(),
                            diff.sensitive_references_added.len(),
                            diff.sensitive_references_removed.len(),
                            diff.sensitive_references_changed.len(),
                        )
                    },
                    Vec::new(),
                    &old,
                )
            }
            BundleCommand::Sign {
                bundle,
                key,
                output,
            } => {
                let signed = bundle_support::sign_bundle(&bundle, &key, output.as_deref())
                    .map_err(|error| bundle_failure(error, &bundle))?;
                bundle_payload_success(
                    reporter,
                    &signed,
                    format!("signed Bundle {} with key {}", signed.output, signed.key_id),
                    Vec::new(),
                    &bundle,
                )
            }
        },
        Command::Serve {
            config,
            bundle,
            watch,
            bundle_keys,
            allow_unsigned_bundle,
            deployment_root,
            admin_bind,
        } => {
            let input = config
                .as_deref()
                .or(bundle.as_deref())
                .expect("clap requires one serve input")
                .to_path_buf();
            let (gateway, warnings) = if let Some(config) = &config {
                let PreparedSnapshot { snapshot, warnings } = prepare_snapshot(config)?;
                (snapshot, warnings)
            } else {
                let bundle = bundle.as_deref().expect("clap requires the Bundle path");
                let loaded = bundle_support::load_bundle_snapshot(
                    bundle,
                    &bundle_keys,
                    allow_unsigned_bundle,
                    deployment_root.as_deref(),
                )
                .map_err(|error| bundle_failure(error, bundle))?;
                let signature_summary = if loaded.verification.verified_key_ids.is_empty() {
                    "unsigned policy".to_owned()
                } else {
                    format!(
                        "{} trusted signature(s)",
                        loaded.verification.verified_key_ids.len()
                    )
                };
                reporter.human_stdout(format!(
                    "activated Bundle content {} with {signature_summary}",
                    loaded.inspection.content_digest
                ));
                (loaded.snapshot, Vec::new())
            };
            let listener_protocols = gateway
                .listeners
                .iter()
                .map(|listener| {
                    (
                        listener.name.clone(),
                        listener_protocol_label(listener.protocol, &listener.http.versions),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            let _ = tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "oxidase=info".into()),
                )
                .try_init();
            trace_compile_warnings(&warnings);
            let mut server = oxidase_server::GatewayServer::bind(gateway)
                .await
                .map_err(server_failure)
                .map_err(|failure| failure.with_prior(&warnings))?;
            if let Some(admin_bind) = admin_bind {
                server = server
                    .with_admin_listener(admin_bind)
                    .await
                    .map_err(server_failure)
                    .map_err(|failure| failure.with_prior(&warnings))?;
            }
            for (name, address) in server.local_addresses() {
                let protocol = listener_protocols
                    .get(&name)
                    .expect("bound listeners originate from the prepared snapshot");
                reporter.human_stdout(format!("listener {name} accepting {protocol} on {address}"));
            }
            if let Some(address) = server.admin_address() {
                reporter.human_stdout(format!("admin listener accepting HTTP/1.1 on {address}"));
            }
            let running = server.spawn();
            let (stop_watcher, watcher_stopped) = tokio::sync::watch::channel(false);
            let watcher = watch.then(|| {
                tokio::spawn(watch_dependencies(
                    config
                        .clone()
                        .expect("--watch is accepted only with source config"),
                    running.reload_handle(),
                    watcher_stopped,
                ))
            });
            tokio::signal::ctrl_c().await.map_err(|error| {
                CliFailure::one(diagnostic_at(
                    "serve.signal",
                    format!("cannot listen for the shutdown signal: {error}"),
                    &input,
                    "serve.signal",
                ))
                .with_prior(&warnings)
            })?;
            let _ = stop_watcher.send(true);
            if let Some(watcher) = watcher {
                watcher.await.map_err(|error| {
                    CliFailure::one(diagnostic_at(
                        "serve.watcher",
                        format!("dependency watcher task failed: {error}"),
                        &input,
                        "serve.watch",
                    ))
                    .with_prior(&warnings)
                })?;
            }
            running
                .shutdown()
                .await
                .map_err(server_failure)
                .map_err(|failure| failure.with_prior(&warnings))?;
            Ok(RunSuccess::with_diagnostics(warnings))
        }
    }
}

fn listener_protocol_label(protocol: ListenerProtocol, versions: &[HttpVersion]) -> String {
    match protocol {
        ListenerProtocol::Http => "HTTP/1.1".to_owned(),
        ListenerProtocol::Https => {
            let alpn = versions
                .iter()
                .map(|version| match version {
                    HttpVersion::Http1 => "http/1.1",
                    HttpVersion::H2 => "h2",
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("HTTPS (ALPN: {alpn})")
        }
    }
}

struct PreparedSnapshot {
    snapshot: RuntimeSnapshot,
    warnings: Vec<Diagnostic>,
}

struct PreparedBundleSource {
    gateway: oxidase_config::CompiledGateway,
    snapshot: RuntimeSnapshot,
    warnings: Vec<Diagnostic>,
}

fn snapshot_resource_count(snapshot: &RuntimeSnapshot) -> usize {
    snapshot.resources.certificates.len()
        + snapshot.resources.secrets.len()
        + snapshot.resources.trust_stores.len()
        + snapshot.resources.clusters.len()
        + snapshot.resources.sites.len()
}

fn prepare_snapshot(config: &Path) -> Result<PreparedSnapshot, CliFailure> {
    let mut gateway = Compiler::compile_path(config).map_err(CliFailure::from)?;
    let mut warnings = std::mem::take(&mut gateway.warnings);
    let snapshot = RuntimeSnapshot::prepare(gateway).map_err(|error| {
        CliFailure {
            diagnostics: error.into_diagnostics(),
        }
        .with_prior(&warnings)
    })?;
    warnings.extend(snapshot.preparation_warnings().iter().cloned());
    Ok(PreparedSnapshot { snapshot, warnings })
}

fn prepare_bundle_source(config: &Path) -> Result<PreparedBundleSource, CliFailure> {
    let mut gateway = Compiler::compile_path(config).map_err(CliFailure::from)?;
    let mut warnings = std::mem::take(&mut gateway.warnings);
    let snapshot = RuntimeSnapshot::prepare(gateway.clone()).map_err(|error| {
        CliFailure {
            diagnostics: error.into_diagnostics(),
        }
        .with_prior(&warnings)
    })?;
    warnings.extend(snapshot.preparation_warnings().iter().cloned());
    Ok(PreparedBundleSource {
        gateway,
        snapshot,
        warnings,
    })
}

fn trace_compile_warnings(warnings: &[Diagnostic]) {
    for warning in warnings {
        tracing::warn!(
            diagnostic_code = warning.code,
            field_path = %warning.primary.field_path,
            message = %warning.message,
            "configuration compiled with a warning"
        );
    }
}

fn server_failure(error: oxidase_server::ServerError) -> CliFailure {
    CliFailure {
        diagnostics: error.into_diagnostics(),
    }
}

fn diagnostic_at(
    code: &'static str,
    message: impl Into<String>,
    file: &Path,
    field_path: &str,
) -> Diagnostic {
    Diagnostic::new(
        code,
        message,
        SourceSpan {
            file: file.to_path_buf(),
            start_byte: 0,
            end_byte: 0,
            line: 1,
            column: 1,
            end_line: 1,
            end_column: 1,
            field_path: field_path.to_owned(),
        },
    )
}

#[derive(Serialize)]
struct CompilationManifest {
    format: &'static str,
    summary: oxidase_config::GatewaySummary,
}

#[derive(Debug, Clone)]
enum ExplainBody {
    Bytes(Bytes),
    Leaf {
        kind: &'static str,
        resource: String,
        request_path: String,
        symbolic: bool,
        cluster: Option<Box<ClusterPlanDescription>>,
    },
}

struct ExplainLeaves<'a> {
    snapshot: &'a RuntimeSnapshot,
}

impl LeafExecutor<(), ExplainBody> for ExplainLeaves<'_> {
    fn body_from_bytes(&self, bytes: Bytes) -> ExplainBody {
        ExplainBody::Bytes(bytes)
    }

    fn execute_site<'a>(
        &'a self,
        resource: &'a ResourceId,
        request: &'a RequestFrame,
    ) -> BoxLeafFuture<'a, ExplainBody> {
        let snapshot = self.snapshot.resources.sites.get(resource).cloned();
        Box::pin(async move {
            let Some(snapshot) = snapshot else {
                return ServiceOutcome::Failed(oxidase_core::ServiceError::new(
                    oxidase_core::ErrorClass::InvalidState,
                    format!("prepared site `{resource}` is missing"),
                ));
            };
            match snapshot.execute(request) {
                Ok(Some(response)) => {
                    let _body_length = match response.body {
                        PreparedSiteBody::Empty => 0,
                        PreparedSiteBody::Bytes(bytes) => bytes.len(),
                        PreparedSiteBody::Asset(asset) => asset.identity.length as usize,
                    };
                    let mut output = ResponseHead::new(
                        response.status,
                        ExplainBody::Leaf {
                            kind: "site",
                            resource: resource.to_string(),
                            request_path: request.path_and_query().to_owned(),
                            symbolic: false,
                            cluster: None,
                        },
                    );
                    output.headers = response.headers;
                    ServiceOutcome::Handled(output)
                }
                Ok(None) => ServiceOutcome::Declined,
                Err(error) => {
                    let class = if matches!(error, oxidase_site::SiteError::TemplateLimit { .. }) {
                        oxidase_core::ErrorClass::TemplateLimit
                    } else {
                        oxidase_core::ErrorClass::InvalidState
                    };
                    ServiceOutcome::Failed(oxidase_core::ServiceError::new(
                        class,
                        error.to_string(),
                    ))
                }
            }
        })
    }

    fn execute_proxy<'a>(
        &'a self,
        resource: &'a ResourceId,
        request: &'a RequestFrame,
        _body: &'a mut Option<()>,
        _max_request_body_bytes: Option<u64>,
    ) -> BoxLeafFuture<'a, ExplainBody> {
        let cluster = self
            .snapshot
            .resources
            .clusters
            .get(resource)
            .map(|cluster| Box::new(describe_cluster_plan(cluster)));
        Box::pin(async move {
            ServiceOutcome::Handled(ResponseHead::new(
                StatusCode::OK,
                ExplainBody::Leaf {
                    kind: "proxy",
                    resource: resource.to_string(),
                    request_path: request.path_and_query().to_owned(),
                    symbolic: true,
                    cluster,
                },
            ))
        })
    }

    fn governance(&self) -> Option<&GovernanceRegistry> {
        Some(&self.snapshot.governance)
    }
}

#[derive(Debug, Serialize)]
struct ExplainOutput {
    config_version: String,
    listener: String,
    outcome: &'static str,
    status: u16,
    body: BodyDescription,
    trace: Vec<TraceDescription>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum BodyDescription {
    Bytes {
        length: usize,
        preview: String,
    },
    Leaf {
        service: &'static str,
        resource: String,
        request_path: String,
        symbolic: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        cluster: Option<Box<ClusterPlanDescription>>,
    },
    SafeError,
}

#[derive(Debug, Clone, Serialize)]
struct ClusterPlanDescription {
    protocol: &'static str,
    load_balance: &'static str,
    endpoint_count: usize,
    health: ClusterHealthDescription,
    retry: ClusterRetryDescription,
    limits: ClusterLimitsDescription,
    endpoint_selection: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct ClusterHealthDescription {
    active: Option<ActiveHealthDescription>,
    passive: Option<PassiveHealthDescription>,
}

#[derive(Debug, Clone, Serialize)]
struct ActiveHealthDescription {
    healthy_statuses: Vec<String>,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
}

#[derive(Debug, Clone, Serialize)]
struct PassiveHealthDescription {
    consecutive_failures: u32,
}

#[derive(Debug, Clone, Serialize)]
struct ClusterRetryDescription {
    max_attempts: u32,
    methods: Vec<String>,
    retry_on: Vec<&'static str>,
    statuses: Vec<String>,
    request_body: &'static str,
    request_body_max_bytes: u64,
    max_concurrent_retries: u32,
}

#[derive(Debug, Clone, Serialize)]
struct ClusterLimitsDescription {
    max_in_flight: u32,
    max_in_flight_per_endpoint: u32,
}

fn describe_cluster_plan(cluster: &oxidase_runtime::PreparedCluster) -> ClusterPlanDescription {
    let spec = cluster.spec();
    ClusterPlanDescription {
        protocol: spec.protocol.as_str(),
        load_balance: spec.load_balance.as_str(),
        endpoint_count: spec.endpoints.len(),
        health: ClusterHealthDescription {
            active: spec
                .health
                .active
                .as_ref()
                .map(|active| ActiveHealthDescription {
                    healthy_statuses: active
                        .healthy_statuses
                        .iter()
                        .map(|status| describe_status_range(status.start, status.end))
                        .collect(),
                    healthy_threshold: active.healthy_threshold,
                    unhealthy_threshold: active.unhealthy_threshold,
                }),
            passive: spec
                .health
                .passive
                .as_ref()
                .map(|passive| PassiveHealthDescription {
                    consecutive_failures: passive.consecutive_failures,
                }),
        },
        retry: ClusterRetryDescription {
            max_attempts: spec.retry.max_attempts,
            methods: spec
                .retry
                .methods
                .iter()
                .map(|method| method.as_str().to_owned())
                .collect(),
            retry_on: spec
                .retry
                .retry_on
                .iter()
                .map(|cause| cause.as_str())
                .collect(),
            statuses: spec
                .retry
                .statuses
                .iter()
                .map(|status| describe_status_range(status.start, status.end))
                .collect(),
            request_body: match spec.retry.request_body.mode {
                oxidase_config::RetryBodyMode::None => "none",
                oxidase_config::RetryBodyMode::Buffer => "buffer",
            },
            request_body_max_bytes: spec.retry.request_body.max_bytes,
            max_concurrent_retries: spec.retry.max_concurrent_retries,
        },
        limits: ClusterLimitsDescription {
            max_in_flight: spec.limits.max_in_flight,
            max_in_flight_per_endpoint: spec.limits.max_in_flight_per_endpoint,
        },
        endpoint_selection: "actual endpoint selection is runtime state dependent",
    }
}

fn describe_status_range(start: u16, end: u16) -> String {
    if start == end {
        start.to_string()
    } else {
        format!("{start}-{end}")
    }
}

#[derive(Debug, Serialize)]
struct TraceDescription {
    service: String,
    route: Option<String>,
    event: &'static str,
    detail: String,
}

async fn explain(
    gateway: &RuntimeSnapshot,
    listener_name: Option<&str>,
    request: &ExplainRequestSource,
    source: &Path,
) -> Result<ExplainOutput, CliFailure> {
    let listener = match listener_name {
        Some(name) => gateway
            .listeners
            .iter()
            .find(|listener| listener.name == name)
            .ok_or_else(|| {
                CliFailure::one(diagnostic_at(
                    "explain.listener_missing",
                    format!("listener `{name}` does not exist"),
                    source,
                    "listener",
                ))
            })?,
        None => gateway.listeners.first().ok_or_else(|| {
            CliFailure::one(diagnostic_at(
                "explain.listener_missing",
                "compiled gateway has no listener",
                source,
                "listeners",
            ))
        })?,
    };
    let program = gateway.program_for(&listener.name).ok_or_else(|| {
        CliFailure::one(diagnostic_at(
            "explain.listener_program",
            "listener root program is unavailable",
            source,
            "listener",
        ))
    })?;
    let frame = request_frame(request, source)?;
    let leaves = ExplainLeaves { snapshot: gateway };
    let report = Executor::new(&program, &leaves)
        .execute_traced(frame, None)
        .await;
    Ok(describe_report(gateway, &listener.name, report))
}

fn request_frame(source: &ExplainRequestSource, file: &Path) -> Result<RequestFrame, CliFailure> {
    let method = source.method.parse::<Method>().map_err(|error| {
        CliFailure::one(diagnostic_at(
            "request.method",
            format!("invalid request method `{}`: {error}", source.method),
            file,
            "request.method",
        ))
    })?;
    let mut headers = HeaderMap::new();
    for (name, value) in &source.headers {
        let parsed_name = name.parse::<HeaderName>().map_err(|error| {
            CliFailure::one(diagnostic_at(
                "request.header_name",
                format!("invalid request Header name `{name}`: {error}"),
                file,
                &format!("request.headers.{name}"),
            ))
        })?;
        let parsed_value = value.parse::<HeaderValue>().map_err(|error| {
            CliFailure::one(diagnostic_at(
                "request.header_value",
                format!("invalid value for request Header `{name}`: {error}"),
                file,
                &format!("request.headers.{name}"),
            ))
        })?;
        headers.insert(parsed_name, parsed_value);
    }
    let metadata =
        RequestMetadata::try_new(method, &source.scheme, &source.host, &source.path, headers)
            .map_err(|error| {
                CliFailure::one(diagnostic_at(
                    "request.metadata",
                    format!("invalid request metadata: {error}"),
                    file,
                    "request",
                ))
            })?;
    Ok(RequestFrame::new(metadata))
}

fn describe_report(
    gateway: &RuntimeSnapshot,
    listener: &str,
    report: ExecutionReport<ExplainBody>,
) -> ExplainOutput {
    let (outcome, status, body) = match report.outcome {
        ServiceOutcome::Handled(response) => {
            let body = match response.body {
                ExplainBody::Bytes(bytes) => BodyDescription::Bytes {
                    length: bytes.len(),
                    preview: String::from_utf8_lossy(&bytes[..bytes.len().min(160)]).into_owned(),
                },
                ExplainBody::Leaf {
                    kind,
                    resource,
                    request_path,
                    symbolic,
                    cluster,
                } => BodyDescription::Leaf {
                    service: kind,
                    resource,
                    request_path,
                    symbolic,
                    cluster,
                },
            };
            ("handled", response.status.as_u16(), body)
        }
        ServiceOutcome::Declined => (
            "declined",
            StatusCode::NOT_FOUND.as_u16(),
            BodyDescription::SafeError,
        ),
        ServiceOutcome::Failed(error) => (
            "failed",
            error.public_status.as_u16(),
            BodyDescription::SafeError,
        ),
    };
    ExplainOutput {
        config_version: gateway.config_version.to_string(),
        listener: listener.to_owned(),
        outcome,
        status,
        body,
        trace: report
            .trace
            .events
            .into_iter()
            .map(|event| TraceDescription {
                service: event.service.to_string(),
                route: event.route.map(|route| route.to_string()),
                event: event.event,
                detail: event.detail,
            })
            .collect(),
    }
}

async fn run_config_tests(
    gateway: &RuntimeSnapshot,
    config: &Path,
    reporter: &Reporter,
) -> Result<(), CliFailure> {
    if gateway.tests.is_empty() {
        return Err(CliFailure::one(diagnostic_at(
            "test.no_cases",
            "configuration contains no declarative tests",
            config,
            "tests",
        )));
    }
    let mut failures = Vec::new();
    for (index, test) in gateway.tests.iter().enumerate() {
        let output = explain(gateway, test.listener.as_deref(), &test.request, config).await?;
        let mismatches = compare_expectation(&output, &test.expect);
        if mismatches.is_empty() {
            reporter.human_stdout(format!("ok - {}", test.name));
        } else {
            failures.extend(mismatches.into_iter().map(|mismatch| {
                diagnostic_at(
                    mismatch.code,
                    format!(
                        "configuration test `{}` failed: {}",
                        test.name, mismatch.message
                    ),
                    config,
                    &format!("tests[{index}].expect"),
                )
            }));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(CliFailure {
            diagnostics: failures,
        })
    }
}

struct ExpectationMismatch {
    code: &'static str,
    message: String,
}

fn compare_expectation(
    output: &ExplainOutput,
    expected: &TestExpectationSource,
) -> Vec<ExpectationMismatch> {
    let mut mismatches = Vec::new();
    if let Some(status) = expected.status
        && output.status != status
    {
        mismatches.push(ExpectationMismatch {
            code: "test.expectation_status",
            message: format!("expected status {status}, got {}", output.status),
        });
    }
    if let Some(service) = &expected.service {
        let service = format!("service:{service}");
        if !output
            .trace
            .iter()
            .any(|event| event.event == "enter" && event.service == service)
        {
            mismatches.push(ExpectationMismatch {
                code: "test.expectation_service",
                message: format!("service `{service}` was not entered"),
            });
        }
    }
    let leaf = match &output.body {
        BodyDescription::Leaf {
            service,
            resource,
            request_path,
            ..
        } => Some((*service, resource, request_path)),
        BodyDescription::Bytes { .. } | BodyDescription::SafeError => None,
    };
    compare_leaf(expected, leaf, &mut mismatches);
    compare_cluster_plan(output, expected, &mut mismatches);
    mismatches
}

fn compare_cluster_plan(
    output: &ExplainOutput,
    expected: &TestExpectationSource,
    mismatches: &mut Vec<ExpectationMismatch>,
) {
    let cluster = match &output.body {
        BodyDescription::Leaf { cluster, .. } => cluster.as_ref(),
        BodyDescription::Bytes { .. } | BodyDescription::SafeError => None,
    };
    if let Some(protocol) = &expected.cluster_protocol
        && !cluster.is_some_and(|cluster| cluster.protocol == protocol)
    {
        mismatches.push(ExpectationMismatch {
            code: "test.expectation_cluster_protocol",
            message: format!("expected Cluster protocol `{protocol}`"),
        });
    }
    if let Some(policy) = &expected.load_balance
        && !cluster.is_some_and(|cluster| cluster.load_balance == policy)
    {
        mismatches.push(ExpectationMismatch {
            code: "test.expectation_load_balance",
            message: format!("expected Cluster load-balancing policy `{policy}`"),
        });
    }
}

fn compare_leaf(
    expected: &TestExpectationSource,
    leaf: Option<(&str, &String, &String)>,
    mismatches: &mut Vec<ExpectationMismatch>,
) {
    let expected_resource = expected
        .cluster
        .as_ref()
        .map(|name| ("proxy", format!("cluster:{name}")))
        .or_else(|| {
            expected
                .site
                .as_ref()
                .map(|name| ("site", format!("site:{name}")))
        });
    if let Some((kind, resource)) = expected_resource
        && !leaf.is_some_and(|(actual_kind, actual_resource, _)| {
            actual_kind == kind && actual_resource == &resource
        })
    {
        mismatches.push(ExpectationMismatch {
            code: "test.expectation_resource",
            message: format!("expected {kind} resource `{resource}"),
        });
    }
    if let Some(path) = &expected.rewritten_path
        && !leaf.is_some_and(|(_, _, actual_path)| actual_path == path)
    {
        mismatches.push(ExpectationMismatch {
            code: "test.expectation_path",
            message: format!("expected rewritten path `{path}"),
        });
    }
}

async fn watch_dependencies(
    config: PathBuf,
    reload: oxidase_server::ReloadHandle,
    stop: tokio::sync::watch::Receiver<bool>,
) {
    watch_dependencies_with_timing(
        config,
        reload,
        stop,
        std::time::Duration::from_millis(500),
        std::time::Duration::from_millis(150),
    )
    .await;
}

async fn watch_dependencies_with_timing(
    config: PathBuf,
    reload: oxidase_server::ReloadHandle,
    mut stop: tokio::sync::watch::Receiver<bool>,
    poll_interval: std::time::Duration,
    debounce: std::time::Duration,
) {
    let mut last = current_dependency_stamp(&reload).await;
    let mut interval = tokio::time::interval(poll_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return;
                }
            }
            _ = interval.tick() => {
                let observed = current_dependency_stamp(&reload).await;
                if observed == last {
                    continue;
                }
                tokio::time::sleep(debounce).await;
                let dependencies_before = reload.watched_dependencies();
                let before_attempt = dependency_stamp(&dependencies_before).await;
                match reload.reload_path(&config).await {
                    Ok(report) => {
                        trace_compile_warnings(&report.warnings);
                        tracing::info!(
                            previous_version = report.previous_version,
                            current_version = report.current_version,
                            reused_certificates = report.reused_certificates,
                            reused_sites = report.reused_sites,
                            reused_clusters = report.reused_clusters,
                            "configuration reload committed"
                        );
                    }
                    Err(error) => {
                        tracing::error!(error = %error, "configuration reload rejected; retaining last-known-good snapshot");
                    }
                }
                let dependencies_after = reload.watched_dependencies();
                let after_attempt = dependency_stamp(&dependencies_after).await;
                // A dependency discovered by the attempt, or a source changed
                // while the blocking compiler was running, leaves one latest
                // dirty state for the next tick. Otherwise this failed/successful
                // state becomes the baseline and cannot create an error loop.
                last = if dependencies_before == dependencies_after
                    && before_attempt == after_attempt
                {
                    after_attempt
                } else {
                    before_attempt
                };
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WatchStamp(ContentDigest);

async fn current_dependency_stamp(reload: &oxidase_server::ReloadHandle) -> WatchStamp {
    let dependencies = reload.watched_dependencies();
    dependency_stamp(&dependencies).await
}

async fn dependency_stamp(dependencies: &[PathBuf]) -> WatchStamp {
    let mut hash = ContentDigestBuilder::new("oxidase/watch-stamp/v1");
    hash.field_u64("dependency_count", dependencies.len() as u64);
    for path in dependencies {
        hash.field_bytes("path", path.to_string_lossy().as_bytes());
        match tokio::fs::metadata(path).await {
            Ok(metadata) => {
                hash.field_bytes("state", b"present");
                hash.field_u64("length", metadata.len());
                hash.field_bytes("is_directory", [u8::from(metadata.is_dir())]);
                if let Ok(modified) = metadata.modified()
                    && let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH)
                {
                    hash.field_u128("modified_ns", duration.as_nanos());
                }
            }
            Err(_) => {
                hash.field_bytes("state", b"missing");
            }
        }
    }
    WatchStamp(hash.finish())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::net::SocketAddr;
    use std::path::Path;
    use std::time::Duration;

    use clap::Parser as _;
    use http::StatusCode;
    use oxidase_config::{
        Compiler, ExplainRequestSource, HttpVersion, ListenerProtocol, TestExpectationSource,
    };
    use oxidase_core::{DiagnosticSeverity, RespondBody, ServiceKind};
    use oxidase_runtime::RuntimeSnapshot;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{
        BundleCommand, Cli, Command, CompilationManifest, compare_expectation, explain,
        listener_protocol_label, prepare_snapshot, snapshot_resource_count,
        watch_dependencies_with_timing,
    };

    #[test]
    fn bundle_cli_inputs_are_explicit_and_source_watch_cannot_target_a_bundle() {
        let parsed = Cli::try_parse_from([
            "oxidase",
            "bundle",
            "build",
            "oxidase.yaml",
            "--output",
            "gateway.oxb",
            "--deployment-root",
            "/srv/oxidase",
        ])
        .expect("Bundle build syntax parses");
        assert!(matches!(
            parsed.command,
            Command::Bundle {
                command: BundleCommand::Build { .. }
            }
        ));

        assert!(
            Cli::try_parse_from([
                "oxidase",
                "serve",
                "oxidase.yaml",
                "--bundle",
                "gateway.oxb"
            ])
            .is_err(),
            "source and Bundle inputs are mutually exclusive"
        );
        assert!(
            Cli::try_parse_from(["oxidase", "serve", "--bundle", "gateway.oxb", "--watch"])
                .is_err(),
            "source watcher cannot reinterpret a Bundle as YAML"
        );
        assert!(
            Cli::try_parse_from(["oxidase", "serve", "--bundle", "gateway.oxb"]).is_ok(),
            "signature policy is enforced after trusted keys are loaded"
        );
        let unsigned = Cli::try_parse_from([
            "oxidase",
            "serve",
            "--bundle",
            "gateway.oxb",
            "--allow-unsigned-bundle",
        ])
        .expect("explicit unsigned development policy parses");
        assert!(matches!(
            unsigned.command,
            Command::Serve {
                allow_unsigned_bundle: true,
                ..
            }
        ));
        assert!(
            Cli::try_parse_from([
                "oxidase",
                "serve",
                "--bundle",
                "gateway.oxb",
                "--allow-unsigned-bundle",
                "--bundle-key",
                "release.pub",
            ])
            .is_err(),
            "unsigned policy cannot be combined with a trusted key"
        );
    }

    #[tokio::test]
    async fn explain_and_declarative_tests_describe_runtime_cluster_policy() {
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        fs::write(
            &config,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    api:
      protocol: h2
      endpoints:
        - name: primary
          url: http://127.0.0.1:3000
          weight: 2
        - name: secondary
          url: http://127.0.0.1:3001
          weight: 1
      load_balance:
        policy: least_requests
      health:
        active:
          path: /healthz
          interval: 5s
          timeout: 1s
          healthy_statuses: ["200-299"]
          healthy_threshold: 2
          unhealthy_threshold: 3
        passive:
          consecutive_failures: 4
          eject_for: 30s
      retry:
        max_attempts: 2
        methods: [GET, HEAD]
        retry_on: [connect_failure, refused_stream]
        statuses: [503]
        request_body:
          mode: none
          max_bytes: 64KiB
        max_concurrent_retries: 7
      limits:
        max_in_flight: 100
        max_in_flight_per_endpoint: 40
        queue_timeout: 0ms
services:
  root:
    type: proxy
    cluster: api
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: root
"#,
        )
        .expect("Cluster explain fixture can be written");
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("Cluster explain fixture compiles"),
        )
        .expect("Cluster explain fixture prepares");
        let request = ExplainRequestSource {
            method: "GET".to_owned(),
            scheme: "http".to_owned(),
            host: "example.test".to_owned(),
            path: "/api".to_owned(),
            headers: BTreeMap::new(),
        };

        let output = explain(&snapshot, None, &request, &config)
            .await
            .expect("symbolic Cluster request explains");
        let json = serde_json::to_value(&output).expect("Explain output serializes");
        assert_eq!(json["body"]["cluster"]["protocol"], "h2");
        assert_eq!(json["body"]["cluster"]["load_balance"], "least_requests");
        assert_eq!(json["body"]["cluster"]["endpoint_count"], 2);
        assert_eq!(
            json["body"]["cluster"]["health"]["active"]["healthy_statuses"],
            serde_json::json!(["200-299"])
        );
        assert_eq!(
            json["body"]["cluster"]["health"]["passive"]["consecutive_failures"],
            4
        );
        assert_eq!(json["body"]["cluster"]["retry"]["max_attempts"], 2);
        assert_eq!(
            json["body"]["cluster"]["retry"]["retry_on"],
            serde_json::json!(["connect_failure", "refused_stream"])
        );
        assert_eq!(json["body"]["cluster"]["limits"]["max_in_flight"], 100);
        assert_eq!(
            json["body"]["cluster"]["endpoint_selection"],
            "actual endpoint selection is runtime state dependent"
        );

        let expected = TestExpectationSource {
            cluster: Some("api".to_owned()),
            cluster_protocol: Some("h2".to_owned()),
            load_balance: Some("least_requests".to_owned()),
            ..TestExpectationSource::default()
        };
        assert!(compare_expectation(&output, &expected).is_empty());

        let mismatches = compare_expectation(
            &output,
            &TestExpectationSource {
                cluster_protocol: Some("http1".to_owned()),
                load_balance: Some("round_robin".to_owned()),
                ..TestExpectationSource::default()
            },
        );
        assert_eq!(
            mismatches
                .iter()
                .map(|mismatch| mismatch.code)
                .collect::<Vec<_>>(),
            vec![
                "test.expectation_cluster_protocol",
                "test.expectation_load_balance"
            ]
        );
    }

    #[tokio::test]
    async fn explain_describes_ingress_governance_without_dynamic_key_values() {
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        fs::write(
            &config,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
services:
  root:
    type: request_body_limit
    max_bytes: 4KiB
    service:
      type: concurrency_limit
      name: public-admission
      max_in_flight: 7
      queue_timeout: 25ms
      on_reject:
        status: 503
      service:
        type: rate_limit
        name: public-rate
        key:
          source: peer_ip
        rate:
          requests: 10
          per: 1s
        burst: 20
        state:
          max_keys: 100
          idle_ttl: 1m
        service:
          type: respond
          body:
            text: allowed
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: root
"#,
        )
        .expect("governance explain fixture can be written");
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("governance explain fixture compiles"),
        )
        .expect("governance explain fixture prepares");
        let request = ExplainRequestSource {
            method: "GET".to_owned(),
            scheme: "http".to_owned(),
            host: "example.test".to_owned(),
            path: "/private?token=not-a-label".to_owned(),
            headers: BTreeMap::new(),
        };

        let output = explain(&snapshot, None, &request, &config)
            .await
            .expect("governed request explains");
        assert_eq!(output.status, StatusCode::TOO_MANY_REQUESTS.as_u16());
        let policies = output
            .trace
            .iter()
            .filter(|event| event.event == "policy")
            .map(|event| event.detail.as_str())
            .collect::<Vec<_>>();
        assert_eq!(policies.len(), 3);
        assert!(policies.contains(&"max_bytes=4096"));
        assert!(policies.iter().any(|detail| {
            detail.contains("name=public-admission")
                && detail.contains("max_in_flight=7")
                && detail.contains("queue_timeout=25ms")
                && detail.contains("reject_status=503")
        }));
        assert!(policies.iter().any(|detail| {
            detail.contains("name=public-rate")
                && detail.contains("key=peer_ip")
                && detail.contains("requests=10")
                && detail.contains("burst=20")
                && detail.contains("max_keys=100")
        }));
        let serialized = serde_json::to_string(&output).expect("Explain output serializes");
        assert!(!serialized.contains("token=not-a-label"));
        assert!(
            compare_expectation(
                &output,
                &TestExpectationSource {
                    service: Some("root".to_owned()),
                    status: Some(StatusCode::TOO_MANY_REQUESTS.as_u16()),
                    ..TestExpectationSource::default()
                }
            )
            .is_empty()
        );
    }

    #[test]
    fn snapshot_preparation_preserves_non_fatal_compiler_warnings() {
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        fs::write(
            &config,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    api:
      endpoints:
        - name: primary
          url: http://127.0.0.1:3000
      retry:
        max_attempts: 2
        methods: [POST]
        retry_on: [connect_failure]
services:
  root:
    type: respond
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: root
"#,
        )
        .expect("warning fixture can be written");

        let prepared = prepare_snapshot(&config).expect("warning does not reject preparation");
        assert_eq!(snapshot_resource_count(&prepared.snapshot), 1);
        assert_eq!(prepared.warnings.len(), 1);
        assert_eq!(prepared.warnings[0].severity, DiagnosticSeverity::Warning);
        assert_eq!(prepared.warnings[0].code, "resource.cluster_retry_post");
        assert_eq!(
            prepared.warnings[0].primary.field_path,
            "resources.clusters.api.retry.methods[0]"
        );
        assert_eq!(prepared.snapshot.resources.clusters.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn initial_preparation_reports_resource_warnings_without_secret_values_or_paths() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempdir().expect("temporary directory is available");
        let secret = directory.path().join("distinctive-admin-token.secret");
        fs::write(&secret, b"do-not-render-this-token").expect("secret can be written");
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o644))
            .expect("secret permissions can be set");
        let config = directory.path().join("oxidase.yaml");
        fs::write(
            &config,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  secrets:
    admin-token:
      file: distinctive-admin-token.secret
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      type: respond
"#,
        )
        .expect("gateway config can be written");

        let prepared = prepare_snapshot(&config).expect("warning does not reject preparation");
        assert_eq!(prepared.warnings.len(), 1);
        assert_eq!(prepared.warnings[0].code, "secret.file_permissions");
        let rendered = String::from_utf8(
            oxidase_cli::encode_json_diagnostics(
                &oxidase_cli::DiagnosticRoot::for_config(&config),
                prepared.warnings.clone(),
            )
            .expect("warnings encode"),
        )
        .expect("diagnostic JSON is UTF-8");
        assert!(!rendered.contains("do-not-render-this-token"));
        assert!(!rendered.contains("distinctive-admin-token.secret"));
        let manifest = serde_json::to_string(&CompilationManifest {
            format: "oxidase.snapshot-manifest/v1",
            summary: prepared.snapshot.summary().clone(),
        })
        .expect("inspection manifest serializes");
        assert!(!manifest.contains("do-not-render-this-token"));
        assert!(!manifest.contains("distinctive-admin-token.secret"));
        let independently_prepared =
            prepare_snapshot(&config).expect("the same Secret-backed source prepares again");
        let repeated_manifest = serde_json::to_string(&CompilationManifest {
            format: "oxidase.snapshot-manifest/v1",
            summary: independently_prepared.snapshot.summary().clone(),
        })
        .expect("repeated inspection manifest serializes");
        assert_eq!(
            manifest, repeated_manifest,
            "opaque runtime Secret tokens must not make compile output nondeterministic"
        );
    }

    #[test]
    fn listener_protocol_labels_describe_cleartext_and_tls_alpn() {
        assert_eq!(
            listener_protocol_label(ListenerProtocol::Http, &[HttpVersion::Http1]),
            "HTTP/1.1"
        );
        assert_eq!(
            listener_protocol_label(
                ListenerProtocol::Https,
                &[HttpVersion::H2, HttpVersion::Http1]
            ),
            "HTTPS (ALPN: h2, http/1.1)"
        );
        assert_eq!(
            listener_protocol_label(ListenerProtocol::Https, &[HttpVersion::H2]),
            "HTTPS (ALPN: h2)"
        );
    }

    async fn wait_until(mut condition: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if condition() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("condition becomes true before timeout");
    }

    async fn get(address: SocketAddr, path: &str) -> String {
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("test server accepts connections");
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .expect("request can be written");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("response can be read");
        String::from_utf8(response).expect("test response is UTF-8")
    }

    fn write_initial_gateway(config: &Path) {
        fs::write(
            config,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
services:
  root:
    type: respond
    body:
      text: old-version
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: root
"#,
        )
        .expect("initial config can be written");
    }

    fn write_site_gateway(config: &Path) {
        fs::write(
            config,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  sites:
    web:
      root: site
services:
  root:
    type: site
    site: web
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: root
"#,
        )
        .expect("site candidate config can be written");
    }

    async fn start_watched_gateway(
        config: &Path,
    ) -> (
        oxidase_server::RunningServer,
        oxidase_server::ReloadHandle,
        SocketAddr,
        String,
        tokio::sync::watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
    ) {
        write_initial_gateway(config);
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(config).expect("initial config compiles"),
        )
        .expect("initial snapshot prepares");
        let running = oxidase_server::GatewayServer::bind(snapshot)
            .await
            .expect("gateway binds")
            .spawn();
        let address = running.local_addresses()[0].1;
        let reload = running.reload_handle();
        let initial_version = reload.current_snapshot().config_version.to_string();
        let (stop, receiver) = tokio::sync::watch::channel(false);
        let watcher = tokio::spawn(watch_dependencies_with_timing(
            config.to_path_buf(),
            reload.clone(),
            receiver,
            Duration::from_millis(10),
            Duration::from_millis(5),
        ));
        tokio::time::sleep(Duration::from_millis(30)).await;
        (running, reload, address, initial_version, stop, watcher)
    }

    async fn stop_watched_gateway(
        running: oxidase_server::RunningServer,
        stop: tokio::sync::watch::Sender<bool>,
        watcher: tokio::task::JoinHandle<()>,
    ) {
        let _ = stop.send(true);
        watcher.await.expect("watcher task stops");
        running.shutdown().await.expect("gateway shuts down");
    }

    #[tokio::test]
    async fn watcher_recovers_when_only_failed_import_is_fixed() {
        let directory = tempdir().expect("temporary directory is available");
        let root = directory.path().join("oxidase.yaml");
        fs::write(
            &root,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
services:
  root:
    type: respond
    body:
      text: old
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: root
"#,
        )
        .expect("initial config can be written");
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&root).expect("initial config compiles"),
        )
        .expect("initial snapshot prepares");
        let running = oxidase_server::GatewayServer::bind(snapshot)
            .await
            .expect("gateway binds")
            .spawn();
        let reload = running.reload_handle();
        let initial_version = reload.current_snapshot().config_version.to_string();
        let (stop, receiver) = tokio::sync::watch::channel(false);
        let watcher = tokio::spawn(watch_dependencies_with_timing(
            root.clone(),
            reload.clone(),
            receiver,
            Duration::from_millis(10),
            Duration::from_millis(5),
        ));
        tokio::time::sleep(Duration::from_millis(30)).await;

        let imported = directory.path().join("candidate.yaml");
        fs::write(
            &imported,
            "api_version: oxidase.dev/v1alpha1\nkind: gateway\nservices: invalid\n",
        )
        .expect("invalid import can be written");
        fs::write(
            &root,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
imports: [candidate.yaml]
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: candidate
"#,
        )
        .expect("candidate root can be written");

        let canonical_import = imported.canonicalize().expect("import path canonicalizes");
        wait_until(|| reload.watched_dependencies().contains(&canonical_import)).await;
        assert_eq!(
            reload.current_snapshot().config_version.as_str(),
            initial_version
        );

        fs::write(
            &imported,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
services:
  candidate:
    type: respond
    body:
      text: recovered
"#,
        )
        .expect("import can be fixed");

        wait_until(|| reload.current_snapshot().config_version.as_str() != initial_version).await;
        let snapshot = reload.current_snapshot();
        let program = snapshot
            .program_for("test")
            .expect("listener program exists");
        let node = program
            .graph
            .get(&program.entry)
            .expect("entry service exists");
        let ServiceKind::Respond {
            body: RespondBody::Text(body),
            ..
        } = &node.kind
        else {
            panic!("recovered listener enters Respond");
        };
        assert_eq!(body.source(), "recovered");

        let _ = stop.send(true);
        watcher.await.expect("watcher task stops");
        running.shutdown().await.expect("gateway shuts down");
    }

    #[tokio::test]
    async fn watcher_recovers_when_existing_invalid_oxt_is_fixed_in_place() {
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        let site = directory.path().join("site");
        let templates = site.join("_templates");
        fs::create_dir_all(&templates).expect("template directory can be created");
        fs::write(
            site.join("site.oxsite"),
            "oxista: site/v1\ntemplates:\n  roots: [_templates]\n",
        )
        .expect("manifest can be written");
        fs::write(
            site.join("index.html.oxr"),
            r#"---
oxista: response/v1
response:
  body:
    template:
      source: _templates/page.oxt
---
"#,
        )
        .expect("OXR can be written");
        let template = templates.join("page.oxt");
        fs::write(&template, "invalid OXT").expect("invalid OXT can be written");
        let (running, reload, address, initial_version, stop, watcher) =
            start_watched_gateway(&config).await;

        write_site_gateway(&config);
        let watched_template = template.canonicalize().expect("template canonicalizes");
        wait_until(|| reload.watched_dependencies().contains(&watched_template)).await;
        assert_eq!(
            reload.current_snapshot().config_version.as_str(),
            initial_version
        );
        assert!(get(address, "/").await.ends_with("old-version"));

        fs::write(
            &template,
            r#"---
oxista: template/v1
output: text
---
recovered-oxt
"#,
        )
        .expect("OXT can be fixed");
        wait_until(|| reload.current_snapshot().config_version.as_str() != initial_version).await;
        assert!(get(address, "/").await.ends_with("recovered-oxt\n"));

        stop_watched_gateway(running, stop, watcher).await;
    }

    #[tokio::test]
    async fn watcher_recovers_when_existing_invalid_oxr_is_fixed_in_place() {
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        let site = directory.path().join("site");
        fs::create_dir(&site).expect("site directory can be created");
        fs::write(site.join("site.oxsite"), "oxista: site/v1\n").expect("manifest can be written");
        let oxr = site.join("index.html.oxr");
        fs::write(&oxr, "invalid OXR").expect("invalid OXR can be written");
        let (running, reload, address, initial_version, stop, watcher) =
            start_watched_gateway(&config).await;

        write_site_gateway(&config);
        let watched_oxr = oxr.canonicalize().expect("OXR canonicalizes");
        wait_until(|| reload.watched_dependencies().contains(&watched_oxr)).await;
        assert_eq!(
            reload.current_snapshot().config_version.as_str(),
            initial_version
        );
        assert!(get(address, "/").await.ends_with("old-version"));

        fs::write(
            &oxr,
            r#"---
oxista: response/v1
response:
  body:
    text: recovered-oxr
---
"#,
        )
        .expect("OXR can be fixed");
        wait_until(|| reload.current_snapshot().config_version.as_str() != initial_version).await;
        assert!(get(address, "/").await.ends_with("recovered-oxr"));

        stop_watched_gateway(running, stop, watcher).await;
    }

    #[tokio::test]
    async fn watcher_recovers_when_missing_template_is_created() {
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        let site = directory.path().join("site");
        let templates = site.join("_templates");
        fs::create_dir_all(&templates).expect("template directory can be created");
        fs::write(
            site.join("site.oxsite"),
            "oxista: site/v1\ntemplates:\n  roots: [_templates]\n",
        )
        .expect("manifest can be written");
        fs::write(
            site.join("index.html.oxr"),
            r#"---
oxista: response/v1
response:
  body:
    template:
      source: _templates/page.oxt
---
"#,
        )
        .expect("OXR can be written");
        let missing = site
            .canonicalize()
            .expect("site root canonicalizes")
            .join("_templates/page.oxt");
        let (running, reload, address, initial_version, stop, watcher) =
            start_watched_gateway(&config).await;

        write_site_gateway(&config);
        wait_until(|| reload.watched_dependencies().contains(&missing)).await;
        assert_eq!(
            reload.current_snapshot().config_version.as_str(),
            initial_version
        );
        assert!(get(address, "/").await.ends_with("old-version"));

        fs::write(
            templates.join("page.oxt"),
            r#"---
oxista: template/v1
output: text
---
created-template
"#,
        )
        .expect("missing OXT can be created");
        wait_until(|| reload.current_snapshot().config_version.as_str() != initial_version).await;
        assert!(get(address, "/").await.ends_with("created-template\n"));

        stop_watched_gateway(running, stop, watcher).await;
    }
}
