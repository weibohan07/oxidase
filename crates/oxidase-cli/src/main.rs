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
use oxidase_runtime::{BoxLeafFuture, ExecutionReport, Executor, LeafExecutor, RuntimeSnapshot};
use oxidase_site::PreparedSiteBody;
use serde::Serialize;

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
    /// Serve a compiled gateway (enabled by the data-plane phase).
    Serve {
        config: PathBuf,
        #[arg(long)]
        watch: bool,
        /// Explicit bind for the separate health/metrics listener.
        #[arg(long)]
        admin_bind: Option<SocketAddr>,
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
            | Command::Serve { config, .. }
            | Command::Explain { config, .. } => config,
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
                gateway.resources.certificates.len()
                    + gateway.resources.clusters.len()
                    + gateway.resources.sites.len()
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
        Command::Serve {
            config,
            watch,
            admin_bind,
        } => {
            let PreparedSnapshot {
                snapshot: gateway,
                warnings,
            } = prepare_snapshot(&config)?;
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
                    config.clone(),
                    running.reload_handle(),
                    watcher_stopped,
                ))
            });
            tokio::signal::ctrl_c().await.map_err(|error| {
                CliFailure::one(diagnostic_at(
                    "serve.signal",
                    format!("cannot listen for the shutdown signal: {error}"),
                    &config,
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
                        &config,
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

fn prepare_snapshot(config: &Path) -> Result<PreparedSnapshot, CliFailure> {
    let mut gateway = Compiler::compile_path(config).map_err(CliFailure::from)?;
    let warnings = std::mem::take(&mut gateway.warnings);
    let snapshot = RuntimeSnapshot::prepare(gateway).map_err(|error| {
        CliFailure {
            diagnostics: error.into_diagnostics(),
        }
        .with_prior(&warnings)
    })?;
    Ok(PreparedSnapshot { snapshot, warnings })
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
    ) -> BoxLeafFuture<'a, ExplainBody> {
        Box::pin(async move {
            ServiceOutcome::Handled(ResponseHead::new(
                StatusCode::OK,
                ExplainBody::Leaf {
                    kind: "proxy",
                    resource: resource.to_string(),
                    request_path: request.path_and_query().to_owned(),
                    symbolic: true,
                },
            ))
        })
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
    },
    SafeError,
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
                } => BodyDescription::Leaf {
                    service: kind,
                    resource,
                    request_path,
                    symbolic,
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
    mismatches
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
    use std::fs;
    use std::net::SocketAddr;
    use std::path::Path;
    use std::time::Duration;

    use oxidase_config::{Compiler, HttpVersion, ListenerProtocol};
    use oxidase_core::{DiagnosticSeverity, RespondBody, ServiceKind};
    use oxidase_runtime::RuntimeSnapshot;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{listener_protocol_label, prepare_snapshot, watch_dependencies_with_timing};

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
        assert_eq!(prepared.warnings.len(), 1);
        assert_eq!(prepared.warnings[0].severity, DiagnosticSeverity::Warning);
        assert_eq!(prepared.warnings[0].code, "resource.cluster_retry_post");
        assert_eq!(
            prepared.warnings[0].primary.field_path,
            "resources.clusters.api.retry.methods[0]"
        );
        assert_eq!(prepared.snapshot.resources.clusters.len(), 1);
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
