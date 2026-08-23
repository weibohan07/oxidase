use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;

use bytes::Bytes;
use clap::{Parser, Subcommand};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use oxidase_config::{Compiler, ExplainRequestSource, TestExpectationSource};
use oxidase_core::{RequestFrame, RequestMetadata, ResourceId, ResponseHead, ServiceOutcome};
use oxidase_runtime::{BoxLeafFuture, ExecutionReport, Executor, LeafExecutor, RuntimeSnapshot};
use oxidase_site::PreparedSiteBody;
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(
    name = "oxidase",
    version,
    about = "Declarative HTTP Service compiler and runtime"
)]
struct Cli {
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
    if let Err(error) = run(Cli::parse()).await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    match cli.command {
        Command::Check { config } => {
            let gateway = RuntimeSnapshot::prepare(Compiler::compile_path(config)?)?;
            println!(
                "configuration {} is valid: {} listener(s), {} service node(s), {} resource(s)",
                gateway.config_version,
                gateway.listeners.len(),
                gateway.graph.len(),
                gateway.resources.clusters.len() + gateway.resources.sites.len()
            );
            Ok(())
        }
        Command::Explain {
            config,
            request,
            listener,
        } => {
            let gateway = RuntimeSnapshot::prepare(Compiler::compile_path(config)?)?;
            let request = Compiler::parse_request_file(request)?;
            let output = explain(&gateway, listener.as_deref(), &request).await?;
            println!("{}", serde_json::to_string_pretty(&output)?);
            Ok(())
        }
        Command::Compile { config, output } => {
            let gateway = RuntimeSnapshot::prepare(Compiler::compile_path(config)?)?;
            let manifest = CompilationManifest {
                format: "oxidase.snapshot-manifest/v1",
                summary: gateway.summary().clone(),
            };
            std::fs::write(output, serde_json::to_vec_pretty(&manifest)?)?;
            Ok(())
        }
        Command::Test { config } => {
            let gateway = RuntimeSnapshot::prepare(Compiler::compile_path(config)?)?;
            run_config_tests(&gateway).await
        }
        Command::Serve {
            config,
            watch,
            admin_bind,
        } => {
            let gateway = RuntimeSnapshot::prepare(Compiler::compile_path(&config)?)?;
            let _ = tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "oxidase=info".into()),
                )
                .try_init();
            let mut server = oxidase_server::GatewayServer::bind(gateway).await?;
            if let Some(admin_bind) = admin_bind {
                server = server.with_admin_listener(admin_bind).await?;
            }
            for (name, address) in server.local_addresses() {
                println!("listener {name} accepting HTTP/1.1 on {address}");
            }
            if let Some(address) = server.admin_address() {
                println!("admin listener accepting HTTP/1.1 on {address}");
            }
            let running = server.spawn();
            let (stop_watcher, watcher_stopped) = tokio::sync::watch::channel(false);
            let watcher = watch.then(|| {
                tokio::spawn(watch_dependencies(
                    config,
                    running.reload_handle(),
                    watcher_stopped,
                ))
            });
            let _ = tokio::signal::ctrl_c().await;
            let _ = stop_watcher.send(true);
            if let Some(watcher) = watcher {
                let _ = watcher.await;
            }
            running.shutdown().await?;
            Ok(())
        }
    }
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
                Err(error) => ServiceOutcome::Failed(oxidase_core::ServiceError::new(
                    oxidase_core::ErrorClass::SiteIo,
                    error.to_string(),
                )),
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
) -> Result<ExplainOutput, Box<dyn Error>> {
    let listener = match listener_name {
        Some(name) => gateway
            .listeners
            .iter()
            .find(|listener| listener.name == name)
            .ok_or_else(|| format!("listener `{name}` does not exist"))?,
        None => gateway
            .listeners
            .first()
            .ok_or("compiled gateway has no listener")?,
    };
    let program = gateway
        .program_for(&listener.name)
        .ok_or("listener root program is unavailable")?;
    let frame = request_frame(request)?;
    let leaves = ExplainLeaves { snapshot: gateway };
    let report = Executor::new(&program, &leaves)
        .execute_traced(frame, None)
        .await;
    Ok(describe_report(gateway, &listener.name, report))
}

fn request_frame(source: &ExplainRequestSource) -> Result<RequestFrame, Box<dyn Error>> {
    let method = source.method.parse::<Method>()?;
    let mut headers = HeaderMap::new();
    for (name, value) in &source.headers {
        headers.insert(name.parse::<HeaderName>()?, value.parse::<HeaderValue>()?);
    }
    Ok(RequestFrame::new(RequestMetadata::try_new(
        method,
        &source.scheme,
        &source.host,
        &source.path,
        headers,
    )?))
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

async fn run_config_tests(gateway: &RuntimeSnapshot) -> Result<(), Box<dyn Error>> {
    if gateway.tests.is_empty() {
        return Err("configuration contains no declarative tests".into());
    }
    let mut failures = Vec::new();
    for test in &gateway.tests {
        let output = explain(gateway, test.listener.as_deref(), &test.request).await?;
        let mismatches = compare_expectation(&output, &test.expect);
        if mismatches.is_empty() {
            println!("ok - {}", test.name);
        } else {
            failures.push(format!("{}: {}", test.name, mismatches.join(", ")));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} configuration test(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        )
        .into())
    }
}

fn compare_expectation(output: &ExplainOutput, expected: &TestExpectationSource) -> Vec<String> {
    let mut mismatches = Vec::new();
    if let Some(status) = expected.status
        && output.status != status
    {
        mismatches.push(format!("expected status {status}, got {}", output.status));
    }
    if let Some(service) = &expected.service {
        let service = format!("service:{service}");
        if !output
            .trace
            .iter()
            .any(|event| event.event == "enter" && event.service == service)
        {
            mismatches.push(format!("service `{service}` was not entered"));
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
    mismatches: &mut Vec<String>,
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
        mismatches.push(format!("expected {kind} resource `{resource}`"));
    }
    if let Some(path) = &expected.rewritten_path
        && !leaf.is_some_and(|(_, _, actual_path)| actual_path == path)
    {
        mismatches.push(format!("expected rewritten path `{path}`"));
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
                        tracing::info!(
                            previous_version = report.previous_version,
                            current_version = report.current_version,
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

async fn current_dependency_stamp(reload: &oxidase_server::ReloadHandle) -> u64 {
    let dependencies = reload.watched_dependencies();
    dependency_stamp(&dependencies).await
}

async fn dependency_stamp(dependencies: &[PathBuf]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for path in dependencies {
        update_stamp(&mut hash, path.to_string_lossy().as_bytes());
        match tokio::fs::metadata(path).await {
            Ok(metadata) => {
                update_stamp(&mut hash, &metadata.len().to_le_bytes());
                update_stamp(&mut hash, &[u8::from(metadata.is_dir())]);
                if let Ok(modified) = metadata.modified()
                    && let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH)
                {
                    update_stamp(&mut hash, &duration.as_nanos().to_le_bytes());
                }
            }
            Err(_) => update_stamp(&mut hash, b"missing"),
        }
    }
    hash
}

fn update_stamp(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::Duration;

    use oxidase_config::Compiler;
    use oxidase_core::{RespondBody, ServiceKind};
    use oxidase_runtime::RuntimeSnapshot;
    use tempfile::tempdir;

    use super::watch_dependencies_with_timing;

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
}
