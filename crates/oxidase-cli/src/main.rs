use std::error::Error;
use std::path::PathBuf;

use bytes::Bytes;
use clap::{Parser, Subcommand};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use oxidase_config::{CompiledGateway, Compiler, ExplainRequestSource, TestExpectationSource};
use oxidase_core::{RequestFrame, RequestMetadata, ResourceId, ResponseHead, ServiceOutcome};
use oxidase_runtime::{BoxLeafFuture, ExecutionReport, Executor, LeafExecutor};
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
    Serve { config: PathBuf },
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
            let gateway = Compiler::compile_path(config)?;
            println!(
                "configuration {} is valid: {} listener(s), {} service node(s), {} resource(s)",
                gateway.config_version,
                gateway.listeners.len(),
                gateway.nodes.len(),
                gateway.resources.clusters.len() + gateway.resources.sites.len()
            );
            Ok(())
        }
        Command::Explain {
            config,
            request,
            listener,
        } => {
            let gateway = Compiler::compile_path(config)?;
            let request = Compiler::parse_request_file(request)?;
            let output = explain(&gateway, listener.as_deref(), &request).await?;
            println!("{}", serde_json::to_string_pretty(&output)?);
            Ok(())
        }
        Command::Compile { config, output } => {
            let gateway = Compiler::compile_path(config)?;
            let manifest = CompilationManifest {
                format: "oxidase.snapshot-manifest/v1",
                summary: gateway.summary(),
            };
            std::fs::write(output, serde_json::to_vec_pretty(&manifest)?)?;
            Ok(())
        }
        Command::Test { config } => {
            let gateway = Compiler::compile_path(config)?;
            run_config_tests(&gateway).await
        }
        Command::Serve { config } => {
            let _gateway = Compiler::compile_path(config)?;
            Err(
                "`oxidase serve` requires the HTTP data-plane phase, which is not implemented yet"
                    .into(),
            )
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
    },
}

#[derive(Default)]
struct ExplainLeaves;

impl LeafExecutor<(), ExplainBody> for ExplainLeaves {
    fn body_from_bytes(&self, bytes: Bytes) -> ExplainBody {
        ExplainBody::Bytes(bytes)
    }

    fn execute_site<'a>(
        &'a self,
        resource: &'a ResourceId,
        request: &'a RequestFrame,
    ) -> BoxLeafFuture<'a, ExplainBody> {
        Box::pin(async move {
            ServiceOutcome::Handled(ResponseHead::new(
                StatusCode::OK,
                ExplainBody::Leaf {
                    kind: "site",
                    resource: resource.to_string(),
                    request_path: request.path_and_query().to_owned(),
                },
            ))
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
    gateway: &CompiledGateway,
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
    let leaves = ExplainLeaves;
    let report = Executor::new(&program, &leaves).execute(frame, None).await;
    Ok(describe_report(gateway, &listener.name, report))
}

fn request_frame(source: &ExplainRequestSource) -> Result<RequestFrame, Box<dyn Error>> {
    let method = source.method.parse::<Method>()?;
    let mut headers = HeaderMap::new();
    for (name, value) in &source.headers {
        headers.insert(name.parse::<HeaderName>()?, value.parse::<HeaderValue>()?);
    }
    Ok(RequestFrame::new(RequestMetadata::new(
        method,
        &source.scheme,
        &source.host,
        &source.path,
        headers,
    )))
}

fn describe_report(
    gateway: &CompiledGateway,
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
                } => BodyDescription::Leaf {
                    service: kind,
                    resource,
                    request_path,
                    symbolic: true,
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

async fn run_config_tests(gateway: &CompiledGateway) -> Result<(), Box<dyn Error>> {
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
    if let Some((kind, resource)) = expected_resource {
        if !leaf.is_some_and(|(actual_kind, actual_resource, _)| {
            actual_kind == kind && actual_resource == &resource
        }) {
            mismatches.push(format!("expected {kind} resource `{resource}`"));
        }
    }
    if let Some(path) = &expected.rewritten_path
        && !leaf.is_some_and(|(_, _, actual_path)| actual_path == path)
    {
        mismatches.push(format!("expected rewritten path `{path}`"));
    }
}
