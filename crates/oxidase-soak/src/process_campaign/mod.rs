//! Separate-process Linux qualification. The gateway is the actual CLI; this
//! module has no publisher or access to its in-process runtime state.

#[cfg(unix)]
mod client;
mod fixture;
#[cfg(unix)]
mod monitor;
#[cfg(unix)]
mod resource_campaign;
#[cfg(unix)]
mod resource_evidence;
#[cfg(unix)]
mod resource_identity;
#[cfg(unix)]
mod resource_sampler;

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

use crate::SoakError;

/// CLI for validation-only process roles.
#[derive(Debug, Parser)]
#[command(
    name = "oxidase-discovery-soak",
    about = "Process-separated bounded Linux discovery qualification"
)]
pub struct ProcessCli {
    #[command(subcommand)]
    command: ProcessCommand,
}

#[derive(Debug, Subcommand)]
enum ProcessCommand {
    Run(ProcessArguments),
    ResourceRun(ResourceArguments),
    #[cfg(unix)]
    ResourceBuildRecord {
        #[arg(long)]
        gateway: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    #[cfg(unix)]
    #[command(hide = true)]
    ResourceSampler(resource_sampler::ResourceSamplerArguments),
    #[command(hide = true)]
    FixtureDns {
        #[arg(long)]
        root: PathBuf,
    },
    #[command(hide = true)]
    FixtureUpstream {
        #[arg(long)]
        root: PathBuf,
    },
}

/// Validation-only resource lanes. Never changes the gateway's own contracts.
#[derive(Debug, Clone, Copy, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum ResourceCampaign {
    Healthy,
    Churn,
    Respond,
    StaticProxy,
    DnsOnly,
    PublishOnly,
    BackgroundOnly,
    GrpcOnly,
    UpgradeOnly,
    ScrapeOnly,
}

#[derive(Debug, Parser)]
struct ResourceArguments {
    #[arg(long)]
    gateway: PathBuf,
    /// Created immediately after a documented locked build on the frozen source.
    #[arg(long)]
    build_record: PathBuf,
    #[arg(long, value_enum, default_value = "healthy")]
    campaign: ResourceCampaign,
    #[arg(long, value_parser = crate::parse_duration, default_value = "60m")]
    duration: Duration,
    #[arg(long, value_parser = crate::parse_duration, default_value = "3m")]
    warm_up: Duration,
    #[arg(long, value_parser = crate::parse_duration, default_value = "15m")]
    recovery_running: Duration,
    #[arg(long, value_parser = crate::parse_duration, default_value = "5m")]
    quiet_running: Duration,
    #[arg(long, value_parser = crate::parse_duration, default_value = "5m")]
    post_drain: Duration,
    #[arg(long, default_value_t = 8)]
    concurrency: usize,
    #[arg(long, default_value_t = 700201)]
    seed: u64,
    #[arg(long, value_parser = crate::parse_duration, default_value = "5s")]
    control_interval: Duration,
    /// Zero disables periodic admin scrape, not independent OS sampling.
    #[arg(long, default_value_t = 1000)]
    scrape_interval_ms: u64,
    #[arg(long, default_value_t = 1000)]
    sample_interval_ms: u64,
    #[arg(long, default_value_t = 32768)]
    payload_size: usize,
    #[arg(long, default_value_t = 1048576)]
    upload_size: usize,
    #[arg(long)]
    formal: bool,
    #[arg(long)]
    observation_disabled: bool,
    #[arg(long)]
    output: PathBuf,
}

/// Workloads exercise existing transport, discovery and administration paths.
#[derive(Debug, Clone, Copy, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum Campaign {
    Discovery,
    Protocol,
}

#[derive(Debug, Parser)]
struct ProcessArguments {
    #[arg(long)]
    gateway: PathBuf,
    #[arg(long, value_enum, default_value = "discovery")]
    campaign: Campaign,
    #[arg(long, value_parser=crate::parse_duration, default_value="10m")]
    duration: Duration,
    #[arg(long, default_value_t = 8)]
    concurrency: usize,
    #[arg(long, default_value_t = 600601)]
    seed: u64,
    #[arg(long, value_parser=crate::parse_duration, default_value="3s")]
    reload_interval: Duration,
    #[arg(long, value_parser=crate::parse_duration, default_value="30s")]
    warm_up: Duration,
    #[arg(long, value_parser=crate::parse_duration, default_value="120s")]
    cooldown: Duration,
    #[arg(long, value_parser=crate::parse_duration, default_value="1s")]
    sample_interval: Duration,
    #[arg(long, default_value_t = 32768)]
    payload_size: usize,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Ready {
    role: String,
    pid: u32,
    address: std::net::SocketAddr,
    alternate: Option<std::net::SocketAddr>,
    #[serde(default)]
    ipv6: Option<std::net::SocketAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum FixtureCommand {
    Dns {
        mode: String,
        ttl: u32,
    },
    Health {
        healthy_a: bool,
        healthy_b: bool,
        retry_a: bool,
    },
    ResourceFault {
        mode: String,
        target: String,
        delay_ms: u64,
        after_bytes: u64,
        case_id: u64,
    },
    Release,
    Status,
    Stop,
}

struct FixtureProcess {
    child: Child,
    input: ChildStdin,
    output: tokio::io::Lines<BufReader<ChildStdout>>,
    ready: Ready,
}

impl FixtureProcess {
    async fn spawn(role: &str, root: &Path, results: &Path) -> Result<Self, SoakError> {
        let executable = std::env::current_exe().map_err(io_error)?;
        let log =
            std::fs::File::create(results.join(format!("{role}.stderr.log"))).map_err(io_error)?;
        let mut child = Command::new(executable)
            .arg(format!("fixture-{role}"))
            .arg("--root")
            .arg(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(log))
            .kill_on_drop(true)
            .spawn()
            .map_err(io_error)?;
        let input = child
            .stdin
            .take()
            .ok_or_else(|| fail("fixture stdin missing"))?;
        let mut output = BufReader::new(
            child
                .stdout
                .take()
                .ok_or_else(|| fail("fixture stdout missing"))?,
        )
        .lines();
        let line = tokio::time::timeout(Duration::from_secs(10), output.next_line())
            .await
            .map_err(|_| fail("fixture readiness timeout"))?
            .map_err(io_error)?
            .ok_or_else(|| fail("fixture exited before readiness"))?;
        if line.len() > 16 * 1024 {
            return Err(fail("fixture readiness exceeds limit"));
        }
        let ready: Ready = serde_json::from_str(&line).map_err(json_error)?;
        if child.id() != Some(ready.pid) || ready.role != role {
            return Err(fail("fixture PID/role acknowledgment mismatch"));
        }
        Ok(Self {
            child,
            input,
            output,
            ready,
        })
    }

    async fn command(&mut self, command: FixtureCommand) -> Result<Value, SoakError> {
        let mut bytes = serde_json::to_vec(&command).map_err(json_error)?;
        bytes.push(b'\n');
        self.input.write_all(&bytes).await.map_err(io_error)?;
        self.input.flush().await.map_err(io_error)?;
        let line = tokio::time::timeout(Duration::from_secs(5), self.output.next_line())
            .await
            .map_err(|_| fail("fixture control timeout"))?
            .map_err(io_error)?
            .ok_or_else(|| fail("fixture control EOF"))?;
        if line.len() > 64 * 1024 {
            return Err(fail("fixture control response limit"));
        }
        let value: Value = serde_json::from_str(&line).map_err(json_error)?;
        if value["ok"] != true {
            return Err(fail("fixture rejected control operation"));
        }
        Ok(value)
    }

    async fn stop(mut self) -> Result<(), SoakError> {
        self.command(FixtureCommand::Stop).await?;
        let status = tokio::time::timeout(Duration::from_secs(5), self.child.wait())
            .await
            .map_err(|_| fail("fixture required forced termination"))?
            .map_err(io_error)?;
        if !status.success() {
            return Err(fail("fixture exited unsuccessfully"));
        }
        Ok(())
    }
}

fn fail(message: impl Into<String>) -> SoakError {
    SoakError::message(message)
}
fn io_error(error: impl std::fmt::Display) -> SoakError {
    fail(format!("qualification I/O: {error}"))
}
fn json_error(error: serde_json::Error) -> SoakError {
    fail(format!("qualification JSON: {error}"))
}

/// Execute one controller or fixture role.
pub async fn run_cli(cli: ProcessCli) -> Result<(), SoakError> {
    match cli.command {
        ProcessCommand::Run(args) => run(args).await,
        ProcessCommand::ResourceRun(args) => {
            #[cfg(unix)]
            return resource_campaign::run(args).await;
            #[cfg(not(unix))]
            {
                let _ = args;
                Err(fail(
                    "resource qualification requires Linux process identity",
                ))
            }
        }
        #[cfg(unix)]
        ProcessCommand::ResourceBuildRecord { gateway, output } => {
            resource_campaign::build_record(&gateway, &output)
        }
        #[cfg(unix)]
        ProcessCommand::ResourceSampler(args) => resource_sampler::run_sampler(args).await,
        ProcessCommand::FixtureDns { root } => fixture::dns(root).await,
        ProcessCommand::FixtureUpstream { root } => fixture::upstream(root).await,
    }
}

#[cfg(unix)]
async fn run(args: ProcessArguments) -> Result<(), SoakError> {
    client::run_controller(args).await
}

#[cfg(not(unix))]
async fn run(_args: ProcessArguments) -> Result<(), SoakError> {
    Err(fail(
        "process qualification requires Unix administration sockets and signaling",
    ))
}
