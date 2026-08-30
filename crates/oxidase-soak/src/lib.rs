//! Bounded, reproducible transport and cluster soak campaigns for Oxidase.
//!
//! This crate is a validation tool, not a production server binary. Every
//! fixture binds an ephemeral loopback port and every generated TLS identity is
//! test-only material held in a temporary directory.

mod combined;
mod common;
mod protocol;

use std::fmt;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use serde::Serialize;

/// A bounded soak campaign mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// TLS HTTP/1.1 and HTTP/2, reload, certificate rotation, health, retry, and cancellation.
    Combined,
    /// Transparent gRPC trailers and TLS HTTP/1.1 Upgrade tunnels.
    Protocol,
}

/// Command-line parameters shared by every campaign mode.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "oxidase-soak",
    about = "Run a bounded in-process Oxidase transport/cluster soak campaign"
)]
pub struct Arguments {
    /// Campaign mode.
    #[arg(long, value_enum, default_value_t = Mode::Combined)]
    pub mode: Mode,

    /// Wall-clock campaign duration (`ms`, `s`, or `m`).
    #[arg(long, value_parser = parse_duration, default_value = "60s")]
    pub duration: Duration,

    /// Number of concurrent client workers.
    #[arg(long, value_parser = parse_positive_usize, default_value_t = 8)]
    pub concurrency: usize,

    /// Interval between snapshot reloads and test-only certificate rotations.
    #[arg(long, value_parser = parse_duration, default_value = "5s")]
    pub reload_interval: Duration,

    /// Response payload bytes used by fixtures.
    #[arg(long, value_parser = parse_positive_usize, default_value_t = 32 * 1024)]
    pub payload_size: usize,

    /// Deterministic workload seed.
    #[arg(long, default_value_t = 0x0D1D_A5E5_u64)]
    pub seed: u64,
}

/// Resource samples observed inside this process.
#[derive(Debug, Clone, Serialize)]
pub struct ResourceObservation {
    pub baseline: Option<u64>,
    pub peak: Option<u64>,
    pub final_value: Option<u64>,
}

/// Resource observations available on Linux through `/proc`.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessObservation {
    pub rss_kib: ResourceObservation,
    pub open_fds: ResourceObservation,
}

/// Exact command parameters embedded in a result for reproducibility.
#[derive(Debug, Clone, Serialize)]
pub struct CampaignParameters {
    pub mode: Mode,
    pub requested_duration_ms: u64,
    pub concurrency: usize,
    pub reload_interval_ms: u64,
    pub payload_size: usize,
    pub seed: u64,
}

impl From<&Arguments> for CampaignParameters {
    fn from(arguments: &Arguments) -> Self {
        Self {
            mode: arguments.mode,
            requested_duration_ms: millis(arguments.duration),
            concurrency: arguments.concurrency,
            reload_interval_ms: millis(arguments.reload_interval),
            payload_size: arguments.payload_size,
            seed: arguments.seed,
        }
    }
}

/// Machine-readable result emitted by the soak binary.
#[derive(Debug, Clone, Serialize)]
pub struct CampaignSummary {
    pub schema_version: &'static str,
    pub parameters: CampaignParameters,
    pub elapsed_ms: u64,
    pub requests: u64,
    pub successes: u64,
    pub errors: u64,
    pub retries: u64,
    pub health_transitions: u64,
    pub body_cancellations: u64,
    pub bytes: u64,
    pub reloads: u64,
    pub certificate_rotations: u64,
    pub http1_requests: u64,
    pub http2_requests: u64,
    pub grpc_requests: u64,
    pub websocket_tunnels: u64,
    pub process: ProcessObservation,
}

/// Machine-readable fatal failure envelope.
#[derive(Debug, Serialize)]
pub struct FailureSummary {
    schema_version: &'static str,
    error: String,
}

impl FailureSummary {
    #[must_use]
    pub fn new(error: String) -> Self {
        Self {
            schema_version: "oxidase.soak/v1",
            error,
        }
    }
}

/// Error returned when a campaign cannot start or its control plane fails.
#[derive(Debug)]
pub struct SoakError(String);

impl SoakError {
    pub(crate) fn message(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for SoakError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for SoakError {}

/// Run one bounded campaign.
pub async fn run(arguments: Arguments) -> Result<CampaignSummary, SoakError> {
    if arguments.duration.is_zero() {
        return Err(SoakError::message("duration must be greater than zero"));
    }
    if arguments.reload_interval.is_zero() {
        return Err(SoakError::message(
            "reload interval must be greater than zero",
        ));
    }
    match arguments.mode {
        Mode::Combined => combined::run(arguments).await,
        Mode::Protocol => protocol::run(arguments).await,
    }
}

fn parse_positive_usize(source: &str) -> Result<usize, String> {
    let value = source
        .parse::<usize>()
        .map_err(|error| format!("`{source}` is not a positive integer: {error}"))?;
    if value == 0 {
        return Err("value must be greater than zero".to_owned());
    }
    Ok(value)
}

fn parse_duration(source: &str) -> Result<Duration, String> {
    let (number, unit) = if let Some(number) = source.strip_suffix("ms") {
        (number, "ms")
    } else if let Some(number) = source.strip_suffix('s') {
        (number, "s")
    } else if let Some(number) = source.strip_suffix('m') {
        (number, "m")
    } else {
        return Err("duration must end in `ms`, `s`, or `m`".to_owned());
    };
    let value = number
        .parse::<u64>()
        .map_err(|error| format!("invalid duration `{source}`: {error}"))?;
    match unit {
        "ms" => Ok(Duration::from_millis(value)),
        "s" => Ok(Duration::from_secs(value)),
        "m" => value
            .checked_mul(60)
            .map(Duration::from_secs)
            .ok_or_else(|| format!("duration `{source}` is too large")),
        _ => Err(format!("unsupported duration `{source}`")),
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_parser_has_explicit_units_and_bounds() {
        assert_eq!(parse_duration("250ms"), Ok(Duration::from_millis(250)));
        assert_eq!(parse_duration("3s"), Ok(Duration::from_secs(3)));
        assert_eq!(parse_duration("2m"), Ok(Duration::from_secs(120)));
        assert!(parse_duration("1").is_err());
        assert!(parse_duration("soon").is_err());
    }

    #[test]
    fn summary_schema_is_stable_json() {
        let summary = CampaignSummary {
            schema_version: "oxidase.soak/v1",
            parameters: CampaignParameters {
                mode: Mode::Protocol,
                requested_duration_ms: 1,
                concurrency: 1,
                reload_interval_ms: 1,
                payload_size: 1,
                seed: 1,
            },
            elapsed_ms: 1,
            requests: 2,
            successes: 2,
            errors: 0,
            retries: 0,
            health_transitions: 0,
            body_cancellations: 0,
            bytes: 2,
            reloads: 0,
            certificate_rotations: 0,
            http1_requests: 1,
            http2_requests: 1,
            grpc_requests: 1,
            websocket_tunnels: 1,
            process: ProcessObservation {
                rss_kib: ResourceObservation {
                    baseline: None,
                    peak: None,
                    final_value: None,
                },
                open_fds: ResourceObservation {
                    baseline: None,
                    peak: None,
                    final_value: None,
                },
            },
        };
        let value = serde_json::to_value(summary).expect("summary serializes");
        assert_eq!(value["schema_version"], "oxidase.soak/v1");
        assert_eq!(value["parameters"]["mode"], "protocol");
        assert_eq!(
            value["process"]["rss_kib"]["baseline"],
            serde_json::Value::Null
        );
    }

    #[tokio::test]
    async fn combined_campaign_has_bounded_real_smoke() {
        let summary = run(Arguments {
            mode: Mode::Combined,
            duration: Duration::from_millis(600),
            concurrency: 1,
            reload_interval: Duration::from_millis(200),
            payload_size: 2 * 1024,
            seed: 7,
        })
        .await
        .expect("combined loopback campaign succeeds");
        assert!(summary.requests > 0);
        assert_eq!(summary.requests, summary.successes + summary.errors);
        assert_eq!(summary.errors, 0);
        assert!(summary.http1_requests > 0);
        assert!(summary.http2_requests > 0);
        assert!(summary.reloads > 0);
        assert!(summary.certificate_rotations > 0);
        assert!(summary.body_cancellations > 0);
    }

    #[tokio::test]
    async fn protocol_campaign_exercises_grpc_and_upgrade() {
        let summary = run(Arguments {
            mode: Mode::Protocol,
            duration: Duration::from_millis(600),
            concurrency: 1,
            reload_interval: Duration::from_millis(200),
            payload_size: 2 * 1024,
            seed: 11,
        })
        .await
        .expect("protocol loopback campaign succeeds");
        assert!(summary.requests > 0);
        assert_eq!(summary.requests, summary.successes + summary.errors);
        assert_eq!(summary.errors, 0);
        assert!(summary.grpc_requests > 0);
        assert!(summary.websocket_tunnels > 0);
        assert!(summary.reloads > 0);
        assert!(summary.certificate_rotations > 0);
        assert!(summary.body_cancellations > 0);
    }
}
