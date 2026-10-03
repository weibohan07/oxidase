//! Process-separated discovery qualification tool, never a production binary.

use clap::Parser as _;
use oxidase_soak::process_campaign::{ProcessCli, run_cli};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run_cli(ProcessCli::parse()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::json!({"schema_version":"oxidase.discovery-soak/v1", "error":error.to_string()})
            );
            std::process::ExitCode::FAILURE
        }
    }
}
