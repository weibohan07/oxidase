use std::process::ExitCode;

use clap::Parser as _;
use oxidase_soak::{Arguments, FailureSummary, run};

#[tokio::main]
async fn main() -> ExitCode {
    let arguments = Arguments::parse();
    match run(arguments).await {
        Ok(summary) => match serde_json::to_string_pretty(&summary) {
            Ok(output) => {
                println!("{output}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("failed to serialize soak summary: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            let failure = FailureSummary::new(error.to_string());
            match serde_json::to_string_pretty(&failure) {
                Ok(output) => eprintln!("{output}"),
                Err(serialization_error) => {
                    eprintln!(
                        "soak failed: {error}; summary serialization failed: {serialization_error}"
                    );
                }
            }
            ExitCode::FAILURE
        }
    }
}
