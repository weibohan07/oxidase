//! Ordinary CI proof uses the real CLI executable and independent process roles.
//! The CLI is built by workspace tests; a focused soak-only run must first build
//! `cargo build -p oxidase-cli --locked`, or set the explicit test executable.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use serde_json::Value;
use tokio::process::Command;

fn gateway() -> PathBuf {
    let path = std::env::var_os("OXIDASE_DISCOVERY_TEST_GATEWAY").map_or_else(
        || {
            std::env::current_exe()
                .expect("test executable")
                .parent()
                .expect("deps directory")
                .parent()
                .expect("target directory")
                .join("oxidase")
        },
        PathBuf::from,
    );
    assert!(
        path.is_file(),
        "real CLI executable missing at {}; build oxidase-cli before a focused soak-only test",
        path.display()
    );
    path
}

async fn real_process_campaign(campaign: &str, seed: &str) {
    let output = tempfile::tempdir().expect("isolated evidence directory");
    let command = Command::new(env!("CARGO_BIN_EXE_oxidase-discovery-soak"))
        .arg("run")
        .arg("--gateway")
        .arg(gateway())
        .args([
            "--campaign",
            campaign,
            "--duration",
            "3s",
            "--concurrency",
            "2",
            "--seed",
            seed,
            "--reload-interval",
            "400ms",
            "--warm-up",
            "500ms",
            "--cooldown",
            "500ms",
            "--sample-interval",
            "200ms",
            "--payload-size",
            "4096",
            "--output",
        ])
        .arg(output.path())
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .output();
    let result = tokio::time::timeout(Duration::from_secs(60), command)
        .await
        .expect("bounded campaign")
        .expect("real process spawn");
    let summary =
        std::fs::read(output.path().join("summary.json")).expect("actual campaign receipt");
    assert!(
        result.status.success(),
        "campaign {campaign} failed:\n{}\n{}\n{}",
        String::from_utf8_lossy(&result.stderr),
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&summary)
    );
    let summary: Value = serde_json::from_slice(&summary).expect("valid JSON receipt");
    assert_eq!(summary["result"], "pass");
    let mut pids = ["gateway", "generator", "dns", "upstream"]
        .map(|name| summary["pids"][name].as_u64().expect("actual child PID"));
    pids.sort_unstable();
    assert!(
        pids.windows(2).all(|ids| ids[0] != ids[1]),
        "process roles must be separate"
    );
    assert!(summary["success"].as_u64().expect("completed responses") > 0);
    assert!(
        summary["cancelled_responses"]
            .as_u64()
            .expect("partial cancelled responses")
            > 0
    );
    assert_eq!(summary["unexpected_errors"], 0);
    assert_eq!(summary["upstream"]["request_faults"], 0);
    assert_eq!(
        summary["retained_stream_proof"]["opaque_grpc_bytes_verified"],
        true
    );
    assert_eq!(
        summary["retained_stream_proof"]["grpc_status_trailer"],
        true
    );
    assert_eq!(
        summary["retained_stream_proof"]["successful_new_b_streams"],
        8
    );
    assert_eq!(
        summary["retained_stream_proof"]["gateway_cancelled_termination_delta"],
        1
    );
    assert_eq!(
        summary["retained_stream_proof"]["upgrade_across_withdrawal_and_publication"],
        true
    );
    assert_eq!(summary["drained_runtime"]["serving_state"], "drained");
    assert_eq!(summary["final_sample"]["discovery_tasks"], 0);
    assert_eq!(summary["final_sample"]["cluster_permits"], 0);
    assert_eq!(summary["final_sample"]["retry_permits"], 0);
    assert_eq!(summary["final_sample"]["health_tasks"], Value::Null);
    assert_eq!(summary["final_sample"]["pools"], Value::Null);
    assert!(
        std::fs::metadata(output.path().join("metrics-samples.jsonl"))
            .expect("raw PID-scoped scrapes")
            .len()
            > 0
    );
    if campaign == "protocol" {
        assert!(
            summary["grpc_completed"]
                .as_u64()
                .expect("complete opaque gRPC calls")
                > 0
        );
    }
    assert_eq!(summary["gateway_exited"], true);
    assert_eq!(summary["post_exit_rss"], Value::Null);
}

#[tokio::test]
async fn address_campaign_uses_actual_gateway_and_cancel_safe_fixture_processes() {
    real_process_campaign("discovery", "600601").await;
}

#[tokio::test]
async fn srv_campaign_qualifies_opaque_grpc_upgrade_and_signed_bundle_publication() {
    real_process_campaign("protocol", "600602").await;
}
