//! Ordinary CI proof uses the real CLI executable and independent process roles.
//! The CLI is built by workspace tests; a focused soak-only run must first build
//! `cargo build -p oxidase-cli --locked`, or set the explicit test executable.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use std::{io::Write, path::Path};

use serde_json::Value;
use tokio::process::Command;

struct CampaignEvidence(Option<tempfile::TempDir>);

impl CampaignEvidence {
    fn path(&self) -> &Path {
        self.0.as_ref().expect("active evidence directory").path()
    }

    fn keep(&mut self) -> PathBuf {
        self.0.take().expect("active evidence directory").keep()
    }
}

impl Drop for CampaignEvidence {
    fn drop(&mut self) {
        if std::thread::panicking()
            && let Some(directory) = self.0.take()
        {
            let retained = directory.keep();
            // Reporting evidence must not introduce a second panic during
            // timeout/spawn/parse/assertion unwinding.
            let _ = writeln!(
                std::io::stderr(),
                "retained failed campaign evidence at {}",
                retained.display()
            );
        }
    }
}

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
    let mut output = CampaignEvidence(Some(
        tempfile::tempdir().expect("isolated evidence directory"),
    ));
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
    if !result.status.success() {
        // Do not destroy the only concrete fault/cancellation evidence, or mask
        // it behind a missing-success-summary error, when a campaign fails.
        let evidence = std::fs::read(output.path().join("final-evidence.json"))
            .unwrap_or_else(|error| format!("final evidence unavailable: {error}").into_bytes());
        let retained = output.keep();
        panic!(
            "campaign {campaign} failed; retained evidence at {}:\n{}\n{}\n{}",
            retained.display(),
            String::from_utf8_lossy(&result.stderr),
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&evidence)
        );
    }
    let summary =
        std::fs::read(output.path().join("summary.json")).expect("actual campaign receipt");
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
    assert_eq!(
        summary["started_operations"], summary["requests"],
        "every admitted worker operation must have a collected result"
    );
    let accounted = [
        "success",
        "cancelled_responses",
        "expected_unavailable",
        "worker_errors",
    ]
    .into_iter()
    .try_fold(0u64, |total, field| {
        total.checked_add(summary[field].as_u64().expect("worker outcome count"))
    })
    .expect("bounded worker accounting");
    assert_eq!(
        summary["requests"].as_u64(),
        Some(accounted),
        "control-loop Upgrade probes must not enter worker request outcome counts"
    );
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
    assert_eq!(summary["final_sample"]["health_tasks"], 0);
    assert_eq!(summary["final_sample"]["old_snapshots"], 0);
    assert_eq!(summary["final_sample"]["retired_pools"], 0);
    let live_families = summary["final_sample"]["pools"]
        .as_u64()
        .expect("actual Client families are measured, not fabricated null/zero");
    // The current PublishedRuntime and its bounded current registry ownership
    // remain legal after drain. They are not retired body-held Client families.
    assert!(
        live_families <= 2 * 1024,
        "both current registry bounds hold"
    );
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
async fn timeout_and_post_success_assertion_preserve_the_original_evidence() {
    let parent = tempfile::tempdir().expect("isolated retention regression");
    for timeout in [true, false] {
        let directory = tempfile::tempdir_in(parent.path()).expect("child evidence directory");
        let path = directory.path().to_owned();
        std::fs::write(path.join("receipt.json"), br#"{"result":"contradictory"}"#)
            .expect("original fixture evidence");
        let failed = tokio::spawn(async move {
            let evidence = CampaignEvidence(Some(directory));
            if timeout {
                tokio::time::timeout(Duration::from_millis(1), std::future::pending::<()>())
                    .await
                    .expect("bounded campaign timed out before an output existed");
            } else {
                let receipt: Value = serde_json::from_slice(
                    &std::fs::read(evidence.path().join("receipt.json")).expect("receipt"),
                )
                .expect("original JSON");
                assert_eq!(receipt["result"], "pass", "post-success receipt assertion");
            }
        })
        .await
        .expect_err("the boundary must actually panic");
        assert!(failed.is_panic());
        assert_eq!(
            std::fs::read(path.join("receipt.json")).expect("panic retained original bytes"),
            br#"{"result":"contradictory"}"#
        );
    }
    let directory = tempfile::tempdir_in(parent.path()).expect("successful evidence directory");
    let path = directory.path().to_owned();
    drop(CampaignEvidence(Some(directory)));
    assert!(!path.exists(), "successful tests retain no temporary state");
}

#[tokio::test]
async fn address_campaign_uses_actual_gateway_and_cancel_safe_fixture_processes() {
    real_process_campaign("discovery", "600601").await;
}

#[tokio::test]
async fn srv_campaign_qualifies_opaque_grpc_upgrade_and_signed_bundle_publication() {
    real_process_campaign("protocol", "600602").await;
}
