//! Linux implementation smoke: actual independent PIDs, raw HTTP/trailers,
//! five phases and independent replay. This does not qualify hour-scale memory.
#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use serde_json::Value;
use tokio::process::Command;

struct Evidence(Option<tempfile::TempDir>);
impl Evidence {
    fn create() -> Self {
        let directory = if let Some(root) = std::env::var_os("OXIDASE_RESOURCE_TEST_ARTIFACTS") {
            std::fs::create_dir_all(&root).expect("public failure artifact root");
            tempfile::Builder::new()
                .prefix("resource-7a-smoke-")
                .tempdir_in(root)
                .expect("isolated public evidence")
        } else {
            tempfile::tempdir().expect("private evidence")
        };
        Self(Some(directory))
    }
    fn path(&self) -> &std::path::Path {
        self.0.as_ref().expect("active evidence").path()
    }
    fn keep(&mut self) -> PathBuf {
        self.0.take().expect("active evidence").keep()
    }
}
impl Drop for Evidence {
    fn drop(&mut self) {
        if std::thread::panicking()
            && let Some(directory) = self.0.take()
        {
            use std::io::Write as _;
            let path = directory.keep();
            let _ = writeln!(
                std::io::stderr(),
                "retained original resource smoke evidence {}",
                path.display()
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
                .expect("deps")
                .parent()
                .expect("target")
                .join("oxidase")
        },
        PathBuf::from,
    );
    assert!(
        path.is_file(),
        "build the real oxidase-cli before a focused soak-only test"
    );
    path
}

#[tokio::test]
async fn healthy_resource_run_preserves_raw_evidence_and_independent_replay() {
    let mut directory = Evidence::create();
    let output = directory.path().join("campaign");
    let build = directory.path().join("build-record.json");
    let executable = env!("CARGO_BIN_EXE_oxidase-discovery-soak");
    let record = Command::new(executable)
        .arg("resource-build-record")
        .arg("--gateway")
        .arg(gateway())
        .arg("--output")
        .arg(&build)
        .output()
        .await
        .expect("build identity record");
    assert!(
        record.status.success(),
        "{}",
        String::from_utf8_lossy(&record.stderr)
    );
    let run = tokio::time::timeout(
        Duration::from_secs(120),
        Command::new(executable)
            .arg("resource-run")
            .arg("--gateway")
            .arg(gateway())
            .arg("--build-record")
            .arg(&build)
            .args([
                "--campaign",
                "healthy",
                "--duration",
                "4s",
                "--warm-up",
                "3s",
                "--recovery-running",
                "3s",
                "--quiet-running",
                "2s",
                "--post-drain",
                "2s",
                "--concurrency",
                "4",
                "--sample-interval-ms",
                "200",
                "--scrape-interval-ms",
                "200",
                "--payload-size",
                "32768",
                "--upload-size",
                "65536",
                "--seed",
                "700209",
                "--output",
            ])
            .arg(&output)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("bounded real campaign")
    .expect("campaign process");
    if !run.status.success() {
        let retained = directory.keep();
        panic!(
            "real campaign failed; original evidence {}\n{}\n{}",
            retained.display(),
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
    }
    let receipt: Value =
        serde_json::from_slice(&std::fs::read(output.join("receipt.json")).expect("receipt"))
            .expect("receipt JSON");
    assert_eq!(receipt["complete"], true);
    assert_eq!(
        receipt["final_counts"]["offered"],
        receipt["final_counts"]["received_operations"]
    );
    assert!(
        receipt["final_counts"]["admitted_http_operations"]
            .as_u64()
            .expect("real HTTP denominator")
            > 8
    );
    let analyzer = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/qualification/verify_resource_lifecycle.py");
    let replay = Command::new("python3")
        .arg(analyzer)
        .arg(&output)
        .output()
        .await
        .expect("independent replay");
    let report: Value = serde_json::from_slice(&replay.stdout).expect("legal independent JSON");
    assert_eq!(report["schema_version"], "oxidase.resource-analysis/v1");
    assert!(
        matches!(
            report["result"].as_str(),
            Some("PASS_IMPLEMENTATION" | "INCONCLUSIVE" | "FAIL")
        ),
        "unknown analyzer result"
    );
    // The oracle may honestly leave positive RSS drift/short duration
    // INCONCLUSIVE. Any factual failure remains a failing implementation smoke.
    if report["result"] == "FAIL" {
        let retained = directory.keep();
        panic!(
            "independent replay rejects raw evidence {}\n{}",
            retained.display(),
            String::from_utf8_lossy(&replay.stdout)
        );
    }
    assert!(
        report["counts"]["completed_success"]
            .as_u64()
            .expect("actual complete response")
            > 8
    );
    if report["result"] == "INCONCLUSIVE" {
        assert_eq!(replay.status.code(), Some(2));
        assert!(
            report["findings"]
                .as_array()
                .expect("explicit inconclusive reason")
                .iter()
                .any(|row| row["result"] == "INCONCLUSIVE")
        );
    } else {
        assert!(replay.status.success());
        assert_eq!(report["result"], "PASS_IMPLEMENTATION");
    }
}
