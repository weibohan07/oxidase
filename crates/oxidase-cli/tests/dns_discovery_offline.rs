//! Actual CLI policy validation must not depend on a DNS service being available.

use std::fs;
use std::io::ErrorKind;
use std::net::{TcpListener, UdpSocket};
use std::process::{Command, Output};

use oxidase_bundle::{BundleArchive, BundleBuilder, BundleLimits};
use serde_json::Value;
use tempfile::tempdir;

fn execute(root: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_oxidase"))
        .current_dir(root)
        .args(["--diagnostic-format", "json"])
        .args(args)
        .output()
        .expect("actual CLI process executes")
}

#[test]
fn actual_check_bundle_build_and_verify_are_offline_and_do_not_query_dns() {
    // Reserve a DNS-shaped ephemeral address without implementing a DNS server.
    // Any attempted UDP query remains observable; any TCP fallback is accepted
    // only by the test's final nonblocking inspection, never answered.
    let udp = UdpSocket::bind("127.0.0.1:0").expect("local DNS observation socket");
    let address = udp.local_addr().expect("ephemeral DNS address");
    let tcp = TcpListener::bind(address).expect("matching TCP observation socket");
    udp.set_nonblocking(true)
        .expect("nonblocking UDP inspection");
    tcp.set_nonblocking(true)
        .expect("nonblocking TCP inspection");
    let directory = tempdir().expect("deployment root");
    fs::write(directory.path().join("oxidase.yaml"), format!(
        "api_version: oxidase.dev/v1alpha1\nkind: gateway\nresources:\n  clusters:\n    api:\n      discovery:\n        dns:\n          name: unreachable.example.test\n          port: 8443\n          origin: http://fixed-origin.example.test/base/\n          resolver:\n            nameservers: [\"{address}\"]\nservices:\n  root:\n    type: respond\n    body:\n      text: ready\nlisteners:\n  - name: public\n    bind: 127.0.0.1:0\n    service:\n      ref: root\n"
    )).expect("offline source writes");
    let root = directory.path().to_str().expect("UTF-8 deployment root");
    for args in [
        vec!["check", "oxidase.yaml"],
        vec![
            "bundle",
            "build",
            "oxidase.yaml",
            "--output",
            "gateway.oxb",
            "--deployment-root",
            root,
        ],
        vec!["bundle", "verify", "gateway.oxb", "--deployment-root", root],
    ] {
        let output = execute(directory.path(), &args);
        assert!(
            output.status.success(),
            "{args:?}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value =
            serde_json::from_slice(&output.stdout).expect("one valid CLI JSON document");
        if let Some(diagnostics) = value.get("diagnostics") {
            assert_eq!(diagnostics.as_array().map(Vec::len), Some(0));
        }
        let mut bytes = [0; 512];
        assert!(
            matches!(udp.recv_from(&mut bytes), Err(error) if error.kind() == ErrorKind::WouldBlock),
            "{args:?} sent a DNS datagram"
        );
        assert!(
            matches!(tcp.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock),
            "{args:?} attempted DNS TCP fallback"
        );
    }
    let archive = BundleArchive::read_path(
        directory.path().join("gateway.oxb"),
        &BundleLimits::default(),
    )
    .expect("real CLI-produced Bundle");
    for feature in [
        oxidase_config::DNS_ADDRESS_DISCOVERY_FEATURE,
        oxidase_config::UPSTREAM_DEADLINES_FEATURE,
    ] {
        assert!(archive.manifest().required_features.contains(feature));
    }
    let plan: oxidase_runtime::PortableRuntimePlanV1 = archive.manifest().sections["runtime"]
        .to_serde()
        .expect("static portable policy");
    let cluster = &plan.gateway.clusters["cluster:api"];
    assert!(cluster.endpoints.is_empty());
    assert!(cluster.timeouts.is_some());
    let policy = serde_json::to_value(&cluster.discovery).expect("portable DNS policy JSON");
    for field in ["answers", "addresses", "generation", "expires_at", "health"] {
        assert!(policy.get(field).is_none());
    }
    for feature in [
        oxidase_config::DNS_ADDRESS_DISCOVERY_FEATURE,
        oxidase_config::UPSTREAM_DEADLINES_FEATURE,
    ] {
        let mut manifest = archive.manifest().clone();
        manifest.required_features.remove(feature);
        let filename = format!("missing-{feature}.oxb");
        BundleBuilder::new(manifest)
            .write_atomic(directory.path().join(&filename))
            .expect("undeclared capability fixture");
        let output = execute(
            directory.path(),
            &["bundle", "verify", &filename, "--deployment-root", root],
        );
        assert!(
            !output.status.success(),
            "{feature} cannot be silently omitted"
        );
        let json: Value =
            serde_json::from_slice(&output.stdout).expect("capability error is valid JSON");
        assert_eq!(
            json["diagnostics"][0]["code"],
            "bundle.required_feature_missing"
        );
        let mut bytes = [0; 512];
        assert!(
            matches!(udp.recv_from(&mut bytes), Err(error) if error.kind() == ErrorKind::WouldBlock)
        );
        assert!(matches!(tcp.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock));
    }
}
