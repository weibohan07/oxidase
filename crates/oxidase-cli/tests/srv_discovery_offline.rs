//! Actual SRV CLI preparation is offline, including signed/source-free Bundles.

use std::fs;
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::path::Path;
use std::process::{Command, Output};

use oxidase_bundle::{BundleArchive, BundleBuilder, BundleLimits, BundleSigningKey};
use serde_json::Value;
use tempfile::tempdir;

struct DnsObservation {
    udp: UdpSocket,
    tcp: TcpListener,
    address: SocketAddr,
}

impl DnsObservation {
    fn bind() -> Self {
        // The socket observes queries but never returns DNS data. If a randomly
        // chosen UDP port is already occupied for TCP, choose another ephemeral
        // pair rather than relying on any fixed open test port.
        for _ in 0..16 {
            let udp = UdpSocket::bind("127.0.0.1:0").expect("local UDP observation socket");
            let address = udp.local_addr().expect("ephemeral port");
            let Ok(tcp) = TcpListener::bind(address) else {
                continue;
            };
            udp.set_nonblocking(true).expect("UDP observation");
            tcp.set_nonblocking(true).expect("TCP observation");
            return Self { udp, tcp, address };
        }
        panic!("no ephemeral UDP/TCP observation pair available");
    }

    fn assert_no_query(&self, operation: &[&str]) {
        let mut buffer = [0; 4096];
        assert!(
            matches!(self.udp.recv_from(&mut buffer), Err(error) if error.kind() == ErrorKind::WouldBlock),
            "{operation:?} sent a DNS datagram during static preparation"
        );
        assert!(
            matches!(self.tcp.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock),
            "{operation:?} opened a DNS TCP connection during static preparation"
        );
    }

    fn execute(&self, root: &Path, args: &[&str]) -> Output {
        let output = Command::new(env!("CARGO_BIN_EXE_oxidase"))
            .current_dir(root)
            .args(["--diagnostic-format", "json"])
            .args(args)
            .output()
            .expect("actual CLI process");
        self.assert_no_query(args);
        output
    }

    fn success(&self, root: &Path, args: &[&str]) -> Value {
        let output = self.execute(root, args);
        assert!(
            output.status.success(),
            "{args:?}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stdout.contains(&0x1b), "JSON has no ANSI");
        serde_json::from_slice(&output.stdout).expect("one valid CLI JSON document")
    }
}

fn gateway(address: SocketAddr) -> String {
    format!(
        "api_version: oxidase.dev/v1alpha1\nkind: gateway\nresources:\n  clusters:\n    api:\n      discovery:\n        dns:\n          name: _HTTPS._TCP.UNREACHABLE.EXAMPLE.TEST.\n          record: srv\n          origin: http://fixed-origin.example.test:8080/base/\n          resolver:\n            nameservers: [\"{address}\"]\nservices:\n  root:\n    type: respond\n    body:\n      text: ready\nlisteners:\n  - name: public\n    bind: 127.0.0.1:0\n    service:\n      ref: root\n"
    )
}

fn test_only_keys(root: &Path) {
    // Publicly known deterministic seed, exclusively for test fixtures.
    let private = root.join("test-only-signing-key");
    fs::write(&private, [31; 32]).expect("test-only key");
    let signer = BundleSigningKey::read_file(private).expect("test signer");
    fs::write(
        root.join("operator.pub"),
        signer.verification_key().as_bytes(),
    )
    .expect("public key");
    let other =
        BundleSigningKey::from_bytes("wrong-test-key", &[32; 32]).expect("different test signer");
    fs::write(
        root.join("wrong-operator.pub"),
        other.verification_key().as_bytes(),
    )
    .expect("untrusted public key");
}

#[test]
fn actual_explain_describes_both_discovery_policies_and_phased_budget_without_dns() {
    let observation = DnsObservation::bind();
    let directory = tempdir().expect("offline explain root");
    fs::write(
        directory.path().join("request.yaml"),
        "method: GET\nscheme: http\nhost: public.example.test\npath: /data?b=2&a=1&a=3\n",
    )
    .expect("symbolic request");
    for record in ["srv", "a_aaaa"] {
        let mut source = gateway(observation.address).replace(
            "type: respond\n    body:\n      text: ready",
            "type: proxy\n    cluster: api",
        );
        if record == "a_aaaa" {
            source = source
                .replace(
                    "_HTTPS._TCP.UNREACHABLE.EXAMPLE.TEST.",
                    "UNREACHABLE.EXAMPLE.TEST.",
                )
                .replace("record: srv", "record: a_aaaa\n          port: 8444");
        }
        fs::write(directory.path().join("oxidase.yaml"), source).expect("offline policy");
        let output = observation.success(
            directory.path(),
            &["explain", "oxidase.yaml", "--request", "request.yaml"],
        );
        let cluster = &output["body"]["cluster"];
        assert_eq!(cluster["endpoint_count"], 0);
        assert_eq!(cluster["discovery"]["record"], record);
        assert_eq!(
            cluster["discovery"]["origin"],
            "http://fixed-origin.example.test:8080/base/"
        );
        assert_eq!(cluster["discovery"]["resolver_source"], "nameservers");
        assert_eq!(
            cluster["discovery"]["address_policy"]["allow_loopback"],
            false
        );
        assert_eq!(
            cluster["discovery"]["observed_addresses"],
            "not resolved by offline explain"
        );
        assert_eq!(cluster["timing"]["mode"], "phased");
        assert_eq!(cluster["timing"]["retries_share_total"], true);
        for phase in [
            "connect_seconds",
            "tls_handshake_seconds",
            "request_body_idle_seconds",
            "response_header_seconds",
            "response_body_idle_seconds",
            "pre_response_total_seconds",
        ] {
            assert!(
                cluster["timing"][phase]
                    .as_f64()
                    .is_some_and(|value| value > 0.)
            );
        }
        assert_eq!(
            cluster["discovery"].get("port").and_then(Value::as_u64),
            (record == "a_aaaa").then_some(8444)
        );
        assert_eq!(
            cluster["endpoint_selection"],
            "actual endpoint selection is runtime state dependent"
        );
        for field in ["generation", "answers", "expires_at"] {
            assert!(cluster["discovery"].get(field).is_none());
        }
    }
}

#[test]
fn actual_srv_check_build_sign_and_source_free_verify_never_query_dns() {
    let observation = DnsObservation::bind();
    let directory = tempdir().expect("deployment root");
    let root = directory.path().to_str().expect("UTF-8 fixture root");
    let source = directory.path().join("oxidase.yaml");
    fs::write(&source, gateway(observation.address)).expect("SRV source");
    test_only_keys(directory.path());
    let check = observation.success(directory.path(), &["check", "oxidase.yaml"]);
    assert_eq!(check["schema_version"], "oxidase.diagnostics/v1");
    assert_eq!(check["diagnostics"].as_array().map(Vec::len), Some(0));
    let built = observation.success(
        directory.path(),
        &[
            "bundle",
            "build",
            "oxidase.yaml",
            "--output",
            "gateway.oxb",
            "--deployment-root",
            root,
        ],
    );
    observation.success(
        directory.path(),
        &[
            "bundle",
            "sign",
            "gateway.oxb",
            "--key",
            "test-only-signing-key",
        ],
    );
    let archive = BundleArchive::read_path(
        directory.path().join("gateway.oxb"),
        &BundleLimits::default(),
    )
    .expect("CLI-produced Bundle");
    assert_eq!(archive.signatures().signatures.len(), 1);
    assert_eq!(
        built["content_digest"],
        archive.content_digest().to_string()
    );
    for feature in [
        oxidase_config::DNS_SRV_DISCOVERY_FEATURE,
        oxidase_config::DNS_ADDRESS_DISCOVERY_FEATURE,
        oxidase_config::UPSTREAM_DEADLINES_FEATURE,
    ] {
        assert!(
            archive.manifest().required_features.contains(feature),
            "{feature}"
        );
    }
    let plan: oxidase_runtime::PortableRuntimePlanV1 = archive.manifest().sections["runtime"]
        .to_serde()
        .expect("source-free runtime plan");
    let cluster = &plan.gateway.clusters["cluster:api"];
    assert!(cluster.endpoints.is_empty());
    assert!(cluster.timeouts.is_some());
    let dns = cluster.discovery.as_ref().expect("SRV policy");
    assert_eq!(dns.record, "srv");
    assert_eq!(dns.name, "_https._tcp.unreachable.example.test.");
    assert_eq!(dns.port, None);
    assert_eq!(dns.origin, "http://fixed-origin.example.test:8080/base/");
    let policy = serde_json::to_value(dns).expect("static policy JSON");
    for field in [
        "port",
        "answers",
        "addresses",
        "priority",
        "weight",
        "generation",
        "expires_at",
        "health",
    ] {
        assert!(policy.get(field).is_none(), "no runtime {field}");
    }

    // Prove the actual verify command no longer has Gateway source to reopen.
    fs::remove_file(&source).expect("remove only this test-owned source fixture");
    let verified = observation.success(
        directory.path(),
        &[
            "bundle",
            "verify",
            "gateway.oxb",
            "--key",
            "operator.pub",
            "--deployment-root",
            root,
        ],
    );
    assert_eq!(
        verified["content_digest"],
        archive.content_digest().to_string()
    );
    assert_eq!(
        verified["verified_key_ids"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(verified["untrusted_signature_count"], 0);

    let rejected = observation.execute(
        directory.path(),
        &[
            "bundle",
            "verify",
            "gateway.oxb",
            "--key",
            "wrong-operator.pub",
            "--deployment-root",
            root,
        ],
    );
    assert!(
        !rejected.status.success(),
        "wrong signing key cannot authorize the plan"
    );
    let error: Value =
        serde_json::from_slice(&rejected.stdout).expect("safe signature diagnostic JSON");
    assert_eq!(
        error["diagnostics"][0]["code"],
        "bundle.signature_verification_failed"
    );
}

#[test]
fn actual_signed_srv_bundle_cannot_strip_any_behavioral_capability() {
    let observation = DnsObservation::bind();
    let directory = tempdir().expect("deployment root");
    let root = directory.path().to_str().expect("UTF-8 fixture root");
    fs::write(
        directory.path().join("oxidase.yaml"),
        gateway(observation.address),
    )
    .expect("SRV source");
    test_only_keys(directory.path());
    observation.success(
        directory.path(),
        &[
            "bundle",
            "build",
            "oxidase.yaml",
            "--output",
            "gateway.oxb",
            "--deployment-root",
            root,
        ],
    );
    let archive = BundleArchive::read_path(
        directory.path().join("gateway.oxb"),
        &BundleLimits::default(),
    )
    .expect("CLI-produced Bundle");
    fs::remove_file(directory.path().join("oxidase.yaml")).expect("remove test-owned source");
    for feature in [
        oxidase_config::DNS_SRV_DISCOVERY_FEATURE,
        oxidase_config::DNS_ADDRESS_DISCOVERY_FEATURE,
        oxidase_config::UPSTREAM_DEADLINES_FEATURE,
    ] {
        let mut manifest = archive.manifest().clone();
        manifest.required_features.remove(feature);
        let filename = format!("stripped-{feature}.oxb");
        BundleBuilder::new(manifest)
            .write_atomic(directory.path().join(&filename))
            .expect("well-formed capability-stripped fixture");
        observation.success(
            directory.path(),
            &[
                "bundle",
                "sign",
                &filename,
                "--key",
                "test-only-signing-key",
            ],
        );
        let stripped =
            BundleArchive::read_path(directory.path().join(&filename), &BundleLimits::default())
                .expect("signed fixture");
        assert_eq!(stripped.signatures().signatures.len(), 1);
        let output = observation.execute(
            directory.path(),
            &[
                "bundle",
                "verify",
                &filename,
                "--key",
                "operator.pub",
                "--deployment-root",
                root,
            ],
        );
        assert!(
            !output.status.success(),
            "valid signature must not conceal omitted {feature}"
        );
        let error: Value =
            serde_json::from_slice(&output.stdout).expect("capability diagnostic JSON");
        assert_eq!(error["schema_version"], "oxidase.diagnostics/v1");
        assert_eq!(
            error["diagnostics"][0]["code"],
            "bundle.required_feature_missing"
        );
        assert!(
            error["diagnostics"][0]["message"]
                .as_str()
                .expect("message")
                .contains(feature)
        );
    }
}
