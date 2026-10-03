//! Actual CLI commands against the real server, signed Bundles, and local storage.

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use bytes::Bytes;
use http::{Request, header};
use http_body_util::{BodyExt as _, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use oxidase_config::Compiler;
use oxidase_runtime::RuntimeSnapshot;
use oxidase_server::{GatewayServer, RunningServer};
use serde_json::Value;
use tempfile::{TempDir, tempdir};
use tokio::net::TcpStream;

struct Demo {
    _directory: TempDir,
    root: PathBuf,
    token: PathBuf,
    socket: PathBuf,
    signing_key: PathBuf,
    address: std::net::SocketAddr,
    running: RunningServer,
}

fn data_source(label: &str) -> String {
    format!(
        "api_version: oxidase.dev/v1alpha1\nkind: gateway\nservices:\n  root:\n    type: respond\n    body:\n      text: {label}\nlisteners:\n  - name: public\n    bind: 127.0.0.1:0\n    protocol: http\n    service:\n      ref: root\n"
    )
}

impl Demo {
    async fn start(read: bool) -> Self {
        let directory = tempdir().expect("temporary demo deployment");
        let root = directory
            .path()
            .canonicalize()
            .expect("canonical demo root");
        let signing_key = root.join("test-only-signing-key");
        fs::write(&signing_key, [31; 32]).expect("test-only signing seed");
        let signing =
            oxidase_bundle::BundleSigningKey::read_file(&signing_key).expect("test-only signer");
        fs::write(
            root.join("operator.pub"),
            signing.verification_key().as_bytes(),
        )
        .expect("public verification material");
        let token = root.join("admin.token");
        fs::write(&token, b"test-only-ctl-demo-token\n").expect("test-only LF token");
        let socket = root.join("admin.sock");
        let source = format!(
            "{}resources:\n  secrets:\n    admin-token:\n      file: admin.token\nadmin:\n  listen:\n    unix:\n      path: {}\n      mode: \"0600\"\n  auth:\n    mode: bearer\n    token_secret: admin-token\n  storage:\n    directory: {}\n  bundle_trust:\n    verification_keys: [operator.pub]\n  permissions:\n    read: {read}\n    stage: true\n    activate: true\n    rollback: true\n    drain: true\n    reload_source: true\n  audit:\n    destination: file\n    file: {}\n",
            data_source("initial"),
            socket.display(),
            root.join("state").display(),
            root.join("audit.jsonl").display()
        );
        let config = root.join("oxidase.yaml");
        fs::write(&config, source).expect("demo source written");
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("demo source compiles"),
        )
        .expect("demo snapshot prepares");
        let server = GatewayServer::bind(snapshot)
            .await
            .expect("real gateway binds");
        let address = server.local_addresses()[0].1;
        Self {
            _directory: directory,
            root,
            token,
            socket,
            signing_key,
            address,
            running: server.spawn(),
        }
    }

    fn ctl_args(&self, operation: &[String], etag: Option<&str>, key: Option<&str>) -> Vec<String> {
        let mut args = vec![
            "ctl".to_owned(),
            "--unix".to_owned(),
            self.socket
                .to_str()
                .expect("UTF-8 fixture socket")
                .to_owned(),
            "--token-file".to_owned(),
            self.token.to_str().expect("UTF-8 token path").to_owned(),
            "--connect-timeout".to_owned(),
            "2s".to_owned(),
            "--timeout".to_owned(),
            "5s".to_owned(),
        ];
        if let Some(etag) = etag {
            args.extend(["--if-match".to_owned(), etag.to_owned()]);
        }
        if let Some(key) = key {
            args.extend(["--idempotency-key".to_owned(), key.to_owned()]);
        }
        args.extend_from_slice(operation);
        args
    }

    async fn ctl(&self, operation: &[String]) -> Value {
        cli_json(self.ctl_args(operation, None, None)).await
    }

    async fn bundle(&self, label: &str) -> (PathBuf, String) {
        let source = self.root.join(format!("{label}.yaml"));
        let output = self.root.join(format!("{label}.oxb"));
        fs::write(&source, data_source(label)).expect("candidate source");
        let result = cli_json(vec![
            "bundle".to_owned(),
            "build".to_owned(),
            utf8(&source),
            "--output".to_owned(),
            utf8(&output),
            "--deployment-root".to_owned(),
            utf8(&self.root),
        ])
        .await;
        let digest = result["content_digest"]
            .as_str()
            .expect("build output has digest")
            .to_owned();
        cli_json(vec![
            "bundle".to_owned(),
            "sign".to_owned(),
            utf8(&output),
            "--key".to_owned(),
            utf8(&self.signing_key),
        ])
        .await;
        (output, digest)
    }

    async fn body(&self) -> Bytes {
        let tcp = TcpStream::connect(self.address)
            .await
            .expect("data listener connects");
        let (mut sender, connection) = http1::handshake(TokioIo::new(tcp))
            .await
            .expect("data HTTP handshake");
        let driver = tokio::spawn(connection);
        let response = sender
            .send_request(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, "test.example")
                    .body(Full::new(Bytes::new()))
                    .expect("data request"),
            )
            .await
            .expect("data response");
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("data body")
            .to_bytes();
        drop(sender);
        driver.abort();
        let _ = driver.await;
        bytes
    }
}

fn utf8(path: &Path) -> String {
    path.to_str().expect("UTF-8 fixture path").to_owned()
}

async fn cli_json(args: Vec<String>) -> Value {
    let description = args.first().cloned().unwrap_or_default();
    let output = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_oxidase"))
            .arg("--diagnostic-format")
            .arg("json")
            .args(args)
            .output()
            .expect("actual CLI process runs")
    })
    .await
    .expect("CLI process joins");
    assert!(
        output.status.success(),
        "{description} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("test-only-ctl-demo-token"));
    serde_json::from_slice(&output.stdout).expect("actual CLI stdout is one JSON document")
}

#[tokio::test]
async fn actual_ctl_demo_build_sign_stage_validate_activate_history_rollback_operation_and_drain() {
    let demo = Demo::start(true).await;
    let status = demo.ctl(&["status".to_owned()]).await;
    assert_eq!(status["origin"]["kind"], "source");
    let (a_file, a) = demo.bundle("A").await;
    let (b_file, b) = demo.bundle("B").await;
    for (file, digest) in [(&a_file, &a), (&b_file, &b)] {
        demo.ctl(&["stage".to_owned(), utf8(file)]).await;
        demo.ctl(&["validate".to_owned(), digest.clone()]).await;
    }
    let activation = demo.ctl(&["activate".to_owned(), a.clone()]).await;
    assert_eq!(demo.body().await, "A");
    let operation = activation["operation_id"]
        .as_str()
        .expect("activation operation ID");
    let receipt = demo
        .ctl(&[
            "operation".to_owned(),
            "status".to_owned(),
            operation.to_owned(),
        ])
        .await;
    assert_eq!(receipt["operation"]["phase"], "committed");
    demo.ctl(&["activate".to_owned(), b.clone()]).await;
    assert_eq!(demo.body().await, "B");
    let history = demo.ctl(&["history".to_owned()]).await;
    assert!(
        history["history"]
            .as_array()
            .expect("retained history")
            .iter()
            .any(|entry| entry["digest"] == a)
    );
    demo.ctl(&["rollback".to_owned(), a.clone()]).await;
    assert_eq!(demo.body().await, "A");
    demo.ctl(&["reload-source".to_owned()]).await;
    assert_eq!(demo.body().await, "initial");
    demo.ctl(&["drain".to_owned()]).await;
    let status = demo.ctl(&["status".to_owned()]).await;
    assert_eq!(status["serving_state"], "drained");
    println!(
        "actual ctl demo verified: Bundle build/sign, stage/validate, A/B activation, history, rollback, operation query, reload-source, drain"
    );
    demo.running.shutdown().await.expect("demo shutdown");
}

#[tokio::test]
async fn actual_ctl_explicit_revision_mutates_real_server_with_no_read_permission() {
    let demo = Demo::start(false).await;
    let (file, digest) = demo.bundle("A").await;
    let etag = demo.running.reload_handle().published_runtime().etag();
    for (operation, key) in [
        (vec!["stage".to_owned(), utf8(&file)], "readless-stage"),
        (
            vec!["validate".to_owned(), digest.clone()],
            "readless-validate",
        ),
        (
            vec!["activate".to_owned(), digest.clone()],
            "readless-activate",
        ),
    ] {
        cli_json(demo.ctl_args(&operation, Some(&etag), Some(key))).await;
    }
    assert_eq!(demo.body().await, "A");
    let current = demo.running.reload_handle().published_runtime().etag();
    cli_json(demo.ctl_args(
        &["drain".to_owned()],
        Some(&current),
        Some("readless-drain"),
    ))
    .await;
    assert_eq!(
        demo.running
            .reload_handle()
            .published_runtime()
            .serving_state,
        oxidase_runtime::ServingState::Drained
    );
    demo.running
        .shutdown()
        .await
        .expect("readless demo shutdown");
}
