use std::fs;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::tempdir;

const VALID_GATEWAY: &str = r#"api_version: oxidase.dev/v1alpha1
kind: gateway
services:
  root:
    type: respond
    body:
      text: ok
listeners:
  - name: public
    bind: 127.0.0.1:0
    protocol: http
    service:
      ref: root
"#;

fn run(directory: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_oxidase"))
        .current_dir(directory)
        .args(arguments)
        .output()
        .expect("oxidase command runs")
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout must contain exactly one JSON value: {error}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn assert_envelope(value: &Value) {
    assert_eq!(value["schema_version"], "oxidase.diagnostics/v1");
    assert!(value["diagnostics"].is_array());
}

#[test]
fn human_and_json_report_the_same_code() {
    let directory = tempdir().expect("temporary directory exists");
    fs::write(
        directory.path().join("oxidase.yaml"),
        "api_version: oxidase.dev/unknown\nkind: gateway\n",
    )
    .expect("invalid config can be written");

    let human = run(directory.path(), &["check", "oxidase.yaml"]);
    assert!(!human.status.success());
    assert!(human.stdout.is_empty());
    let human_stderr = String::from_utf8_lossy(&human.stderr);
    assert!(human_stderr.contains("error[config.api_version]"));

    let machine = run(
        directory.path(),
        &["check", "oxidase.yaml", "--diagnostic-format", "json"],
    );
    assert!(!machine.status.success());
    let value = json(&machine);
    assert_envelope(&value);
    assert!(value["diagnostics"].as_array().is_some_and(|diagnostics| {
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic["code"] == "config.api_version")
    }));
    assert!(!machine.stdout.contains(&0x1b));
}

#[test]
fn missing_config_io_error_is_valid_json_and_nonzero() {
    let directory = tempdir().expect("temporary directory exists");
    let output = run(
        directory.path(),
        &["check", "missing.yaml", "--diagnostic-format=json"],
    );
    assert!(!output.status.success());
    let value = json(&output);
    assert_envelope(&value);
    assert_eq!(value["diagnostics"][0]["code"], "config.read");
    assert_eq!(value["diagnostics"][0]["primary"]["file"], "missing.yaml");
    assert_eq!(value["diagnostics"][0]["primary"]["file_encoding"], "utf-8");
}

#[test]
fn json_diagnostic_order_and_bytes_are_deterministic() {
    let directory = tempdir().expect("temporary directory exists");
    fs::write(
        directory.path().join("oxidase.yaml"),
        "api_version: wrong\nkind: also-wrong\n",
    )
    .expect("invalid config can be written");
    let arguments = ["check", "oxidase.yaml", "--diagnostic-format", "json"];
    let first = run(directory.path(), &arguments);
    let second = run(directory.path(), &arguments);
    assert!(!first.status.success());
    assert!(!second.status.success());
    assert_eq!(first.stdout, second.stdout);
    let value = json(&first);
    let diagnostics = value["diagnostics"]
        .as_array()
        .expect("diagnostics are an array");
    let keys = diagnostics
        .iter()
        .map(|diagnostic| {
            (
                diagnostic["primary"]["start"]["byte"]
                    .as_u64()
                    .unwrap_or_default(),
                diagnostic["code"].as_str().unwrap_or_default(),
            )
        })
        .collect::<Vec<_>>();
    assert!(keys.windows(2).all(|window| window[0] <= window[1]));
}

#[test]
fn compile_output_io_error_is_a_json_diagnostic() {
    let directory = tempdir().expect("temporary directory exists");
    fs::write(directory.path().join("oxidase.yaml"), VALID_GATEWAY).expect("config can be written");
    fs::create_dir(directory.path().join("manifest-dir"))
        .expect("manifest directory can be created");
    let output = run(
        directory.path(),
        &[
            "compile",
            "oxidase.yaml",
            "--output",
            "manifest-dir",
            "--diagnostic-format",
            "json",
        ],
    );
    assert!(!output.status.success());
    let value = json(&output);
    assert_eq!(value["diagnostics"][0]["code"], "compile.output_write");
    assert_eq!(value["diagnostics"][0]["primary"]["file"], "manifest-dir");
}

#[test]
fn declarative_test_mismatch_is_structured_and_nonzero() {
    let directory = tempdir().expect("temporary directory exists");
    let source = format!(
        "{VALID_GATEWAY}\n{}",
        r#"tests:
  - name: passing status
    listener: public
    request:
      host: example.test
      path: /
    expect:
      status: 200

  - name: wrong status
    listener: public
    request:
      host: example.test
      path: /
    expect:
      status: 201
"#
    );
    fs::write(directory.path().join("oxidase.yaml"), source).expect("config can be written");
    let output = run(
        directory.path(),
        &["test", "oxidase.yaml", "--diagnostic-format", "json"],
    );
    assert!(!output.status.success());
    let value = json(&output);
    assert_eq!(value["diagnostics"][0]["code"], "test.expectation_status");
    assert_eq!(value["diagnostics"][0]["primary"]["file"], "oxidase.yaml");
}

#[test]
fn successful_json_check_emits_one_empty_envelope() {
    let directory = tempdir().expect("temporary directory exists");
    fs::write(directory.path().join("oxidase.yaml"), VALID_GATEWAY).expect("config can be written");
    let output = run(
        directory.path(),
        &["check", "oxidase.yaml", "--diagnostic-format", "json"],
    );
    assert!(output.status.success());
    let value = json(&output);
    assert_envelope(&value);
    assert_eq!(value["diagnostics"].as_array().map(Vec::len), Some(0));
}

#[test]
fn explain_failure_honors_json_diagnostic_format() {
    let directory = tempdir().expect("temporary directory exists");
    fs::write(directory.path().join("oxidase.yaml"), VALID_GATEWAY).expect("config can be written");
    fs::write(
        directory.path().join("request.yaml"),
        "host: example.test\npath: /\n",
    )
    .expect("request can be written");
    let output = run(
        directory.path(),
        &[
            "explain",
            "oxidase.yaml",
            "--request",
            "request.yaml",
            "--listener",
            "missing",
            "--diagnostic-format",
            "json",
        ],
    );
    assert!(!output.status.success());
    let value = json(&output);
    assert_eq!(value["diagnostics"][0]["code"], "explain.listener_missing");
}

#[test]
fn serve_bind_failure_keeps_stdout_json_pure() {
    let directory = tempdir().expect("temporary directory exists");
    let occupied = TcpListener::bind("127.0.0.1:0").expect("test port can be reserved");
    let address = occupied.local_addr().expect("reserved port has an address");
    let source = VALID_GATEWAY.replace("127.0.0.1:0", &address.to_string());
    fs::write(directory.path().join("oxidase.yaml"), source).expect("config can be written");
    let output = run(
        directory.path(),
        &["serve", "oxidase.yaml", "--diagnostic-format", "json"],
    );
    assert!(!output.status.success());
    let value = json(&output);
    assert_envelope(&value);
    assert_eq!(value["diagnostics"][0]["code"], "server.listener_bind");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("listener public accepting"));
}
