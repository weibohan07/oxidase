//! Real `oxidase ctl` processes against local authenticated HTTP fixtures.

#![cfg(unix)]

use std::convert::Infallible;
use std::process::Command;

use bytes::Bytes;
use http::{Request, Response, StatusCode, header};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tempfile::tempdir;
use tokio::net::UnixListener;

#[tokio::test]
async fn explicit_revision_allows_ctl_mutation_without_read_permission() {
    let directory = tempdir().expect("temporary socket/token");
    let socket = directory.path().join("admin.sock");
    let token = directory.path().join("token");
    std::fs::write(&token, b"test-only-token\r\n").expect("test-only token written");
    let listener = UnixListener::bind(&socket).expect("fixture socket binds");
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("ctl connects");
        let service = service_fn(|request: Request<Incoming>| async {
            assert_eq!(
                request.method(),
                http::Method::POST,
                "the operator has no read permission"
            );
            assert_eq!(request.uri().path(), "/api/v1/drain");
            assert_eq!(
                request.headers()[header::AUTHORIZATION],
                "Bearer test-only-token"
            );
            assert_eq!(request.headers()[header::IF_MATCH], "\"runtime-test-9\"");
            assert_eq!(request.headers()["idempotency-key"], "controlled-receipt");
            assert_eq!(
                request
                    .into_body()
                    .collect()
                    .await
                    .expect("body")
                    .to_bytes(),
                b"{}".as_slice()
            );
            Ok::<_, Infallible>(Response::builder().status(StatusCode::ACCEPTED).header(header::CONTENT_TYPE, "application/json").body(Full::new(Bytes::from_static(b"{\"schema_version\":\"oxidase.admin/v1\",\"operation_id\":\"operation-test\",\"status\":\"accepted\"}"))).expect("response"))
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });
    let output = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_oxidase"))
            .arg("--diagnostic-format")
            .arg("json")
            .arg("ctl")
            .arg("--unix")
            .arg(socket)
            .arg("--token-file")
            .arg(token)
            .arg("--if-match")
            .arg("\"runtime-test-9\"")
            .arg("--idempotency-key")
            .arg("controlled-receipt")
            .arg("--connect-timeout")
            .arg("1s")
            .arg("--timeout")
            .arg("2s")
            .arg("drain")
            .output()
            .expect("ctl process executes")
    })
    .await
    .expect("process joins");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("ctl JSON stdout is one valid document");
    assert_eq!(json["operation_id"], "operation-test");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("test-only-token"));
    server.await.expect("fixture assertions pass");
}

#[test]
fn ctl_rejects_nonpositive_or_unbounded_timeout_flags_before_connecting() {
    for value in ["0s", "86401s", "2days"] {
        let output = Command::new(env!("CARGO_BIN_EXE_oxidase"))
            .arg("ctl")
            .arg("--unix")
            .arg("/does-not-exist.sock")
            .arg("--timeout")
            .arg(value)
            .arg("status")
            .output()
            .expect("ctl process executes");
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("timeout"));
    }
}
