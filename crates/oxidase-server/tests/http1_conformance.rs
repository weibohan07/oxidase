//! Adversarial HTTP/1.1 wire conformance tests.
//!
//! These tests deliberately bypass Hyper's client API so malformed message
//! syntax reaches the same parser boundary as an untrusted downstream peer.

use std::fs;
use std::time::Duration;

use bytes::Bytes;
use http::{Response, header};
use http_body_util::{BodyExt as _, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use oxidase_config::Compiler;
use oxidase_runtime::RuntimeSnapshot;
use oxidase_server::{GatewayServer, RunningServer};
use tempfile::{TempDir, tempdir};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

struct TestGateway {
    _directory: TempDir,
    address: std::net::SocketAddr,
    running: RunningServer,
    upstream_shutdown: oneshot::Sender<()>,
    upstream_task: tokio::task::JoinHandle<()>,
}

impl TestGateway {
    async fn shutdown(self) {
        self.running
            .shutdown()
            .await
            .expect("HTTP/1 conformance gateway shuts down");
        let _ = self.upstream_shutdown.send(());
        self.upstream_task
            .await
            .expect("HTTP/1 conformance upstream exits");
    }
}

async fn start_gateway() -> TestGateway {
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback upstream binds");
    let upstream_address = upstream.local_addr().expect("upstream address is known");
    let (upstream_shutdown, mut shutdown_receiver) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut shutdown_receiver => break,
                accepted = upstream.accept() => {
                    let Ok((stream, _)) = accepted else { break };
                    connections.spawn(async move {
                        let service = service_fn(|request: http::Request<hyper::body::Incoming>| async move {
                            let path = request
                                .uri()
                                .path_and_query()
                                .map_or("/", http::uri::PathAndQuery::as_str)
                                .to_owned();
                            let forwarded_host = request
                                .headers()
                                .get("x-forwarded-host")
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or("<none>")
                                .to_owned();
                            let content_length = request
                                .headers()
                                .get(header::CONTENT_LENGTH)
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or("<none>")
                                .to_owned();
                            let transfer_encoding = request
                                .headers()
                                .get(header::TRANSFER_ENCODING)
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or("<none>")
                                .to_owned();
                            let trailer_was_promoted = request.headers().contains_key("x-actual");
                            let collected = request.into_body().collect().await?;
                            let mut trailers = collected
                                .trailers()
                                .into_iter()
                                .flat_map(http::HeaderMap::keys)
                                .map(|name| name.as_str().to_owned())
                                .collect::<Vec<_>>();
                            trailers.sort_unstable();
                            let data = String::from_utf8_lossy(&collected.to_bytes()).into_owned();
                            let body = format!(
                                "path={path};host={forwarded_host};data={data};cl={content_length};te={transfer_encoding};promoted={trailer_was_promoted};trailers={}",
                                trailers.join(",")
                            );
                            Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from(body))))
                        });
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                }
            }
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    });

    let directory = tempdir().expect("temporary gateway directory is available");
    let config = directory.path().join("oxidase.yaml");
    fs::write(
        &config,
        format!(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    upstream:
      protocol: http1
      endpoints:
        - http://{upstream_address}
      connect_timeout: 1s
      response_timeout: 2s
services:
  root:
    type: route
    cases:
      - when:
          path: /inspect-authority
        service:
          type: respond
          body:
            text: "{{{{ request.authority }}}}|{{{{ request.headers.host.first }}}}"
    default:
      type: proxy
      cluster: upstream
listeners:
  - name: plain
    bind: 127.0.0.1:0
    protocol: http
    http:
      versions: [http1]
      http1:
        header_read_timeout: 2s
    service:
      ref: root
"#
        ),
    )
    .expect("HTTP/1 conformance config can be written");
    let snapshot = RuntimeSnapshot::prepare(
        Compiler::compile_path(&config).expect("HTTP/1 conformance source compiles"),
    )
    .expect("HTTP/1 conformance snapshot prepares");
    let running = GatewayServer::bind(snapshot)
        .await
        .expect("HTTP/1 conformance gateway binds")
        .spawn();
    let address = running.local_addresses()[0].1;
    TestGateway {
        _directory: directory,
        address,
        running,
        upstream_shutdown,
        upstream_task,
    }
}

async fn exchange(address: std::net::SocketAddr, request: impl AsRef<[u8]>) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut stream = TcpStream::connect(address)
            .await
            .expect("raw HTTP/1 client connects");
        stream
            .write_all(request.as_ref())
            .await
            .expect("raw HTTP/1 request is written");
        let mut response = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => break,
                Ok(read) => response.extend_from_slice(&buffer[..read]),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::BrokenPipe
                            | std::io::ErrorKind::UnexpectedEof
                    ) =>
                {
                    break;
                }
                Err(error) => panic!("raw HTTP/1 response read failed: {error}"),
            }
        }
        response
    })
    .await
    .expect("raw HTTP/1 exchange completes")
}

fn text(response: &[u8]) -> String {
    String::from_utf8_lossy(response).into_owned()
}

fn assert_status(response: &[u8], status: u16) {
    let response = text(response);
    assert!(
        response.starts_with(&format!("HTTP/1.1 {status} ")),
        "unexpected wire response: {response:?}"
    );
}

#[tokio::test]
async fn framing_ambiguity_cannot_create_a_second_request() {
    let gateway = start_gateway().await;

    let ambiguous = exchange(
        gateway.address,
        b"POST /first HTTP/1.1\r\nHost: gateway.test\r\nContent-Length: 51\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n4\r\ntest\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: gateway.test\r\n\r\n",
    )
    .await;
    assert_status(&ambiguous, 200);
    let ambiguous = text(&ambiguous);
    assert_eq!(ambiguous.matches("HTTP/1.1 ").count(), 1);
    assert!(ambiguous.contains("path=/first"));
    assert!(ambiguous.contains("data=test"));
    assert!(ambiguous.contains("cl=&lt;none&gt;") || ambiguous.contains("cl=<none>"));
    assert!(!ambiguous.contains("path=/smuggled"));

    let equal_lengths = exchange(
        gateway.address,
        b"POST /equal HTTP/1.1\r\nHost: gateway.test\r\nContent-Length: 4\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest",
    )
    .await;
    assert_status(&equal_lengths, 200);
    assert!(text(&equal_lengths).contains("data=test"));

    let conflicting_lengths = exchange(
        gateway.address,
        b"POST /conflict HTTP/1.1\r\nHost: gateway.test\r\nContent-Length: 4\r\nContent-Length: 5\r\nConnection: close\r\n\r\ntest!",
    )
    .await;
    assert_status(&conflicting_lengths, 400);

    gateway.shutdown().await;
}

#[tokio::test]
async fn host_and_request_target_forms_have_one_unambiguous_authority() {
    let gateway = start_gateway().await;

    for request in [
        b"GET / HTTP/1.1\r\nHost: first.test\r\nHost: second.test\r\nConnection: close\r\n\r\n"
            .as_slice(),
        b"GET / HTTP/1.1\r\nHost:\r\nConnection: close\r\n\r\n".as_slice(),
        b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n".as_slice(),
    ] {
        let response = exchange(gateway.address, request).await;
        assert_status(&response, 400);
    }

    for request in [
        b"GET  / HTTP/1.1\r\nHost: gateway.test\r\nConnection: close\r\n\r\n".as_slice(),
        b"GET /  HTTP/1.1\r\nHost: gateway.test\r\nConnection: close\r\n\r\n".as_slice(),
    ] {
        let response = exchange(gateway.address, request).await;
        assert_status(&response, 400);
    }

    let absolute = exchange(
        gateway.address,
        b"GET http://absolute.example/target?x=1 HTTP/1.1\r\nHost: conflicting.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_status(&absolute, 200);
    let absolute = text(&absolute);
    assert!(absolute.contains("path=/target?x=1"), "{absolute:?}");
    assert!(absolute.contains("host=absolute.example"), "{absolute:?}");
    assert!(
        !absolute.contains("host=conflicting.example"),
        "{absolute:?}"
    );

    let inspected = exchange(
        gateway.address,
        b"GET http://absolute.example/inspect-authority HTTP/1.1\r\nHost: conflicting.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_status(&inspected, 200);
    let inspected = text(&inspected);
    assert!(
        inspected.ends_with("absolute.example|absolute.example"),
        "Service expressions must observe one canonical authority: {inspected:?}"
    );

    let authority_form = exchange(
        gateway.address,
        b"GET example.test:80 HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_status(&authority_form, 400);

    let http10_authority_form = exchange(
        gateway.address,
        b"GET example.test:80 HTTP/1.0\r\nHost: example.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        text(&http10_authority_form).starts_with("HTTP/1.0 400 "),
        "HTTP/1.0 authority-form must be rejected without changing the response version"
    );

    let connect = exchange(
        gateway.address,
        b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_status(&connect, 400);

    gateway.shutdown().await;
}

#[tokio::test]
async fn malformed_or_oversized_request_heads_are_rejected_at_the_wire_boundary() {
    let gateway = start_gateway().await;

    for request in [
        b"GET / HTTP/1.1\r\nHost: gateway.test\r\nX-Test: first\r\n second\r\nConnection: close\r\n\r\n".as_slice(),
        b"GET / HTTP/1.1\r\nHost: gateway.test\r\nX-Test: nul\0value\r\nConnection: close\r\n\r\n".as_slice(),
        b"GET / HTTP/1.1\r\nHost: gateway.test\r\nX-Test: bare\rvalue\r\nConnection: close\r\n\r\n".as_slice(),
    ] {
        let response = exchange(gateway.address, request).await;
        assert_status(&response, 400);
    }

    // Hyper deliberately accepts bare-LF line endings as a robustness input.
    // The request is decoded once and re-emitted with canonical framing, so it
    // cannot create a second interpretation at the upstream hop.
    let bare_lf = exchange(
        gateway.address,
        b"GET /bare-lf HTTP/1.1\nHost: gateway.test\nConnection: close\n\n",
    )
    .await;
    assert_status(&bare_lf, 200);
    let bare_lf = text(&bare_lf);
    assert_eq!(bare_lf.matches("HTTP/1.1 ").count(), 1);
    assert!(bare_lf.contains("path=/bare-lf"));

    let long_target = format!(
        "GET /{} HTTP/1.1\r\nHost: gateway.test\r\nConnection: close\r\n\r\n",
        "a".repeat(9_000)
    );
    let response = exchange(gateway.address, long_target).await;
    assert_status(&response, 414);

    let many_headers = format!(
        "GET /many HTTP/1.1\r\nHost: gateway.test\r\n{}Connection: close\r\n\r\n",
        (0..101)
            .map(|index| format!("X-Header-{index}: value\r\n"))
            .collect::<String>()
    );
    let response = exchange(gateway.address, many_headers).await;
    assert_status(&response, 431);

    let large_header = format!(
        "GET /large HTTP/1.1\r\nHost: gateway.test\r\nX-Large: {}\r\nConnection: close\r\n\r\n",
        "a".repeat(70 * 1024)
    );
    let response = exchange(gateway.address, large_header).await;
    assert_status(&response, 431);

    gateway.shutdown().await;
}

#[tokio::test]
async fn chunk_extensions_and_trailers_remain_framed_while_invalid_chunks_fail() {
    let gateway = start_gateway().await;

    let extension = exchange(
        gateway.address,
        b"POST /chunk HTTP/1.1\r\nHost: gateway.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4;fixture=valid\r\ntest\r\n0\r\n\r\n",
    )
    .await;
    assert_status(&extension, 200);
    assert!(text(&extension).contains("data=test"));

    let invalid_size = exchange(
        gateway.address,
        b"POST /bad-chunk HTTP/1.1\r\nHost: gateway.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nZ\r\ntest\r\n0\r\n\r\n",
    )
    .await;
    assert_status(&invalid_size, 400);
    assert!(!text(&invalid_size).contains("data=test"));

    let declared_trailer = exchange(
        gateway.address,
        b"POST /trailer HTTP/1.1\r\nHost: gateway.test\r\nTransfer-Encoding: chunked\r\nTrailer: X-Actual\r\nConnection: close\r\n\r\n4\r\ntest\r\n0\r\nX-Actual: value\r\n\r\n",
    )
    .await;
    assert_status(&declared_trailer, 200);
    let declared_trailer = text(&declared_trailer);
    assert!(declared_trailer.contains("promoted=false"));
    assert!(declared_trailer.contains("trailers=x-actual"));

    // A declaration mismatch fails the streaming upstream request instead of
    // silently dropping or promoting the undeclared trailer.
    let mismatched_trailer = exchange(
        gateway.address,
        b"POST /trailer HTTP/1.1\r\nHost: gateway.test\r\nTransfer-Encoding: chunked\r\nTrailer: X-Declared\r\nConnection: close\r\n\r\n4\r\ntest\r\n0\r\nX-Actual: value\r\n\r\n",
    )
    .await;
    assert_status(&mismatched_trailer, 400);
    let mismatched_trailer = text(&mismatched_trailer);
    assert!(!mismatched_trailer.contains("trailers=x-actual"));

    let forbidden_trailer = exchange(
        gateway.address,
        b"POST /trailer HTTP/1.1\r\nHost: gateway.test\r\nTransfer-Encoding: chunked\r\nTrailer: Authorization\r\nConnection: close\r\n\r\n4\r\ntest\r\n0\r\nAuthorization: late-secret\r\n\r\n",
    )
    .await;
    assert_status(&forbidden_trailer, 400);
    assert!(!text(&forbidden_trailer).contains("late-secret"));

    gateway.shutdown().await;
}
