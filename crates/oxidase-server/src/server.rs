use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderValue, Method, Request, Response, StatusCode, header};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use oxidase_core::{RequestFrame, RequestMetadata, ServiceOutcome};
use oxidase_runtime::{Executor, RuntimeSnapshot, SnapshotStore};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use crate::body::{GatewayBody, GatewayBodyPlan, full_body};
use crate::leaves::{HyperLeaves, ProxyClient};

static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub struct GatewayServer {
    store: Arc<SnapshotStore>,
    proxy: Arc<ProxyClient>,
    listeners: Vec<BoundListener>,
    drain_timeout: Duration,
}

struct BoundListener {
    name: String,
    listener: TcpListener,
    local_address: SocketAddr,
}

impl GatewayServer {
    pub async fn bind(snapshot: RuntimeSnapshot) -> Result<Self, ServerError> {
        let mut listeners = Vec::new();
        for configured in &snapshot.listeners {
            let listener =
                TcpListener::bind(configured.bind)
                    .await
                    .map_err(|source| ServerError::Bind {
                        listener: configured.name.clone(),
                        address: configured.bind,
                        source,
                    })?;
            let local_address =
                listener
                    .local_addr()
                    .map_err(|source| ServerError::LocalAddress {
                        listener: configured.name.clone(),
                        source,
                    })?;
            listeners.push(BoundListener {
                name: configured.name.clone(),
                listener,
                local_address,
            });
        }
        Ok(Self {
            store: Arc::new(SnapshotStore::new(snapshot)),
            proxy: Arc::new(ProxyClient::new().map_err(ServerError::DataPlane)?),
            listeners,
            drain_timeout: Duration::from_secs(10),
        })
    }

    #[must_use]
    pub fn local_addresses(&self) -> Vec<(String, SocketAddr)> {
        self.listeners
            .iter()
            .map(|listener| (listener.name.clone(), listener.local_address))
            .collect()
    }

    #[must_use]
    pub fn snapshot_store(&self) -> Arc<SnapshotStore> {
        self.store.clone()
    }

    pub fn spawn(self) -> RunningServer {
        let addresses = self.local_addresses();
        let (shutdown, receiver) = watch::channel(false);
        let task = tokio::spawn(self.run(receiver));
        RunningServer {
            addresses,
            shutdown,
            task,
        }
    }

    pub async fn run_until<F>(self, signal: F) -> Result<(), ServerError>
    where
        F: Future<Output = ()>,
    {
        let running = self.spawn();
        signal.await;
        running.shutdown().await
    }

    async fn run(self, receiver: watch::Receiver<bool>) -> Result<(), ServerError> {
        let mut tasks = JoinSet::new();
        for listener in self.listeners {
            tasks.spawn(run_listener(
                listener,
                self.store.clone(),
                self.proxy.clone(),
                receiver.clone(),
                self.drain_timeout,
            ));
        }
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => return Err(error),
                Err(error) if error.is_cancelled() => {}
                Err(error) => return Err(ServerError::Task(error.to_string())),
            }
        }
        Ok(())
    }
}

pub struct RunningServer {
    addresses: Vec<(String, SocketAddr)>,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<Result<(), ServerError>>,
}

impl RunningServer {
    #[must_use]
    pub fn local_addresses(&self) -> &[(String, SocketAddr)] {
        &self.addresses
    }

    pub async fn shutdown(self) -> Result<(), ServerError> {
        let _ = self.shutdown.send(true);
        self.task
            .await
            .map_err(|error| ServerError::Task(error.to_string()))?
    }
}

async fn run_listener(
    listener: BoundListener,
    store: Arc<SnapshotStore>,
    proxy: Arc<ProxyClient>,
    mut shutdown: watch::Receiver<bool>,
    drain_timeout: Duration,
) -> Result<(), ServerError> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.listener.accept() => {
                let (stream, peer_address) = accepted.map_err(|source| ServerError::Accept {
                    listener: listener.name.clone(),
                    source,
                })?;
                let listener_name = listener.name.clone();
                let store = store.clone();
                let proxy = proxy.clone();
                connections.spawn(async move {
                    serve_connection(stream, peer_address, listener_name, store, proxy).await;
                });
            }
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = result {
                    tracing::warn!(error = %error, "connection task failed");
                }
            }
        }
    }

    let drained = tokio::time::timeout(drain_timeout, async {
        while let Some(result) = connections.join_next().await {
            if let Err(error) = result {
                tracing::warn!(error = %error, "connection task failed during drain");
            }
        }
    })
    .await;
    if drained.is_err() {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    Ok(())
}

async fn serve_connection(
    stream: TcpStream,
    peer_address: SocketAddr,
    listener_name: String,
    store: Arc<SnapshotStore>,
    proxy: Arc<ProxyClient>,
) {
    let service = service_fn(move |request| {
        handle_request(
            request,
            peer_address,
            listener_name.clone(),
            store.clone(),
            proxy.clone(),
        )
    });
    if let Err(error) = http1::Builder::new()
        .keep_alive(true)
        .serve_connection(TokioIo::new(stream), service)
        .await
    {
        tracing::debug!(error = %error, "HTTP connection ended with an error");
    }
}

async fn handle_request(
    request: Request<Incoming>,
    peer_address: SocketAddr,
    listener_name: String,
    store: Arc<SnapshotStore>,
    proxy: Arc<ProxyClient>,
) -> Result<Response<GatewayBody>, Infallible> {
    let request_id = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let snapshot = store.pin();
    let config_version = snapshot.config_version.to_string();
    let Some(program) = snapshot.program_for(&listener_name) else {
        tracing::error!(
            request_id,
            config_version,
            listener = listener_name,
            error_class = "invalid_state",
            "listener root is missing from pinned snapshot"
        );
        return Ok(safe_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error",
            false,
        ));
    };

    let (parts, body) = request.into_parts();
    let is_head = parts.method == Method::HEAD;
    let authority = parts
        .headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .or_else(|| parts.uri.authority().map(ToString::to_string))
        .unwrap_or_default();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or_else(|| "/".to_owned(), |value| value.as_str().to_owned());
    let mut metadata = RequestMetadata::new(
        parts.method,
        "http",
        authority,
        path_and_query,
        parts.headers,
    );
    metadata.peer_address = Some(peer_address.to_string());
    let leaves = HyperLeaves::new(snapshot.clone(), proxy);
    let started = std::time::Instant::now();
    let report = Executor::new(&program, &leaves)
        .execute(RequestFrame::new(metadata), Some(body))
        .await;

    let (outcome, status, response) = match report.outcome {
        ServiceOutcome::Handled(response) => {
            let status = response.status;
            ("handled", status, response_from_head(response, is_head))
        }
        ServiceOutcome::Declined => (
            "declined",
            StatusCode::NOT_FOUND,
            safe_response(StatusCode::NOT_FOUND, "Not Found", is_head),
        ),
        ServiceOutcome::Failed(error) => {
            tracing::error!(
                request_id,
                config_version,
                listener = listener_name,
                error_class = ?error.class,
                internal_detail = %error.internal_detail,
                "Service execution failed"
            );
            (
                "failed",
                error.public_status,
                safe_response(
                    error.public_status,
                    safe_error_body(error.public_status),
                    is_head,
                ),
            )
        }
    };
    tracing::info!(
        request_id,
        config_version,
        listener = listener_name,
        outcome,
        status = status.as_u16(),
        latency_micros = started.elapsed().as_micros(),
        "request complete"
    );
    Ok(response)
}

fn response_from_head(
    mut response: oxidase_core::ResponseHead<GatewayBodyPlan>,
    is_head: bool,
) -> Response<GatewayBody> {
    if !response.headers.contains_key(header::CONTENT_LENGTH)
        && let Some(length) = response.body.length()
        && let Ok(value) = HeaderValue::from_str(&length.to_string())
    {
        response.headers.insert(header::CONTENT_LENGTH, value);
    }
    let body_forbidden = is_head
        || response.status == StatusCode::NO_CONTENT
        || response.status == StatusCode::NOT_MODIFIED;
    let mut output = Response::new(response.body.into_body(body_forbidden));
    *output.status_mut() = response.status;
    *output.headers_mut() = response.headers;
    output
}

fn safe_error_body(status: StatusCode) -> &'static str {
    if status == StatusCode::GATEWAY_TIMEOUT {
        "Gateway Timeout"
    } else if status == StatusCode::BAD_GATEWAY {
        "Bad Gateway"
    } else {
        "Internal Server Error"
    }
}

fn safe_response(
    status: StatusCode,
    message: &'static str,
    head_only: bool,
) -> Response<GatewayBody> {
    let bytes = Bytes::from_static(message.as_bytes());
    let mut response = Response::new(if head_only {
        GatewayBodyPlan::Empty.into_body(true)
    } else {
        full_body(bytes.clone())
    });
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    if let Ok(length) = HeaderValue::from_str(&bytes.len().to_string()) {
        response
            .headers_mut()
            .insert(header::CONTENT_LENGTH, length);
    }
    response
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("cannot bind listener `{listener}` to {address}: {source}")]
    Bind {
        listener: String,
        address: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot read local address for listener `{listener}`: {source}")]
    LocalAddress {
        listener: String,
        #[source]
        source: std::io::Error,
    },
    #[error("listener `{listener}` failed while accepting a connection: {source}")]
    Accept {
        listener: String,
        #[source]
        source: std::io::Error,
    },
    #[error("server task failed: {0}")]
    Task(String),
    #[error("cannot initialize HTTP data plane: {0}")]
    DataPlane(String),
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::fs;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use bytes::Bytes;
    use http::{HeaderName, HeaderValue, Response, header};
    use http_body_util::{BodyExt, Full};
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use oxidase_config::Compiler;
    use oxidase_runtime::RuntimeSnapshot;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::watch;

    use super::GatewayServer;

    async fn request(address: std::net::SocketAddr, path: &str, extra: &str) -> String {
        raw_request(
            address,
            &format!(
                "GET {path} HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n{extra}\r\n"
            ),
        )
        .await
    }

    async fn raw_request(address: std::net::SocketAddr, request: &str) -> String {
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("test server accepts connections");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("request can be written");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("response can be read");
        String::from_utf8(response).expect("test response is UTF-8")
    }

    async fn spawn_upstream() -> (
        std::net::SocketAddr,
        Arc<AtomicUsize>,
        watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream binds");
        let address = listener.local_addr().expect("upstream address is known");
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts_for_task = accepts.clone();
        let (shutdown, mut receiver) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    changed = receiver.changed() => {
                        if changed.is_err() || *receiver.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else {
                            break;
                        };
                        accepts_for_task.fetch_add(1, Ordering::Relaxed);
                        connections.spawn(async move {
                            let service = service_fn(|request: http::Request<hyper::body::Incoming>| async move {
                                let path = request
                                    .uri()
                                    .path_and_query()
                                    .map_or("/", http::uri::PathAndQuery::as_str)
                                    .to_owned();
                                let host = request
                                    .headers()
                                    .get(header::HOST)
                                    .and_then(|value| value.to_str().ok())
                                    .unwrap_or("")
                                    .to_owned();
                                let forwarded = request
                                    .headers()
                                    .get("x-forwarded-for")
                                    .and_then(|value| value.to_str().ok())
                                    .unwrap_or("")
                                    .to_owned();
                                let has_hop_header = request.headers().contains_key("x-hop");
                                if path.starts_with("/slow") {
                                    tokio::time::sleep(Duration::from_millis(150)).await;
                                }
                                let body = request
                                    .into_body()
                                    .collect()
                                    .await
                                    .expect("fixture request body is readable")
                                    .to_bytes();
                                let message = format!(
                                    "{path}|{}|{host}|{forwarded}|{has_hop_header}",
                                    String::from_utf8_lossy(&body)
                                );
                                let mut response = Response::new(Full::new(Bytes::from(message)));
                                response.headers_mut().insert(
                                    header::CONNECTION,
                                    HeaderValue::from_static("x-remove"),
                                );
                                response.headers_mut().insert(
                                    HeaderName::from_static("x-remove"),
                                    HeaderValue::from_static("secret"),
                                );
                                response.headers_mut().insert(
                                    HeaderName::from_static("x-keep"),
                                    HeaderValue::from_static("kept"),
                                );
                                Ok::<_, Infallible>(response)
                            });
                            let _ = http1::Builder::new()
                                .keep_alive(true)
                                .serve_connection(TokioIo::new(stream), service)
                                .await;
                        });
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        (address, accepts, shutdown, task)
    }

    #[tokio::test]
    async fn serves_route_redirect_fallback_and_graceful_shutdown() {
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        fs::write(
            &config,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
services:
  root:
    type: route
    cases:
      - when:
          path: /hello
        service:
          type: respond
          body:
            text: hello
      - when:
          path: /old
        service:
          type: redirect
          location: /new
    default:
      type: respond
      status: 404
      body:
        text: missing
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: root
"#,
        )
        .expect("config can be written");
        let snapshot =
            RuntimeSnapshot::prepare(Compiler::compile_path(&config).expect("config compiles"))
                .expect("snapshot prepares");
        let server = GatewayServer::bind(snapshot).await.expect("server binds");
        let running = server.spawn();
        let address = running.local_addresses()[0].1;

        let hello = request(address, "/hello", "").await;
        assert!(hello.starts_with("HTTP/1.1 200 OK"));
        assert!(hello.ends_with("hello"));
        let redirect = request(address, "/old", "").await;
        assert!(redirect.starts_with("HTTP/1.1 308 Permanent Redirect"));
        assert!(redirect.to_ascii_lowercase().contains("location: /new"));
        let missing = request(address, "/missing", "").await;
        assert!(missing.starts_with("HTTP/1.1 404 Not Found"));
        assert!(missing.ends_with("missing"));
        running.shutdown().await.expect("server shuts down cleanly");
    }

    #[tokio::test]
    async fn streams_asset_and_honors_single_range() {
        let directory = tempdir().expect("temporary directory is available");
        let site = directory.path().join("site");
        fs::create_dir(&site).expect("site directory can be created");
        fs::write(
            site.join("site.oxsite"),
            "oxista: site/v1\npaths:\n  missing: decline\n",
        )
        .expect("manifest can be written");
        fs::write(site.join("large.bin"), b"abcdefghij").expect("asset can be written");
        let config = directory.path().join("oxidase.yaml");
        fs::write(
            &config,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  sites:
    web:
      root: site
services:
  root:
    type: site
    site: web
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: root
"#,
        )
        .expect("config can be written");
        let snapshot =
            RuntimeSnapshot::prepare(Compiler::compile_path(&config).expect("config compiles"))
                .expect("snapshot prepares");
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("server binds")
            .spawn();
        let address = running.local_addresses()[0].1;
        let response = request(address, "/large.bin", "Range: bytes=2-5\r\n").await;
        assert!(response.starts_with("HTTP/1.1 206 Partial Content"));
        assert!(
            response
                .to_ascii_lowercase()
                .contains("content-range: bytes 2-5/10")
        );
        assert!(response.ends_with("cdef"));
        running.shutdown().await.expect("server shuts down cleanly");
    }

    #[tokio::test]
    async fn proxies_streaming_bodies_with_pooling_headers_and_timeout() {
        let (upstream, accepts, upstream_shutdown, upstream_task) = spawn_upstream().await;
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        fs::write(
            &config,
            format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    api:
      endpoints:
        - http://{upstream}
      connect_timeout: 25ms
      response_timeout: 25ms
services:
  root:
    type: proxy
    cluster: api
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: root
"#
            ),
        )
        .expect("proxy config can be written");
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("proxy config compiles"),
        )
        .expect("proxy snapshot prepares");
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("gateway binds")
            .spawn();
        let address = running.local_addresses()[0].1;

        let first = raw_request(
            address,
            "POST /upload?b=2&a=1 HTTP/1.1\r\nHost: incoming.test\r\nConnection: close, x-hop\r\nX-Hop: remove-me\r\nContent-Length: 6\r\n\r\nstream",
        )
        .await;
        assert!(first.starts_with("HTTP/1.1 200 OK"));
        assert!(first.ends_with(&format!(
            "/upload?b=2&a=1|stream|{upstream}|127.0.0.1|false"
        )));
        let first_lower = first.to_ascii_lowercase();
        assert!(first_lower.contains("x-keep: kept"));
        assert!(!first_lower.contains("x-remove: secret"));

        let second = request(address, "/second", "").await;
        assert!(second.starts_with("HTTP/1.1 200 OK"));
        assert_eq!(accepts.load(Ordering::Relaxed), 1);

        let timeout = request(address, "/slow", "").await;
        assert!(timeout.starts_with("HTTP/1.1 504 Gateway Timeout"));
        assert!(timeout.ends_with("Gateway Timeout"));

        running.shutdown().await.expect("gateway shuts down");
        let _ = upstream_shutdown.send(true);
        upstream_task.await.expect("upstream task shuts down");
    }
}
