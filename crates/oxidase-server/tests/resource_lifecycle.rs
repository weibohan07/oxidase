//! Actual Running-state retirement of a streamed Site Asset, without Proxy,
//! discovery, drain, or a metrics scrape performing the reclamation.
//!
//! The bounded Asset exceeds Hyper's locked 400 KiB H2 send buffer. A real H2
//! receive window is kept closed until publication and sibling requests finish.
//! Every certificate and key is generated locally for tests only.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};
use std::time::Duration;

use bytes::Bytes;
use futures_util::future::poll_fn;
use h2::client::SendRequest;
use http::{Request, StatusCode};
use oxidase_config::Compiler;
use oxidase_runtime::{
    ResourceCensus, ResourceCount, ResourceKind, ResourceState, RuntimeSnapshot, ServingState,
    SnapshotStore,
};
use oxidase_server::{GatewayServer, RunningServer};
use rcgen::{CertifiedKey as GeneratedCertificate, generate_simple_self_signed};
use tempfile::{TempDir, tempdir};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::crypto::ring::default_provider;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

const ASSET_LENGTH: usize = 512 * 1024 + 37;
const STREAM_WINDOW: u32 = 1024;
const IO_BOUND: Duration = Duration::from_secs(10);
const REPLACEMENT: &[u8] = b"current-running-snapshot";

struct Fixture {
    _directory: TempDir,
    source: PathBuf,
    running: RunningServer,
    store: Arc<SnapshotStore>,
    census: Arc<ResourceCensus>,
    client: SendRequest<Bytes>,
    driver: tokio::task::JoinHandle<Result<(), h2::Error>>,
}

fn gateway_source(service: &str) -> String {
    format!(
        "api_version: oxidase.dev/v1alpha1\nkind: gateway\nresources:\n  certificates:\n    test:\n      cert_chain: cert.pem\n      private_key: key.pem\n{service}\nlisteners:\n  - name: public\n    bind: 127.0.0.1:0\n    protocol: https\n    tls:\n      default_certificate: test\n    http:\n      versions: [h2]\n    service:\n      ref: root\n"
    )
}

fn original_source() -> String {
    // One resource graph; its Site is removed by the normal subsequent reload.
    gateway_source(
        "  sites:\n    web:\n      root: site\nservices:\n  root:\n    type: site\n    site: web",
    )
}

fn replacement_source() -> String {
    gateway_source(
        "services:\n  root:\n    type: respond\n    body:\n      text: current-running-snapshot",
    )
}

fn payload_byte(offset: usize) -> u8 {
    ((offset * 31 + 7) % 251) as u8
}

fn verify_bytes(bytes: &[u8], offset: &mut usize) {
    assert!(*offset + bytes.len() <= ASSET_LENGTH, "extra Asset bytes");
    for (index, actual) in bytes.iter().enumerate() {
        assert_eq!(
            *actual,
            payload_byte(*offset + index),
            "Asset byte offset {}",
            *offset + index
        );
    }
    *offset += bytes.len();
}

fn count(census: &ResourceCensus, kind: ResourceKind) -> ResourceCount {
    census
        .sample()
        .resources
        .into_iter()
        .find(|row| row.kind == kind)
        .expect("fixed census kind")
}

fn state_count(census: &ResourceCensus, state: ResourceState) -> u64 {
    count(census, ResourceKind::Snapshot)
        .states
        .into_iter()
        .find(|row| row.state == state)
        .expect("fixed census state")
        .live
}

async fn wait_actual_release(weak: &Weak<RuntimeSnapshot>) {
    // Weak existence is an independent ownership oracle. No status accessor,
    // scrape, reload, or drain is called while waiting for the real last drop.
    tokio::time::timeout(IO_BOUND, async {
        while weak.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("old Snapshot must release while the gateway is Running");
}

async fn wait_bodies_closed(census: &ResourceCensus) {
    tokio::time::timeout(IO_BOUND, async {
        while count(census, ResourceKind::ResponseBody).live != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("actual response adapters finish without drain");
}

async fn fixture() -> Fixture {
    let directory = tempdir().expect("private test fixture directory");
    let site = directory.path().join("site");
    fs::create_dir(&site).expect("Site root");
    fs::write(site.join("site.oxsite"), "oxista: site/v1\n").expect("Site manifest");
    let payload = (0..ASSET_LENGTH).map(payload_byte).collect::<Vec<_>>();
    fs::write(site.join("asset.bin"), payload).expect("bounded deterministic Asset");
    let GeneratedCertificate { cert, signing_key } =
        generate_simple_self_signed(vec!["lifecycle.example.test".to_owned()])
            .expect("ephemeral test-only certificate");
    fs::write(directory.path().join("cert.pem"), cert.pem()).expect("test-only chain");
    fs::write(
        directory.path().join("key.pem"),
        signing_key.serialize_pem(),
    )
    .expect("test-only key");
    let source = directory.path().join("gateway.yaml");
    fs::write(&source, original_source()).expect("Site Gateway source");
    let census = Arc::new(ResourceCensus::default());
    let snapshot = RuntimeSnapshot::prepare_reusing_in(
        Compiler::compile_path(&source).expect("strict Gateway compiles"),
        None,
        Arc::clone(&census),
    )
    .expect("Site prepares")
    .0;
    let gateway = GatewayServer::bind(snapshot)
        .await
        .expect("TLS gateway binds ephemeral loopback");
    let store = gateway.snapshot_store();
    let address = gateway.local_addresses()[0].1;
    let running = gateway.spawn();
    let mut roots = RootCertStore::empty();
    roots
        .add(cert.der().clone())
        .expect("trust only this test certificate");
    let mut client_config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .expect("safe protocols")
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"h2".to_vec()];
    let socket = TcpStream::connect(address)
        .await
        .expect("physical gateway connection");
    let tls = tokio::time::timeout(
        IO_BOUND,
        TlsConnector::from(Arc::new(client_config)).connect(
            ServerName::try_from("lifecycle.example.test").expect("static name"),
            socket,
        ),
    )
    .await
    .expect("TLS bound")
    .expect("verified TLS handshake");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (client, connection) = h2::client::Builder::new()
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(65535)
        .handshake::<_, Bytes>(tls)
        .await
        .expect("manual-flow-control H2 client");
    let driver = tokio::spawn(connection);
    Fixture {
        _directory: directory,
        source,
        running,
        store,
        census,
        client,
        driver,
    }
}

async fn current_request(client: &mut SendRequest<Bytes>) {
    poll_fn(|context| client.poll_ready(context))
        .await
        .expect("connection remains reusable");
    let request = Request::builder()
        .uri("https://lifecycle.example.test/new")
        .body(())
        .expect("sibling H2 request");
    let (response, _send) = client
        .send_request(request, true)
        .expect("sibling request dispatch");
    let response = tokio::time::timeout(IO_BOUND, response)
        .await
        .expect("sibling response bound")
        .expect("sibling response head");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-length")
            .expect("full representation length"),
        REPLACEMENT.len().to_string().as_str()
    );
    let mut body = response.into_body();
    let mut received = Vec::new();
    while let Some(data) = tokio::time::timeout(IO_BOUND, body.data())
        .await
        .expect("sibling DATA bound")
    {
        let data = data.expect("sibling DATA intact");
        assert!(
            received.len() + data.len() <= REPLACEMENT.len(),
            "unexpected extra sibling bytes"
        );
        received.extend_from_slice(&data);
        body.flow_control()
            .release_capacity(data.len())
            .expect("sibling window acknowledgement");
    }
    assert_eq!(received, REPLACEMENT);
    assert!(
        tokio::time::timeout(IO_BOUND, body.trailers())
            .await
            .expect("sibling trailer boundary is bounded")
            .expect("sibling trailers are valid")
            .is_none()
    );
}

async fn assert_running_reclamation(fixture: &Fixture, old: &Weak<RuntimeSnapshot>) {
    wait_actual_release(old).await;
    wait_bodies_closed(&fixture.census).await;
    let published = fixture.store.published();
    assert_eq!(published.serving_state, ServingState::Running);
    assert!(published.ready());
    assert_eq!(state_count(&fixture.census, ResourceState::Current), 1);
    assert_eq!(state_count(&fixture.census, ResourceState::Retired), 0);
    let snapshots = count(&fixture.census, ResourceKind::Snapshot);
    assert_eq!(
        (
            snapshots.created,
            snapshots.destroyed,
            snapshots.live,
            snapshots.published
        ),
        (2, 1, 1, 2)
    );
    assert_eq!(fixture.census.sample().invariant_failures, 0);
}

async fn case(complete: bool) {
    let mut fixture = fixture().await;
    let old = Arc::downgrade(&fixture.store.pin());
    poll_fn(|context| fixture.client.poll_ready(context))
        .await
        .expect("initial H2 ready");
    let request = Request::builder()
        .uri("https://lifecycle.example.test/asset.bin")
        .body(())
        .expect("Asset request");
    let (response, mut cancel) = fixture
        .client
        .send_request(request, true)
        .expect("Asset dispatch");
    let response = tokio::time::timeout(IO_BOUND, response)
        .await
        .expect("Asset head bound")
        .expect("Asset head intact");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-length")
            .expect("Asset length"),
        ASSET_LENGTH.to_string().as_str()
    );
    let mut body = response.into_body();
    let first = tokio::time::timeout(IO_BOUND, body.data())
        .await
        .expect("first DATA bound")
        .expect("real DATA before retention/cancellation")
        .expect("first DATA intact");
    assert!(!first.is_empty());
    assert!(first.len() <= STREAM_WINDOW as usize);
    let mut offset = 0;
    verify_bytes(&first, &mut offset);
    // No stream WINDOW_UPDATE: this concrete response cannot reach EOF merely
    // because the client driver or a separate request continues to run.
    assert!(!body.is_end_stream());
    assert!(old.upgrade().is_some());
    fs::write(&fixture.source, replacement_source()).expect("normal Source replacement");
    let report = tokio::time::timeout(
        IO_BOUND,
        fixture.running.reload_path(Path::new(&fixture.source)),
    )
    .await
    .expect("normal manager publication bound")
    .expect("normal manager publication succeeds");
    assert_eq!(report.listeners_retained, vec!["public"]);
    assert!(report.listeners_removed.is_empty());
    assert!(report.listeners_added.is_empty());
    assert_eq!(state_count(&fixture.census, ResourceState::Retired), 1);
    current_request(&mut fixture.client).await;
    assert!(
        old.upgrade().is_some(),
        "a completed sibling cannot release the held Asset snapshot"
    );
    assert_eq!(state_count(&fixture.census, ResourceState::Retired), 1);
    if complete {
        body.flow_control()
            .release_capacity(first.len())
            .expect("explicitly release the held window");
        while let Some(data) = tokio::time::timeout(IO_BOUND, body.data())
            .await
            .expect("old Asset DATA progresses within bound")
        {
            let data = data.expect("old Asset DATA remains valid after publication");
            verify_bytes(&data, &mut offset);
            body.flow_control()
                .release_capacity(data.len())
                .expect("old stream window acknowledgement");
        }
        assert_eq!(
            offset, ASSET_LENGTH,
            "all old representation bytes arrived exactly once"
        );
        assert!(
            tokio::time::timeout(IO_BOUND, body.trailers())
                .await
                .expect("Asset trailer boundary is bounded")
                .expect("Asset trailer boundary remains valid")
                .is_none()
        );
    } else {
        assert!(offset < ASSET_LENGTH, "cancellation is genuinely mid-body");
        cancel.send_reset(h2::Reason::CANCEL);
    }
    drop((body, cancel));
    assert_running_reclamation(&fixture, &old).await;
    current_request(&mut fixture.client).await;
    assert_running_reclamation(&fixture, &old).await;
    // Cleanup only after every Running-state release assertion has passed.
    fixture.driver.abort();
    assert!(
        fixture
            .driver
            .await
            .expect_err("test client driver explicitly stopped")
            .is_cancelled()
    );
    fixture.running.shutdown().await.expect("gateway cleanup");
}

#[tokio::test]
async fn held_asset_snapshot_finishes_and_reclaims_while_running_over_the_same_h2_connection() {
    tokio::time::timeout(Duration::from_secs(30), case(true))
        .await
        .expect("whole completion case is bounded");
}

#[tokio::test]
async fn cancelled_asset_snapshot_reclaims_without_draining_or_killing_a_sibling_h2_stream() {
    tokio::time::timeout(Duration::from_secs(30), case(false))
        .await
        .expect("whole cancellation case is bounded");
}
