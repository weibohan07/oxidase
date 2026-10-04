use std::collections::VecDeque;
use std::convert::Infallible;
use std::future::Future as _;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use hickory_resolver::proto::op::{Message, ResponseCode};
use hickory_resolver::proto::rr::rdata::{A, AAAA, CNAME, SOA, SRV};
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode, header};
use http_body::{Body, Frame};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;
use tokio_rustls::{TlsAcceptor, rustls};

use super::{FixtureCommand, Ready, SoakError, fail, io_error, json_error};

pub(super) async fn control<F>(ready: Ready, mut handler: F) -> Result<(), SoakError>
where
    F: FnMut(FixtureCommand) -> Value,
{
    let mut stdout = tokio::io::stdout();
    stdout
        .write_all(format!("{}\n", serde_json::to_string(&ready).map_err(json_error)?).as_bytes())
        .await
        .map_err(io_error)?;
    stdout.flush().await.map_err(io_error)?;
    let mut input = BufReader::new(tokio::io::stdin());
    while let Some(command) = read_command(&mut input).await? {
        let stop = matches!(command, FixtureCommand::Stop);
        let value = handler(command);
        stdout
            .write_all(format!("{value}\n").as_bytes())
            .await
            .map_err(io_error)?;
        stdout.flush().await.map_err(io_error)?;
        if stop {
            break;
        }
    }
    Ok(())
}

async fn read_command<R>(input: &mut R) -> Result<Option<FixtureCommand>, SoakError>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    const MAX_COMMAND: usize = 16 * 1024;
    let mut bytes = Vec::with_capacity(MAX_COMMAND + 1);
    let size = input
        .take((MAX_COMMAND + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .await
        .map_err(io_error)?;
    if size == 0 {
        return Ok(None);
    }
    if size > MAX_COMMAND {
        return Err(fail("fixture command exceeds 16 KiB"));
    }
    serde_json::from_slice(&bytes).map(Some).map_err(json_error)
}

#[derive(Clone)]
struct DnsState {
    mode: String,
    ttl: u32,
}

#[derive(Default)]
struct DnsCounts {
    queries: AtomicU64,
    udp_queries: AtomicU64,
    tcp_queries: AtomicU64,
    a_queries: AtomicU64,
    aaaa_queries: AtomicU64,
    srv_queries: AtomicU64,
    successful_response_writes: AtomicU64,
    cname_answers: AtomicU64,
    withdraw_answers: AtomicU64,
    ttl_zero_answers: AtomicU64,
    reversed_srv_answers: AtomicU64,
    truncated_udp_answers: AtomicU64,
    nxdomain_answers: AtomicU64,
    nodata_answers: AtomicU64,
    server_failure_answers: AtomicU64,
    positive_aaaa_answers: AtomicU64,
    srv_equal_weight_answers: AtomicU64,
    srv_weighted_answers: AtomicU64,
}

impl DnsCounts {
    fn query(&self, message: &Message, tcp: bool) {
        self.queries.fetch_add(1, Ordering::Relaxed);
        if tcp {
            self.tcp_queries.fetch_add(1, Ordering::Relaxed);
        } else {
            self.udp_queries.fetch_add(1, Ordering::Relaxed);
        }
        let Some(question) = message.queries.first() else {
            return;
        };
        match question.query_type() {
            RecordType::A => &self.a_queries,
            RecordType::AAAA => &self.aaaa_queries,
            RecordType::SRV => &self.srv_queries,
            _ => return,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    fn response_written(&self, bytes: &[u8], tcp: bool) {
        // Inspect the actual locally encoded packet only after a successful
        // UDP write or complete TCP length-prefix + packet write. Changing
        // fixture mode alone cannot increment response feature coverage.
        let Ok(message) = Message::from_vec(bytes) else {
            return;
        };
        self.successful_response_writes
            .fetch_add(1, Ordering::Relaxed);
        for (counter, present) in [
            (
                &self.cname_answers,
                message
                    .answers
                    .iter()
                    .any(|record| matches!(record.data, RData::CNAME(_))),
            ),
            (
                &self.withdraw_answers,
                message.answers.iter().any(|record| {
                    matches!(&record.data, RData::SRV(data) if data.target == Name::root())
                }),
            ),
            (
                &self.ttl_zero_answers,
                message.answers.iter().any(|record| record.ttl == 0),
            ),
            (
                &self.truncated_udp_answers,
                !tcp && message.metadata.truncation,
            ),
            (
                &self.nxdomain_answers,
                message.response_code == ResponseCode::NXDomain,
            ),
            (
                &self.nodata_answers,
                message.response_code == ResponseCode::NoError
                    && !message.metadata.truncation
                    && message.answers.is_empty(),
            ),
            (
                &self.server_failure_answers,
                message.response_code == ResponseCode::ServFail,
            ),
            (&self.positive_aaaa_answers,message.answers.iter().any(|record|matches!(&record.data,RData::AAAA(_)))),
        ] {
            if present {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }
        let rows: Vec<_> = message
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RData::SRV(data) => Some((
                    data.target.to_ascii(),
                    data.priority,
                    data.weight,
                    data.port,
                )),
                _ => None,
            })
            .collect();
        if rows.len() == 2
            && rows[0].0 == "a.discovery.test."
            && rows[1].0 == "b.discovery.test."
            && rows[0].1 == 0
            && rows[1].1 == 0
            && rows[0].3 == rows[1].3
        {
            if rows[0].2 == 1 && rows[1].2 == 1 {
                self.srv_equal_weight_answers
                    .fetch_add(1, Ordering::Relaxed);
            }
            if rows[0].2 == 3 && rows[1].2 == 1 {
                self.srv_weighted_answers.fetch_add(1, Ordering::Relaxed);
            }
        }
        let mut rows = message.answers.iter().filter_map(|record| {
            if let RData::SRV(data) = &record.data {
                Some(data.target.to_ascii())
            } else {
                None
            }
        });
        if rows.next().as_deref() == Some("b.discovery.test.")
            && rows.next().as_deref() == Some("a.discovery.test.")
        {
            self.reversed_srv_answers.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn status(&self) -> Value {
        json!({
            "ok":true,
            "queries":self.queries.load(Ordering::Relaxed),
            "udp_queries":self.udp_queries.load(Ordering::Relaxed),
            "tcp_queries":self.tcp_queries.load(Ordering::Relaxed),
            "a_queries":self.a_queries.load(Ordering::Relaxed),
            "aaaa_queries":self.aaaa_queries.load(Ordering::Relaxed),
            "srv_queries":self.srv_queries.load(Ordering::Relaxed),
            "successful_response_writes":self.successful_response_writes.load(Ordering::Relaxed),
            "cname_answers":self.cname_answers.load(Ordering::Relaxed),
            "withdraw_answers":self.withdraw_answers.load(Ordering::Relaxed),
            "ttl_zero_answers":self.ttl_zero_answers.load(Ordering::Relaxed),
            "reversed_srv_answers":self.reversed_srv_answers.load(Ordering::Relaxed),
            "truncated_udp_answers":self.truncated_udp_answers.load(Ordering::Relaxed),
            "nxdomain_answers":self.nxdomain_answers.load(Ordering::Relaxed),
            "nodata_answers":self.nodata_answers.load(Ordering::Relaxed),
            "server_failure_answers":self.server_failure_answers.load(Ordering::Relaxed),
            "positive_aaaa_answers":self.positive_aaaa_answers.load(Ordering::Relaxed),
            "srv_equal_weight_answers":self.srv_equal_weight_answers.load(Ordering::Relaxed),
            "srv_weighted_answers":self.srv_weighted_answers.load(Ordering::Relaxed),
        })
    }
}

pub(super) async fn dns(root: PathBuf) -> Result<(), SoakError> {
    let upstream: Ready =
        serde_json::from_slice(&std::fs::read(root.join("upstream.json")).map_err(io_error)?)
            .map_err(json_error)?;
    let tcp = TcpListener::bind("127.0.0.1:0").await.map_err(io_error)?;
    let address = tcp.local_addr().map_err(io_error)?;
    let udp = Arc::new(UdpSocket::bind(address).await.map_err(io_error)?);
    let state = Arc::new(Mutex::new(DnsState {
        mode: "both".into(),
        ttl: 1,
    }));
    let queries = Arc::new(DnsCounts::default());
    let mut tasks = tokio::task::JoinSet::new();
    let udp_state = Arc::clone(&state);
    let udp_queries = Arc::clone(&queries);
    let udp_upstream = upstream.clone();
    tasks.spawn(async move {
        let mut bytes = vec![0u8; 65535];
        loop {
            let Ok((size, peer)) = udp.recv_from(&mut bytes).await else {
                break;
            };
            let Ok(query) = Message::from_vec(&bytes[..size]) else {
                continue;
            };
            udp_queries.query(&query, false);
            let state = udp_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if state.mode == "timeout" {
                continue;
            }
            if let Some(answer) = dns_answer(query, &state, &udp_upstream, false)
                && udp
                    .send_to(&answer, peer)
                    .await
                    .is_ok_and(|size| size == answer.len())
            {
                udp_queries.response_written(&answer, false);
            }
        }
    });
    let tcp_state = Arc::clone(&state);
    let tcp_queries = Arc::clone(&queries);
    tasks.spawn(async move {
        let gate = Arc::new(Semaphore::new(32));
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                Some(_) = connections.join_next(), if !connections.is_empty() => {},
                accepted = tcp.accept() => {
                    let Ok((mut socket, _)) = accepted else { break };
                    let Ok(permit) = Arc::clone(&gate).try_acquire_owned() else { continue };
                    let state = Arc::clone(&tcp_state);
                    let count = Arc::clone(&tcp_queries);
                    let upstream = upstream.clone();
                    connections.spawn(async move {
                        let _permit = permit;
                        while let Ok(size) = socket.read_u16().await {
                            let mut bytes = vec![0; size as usize];
                            if socket.read_exact(&mut bytes).await.is_err() { break; }
                            let Ok(query) = Message::from_vec(&bytes) else { break };
                            count.query(&query, true);
                            let state = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
                            if state.mode == "timeout" { break; }
                            let Some(answer) = dns_answer(query, &state, &upstream, true) else { break };
                            let Ok(size) = u16::try_from(answer.len()) else { break };
                            if socket.write_u16(size).await.is_err() || socket.write_all(&answer).await.is_err() { break; }
                            count.response_written(&answer, true);
                        }
                    });
                }
            }
        }
    });
    control(
        Ready {
            role: "dns".into(),
            pid: std::process::id(),
            address,
            alternate: None,
            ipv6: None,
        },
        |command| {
            if let FixtureCommand::Dns { mode, ttl } = command {
                let allowed: [&str; 11] = [
                    "a", "b", "both", "reverse", "ttl0", "nxdomain", "nodata", "servfail", "tcp",
                    "cname", "withdraw",
                ];
                if !allowed.contains(&mode.as_str())
                    && !matches!(
                        mode.as_str(),
                        "timeout" | "v6" | "both_v6" | "weights" | "weights_equal"
                    )
                {
                    return json!({"ok":false});
                }
                *state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = DnsState { mode, ttl };
            }
            queries.status()
        },
    )
    .await?;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

fn dns_answer(query: Message, state: &DnsState, upstream: &Ready, tcp: bool) -> Option<Vec<u8>> {
    let question = query.queries.first()?.clone();
    let name = question.name().clone();
    let kind = question.query_type();
    let mut answer = Message::response(query.id, query.op_code);
    answer.queries = query.queries;
    answer.metadata.recursion_available = true;
    answer.metadata.response_code = match state.mode.as_str() {
        "nxdomain" => ResponseCode::NXDomain,
        "servfail" => ResponseCode::ServFail,
        _ => ResponseCode::NoError,
    };
    answer.metadata.truncation = state.mode == "tcp" && !tcp;
    let ttl = if state.mode == "ttl0" { 0 } else { state.ttl };
    if !answer.metadata.truncation
        && answer.response_code == ResponseCode::NoError
        && state.mode != "nodata"
    {
        match kind {
            RecordType::SRV => {
                if state.mode == "withdraw" {
                    answer.answers.push(Record::from_rdata(
                        name.clone(),
                        ttl,
                        RData::SRV(SRV::new(0, 0, 0, Name::root())),
                    ));
                } else {
                    let mut rows = if state.mode == "v6" {
                        vec![("ipv6.discovery.test", 0, 1)]
                    } else if state.mode == "both_v6" {
                        vec![("a.discovery.test", 0, 1), ("ipv6.discovery.test", 0, 1)]
                    } else if state.mode == "weights" {
                        vec![("a.discovery.test", 0, 3), ("b.discovery.test", 0, 1)]
                    } else if state.mode == "weights_equal" {
                        vec![("a.discovery.test", 0, 1), ("b.discovery.test", 0, 1)]
                    } else if state.mode == "b" {
                        vec![("b.discovery.test", 0, 1)]
                    } else if state.mode == "a" {
                        vec![("a.discovery.test", 0, 1)]
                    } else {
                        vec![("a.discovery.test", 0, 1), ("b.discovery.test", 1, 2)]
                    };
                    if state.mode == "reverse" {
                        rows.reverse();
                    }
                    for (target, priority, weight) in rows {
                        answer.answers.push(Record::from_rdata(
                            name.clone(),
                            ttl,
                            RData::SRV(SRV::new(
                                priority,
                                weight,
                                upstream.address.port(),
                                Name::from_ascii(target).ok()?,
                            )),
                        ));
                    }
                }
            }
            RecordType::A | RecordType::AAAA => {
                let text = name.to_ascii();
                let alias = match text.as_str() {
                    "api.discovery.test." => Some("a.discovery.test"),
                    "a.discovery.test." => Some("a-canonical.discovery.test"),
                    "b.discovery.test." => Some("b-canonical.discovery.test"),
                    _ => None,
                };
                if state.mode == "cname" && alias.is_some() {
                    answer.answers.push(Record::from_rdata(
                        name.clone(),
                        ttl,
                        RData::CNAME(CNAME(Name::from_ascii(alias?).ok()?)),
                    ));
                } else {
                    let mut addresses = if text.as_str() == "ipv6.discovery.test."
                        || state.mode == "v6"
                    {
                        vec![upstream.ipv6?.ip()]
                    } else if state.mode == "both_v6" && text.as_str() == "api.discovery.test." {
                        vec![upstream.address.ip(), upstream.ipv6?.ip()]
                    } else if matches!(
                        text.as_str(),
                        "a.discovery.test." | "a-canonical.discovery.test."
                    ) || state.mode == "a"
                    {
                        vec![upstream.address.ip()]
                    } else if matches!(
                        text.as_str(),
                        "b.discovery.test." | "b-canonical.discovery.test."
                    ) || state.mode == "b"
                    {
                        vec![upstream.alternate?.ip()]
                    } else {
                        vec![upstream.address.ip(), upstream.alternate?.ip()]
                    };
                    if state.mode == "reverse" {
                        addresses.reverse();
                    }
                    for ip in addresses {
                        let data = match (kind, ip) {
                            (RecordType::A, std::net::IpAddr::V4(ip)) => RData::A(A(ip)),
                            (RecordType::AAAA, std::net::IpAddr::V6(ip)) => RData::AAAA(AAAA(ip)),
                            _ => continue,
                        };
                        answer
                            .answers
                            .push(Record::from_rdata(name.clone(), ttl, data));
                    }
                }
            }
            _ => {}
        }
    }
    if answer.answers.is_empty() && !answer.metadata.truncation {
        let zone = Name::from_ascii("discovery.test").ok()?;
        answer.authorities.push(Record::from_rdata(
            zone,
            1,
            RData::SOA(SOA::new(
                Name::from_ascii("ns.discovery.test").ok()?,
                Name::from_ascii("hostmaster.discovery.test").ok()?,
                1,
                1,
                1,
                1,
                1,
            )),
        ));
    }
    answer.to_vec().ok()
}

#[derive(Default)]
struct UpstreamState {
    // Immutable namespace for the newer resource campaign's explicit payload
    // faults. Absent in the old fixture plan, preserving legacy 6D behavior.
    resource_mode: bool,
    healthy_a: AtomicBool,
    healthy_b: AtomicBool,
    retry_a: AtomicBool,
    health_success_replies: AtomicU64,
    health_failure_replies: AtomicU64,
    requests: AtomicU64,
    request_faults: AtomicU64,
    request_body_errors: AtomicU64,
    request_content_faults: AtomicU64,
    request_timeouts: AtomicU64,
    retries: AtomicU64,
    cancellations: AtomicU64,
    connections: AtomicU64,
    release_epoch: AtomicU64,
    tunnels: Mutex<tokio::task::JoinSet<()>>,
    active_tunnels: Arc<AtomicU64>,
    payload_size: usize,
    request_read_delay: Duration,
    resource_fault: Mutex<ResourceFault>,
    resource_header_delays_started: AtomicU64,
    resource_mid_body_errors_emitted: AtomicU64,
    resource_cancelled_bodies: AtomicU64,
    resource_completed_bodies: AtomicU64,
    resource_uploads_verified: AtomicU64,
    resource_upload_bytes: AtomicU64,
    resource_cancellations: Mutex<VecDeque<ResourceCancelReceipt>>,
    resource_cancel_receipt_evictions: AtomicU64,
}

#[derive(Clone, serde::Serialize)]
struct ResourceCancelReceipt {
    operation_id: String,
    body_bytes: u64,
    dropped_ns: Option<u64>,
}

fn record_cancellation(state: &UpstreamState, operation_id: String, body_bytes: u64) {
    let mut receipts = state
        .resource_cancellations
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if receipts.len() >= 128 {
        receipts.pop_front();
        state
            .resource_cancel_receipt_evictions
            .fetch_add(1, Ordering::Relaxed);
    }
    receipts.push_back(ResourceCancelReceipt {
        operation_id,
        body_bytes,
        dropped_ns: super::resource_identity::monotonic_ns().ok(),
    });
}

#[derive(Clone, Default)]
struct ResourceFault {
    mode: String,
    target: String,
    delay_ms: u64,
    after_bytes: u64,
    case_id: u64,
}

impl ResourceFault {
    fn applies(&self, target: &str) -> bool {
        self.mode != "none"
            && !self.mode.is_empty()
            && (self.target == target || self.target == "all")
    }
}

struct ResourceStreamBody {
    prefix: Option<Bytes>,
    remaining: usize,
    trailers: Option<HeaderMap>,
    state: Arc<UpstreamState>,
    operation_id: String,
    cancelled_lane: bool,
    completed: bool,
    failed: bool,
    sent: u64,
    fault: Option<ResourceFault>,
    delay: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl Body for ResourceStreamBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if self.failed {
            return Poll::Ready(None);
        }
        if let Some(prefix) = self.prefix.take() {
            self.sent += prefix.len() as u64;
            return Poll::Ready(Some(Ok(Frame::data(prefix))));
        }
        if self.cancelled_lane && self.sent > 0 {
            return Poll::Pending;
        }
        if let Some(fault) = &self.fault
            && self.sent >= fault.after_bytes.max(1)
        {
            if self.delay.is_none() {
                self.delay = Some(Box::pin(tokio::time::sleep(Duration::from_millis(
                    fault.delay_ms.max(100),
                ))));
            }
            if self
                .delay
                .as_mut()
                .expect("error timer installed")
                .as_mut()
                .poll(cx)
                .is_pending()
            {
                return Poll::Pending;
            }
            self.state
                .resource_mid_body_errors_emitted
                .fetch_add(1, Ordering::Release);
            self.fault = None;
            self.failed = true;
            return Poll::Ready(Some(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "test-only injected resource body reset",
            ))));
        }
        if self.remaining > 0 {
            let length = self.remaining.min(1024);
            self.remaining -= length;
            self.sent += length as u64;
            return Poll::Ready(Some(Ok(Frame::data(Bytes::from(vec![b'x'; length])))));
        }
        if let Some(trailers) = self.trailers.take() {
            self.completed = true;
            self.state
                .resource_completed_bodies
                .fetch_add(1, Ordering::Release);
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
        }
        if !self.completed {
            self.completed = true;
            self.state
                .resource_completed_bodies
                .fetch_add(1, Ordering::Release);
        }
        Poll::Ready(None)
    }
}

impl Drop for ResourceStreamBody {
    fn drop(&mut self) {
        if self.cancelled_lane && self.sent > 0 && !self.completed {
            self.state
                .resource_cancelled_bodies
                .fetch_add(1, Ordering::Release);
            record_cancellation(&self.state, self.operation_id.clone(), self.sent);
        }
    }
}

type ResourceFixtureBody = http_body_util::combinators::UnsyncBoxBody<Bytes, std::io::Error>;

/// The exact process fixture route/body/ACK implementation, exposed only to
/// bounded real-gateway regression tests. Shutdown joins every accepted task.
#[cfg(test)]
pub(super) struct ResourceTestFixture {
    pub(super) address: std::net::SocketAddr,
    state: Arc<UpstreamState>,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

#[cfg(test)]
impl ResourceTestFixture {
    pub(super) fn set_retry_a(&self, enabled: bool) {
        self.state.retry_a.store(enabled, Ordering::Relaxed);
    }

    pub(super) fn retryable_status_replies(&self) -> u64 {
        self.state.retries.load(Ordering::Relaxed)
    }

    pub(super) async fn stop(self) {
        let _ = self.stop.send(());
        self.task.await.expect("all real fixture tasks joined");
        let mut tunnels =
            std::mem::take(&mut *self.state.tunnels.lock().expect("fixture tunnel owners"));
        while let Some(result) = tunnels.join_next().await {
            result.expect("actual fixture tunnel task joined");
        }
    }
}

#[cfg(test)]
pub(super) async fn resource_test_fixture(
    identity: &crate::common::TestIdentity,
) -> ResourceTestFixture {
    resource_test_fixture_named(identity, "a").await
}

#[cfg(test)]
pub(super) async fn resource_test_fixture_named(
    identity: &crate::common::TestIdentity,
    id: &'static str,
) -> ResourceTestFixture {
    resource_test_fixture_in_mode(identity, id, true).await
}

#[cfg(test)]
pub(super) async fn resource_test_fixture_in_mode(
    identity: &crate::common::TestIdentity,
    id: &'static str,
    resource_mode: bool,
) -> ResourceTestFixture {
    let key = PrivateKeyDer::from_pem_slice(identity.private_key_pem.as_bytes())
        .expect("ephemeral test-only key");
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("TLS defaults")
    .with_no_client_auth()
    .with_single_cert(vec![identity.certificate_der.clone()], key)
    .expect("matching identity");
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls = Arc::new(tls);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ephemeral upstream");
    let address = listener.local_addr().expect("actual upstream socket");
    let (stop, mut stopped) = tokio::sync::oneshot::channel();
    let state = Arc::new(UpstreamState {
        resource_mode,
        ..UpstreamState::default()
    });
    let serving = Arc::clone(&state);
    let task = tokio::spawn(async move {
        let state = serving;
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut stopped => break,
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    result.expect("fixture connection did not panic");
                }
                accepted = listener.accept() => {
                    let (socket, _) = accepted.expect("actual client");
                    let tls = Arc::clone(&tls);
                    let state = Arc::clone(&state);
                    connections.spawn(async move {
                        let socket = TlsAcceptor::from(tls).accept(socket).await.expect("verified TLS");
                        let sni = socket.get_ref().1.server_name().unwrap_or("").to_owned();
                        let h2 = socket.get_ref().1.alpn_protocol() == Some(b"h2");
                        let service = service_fn(move |request| serve_route(request, id, address, sni.clone(), Arc::clone(&state)));
                        if h2 {
                            let _ = http2::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(socket), service).await;
                        } else {
                            let _ = http1::Builder::new().serve_connection(TokioIo::new(socket), service).with_upgrades().await;
                        }
                    });
                }
            }
        }
        connections.abort_all();
        while let Some(result) = connections.join_next().await {
            if let Err(error) = result {
                assert!(error.is_cancelled(), "fixture task panicked: {error}");
            }
        }
    });
    ResourceTestFixture {
        address,
        state,
        stop,
        task,
    }
}

async fn serve_route(
    request: Request<Incoming>,
    id: &'static str,
    target: std::net::SocketAddr,
    sni: String,
    state: Arc<UpstreamState>,
) -> Result<Response<ResourceFixtureBody>, Infallible> {
    if request.uri().path() == "/__resource_cancel_ack" {
        let operation_id = request
            .headers()
            .get("x-resource-operation-id")
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty() && value.len() <= 128)
            .unwrap_or("");
        let acknowledged = state
            .resource_cancellations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find(|value| value.operation_id == operation_id)
            .cloned();
        let receipt = serde_json::to_vec(
            &json!({"operation_id":operation_id,"body_dropped_after_data":acknowledged.is_some(),"body_bytes":acknowledged.as_ref().map(|receipt|receipt.body_bytes),"dropped_ns":acknowledged.and_then(|receipt|receipt.dropped_ns),"termination":"cancelled_after_data"}),
        )
        .expect("fixed scalar fixture receipt");
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                Full::new(Bytes::from(receipt))
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .expect("fixture receipt metadata"));
    }
    if request.uri().path().starts_with("/base/resource/") {
        return Ok(serve_resource(request, id, target, sni, state).await);
    }
    serve(request, id, target, sni, state)
        .await
        .map(|response| response.map(|body| body.map_err(|never| match never {}).boxed_unsync()))
}

async fn serve_resource(
    mut request: Request<Incoming>,
    id: &'static str,
    target: std::net::SocketAddr,
    sni: String,
    state: Arc<UpstreamState>,
) -> Response<ResourceFixtureBody> {
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", |path| path.as_str())
        .to_owned();
    let authority = request
        .uri()
        .authority()
        .map(|authority| authority.to_string())
        .or_else(|| {
            request
                .headers()
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        })
        .unwrap_or_default();
    let operation_id = request
        .headers()
        .get("x-resource-operation-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 128)
        .unwrap_or("")
        .to_owned();
    let grpc = request
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|value| value == "application/grpc");
    let length = |name: &str| {
        request
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|length| *length <= 16 * 1024 * 1024)
    };
    let (Some(upload_size), Some(payload_size)) = (
        length("x-resource-upload-length"),
        length("x-resource-response-length"),
    ) else {
        return resource_empty_response(StatusCode::BAD_REQUEST);
    };
    if operation_id.is_empty() || payload_size == 0 {
        return resource_empty_response(StatusCode::BAD_REQUEST);
    }
    let attempt = state.requests.fetch_add(1, Ordering::Relaxed);
    let uploaded = match tokio::time::timeout(
        Duration::from_secs(10),
        verify_resource_upload(request.body_mut(), grpc, upload_size),
    )
    .await
    {
        Ok(Ok(receipt)) => receipt,
        _ => {
            state.request_faults.fetch_add(1, Ordering::Relaxed);
            return resource_empty_response(StatusCode::BAD_REQUEST);
        }
    };
    state
        .resource_uploads_verified
        .fetch_add(1, Ordering::Release);
    state
        .resource_upload_bytes
        .fetch_add(uploaded.0, Ordering::Release);
    // The qualification switch must exercise real, pre-head retry behavior
    // for ordinary zero-body GETs, not affect upload/gRPC/cancellation lanes.
    // Keep the legacy fixture's endpoint/method/cadence and actual counter.
    if request.uri().path() == "/base/resource/payload"
        && uploaded.0 == 0
        && !grpc
        && retryable_reply(&state, id, request.method(), attempt)
    {
        return Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .header("x-fixture-upstream", id)
            .header("x-fixture-peer", target.to_string())
            .header("x-fixture-authority", authority)
            .header("x-fixture-path", path)
            .header("x-fixture-sni", sni)
            .header("x-resource-operation-id", operation_id)
            .header("x-resource-upload-bytes", uploaded.0)
            .header("x-resource-upload-sha256", uploaded.1)
            .header("x-resource-upload-eof", "true")
            .body(
                Full::new(Bytes::from_static(b"retryable"))
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .expect("bounded actual retry response");
    }
    let configured = state
        .resource_fault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let fault = configured.applies(id).then_some(configured);
    if let Some(fault) = &fault
        && fault.mode == "header_delay"
    {
        state
            .resource_header_delays_started
            .fetch_add(1, Ordering::Release);
        tokio::time::sleep(Duration::from_millis(fault.delay_ms)).await;
    }
    let mut trailers = HeaderMap::new();
    if grpc {
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        trailers.insert("grpc-message", HeaderValue::from_static("ok"));
    }
    let prefix = if grpc {
        let mut prefix = vec![0];
        prefix.extend_from_slice(&(payload_size as u32).to_be_bytes());
        Some(Bytes::from(prefix))
    } else {
        None
    };
    let body = ResourceStreamBody {
        prefix,
        remaining: payload_size,
        trailers: grpc.then_some(trailers),
        state: Arc::clone(&state),
        operation_id: operation_id.clone(),
        cancelled_lane: path.starts_with("/base/resource/cancel"),
        completed: false,
        failed: false,
        sent: 0,
        fault: fault
            .as_ref()
            .filter(|fault| fault.mode == "mid_body_error")
            .cloned(),
        delay: None,
    }
    .boxed_unsync();
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            if grpc {
                "application/grpc"
            } else {
                "application/octet-stream"
            },
        )
        .header("x-fixture-upstream", id)
        .header("x-fixture-peer", target.to_string())
        .header("x-fixture-authority", authority)
        .header("x-fixture-path", path)
        .header("x-fixture-sni", sni)
        .header("x-resource-operation-id", operation_id)
        .header("x-resource-upload-bytes", uploaded.0)
        .header("x-resource-upload-sha256", uploaded.1)
        .header("x-resource-upload-eof", "true");
    if grpc {
        response = response.header(header::TRAILER, "grpc-status, grpc-message");
    }
    if let Some(fault) = fault {
        response = response.header("x-resource-fault-case-id", fault.case_id);
    }
    response
        .body(body)
        .expect("test-only bounded resource metadata")
}

fn resource_empty_response(status: StatusCode) -> Response<ResourceFixtureBody> {
    Response::builder()
        .status(status)
        .body(
            Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .expect("resource empty response")
}

async fn verify_resource_upload<B: Body<Data = Bytes> + Unpin>(
    body: &mut B,
    grpc: bool,
    size: usize,
) -> Result<(u64, String), RequestFault> {
    let mut prefix = vec![0];
    prefix.extend_from_slice(&(size as u32).to_be_bytes());
    let length = size + if grpc { 5 } else { 0 };
    let mut seen = 0usize;
    let mut digest = Sha256::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| RequestFault::Body)?;
        if let Some(data) = frame.data_ref() {
            let end = seen
                .checked_add(data.len())
                .filter(|end| *end <= length)
                .ok_or(RequestFault::Content)?;
            for (offset, byte) in data.iter().enumerate() {
                let at = seen + offset;
                let expected = if grpc && at < 5 { prefix[at] } else { b'u' };
                if *byte != expected {
                    return Err(RequestFault::Content);
                }
            }
            digest.update(data);
            seen = end;
        }
    }
    if seen != length {
        return Err(RequestFault::Content);
    }
    Ok((
        seen as u64,
        digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    ))
}

struct StreamBody {
    data: Option<Bytes>,
    trailers: Option<HeaderMap>,
    hold: bool,
    state: Arc<UpstreamState>,
    completed: bool,
    remaining: usize,
    release_epoch: u64,
    wait: Option<Pin<Box<tokio::time::Sleep>>>,
    capture_operation_id: Option<String>,
    sent: u64,
}
impl Body for StreamBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if let Some(data) = self.data.take() {
            self.sent += data.len() as u64;
            return Poll::Ready(Some(Ok(Frame::data(data))));
        }
        if self.hold && self.state.release_epoch.load(Ordering::Acquire) == self.release_epoch {
            if self.wait.is_none() {
                self.wait = Some(Box::pin(tokio::time::sleep(Duration::from_millis(20))));
            }
            if self
                .wait
                .as_mut()
                .expect("installed hold timer")
                .as_mut()
                .poll(cx)
                .is_ready()
            {
                self.wait = None;
                cx.waker().wake_by_ref();
            }
            return Poll::Pending;
        }
        if self.remaining > 0 {
            let size = self.remaining.min(1024);
            self.remaining -= size;
            self.sent += size as u64;
            return Poll::Ready(Some(Ok(Frame::data(Bytes::from(vec![b'x'; size])))));
        }
        if let Some(trailers) = self.trailers.take() {
            self.completed = true;
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
        }
        self.completed = true;
        Poll::Ready(None)
    }
}
impl Drop for StreamBody {
    fn drop(&mut self) {
        if self.hold
            && !self.completed
            && self.state.release_epoch.load(Ordering::Acquire) == self.release_epoch
        {
            self.state.cancellations.fetch_add(1, Ordering::Relaxed);
            if self.sent > 0
                && let Some(operation_id) = &self.capture_operation_id
            {
                record_cancellation(&self.state, operation_id.clone(), self.sent);
            }
        }
    }
}
type FixtureBody = http_body_util::combinators::UnsyncBoxBody<Bytes, Infallible>;

pub(super) async fn upstream(root: PathBuf) -> Result<(), SoakError> {
    let pem = std::fs::read(root.join("gateway.pem")).map_err(io_error)?;
    let key = std::fs::read(root.join("gateway-key.pem")).map_err(io_error)?;
    let certs = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(io_error)?;
    let key = PrivateKeyDer::from_pem_slice(&key).map_err(io_error)?;
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(io_error)?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(io_error)?;
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let first = TcpListener::bind("127.0.0.1:0").await.map_err(io_error)?;
    let address = first.local_addr().map_err(io_error)?;
    let second_address =
        std::net::SocketAddr::new("127.0.0.2".parse().map_err(io_error)?, address.port());
    let second = match TcpListener::bind(second_address).await {
        Ok(listener) => listener,
        Err(error) if error.kind() == std::io::ErrorKind::AddrNotAvailable => TcpListener::bind(
            std::net::SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), address.port()),
        )
        .await
        .map_err(io_error)?,
        Err(error) => return Err(io_error(error)),
    };
    let alternate = second.local_addr().map_err(io_error)?;
    // The additional fixture listener is explicit on Linux too: the second
    // IPv4 address is never reported as positive AAAA coverage.
    let ipv6_listener = if alternate.is_ipv6() {
        None
    } else {
        Some(
            TcpListener::bind(std::net::SocketAddr::new(
                std::net::Ipv6Addr::LOCALHOST.into(),
                address.port(),
            ))
            .await
            .map_err(io_error)?,
        )
    };
    let ipv6_address = if let Some(listener) = &ipv6_listener {
        listener.local_addr().map_err(io_error)?
    } else {
        alternate
    };
    let plan: Value =
        serde_json::from_slice(&std::fs::read(root.join("fixture-plan.json")).map_err(io_error)?)
            .map_err(json_error)?;
    let payload_size = plan["payload_size"]
        .as_u64()
        .and_then(|v| usize::try_from(v).ok())
        .filter(|v| *v > 0 && *v <= 16 * 1024 * 1024)
        .ok_or_else(|| fail("fixture payload bound"))?;
    let state = Arc::new(UpstreamState {
        resource_mode: fixture_resource_mode(&plan)?,
        payload_size,
        request_read_delay: Duration::from_millis(
            plan["request_read_delay_ms"].as_u64().unwrap_or(0).min(500),
        ),
        ..UpstreamState::default()
    });
    state.healthy_a.store(true, Ordering::Relaxed);
    state.healthy_b.store(true, Ordering::Relaxed);
    let mut tasks = tokio::task::JoinSet::new();
    let mut listeners = vec![(first, "a"), (second, "b")];
    if let Some(listener) = ipv6_listener {
        listeners.push((listener, "ipv6"));
    }
    for (listener, id) in listeners {
        let tls = Arc::new(tls.clone());
        let state = Arc::clone(&state);
        tasks.spawn(async move{let gate=Arc::new(Semaphore::new(256));let mut conns=tokio::task::JoinSet::new();loop{tokio::select!{Some(_)=conns.join_next(),if !conns.is_empty()=>{},accepted=listener.accept()=>{let Ok((socket,_))=accepted else{break};let Ok(target)=socket.local_addr()else{continue};let Ok(permit)=Arc::clone(&gate).try_acquire_owned()else{continue};let tls=Arc::clone(&tls);let state=Arc::clone(&state);conns.spawn(async move{let _permit=permit;let Ok(socket)=TlsAcceptor::from(tls).accept(socket).await else{return};state.connections.fetch_add(1,Ordering::Relaxed);let sni=socket.get_ref().1.server_name().unwrap_or("").to_owned();let h2=socket.get_ref().1.alpn_protocol()==Some(b"h2");let narrow_upload_window=!state.request_read_delay.is_zero();let service=service_fn(move|request|serve_route(request,id,target,sni.clone(),Arc::clone(&state)));if h2{let mut builder=http2::Builder::new(TokioExecutor::new());if narrow_upload_window{builder.initial_stream_window_size(1);}let _=builder.serve_connection(TokioIo::new(socket),service).await;}else{let _=http1::Builder::new().serve_connection(TokioIo::new(socket),service).with_upgrades().await;}});}}}});
    }
    control(Ready{role:"upstream".into(),pid:std::process::id(),address,alternate:Some(alternate),ipv6:Some(ipv6_address)},|command|{match command{FixtureCommand::Health{healthy_a,healthy_b,retry_a}=>{state.healthy_a.store(healthy_a,Ordering::Relaxed);state.healthy_b.store(healthy_b,Ordering::Relaxed);state.retry_a.store(retry_a,Ordering::Relaxed);},FixtureCommand::Release=>{state.release_epoch.fetch_add(1,Ordering::Release);},FixtureCommand::ResourceFault{mode,target,delay_ms,after_bytes,case_id}=>{
        if !matches!(mode.as_str(),"none"|"header_delay"|"mid_body_error") || !matches!(target.as_str(),"all"|"a"|"b"|"ipv6") || delay_ms>60_000 || after_bytes>16*1024*1024 { return json!({"ok":false,"code":"fixture.invalid_resource_fault"}); }
        *state.resource_fault.lock().unwrap_or_else(std::sync::PoisonError::into_inner)=ResourceFault{mode,target,delay_ms,after_bytes,case_id};
    },_=>{}}
        json!({"ok":true,"requests":state.requests.load(Ordering::Relaxed),"request_faults":state.request_faults.load(Ordering::Relaxed),"request_body_errors":state.request_body_errors.load(Ordering::Relaxed),"request_content_faults":state.request_content_faults.load(Ordering::Relaxed),"request_timeouts":state.request_timeouts.load(Ordering::Relaxed),"retries":state.retries.load(Ordering::Relaxed),"retryable_status_replies":state.retries.load(Ordering::Relaxed),"health_success_replies":state.health_success_replies.load(Ordering::Relaxed),"health_failure_replies":state.health_failure_replies.load(Ordering::Relaxed),"body_drops":state.cancellations.load(Ordering::Relaxed),"connections":state.connections.load(Ordering::Relaxed),"active_tunnels":state.active_tunnels.load(Ordering::Relaxed),"resource_header_delays_started":state.resource_header_delays_started.load(Ordering::Acquire),"resource_mid_body_errors_emitted":state.resource_mid_body_errors_emitted.load(Ordering::Acquire),"resource_cancelled_bodies":state.resource_cancelled_bodies.load(Ordering::Acquire),"resource_completed_bodies":state.resource_completed_bodies.load(Ordering::Acquire),"resource_uploads_verified":state.resource_uploads_verified.load(Ordering::Acquire),"resource_upload_bytes":state.resource_upload_bytes.load(Ordering::Acquire),"resource_cancelled_operation_ids":state.resource_cancellations.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone(),"resource_cancel_receipt_evictions":state.resource_cancel_receipt_evictions.load(Ordering::Relaxed)})}).await?;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    let mut tunnels = std::mem::take(
        &mut *state
            .tunnels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    );
    tunnels.abort_all();
    while tunnels.join_next().await.is_some() {}
    Ok(())
}

fn fixture_resource_mode(plan: &Value) -> Result<bool, SoakError> {
    match plan.get("resource_mode") {
        None => Ok(false),
        Some(Value::Bool(enabled)) => Ok(*enabled),
        Some(_) => Err(fail("fixture.invalid_resource_mode")),
    }
}

async fn serve(
    mut request: Request<Incoming>,
    id: &'static str,
    target: std::net::SocketAddr,
    sni: String,
    state: Arc<UpstreamState>,
) -> Result<Response<FixtureBody>, Infallible> {
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", |path| path.as_str())
        .to_owned();
    let authority = request.uri().authority().map_or_else(
        || {
            request
                .headers()
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned()
        },
        |a| a.to_string(),
    );
    if path.contains("healthz") {
        return Ok(Response::builder()
            .status(health_reply_status(&state, id))
            .body(Full::new(Bytes::new()).boxed_unsync())
            .expect("fixture health response"));
    }
    let attempt = state.requests.fetch_add(1, Ordering::Relaxed);
    if !state.resource_mode && retryable_reply(&state, id, request.method(), attempt) {
        return Ok(Response::builder()
            .status(503)
            .body(Full::new(Bytes::from_static(b"retryable")).boxed_unsync())
            .expect("fixture retry response"));
    }
    if request.headers().get(header::UPGRADE).is_some() {
        let upgrade = hyper::upgrade::on(&mut request);
        let active = Arc::clone(&state.active_tunnels);
        let mut tunnels = state
            .tunnels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while tunnels.try_join_next().is_some() {}
        tunnels.spawn(async move {
            struct TunnelCount(Arc<AtomicU64>);
            impl Drop for TunnelCount {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::Relaxed);
                }
            }
            active.fetch_add(1, Ordering::Relaxed);
            let _guard = TunnelCount(active);
            if let Ok(io) = upgrade.await {
                let mut io = TokioIo::new(io);
                let mut bytes = [0u8; 1024];
                while let Ok(size) = io.read(&mut bytes).await {
                    if size == 0 || io.write_all(&bytes[..size]).await.is_err() {
                        break;
                    }
                }
                // Finish the fixture's transport side, rather than dropping a
                // TLS socket without close-notify and inventing a graceful EOF.
                if io.shutdown().await.is_err() {
                    eprintln!("{}", json!({"event":"fixture_tunnel_shutdown_error"}));
                }
            }
        });
        return Ok(Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(header::CONNECTION, "upgrade")
            .header(header::UPGRADE, "websocket")
            .header("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
            .header("x-fixture-upstream", id)
            .header("x-fixture-peer", target.to_string())
            .header("x-fixture-authority", authority)
            .header("x-fixture-path", path)
            .header("x-fixture-sni", sni)
            .body(Full::new(Bytes::new()).boxed_unsync())
            .expect("fixture trusted upstream upgrade"));
    }
    let grpc = request
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|v| v.as_bytes().starts_with(b"application/grpc"));
    if !state.request_read_delay.is_zero() {
        tokio::time::sleep(state.request_read_delay).await;
    }
    let checked = tokio::time::timeout(
        Duration::from_secs(5),
        verify_request_body(request.body_mut(), grpc),
    )
    .await;
    if !matches!(checked, Ok(Ok(()))) {
        match checked {
            Ok(Err(RequestFault::Body)) => {
                state.request_body_errors.fetch_add(1, Ordering::Relaxed);
            }
            Ok(Err(RequestFault::Content)) => {
                state.request_content_faults.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                state.request_timeouts.fetch_add(1, Ordering::Relaxed);
            }
            Ok(Ok(())) => unreachable!("checked above"),
        }
        state.request_faults.fetch_add(1, Ordering::Relaxed);
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::new(Bytes::new()).boxed_unsync())
            .expect("fixture rejects invalid request without successful gRPC trailers"));
    }
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", HeaderValue::from_static("0"));
    trailers.insert("grpc-message", HeaderValue::from_static("ok"));
    let data = if grpc {
        let mut first = vec![0u8];
        first.extend_from_slice(&(state.payload_size as u32).to_be_bytes());
        first.extend_from_slice(&vec![b'x'; state.payload_size.min(1024)]);
        Bytes::from(first)
    } else {
        Bytes::from(id)
    };
    let hold = path.contains("cancel") || path.contains("hold");
    let body = StreamBody {
        data: Some(data),
        trailers: grpc.then_some(trailers),
        hold,
        remaining: state
            .payload_size
            .saturating_sub(if grpc { 1024 } else { 1 }),
        release_epoch: state.release_epoch.load(Ordering::Acquire),
        state,
        completed: false,
        wait: None,
        capture_operation_id: request
            .headers()
            .get("x-resource-operation-id")
            .and_then(|value| value.to_str().ok())
            .filter(|value| value.starts_with("prelude:") && value.len() <= 128)
            .map(str::to_owned),
        sent: 0,
    }
    .boxed_unsync();
    let mut response = Response::builder()
        .header("x-fixture-upstream", id)
        .header("x-fixture-peer", target.to_string())
        .header("x-fixture-authority", authority)
        .header("x-fixture-path", path)
        .header("x-fixture-sni", sni)
        .header(
            header::CONTENT_TYPE,
            if grpc {
                "application/grpc"
            } else {
                "application/octet-stream"
            },
        );
    if grpc {
        // HTTP/2 itself permits undeclared trailers, but this fixture also
        // deliberately qualifies safe HTTP/2-to-HTTP/1 bridging.
        response = response.header(header::TRAILER, "grpc-status, grpc-message");
    }
    Ok(response.body(body).expect("fixture response metadata"))
}

fn health_reply_status(state: &UpstreamState, id: &str) -> u16 {
    let healthy = if id == "a" {
        state.healthy_a.load(Ordering::Relaxed)
    } else {
        state.healthy_b.load(Ordering::Relaxed)
    };
    // These count responses produced for actual received fixture health
    // requests, not configuration switches. Public gateway health counters
    // separately prove which responses were received and classified.
    if healthy {
        state.health_success_replies.fetch_add(1, Ordering::Relaxed);
        200
    } else {
        state.health_failure_replies.fetch_add(1, Ordering::Relaxed);
        503
    }
}

fn retryable_reply(state: &UpstreamState, id: &str, method: &http::Method, attempt: u64) -> bool {
    if id == "a"
        && method == http::Method::GET
        && state.retry_a.load(Ordering::Relaxed)
        && attempt.is_multiple_of(3)
    {
        // A generated retryable 503 is not proof that the gateway retried;
        // campaign qualification also checks the gateway retry counter.
        state.retries.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        false
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RequestFault {
    Body,
    Content,
}

async fn verify_request_body<B>(body: &mut B, grpc: bool) -> Result<(), RequestFault>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Debug,
{
    // This is an opaque fixture vector, not a protobuf or gRPC decoder. Only
    // seven bytes may be retained, regardless of DATA frame segmentation.
    let expected: &[u8] = if grpc {
        &[0, 0, 0, 0, 2, b'h', b'i']
    } else {
        &[]
    };
    let mut offset = 0usize;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| {
            eprintln!("{}",json!({"event":"fixture_request_body_error","grpc":grpc,"received_bytes":offset,"error":format!("{error:?}")}));
            RequestFault::Body
        })?;
        if let Some(data) = frame.data_ref() {
            let end = offset
                .checked_add(data.len())
                .filter(|end| *end <= expected.len())
                .ok_or(RequestFault::Content)?;
            if data.as_ref() != &expected[offset..end] {
                return Err(RequestFault::Content);
            }
            offset = end;
        }
    }
    if offset != expected.len() {
        return Err(RequestFault::Content);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use hickory_resolver::proto::op::Query;

    use super::*;

    fn resource_body(
        state: Arc<UpstreamState>,
        size: usize,
        cancellation: bool,
    ) -> ResourceStreamBody {
        ResourceStreamBody {
            prefix: None,
            remaining: size,
            trailers: None,
            state,
            operation_id: "cancel-op".into(),
            cancelled_lane: cancellation,
            completed: false,
            failed: false,
            sent: 0,
            fault: None,
            delay: None,
        }
    }

    #[tokio::test]
    async fn resource_completion_cancellation_and_failure_use_actual_body_events() {
        let state = Arc::new(UpstreamState::default());
        let unpolled = resource_body(Arc::clone(&state), 1025, true);
        drop(unpolled);
        assert_eq!(state.resource_cancelled_bodies.load(Ordering::Acquire), 0);
        let mut cancelled = resource_body(Arc::clone(&state), 1025, true);
        assert_eq!(
            cancelled
                .frame()
                .await
                .expect("first DATA")
                .expect("DATA")
                .data_ref()
                .expect("DATA")
                .len(),
            1024
        );
        assert_eq!(state.resource_cancelled_bodies.load(Ordering::Acquire), 0);
        assert!(
            state
                .resource_cancellations
                .lock()
                .expect("receipt lock")
                .is_empty()
        );
        drop(cancelled);
        assert_eq!(state.resource_cancelled_bodies.load(Ordering::Acquire), 1);
        let receipt = state.resource_cancellations.lock().expect("receipt lock")[0].clone();
        assert_eq!(receipt.operation_id, "cancel-op");
        assert_eq!(receipt.body_bytes, 1024);
        assert!(receipt.dropped_ns.is_some());

        let mut complete = resource_body(Arc::clone(&state), 1025, false);
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        complete.trailers = Some(trailers);
        let mut bytes = 0;
        let mut trailer_seen = false;
        while let Some(frame) = complete.frame().await {
            let frame = frame.expect("normal frame");
            if let Some(data) = frame.data_ref() {
                bytes += data.len();
                assert!(data.iter().all(|byte| *byte == b'x'));
            }
            if let Some(trailers) = frame.trailers_ref() {
                trailer_seen = trailers["grpc-status"] == "0";
            }
        }
        assert_eq!(bytes, 1025);
        assert!(trailer_seen);
        drop(complete);
        assert_eq!(state.resource_completed_bodies.load(Ordering::Acquire), 1);
        assert_eq!(state.resource_cancelled_bodies.load(Ordering::Acquire), 1);

        let mut failed = resource_body(Arc::clone(&state), 4096, false);
        failed.fault = Some(ResourceFault {
            mode: "mid_body_error".into(),
            target: "a".into(),
            delay_ms: 0,
            after_bytes: 1,
            case_id: 7,
        });
        assert!(
            failed
                .frame()
                .await
                .expect("actual DATA")
                .expect("DATA")
                .data_ref()
                .is_some()
        );
        assert_eq!(
            state
                .resource_mid_body_errors_emitted
                .load(Ordering::Acquire),
            0
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(1), failed.frame())
                .await
                .expect("bounded fixture timer")
                .expect("actual error frame")
                .is_err()
        );
        assert!(
            failed.frame().await.is_none(),
            "error is terminal, not followed by successful EOF accounting"
        );
        drop(failed);
        assert_eq!(
            state
                .resource_mid_body_errors_emitted
                .load(Ordering::Acquire),
            1
        );
        assert_eq!(state.resource_completed_bodies.load(Ordering::Acquire), 1);
        assert_eq!(state.resource_cancelled_bodies.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn resource_upload_verifier_requires_every_wire_byte_and_eof() {
        for grpc in [false, true] {
            let mut bytes = Vec::new();
            if grpc {
                bytes.extend_from_slice(&[0, 0, 0, 0, 3]);
            }
            bytes.extend_from_slice(b"uuu");
            let expected: String = Sha256::digest(&bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            let mut valid = Full::new(Bytes::from(bytes.clone()));
            assert_eq!(
                verify_resource_upload(&mut valid, grpc, 3)
                    .await
                    .expect("verified upload"),
                (bytes.len() as u64, expected)
            );
            for candidate in [
                bytes[..bytes.len() - 1].to_vec(),
                {
                    let mut v = bytes.clone();
                    v.push(b'u');
                    v
                },
                {
                    let mut v = bytes.clone();
                    *v.last_mut().expect("payload") = b'x';
                    v
                },
            ] {
                let mut invalid = Full::new(Bytes::from(candidate));
                assert!(matches!(
                    verify_resource_upload(&mut invalid, grpc, 3).await,
                    Err(RequestFault::Content)
                ));
            }
        }
    }

    #[tokio::test]
    async fn cancellation_receipts_are_bounded_and_do_not_count_unpolled_bodies() {
        let state = Arc::new(UpstreamState::default());
        for sequence in 0..130 {
            let mut body = resource_body(Arc::clone(&state), 1024, true);
            body.operation_id = format!("cancel-{sequence}");
            body.frame().await.expect("DATA").expect("frame");
            drop(body);
        }
        let receipts = state
            .resource_cancellations
            .lock()
            .expect("bounded receipts");
        assert_eq!(receipts.len(), 128);
        assert_eq!(
            receipts.front().expect("oldest retained").operation_id,
            "cancel-2"
        );
        assert_eq!(
            state
                .resource_cancel_receipt_evictions
                .load(Ordering::Acquire),
            2
        );
        assert_eq!(state.resource_cancelled_bodies.load(Ordering::Acquire), 130);
    }

    #[test]
    fn resource_dns_modes_emit_actual_ipv6_and_explicit_srv_weights() {
        let ipv6 = answer("v6", "api.discovery.test.", RecordType::AAAA);
        assert!(ipv6.answers.iter().any(|record|matches!(&record.data,RData::AAAA(data) if data.0==std::net::Ipv6Addr::LOCALHOST)));
        assert!(
            answer("v6", "api.discovery.test.", RecordType::A)
                .answers
                .is_empty()
        );
        let service = "_https._tcp.api.discovery.test.";
        assert_eq!(
            srv_rows(&answer("v6", service, RecordType::SRV)),
            vec![("ipv6.discovery.test.".into(), 0, 1, 8443)]
        );
        assert_eq!(
            srv_rows(&answer("weights", service, RecordType::SRV)),
            vec![
                ("a.discovery.test.".into(), 0, 3, 8443),
                ("b.discovery.test.".into(), 0, 1, 8443)
            ]
        );
        let equal = srv_rows(&answer("weights_equal", service, RecordType::SRV));
        let weighted = srv_rows(&answer("weights", service, RecordType::SRV));
        assert_eq!(
            equal,
            vec![
                ("a.discovery.test.".into(), 0, 1, 8443),
                ("b.discovery.test.".into(), 0, 1, 8443)
            ]
        );
        assert_eq!(
            equal
                .iter()
                .map(|(target, priority, _, port)| (target, priority, port))
                .collect::<Vec<_>>(),
            weighted
                .iter()
                .map(|(target, priority, _, port)| (target, priority, port))
                .collect::<Vec<_>>(),
            "only weights change, not priority, port or identity"
        );
        let counts = DnsCounts::default();
        assert_eq!(counts.status()["positive_aaaa_answers"], 0);
        assert_eq!(counts.status()["srv_equal_weight_answers"], 0);
        assert_eq!(
            counts.status()["srv_weighted_answers"],
            0,
            "preparing answers alone is not coverage"
        );
        for (mode, name, kind) in [
            ("v6", "api.discovery.test.", RecordType::AAAA),
            ("weights_equal", service, RecordType::SRV),
            ("weights", service, RecordType::SRV),
        ] {
            counts.response_written(
                &answer(mode, name, kind).to_vec().expect("encoded packet"),
                false,
            );
        }
        assert_eq!(counts.status()["positive_aaaa_answers"], 1);
        assert_eq!(counts.status()["srv_equal_weight_answers"], 1);
        assert_eq!(counts.status()["srv_weighted_answers"], 1);
    }

    #[tokio::test]
    async fn resource_upgrade_raw_uses_actual_echo_bytes_and_peer_eof() {
        let identity = crate::common::identity().expect("test-only TLS identity");
        let client = crate::common::client_config(&[&identity], &[b"http/1.1"])
            .expect("verified test client");
        let key =
            PrivateKeyDer::from_pem_slice(identity.private_key_pem.as_bytes()).expect("test key");
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .with_no_client_auth()
        .with_single_cert(vec![identity.certificate_der], key)
        .expect("test chain and key");
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("ephemeral fixture");
        let address = listener.local_addr().expect("actual physical socket");
        let state = Arc::new(UpstreamState::default());
        let serving = Arc::clone(&state);
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("client");
            let socket = TlsAcceptor::from(Arc::new(tls))
                .accept(socket)
                .await
                .expect("real TLS handshake");
            let sni = socket
                .get_ref()
                .1
                .server_name()
                .expect("verified fixture SNI")
                .to_owned();
            let service = service_fn(move |request| {
                serve_route(request, "a", address, sni.clone(), Arc::clone(&serving))
            });
            http1::Builder::new()
                .serve_connection(TokioIo::new(socket), service)
                .with_upgrades()
                .await
                .expect("actual HTTP/1 upgrade driver");
        });
        let facts = super::super::client::measure_resource_upgrade(
            address,
            client,
            "wire-upgrade-1".into(),
        )
        .await;
        assert_eq!(facts.status, Some(101));
        assert!(facts.request_head_sent && facts.tunnel_client_shutdown && facts.eof);
        assert_eq!(facts.error_code, None);
        assert_eq!(facts.echo_iterations, 4);
        assert_eq!(facts.body_bytes, 80);
        let expected: String = Sha256::digest(b"qualification-tunnel".repeat(4))
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(facts.body_sha256, expected);
        assert_eq!(
            facts.upstream_peer.as_deref(),
            Some(address.to_string().as_str())
        );
        assert_eq!(
            facts.path.as_deref(),
            Some("/ws"),
            "this tests the fixture/client directly, not a surrogate gateway"
        );
        assert_eq!(facts.authority.as_deref(), Some("gateway.example.test"));
        assert_eq!(facts.server_name.as_deref(), Some("gateway.example.test"));
        server.await.expect("HTTP/1 driver did not panic");
        tokio::time::timeout(Duration::from_secs(2), async {
            while state.active_tunnels.load(Ordering::Acquire) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("actual fixture tunnel finished while owner is alive");
        let mut tasks = std::mem::take(&mut *state.tunnels.lock().expect("task ownership"));
        while let Some(result) = tasks.join_next().await {
            result.expect("actual tunnel exit acknowledged");
        }
    }

    #[tokio::test]
    async fn forced_pre_head_drop_is_body_error_but_planned_stop_preserves_opaque_post() {
        struct SegmentedPost {
            first: Option<Bytes>,
            tail: Option<Bytes>,
            release: tokio::sync::oneshot::Receiver<()>,
        }
        impl Body for SegmentedPost {
            type Data = Bytes;
            type Error = Infallible;
            fn poll_frame(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
                if let Some(first) = self.first.take() {
                    return Poll::Ready(Some(Ok(Frame::data(first))));
                }
                if self.tail.is_none() {
                    return Poll::Ready(None);
                }
                if Pin::new(&mut self.release).poll(cx).is_pending() {
                    return Poll::Pending;
                }
                Poll::Ready(self.tail.take().map(|bytes| Ok(Frame::data(bytes))))
            }
            fn size_hint(&self) -> http_body::SizeHint {
                http_body::SizeHint::with_exact(
                    (self.first.as_ref().map_or(0, Bytes::len)
                        + self.tail.as_ref().map_or(0, Bytes::len)) as u64,
                )
            }
        }
        struct ObservedIncoming {
            body: Incoming,
            bytes: Arc<AtomicU64>,
        }
        impl Body for ObservedIncoming {
            type Data = Bytes;
            type Error = hyper::Error;
            fn poll_frame(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
                let frame = Pin::new(&mut self.body).poll_frame(cx);
                if let Poll::Ready(Some(Ok(frame))) = &frame
                    && let Some(data) = frame.data_ref()
                {
                    self.bytes.fetch_add(data.len() as u64, Ordering::Release);
                }
                frame
            }
        }
        async fn wait_for(counter: &AtomicU64, expected: u64) {
            tokio::time::timeout(Duration::from_secs(3), async {
                while counter.load(Ordering::Acquire) < expected {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .expect("bounded actual wire acknowledgment");
        }
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("ephemeral fixture");
        let address = listener.local_addr().expect("actual socket");
        let bytes = Arc::new(AtomicU64::new(0));
        let errors = Arc::new(AtomicU64::new(0));
        let complete = Arc::new(AtomicU64::new(0));
        let content_faults = Arc::new(AtomicU64::new(0));
        let observed = Arc::clone(&bytes);
        let observed_errors = Arc::clone(&errors);
        let observed_complete = Arc::clone(&complete);
        let observed_content_faults = Arc::clone(&content_faults);
        let server = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            for _ in 0..2 {
                let (socket, _) = listener.accept().await.expect("actual H2 client");
                let bytes = Arc::clone(&observed);
                let errors = Arc::clone(&observed_errors);
                let complete = Arc::clone(&observed_complete);
                let content_faults = Arc::clone(&observed_content_faults);
                connections.spawn(async move {
                    let service = service_fn(move |request: Request<Incoming>| {
                        let bytes = Arc::clone(&bytes);
                        let errors = Arc::clone(&errors);
                        let complete = Arc::clone(&complete);
                        let content_faults = Arc::clone(&content_faults);
                        async move {
                            assert_eq!(request.method(), http::Method::POST);
                            assert_eq!(request.headers()[header::CONTENT_TYPE], "application/grpc");
                            let mut body = ObservedIncoming {
                                body: request.into_body(),
                                bytes,
                            };
                            let status = match verify_request_body(&mut body, true).await {
                                Ok(()) => {
                                    complete.fetch_add(1, Ordering::Release);
                                    StatusCode::OK
                                }
                                Err(RequestFault::Body) => {
                                    errors.fetch_add(1, Ordering::Release);
                                    StatusCode::BAD_REQUEST
                                }
                                Err(RequestFault::Content) => {
                                    content_faults.fetch_add(1, Ordering::Release);
                                    StatusCode::BAD_REQUEST
                                }
                            };
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(status)
                                    .body(Full::new(Bytes::new()))
                                    .expect("fixture response"),
                            )
                        }
                    });
                    let _ = http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(socket), service)
                        .await;
                });
            }
            while let Some(result) = connections.join_next().await {
                result.expect("fixture task did not panic");
            }
        });
        for planned_stop in [false, true] {
            let socket = tokio::net::TcpStream::connect(address)
                .await
                .expect("actual loopback");
            let (mut sender, connection) = hyper::client::conn::http2::handshake::<
                _,
                _,
                SegmentedPost,
            >(TokioExecutor::new(), TokioIo::new(socket))
            .await
            .expect("actual H2 handshake");
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            let (release, tail) = tokio::sync::oneshot::channel();
            let (stop, mut stopped) = tokio::sync::watch::channel(false);
            let request = Request::builder()
                .method(http::Method::POST)
                .uri("http://opaque.fixture.test/Call")
                .header(header::CONTENT_TYPE, "application/grpc")
                .body(SegmentedPost {
                    first: Some(Bytes::from_static(&[0])),
                    tail: Some(Bytes::from_static(&[0, 0, 0, 2, b'h', b'i'])),
                    release: tail,
                })
                .expect("real seven-byte POST");
            let task = tokio::spawn(async move {
                if planned_stop {
                    super::super::client::complete_bounded_request(sender.send_request(request))
                        .await
                        .map(|response| response.status())
                } else {
                    tokio::select! {_=stopped.changed()=>Err("forced pre-head drop".to_owned()),response=sender.send_request(request)=>response.map(|response|response.status()).map_err(|error|error.to_string())}
                }
            });
            wait_for(&bytes, if planned_stop { 2 } else { 1 }).await;
            stop.send(true).expect("planned stop notification");
            if planned_stop {
                assert!(
                    !task.is_finished(),
                    "planned stop must not drop pending upload"
                );
                release
                    .send(())
                    .expect("release remaining six opaque bytes");
                assert_eq!(
                    task.await
                        .expect("bounded request worker")
                        .expect("intact request"),
                    StatusCode::OK
                );
                wait_for(&complete, 1).await;
            } else {
                assert!(task.await.expect("forced worker").is_err());
                driver.abort();
                wait_for(&errors, 1).await;
                drop(release);
            }
            driver.abort();
            let _ = driver.await;
        }
        assert_eq!(
            bytes.load(Ordering::Acquire),
            8,
            "one cancelled byte plus all seven planned bytes"
        );
        assert_eq!(
            errors.load(Ordering::Acquire),
            1,
            "forced reset is not exact-content corruption"
        );
        assert_eq!(content_faults.load(Ordering::Acquire), 0);
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .expect("fixture joined")
            .expect("fixture did not panic");
    }

    fn upstream() -> Ready {
        Ready {
            role: "upstream".into(),
            pid: 1,
            address: "127.0.0.1:8443".parse().expect("fixture A"),
            alternate: Some("127.0.0.2:8443".parse().expect("fixture B")),
            ipv6: Some("[::1]:8443".parse().expect("fixture IPv6")),
        }
    }

    fn answer(mode: &str, name: &str, kind: RecordType) -> Message {
        let mut query = Message::query();
        query.queries.push(Query::query(
            Name::from_ascii(name).expect("fixture query name"),
            kind,
        ));
        Message::from_vec(
            &dns_answer(
                query,
                &DnsState {
                    mode: mode.into(),
                    ttl: 3,
                },
                &upstream(),
                false,
            )
            .expect("fixture response"),
        )
        .expect("DNS encoded answer")
    }

    fn srv_rows(message: &Message) -> Vec<(String, u16, u16, u16)> {
        message
            .answers
            .iter()
            .map(|record| {
                let RData::SRV(data) = &record.data else {
                    panic!("expected SRV row")
                };
                (
                    data.target.to_ascii(),
                    data.priority,
                    data.weight,
                    data.port,
                )
            })
            .collect()
    }

    #[test]
    fn srv_reverse_changes_wire_order_without_changing_logical_rows() {
        let service = "_https._tcp.api.discovery.test.";
        let normal = srv_rows(&answer("both", service, RecordType::SRV));
        let reversed = srv_rows(&answer("reverse", service, RecordType::SRV));
        assert_eq!(normal.len(), 2);
        assert_eq!(normal[0], ("a.discovery.test.".into(), 0, 1, 8443));
        assert_eq!(normal[1], ("b.discovery.test.".into(), 1, 2, 8443));
        assert_eq!(reversed, normal.into_iter().rev().collect::<Vec<_>>());
    }

    #[test]
    fn srv_target_aliases_preserve_declared_group_and_correct_physical_address() {
        let service = "_https._tcp.api.discovery.test.";
        assert_eq!(
            srv_rows(&answer("cname", service, RecordType::SRV)),
            srv_rows(&answer("both", service, RecordType::SRV))
        );
        for (target, canonical, expected) in [
            (
                "a.discovery.test.",
                "a-canonical.discovery.test.",
                "127.0.0.1",
            ),
            (
                "b.discovery.test.",
                "b-canonical.discovery.test.",
                "127.0.0.2",
            ),
        ] {
            for kind in [RecordType::A, RecordType::AAAA] {
                let alias = answer("cname", target, kind);
                assert_eq!(alias.answers.len(), 1);
                let RData::CNAME(data) = &alias.answers[0].data else {
                    panic!("expected target CNAME")
                };
                assert_eq!(data.0.to_ascii(), canonical);
            }
            let physical = answer("cname", canonical, RecordType::A);
            assert_eq!(physical.answers.len(), 1);
            let RData::A(data) = &physical.answers[0].data else {
                panic!("expected canonical A")
            };
            assert_eq!(data.0.to_string(), expected);
            assert!(
                answer("cname", canonical, RecordType::AAAA)
                    .answers
                    .is_empty()
            );
        }
    }

    #[test]
    fn srv_withdrawal_and_zero_ttl_are_actual_wire_values() {
        let service = "_https._tcp.api.discovery.test.";
        assert_eq!(
            srv_rows(&answer("withdraw", service, RecordType::SRV)),
            vec![(".".into(), 0, 0, 0)]
        );
        let expired = answer("ttl0", service, RecordType::SRV);
        assert_eq!(expired.answers.len(), 2);
        assert!(expired.answers.iter().all(|record| record.ttl == 0));
    }

    #[test]
    fn dns_coverage_counts_received_queries_and_written_packet_features_only() {
        let counts = DnsCounts::default();
        let service = "_https._tcp.api.discovery.test.";
        for (kind, tcp) in [
            (RecordType::A, false),
            (RecordType::AAAA, false),
            (RecordType::SRV, true),
        ] {
            let mut query = Message::query();
            query.queries.push(Query::query(
                Name::from_ascii(service).expect("fixture name"),
                kind,
            ));
            counts.query(&query, tcp);
        }
        let state = counts.status();
        assert_eq!(state["queries"], 3);
        assert_eq!(state["udp_queries"], 2);
        assert_eq!(state["tcp_queries"], 1);
        assert_eq!(state["a_queries"], 1);
        assert_eq!(state["aaaa_queries"], 1);
        assert_eq!(state["srv_queries"], 1);
        assert_eq!(state["successful_response_writes"], 0);

        // Constructing packets or changing mode is not response coverage.
        let reversed = answer("reverse", service, RecordType::SRV);
        assert_eq!(counts.status()["reversed_srv_answers"], 0);
        counts.response_written(&reversed.to_vec().expect("encoded reverse"), false);
        counts.response_written(
            &answer("cname", "a.discovery.test.", RecordType::A)
                .to_vec()
                .expect("encoded alias"),
            false,
        );
        counts.response_written(
            &answer("withdraw", service, RecordType::SRV)
                .to_vec()
                .expect("encoded dot"),
            true,
        );
        counts.response_written(
            &answer("ttl0", service, RecordType::SRV)
                .to_vec()
                .expect("encoded expired"),
            false,
        );
        counts.response_written(
            &answer("tcp", service, RecordType::SRV)
                .to_vec()
                .expect("encoded truncation"),
            false,
        );
        for mode in ["nxdomain", "nodata", "servfail"] {
            counts.response_written(
                &answer(mode, service, RecordType::SRV)
                    .to_vec()
                    .expect("encoded negative"),
                false,
            );
        }
        counts.response_written(b"not a DNS packet", false);
        let state = counts.status();
        assert_eq!(state["successful_response_writes"], 8);
        for name in [
            "cname_answers",
            "withdraw_answers",
            "ttl_zero_answers",
            "reversed_srv_answers",
            "truncated_udp_answers",
            "nxdomain_answers",
            "nodata_answers",
            "server_failure_answers",
        ] {
            assert_eq!(state[name], 1, "actual packet feature {name}");
        }
    }

    #[test]
    fn health_and_retry_coverage_counts_replies_not_control_intentions() {
        let state = UpstreamState::default();
        state.healthy_a.store(true, Ordering::Relaxed);
        state.retry_a.store(true, Ordering::Relaxed);
        assert_eq!(state.health_success_replies.load(Ordering::Relaxed), 0);
        assert_eq!(state.health_failure_replies.load(Ordering::Relaxed), 0);
        assert_eq!(state.retries.load(Ordering::Relaxed), 0);
        assert_eq!(health_reply_status(&state, "a"), 200);
        assert_eq!(health_reply_status(&state, "b"), 503);
        state.healthy_a.store(false, Ordering::Relaxed);
        assert_eq!(state.health_failure_replies.load(Ordering::Relaxed), 1);
        assert_eq!(health_reply_status(&state, "a"), 503);
        assert_eq!(state.health_success_replies.load(Ordering::Relaxed), 1);
        assert_eq!(state.health_failure_replies.load(Ordering::Relaxed), 2);
        assert!(!retryable_reply(&state, "b", &http::Method::GET, 0));
        assert!(!retryable_reply(&state, "a", &http::Method::POST, 0));
        assert!(!retryable_reply(&state, "a", &http::Method::GET, 1));
        assert_eq!(state.retries.load(Ordering::Relaxed), 0);
        assert!(retryable_reply(&state, "a", &http::Method::GET, 3));
        assert_eq!(state.retries.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn resource_fixture_mode_is_explicit_typed_and_defaults_to_legacy() {
        assert!(!fixture_resource_mode(&json!({})).expect("old plan remains legacy"));
        assert!(!fixture_resource_mode(&json!({"resource_mode":false})).expect("explicit legacy"));
        assert!(
            fixture_resource_mode(&json!({"resource_mode":true}))
                .expect("explicit resource isolation")
        );
        for invalid in [json!(null), json!("true"), json!(0), json!([]), json!({})] {
            assert!(fixture_resource_mode(&json!({"resource_mode":invalid})).is_err());
        }
    }

    #[tokio::test]
    async fn resource_retry_switch_emits_actual_503_only_for_zero_body_payload_gets() {
        let identity = crate::common::identity().expect("ephemeral test identity");
        let config =
            crate::common::client_config(&[&identity], &[b"h2"]).expect("verified H2 client");
        let fixture = resource_test_fixture(&identity).await;
        fixture.set_retry_a(true);
        let tcp = tokio::net::TcpStream::connect(fixture.address)
            .await
            .expect("actual socket");
        let name =
            rustls::pki_types::ServerName::try_from("gateway.example.test").expect("test SNI");
        let tls = tokio_rustls::TlsConnector::from(config)
            .connect(name, tcp)
            .await
            .expect("verified TLS");
        let (mut sender, connection) = hyper::client::conn::http2::handshake::<_, _, Full<Bytes>>(
            TokioExecutor::new(),
            TokioIo::new(tls),
        )
        .await
        .expect("real H2");
        let driver = tokio::spawn(connection);
        let mut replies = Vec::new();
        for (sequence, method, path, upload, grpc) in [
            (0, http::Method::GET, "payload", 0, false),
            (1, http::Method::GET, "payload", 0, false),
            (2, http::Method::GET, "payload", 0, false),
            (3, http::Method::POST, "upload", 1024, false),
            (4, http::Method::POST, "grpc", 0, true),
            (5, http::Method::GET, "payload", 1024, false),
            (6, http::Method::GET, "payload", 1024, false),
            (7, http::Method::GET, "payload", 0, false),
            (8, http::Method::GET, "payload", 0, false),
            (9, http::Method::GET, "cancel", 0, false),
        ] {
            let mut bytes = Vec::new();
            if grpc {
                bytes.extend_from_slice(&[0, 0, 0, 0, 0]);
            }
            bytes.extend(std::iter::repeat_n(b'u', upload));
            let request = Request::builder()
                .method(method)
                .uri(format!("https://gateway.example.test/base/resource/{path}"))
                .header(
                    header::CONTENT_TYPE,
                    if grpc {
                        "application/grpc"
                    } else {
                        "application/octet-stream"
                    },
                )
                .header(
                    "x-resource-operation-id",
                    format!("retry-fixture:{sequence}"),
                )
                .header("x-resource-upload-length", upload)
                .header("x-resource-response-length", 4096)
                .body(Full::new(Bytes::from(bytes)))
                .expect("bounded request");
            sender.ready().await.expect("one actual admission");
            let response = sender
                .send_request(request)
                .await
                .expect("actual fixture reply");
            let status = response.status();
            let headers = response.headers().clone();
            let mut body = response.into_body();
            let mut received = Vec::new();
            let mut trailers = HeaderMap::new();
            while let Some(frame) = body.frame().await {
                let frame = frame.expect("actual wire frame");
                if let Some(bytes) = frame.data_ref() {
                    assert!(received.len() + bytes.len() <= 8192);
                    received.extend_from_slice(bytes);
                    if path == "cancel" && !bytes.is_empty() {
                        break;
                    }
                }
                if let Some(values) = frame.trailers_ref() {
                    trailers = values.clone();
                }
            }
            drop(body);
            if path == "cancel" {
                tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        let dropped = fixture
                            .state
                            .resource_cancellations
                            .lock()
                            .expect("bounded ACK ring")
                            .iter()
                            .any(|receipt| {
                                receipt.operation_id == "retry-fixture:9"
                                    && receipt.body_bytes == 1024
                            });
                        if dropped {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("actual cancellation Drop remains available when retry is enabled");
            }
            replies.push((status, headers, received, trailers));
        }
        let count = fixture.retryable_status_replies();
        drop(sender);
        tokio::time::timeout(Duration::from_secs(2), driver)
            .await
            .expect("actual driver exit")
            .expect("driver did not panic")
            .expect("normal transport end");
        fixture.stop().await;
        assert_eq!(count, 1, "actual resource A retry switch must not be inert");
        for (sequence, (status, headers, bytes, trailers)) in replies.iter().enumerate() {
            assert_eq!(headers["x-fixture-upstream"], "a");
            assert_eq!(headers["x-fixture-authority"], "gateway.example.test");
            assert_eq!(headers["x-fixture-sni"], "gateway.example.test");
            assert_eq!(status.as_u16(), if sequence == 0 { 503 } else { 200 });
            if sequence == 0 {
                assert_eq!(bytes, b"retryable");
                assert!(trailers.is_empty());
            } else if sequence == 4 {
                assert_eq!(&bytes[..5], &[0, 0, 0, 16, 0]);
                assert_eq!(&bytes[5..], vec![b'x'; 4096]);
                assert_eq!(trailers["grpc-status"], "0");
            } else if sequence == 9 {
                assert_eq!(bytes, &vec![b'x'; 1024]);
                assert!(trailers.is_empty());
            } else {
                assert_eq!(bytes, &vec![b'x'; 4096]);
                assert!(trailers.is_empty());
            }
        }
    }

    struct TestBody(VecDeque<Result<Frame<Bytes>, ()>>);
    impl Body for TestBody {
        type Data = Bytes;
        type Error = ();

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(self.0.pop_front())
        }
    }

    #[tokio::test]
    async fn opaque_request_verification_handles_split_data_and_rejects_faults() {
        let mut split = TestBody(VecDeque::from([
            Ok(Frame::data(Bytes::from_static(&[0, 0]))),
            Ok(Frame::data(Bytes::from_static(&[0, 0, 2, b'h', b'i']))),
        ]));
        assert_eq!(verify_request_body(&mut split, true).await, Ok(()));
        for bytes in [
            Bytes::new(),
            Bytes::from_static(&[0, 0, 0, 0, 2, b'h']),
            Bytes::from_static(&[0, 0, 0, 0, 2, b'h', b'x']),
            Bytes::from_static(&[0, 0, 0, 0, 2, b'h', b'i', b'x']),
        ] {
            let mut body = TestBody(VecDeque::from([Ok(Frame::data(bytes))]));
            assert_eq!(
                verify_request_body(&mut body, true).await,
                Err(RequestFault::Content)
            );
        }
        let mut failed = TestBody(VecDeque::from([
            Ok(Frame::data(Bytes::from_static(&[0, 0]))),
            Err(()),
        ]));
        assert_eq!(
            verify_request_body(&mut failed, true).await,
            Err(RequestFault::Body)
        );
        let mut empty = TestBody(VecDeque::new());
        assert_eq!(verify_request_body(&mut empty, false).await, Ok(()));
        let mut unexpected = TestBody(VecDeque::from([Ok(Frame::data(Bytes::from_static(
            b"unexpected GET body",
        )))]));
        assert_eq!(
            verify_request_body(&mut unexpected, false).await,
            Err(RequestFault::Content)
        );
    }

    #[tokio::test]
    async fn terminal_trailer_completion_is_not_a_cancelled_hold() {
        let state = Arc::new(UpstreamState::default());
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        let mut body = StreamBody {
            data: Some(Bytes::from_static(b"data")),
            trailers: Some(trailers),
            hold: false,
            state: Arc::clone(&state),
            completed: false,
            remaining: 0,
            release_epoch: 0,
            wait: None,
            capture_operation_id: None,
            sent: 0,
        };
        assert!(body.frame().await.expect("DATA").expect("frame").is_data());
        assert!(
            body.frame()
                .await
                .expect("trailers")
                .expect("frame")
                .is_trailers()
        );
        assert!(body.completed);
        drop(body);
        assert_eq!(state.cancellations.load(Ordering::Relaxed), 0);
        let mut released = StreamBody {
            data: None,
            trailers: None,
            hold: true,
            state: Arc::clone(&state),
            completed: false,
            remaining: 0,
            release_epoch: 0,
            wait: None,
            capture_operation_id: None,
            sent: 0,
        };
        state.release_epoch.fetch_add(1, Ordering::Release);
        assert!(released.frame().await.is_none());
        drop(released);
        assert_eq!(state.cancellations.load(Ordering::Relaxed), 0);
        let cancelled = StreamBody {
            data: None,
            trailers: None,
            hold: true,
            state: Arc::clone(&state),
            completed: false,
            remaining: 0,
            release_epoch: 1,
            wait: None,
            capture_operation_id: None,
            sent: 0,
        };
        drop(cancelled);
        assert_eq!(state.cancellations.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn capture_only_legacy_cancel_has_operation_bound_actual_drop_ack() {
        let state = Arc::new(UpstreamState::default());
        for polled in [false, true] {
            let mut body = StreamBody {
                data: Some(Bytes::from_static(b"data")),
                trailers: None,
                hold: true,
                state: Arc::clone(&state),
                completed: false,
                remaining: 0,
                release_epoch: 0,
                wait: None,
                capture_operation_id: Some(if polled { "prelude:2" } else { "prelude:1" }.into()),
                sent: 0,
            };
            if polled {
                body.frame().await.expect("actual DATA").expect("frame");
            }
            drop(body);
        }
        assert_eq!(
            state.cancellations.load(Ordering::Acquire),
            2,
            "legacy counter policy remains unchanged"
        );
        assert_eq!(
            state.resource_cancelled_bodies.load(Ordering::Acquire),
            0,
            "legacy body is not mislabeled as the new resource lane"
        );
        let receipts = state.resource_cancellations.lock().expect("bound receipt");
        assert_eq!(
            receipts.len(),
            1,
            "no actual DATA means no cancellation qualification ACK"
        );
        assert_eq!(receipts[0].operation_id, "prelude:2");
        assert_eq!(receipts[0].body_bytes, 4);
        assert!(receipts[0].dropped_ns.is_some());
    }

    #[tokio::test]
    async fn control_input_rejects_oversized_unterminated_line_before_collecting_it() {
        let oversized = vec![b'x'; 32 * 1024];
        let mut input = BufReader::new(oversized.as_slice());
        assert!(read_command(&mut input).await.is_err());
        let commands = b"{\"op\":\"status\"}\n{\"op\":\"stop\"}\n";
        let mut input = BufReader::new(commands.as_slice());
        assert!(matches!(
            read_command(&mut input).await.expect("status command"),
            Some(FixtureCommand::Status)
        ));
        assert!(matches!(
            read_command(&mut input).await.expect("stop command"),
            Some(FixtureCommand::Stop)
        ));
        assert!(read_command(&mut input).await.expect("EOF").is_none());
    }
}
