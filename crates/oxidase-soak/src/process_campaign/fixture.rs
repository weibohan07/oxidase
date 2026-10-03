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
        ] {
            if present {
                counter.fetch_add(1, Ordering::Relaxed);
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
        },
        |command| {
            if let FixtureCommand::Dns { mode, ttl } = command {
                let allowed: [&str; 11] = [
                    "a", "b", "both", "reverse", "ttl0", "nxdomain", "nodata", "servfail", "tcp",
                    "cname", "withdraw",
                ];
                if !allowed.contains(&mode.as_str()) && mode != "timeout" {
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
                    let mut rows = if state.mode == "b" {
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
                    let mut addresses = if matches!(
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
    healthy_a: AtomicBool,
    healthy_b: AtomicBool,
    retry_a: AtomicBool,
    health_success_replies: AtomicU64,
    health_failure_replies: AtomicU64,
    requests: AtomicU64,
    request_faults: AtomicU64,
    retries: AtomicU64,
    cancellations: AtomicU64,
    connections: AtomicU64,
    release_epoch: AtomicU64,
    tunnels: Mutex<tokio::task::JoinSet<()>>,
    active_tunnels: Arc<AtomicU64>,
    payload_size: usize,
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
}
impl Body for StreamBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if let Some(data) = self.data.take() {
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
    let plan: Value =
        serde_json::from_slice(&std::fs::read(root.join("fixture-plan.json")).map_err(io_error)?)
            .map_err(json_error)?;
    let payload_size = plan["payload_size"]
        .as_u64()
        .and_then(|v| usize::try_from(v).ok())
        .filter(|v| *v > 0 && *v <= 16 * 1024 * 1024)
        .ok_or_else(|| fail("fixture payload bound"))?;
    let state = Arc::new(UpstreamState {
        payload_size,
        ..UpstreamState::default()
    });
    state.healthy_a.store(true, Ordering::Relaxed);
    state.healthy_b.store(true, Ordering::Relaxed);
    let mut tasks = tokio::task::JoinSet::new();
    for (listener, id) in [(first, "a"), (second, "b")] {
        let tls = Arc::new(tls.clone());
        let state = Arc::clone(&state);
        tasks.spawn(async move{let gate=Arc::new(Semaphore::new(256));let mut conns=tokio::task::JoinSet::new();loop{tokio::select!{Some(_)=conns.join_next(),if !conns.is_empty()=>{},accepted=listener.accept()=>{let Ok((socket,_))=accepted else{break};let Ok(target)=socket.local_addr()else{continue};let Ok(permit)=Arc::clone(&gate).try_acquire_owned()else{continue};let tls=Arc::clone(&tls);let state=Arc::clone(&state);conns.spawn(async move{let _permit=permit;let Ok(socket)=TlsAcceptor::from(tls).accept(socket).await else{return};state.connections.fetch_add(1,Ordering::Relaxed);let sni=socket.get_ref().1.server_name().unwrap_or("").to_owned();let h2=socket.get_ref().1.alpn_protocol()==Some(b"h2");let service=service_fn(move|request|serve(request,id,target,sni.clone(),Arc::clone(&state)));if h2{let _=http2::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(socket),service).await;}else{let _=http1::Builder::new().serve_connection(TokioIo::new(socket),service).with_upgrades().await;}});}}}});
    }
    control(Ready{role:"upstream".into(),pid:std::process::id(),address,alternate:Some(alternate)},|command|{match command{FixtureCommand::Health{healthy_a,healthy_b,retry_a}=>{state.healthy_a.store(healthy_a,Ordering::Relaxed);state.healthy_b.store(healthy_b,Ordering::Relaxed);state.retry_a.store(retry_a,Ordering::Relaxed);},FixtureCommand::Release=>{state.release_epoch.fetch_add(1,Ordering::Release);},_=>{}}
        json!({"ok":true,"requests":state.requests.load(Ordering::Relaxed),"request_faults":state.request_faults.load(Ordering::Relaxed),"retries":state.retries.load(Ordering::Relaxed),"retryable_status_replies":state.retries.load(Ordering::Relaxed),"health_success_replies":state.health_success_replies.load(Ordering::Relaxed),"health_failure_replies":state.health_failure_replies.load(Ordering::Relaxed),"body_drops":state.cancellations.load(Ordering::Relaxed),"connections":state.connections.load(Ordering::Relaxed),"active_tunnels":state.active_tunnels.load(Ordering::Relaxed)})}).await?;
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
    if retryable_reply(&state, id, request.method(), attempt) {
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
    let checked = tokio::time::timeout(
        Duration::from_secs(5),
        verify_request_body(request.body_mut(), grpc),
    )
    .await;
    if !matches!(checked, Ok(Ok(()))) {
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
        let frame = frame.map_err(|_| RequestFault::Body)?;
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

    fn upstream() -> Ready {
        Ready {
            role: "upstream".into(),
            pid: 1,
            address: "127.0.0.1:8443".parse().expect("fixture A"),
            alternate: Some("127.0.0.2:8443".parse().expect("fixture B")),
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
        };
        drop(cancelled);
        assert_eq!(state.cancellations.load(Ordering::Relaxed), 1);
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
