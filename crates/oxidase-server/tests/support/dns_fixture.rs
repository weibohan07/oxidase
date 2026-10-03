//! Local test-only DNS fixture. Hickory parses/encodes both sides; this is not a
//! second production DNS parser. UDP and TCP use the same ephemeral IP:port.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_resolver::proto::op::{Message, Query, ResponseCode};
use hickory_resolver::proto::rr::{Record, RecordType};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

#[derive(Clone)]
pub struct FixtureReply {
    pub code: ResponseCode,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub truncate_udp: bool,
    pub delay: Duration,
    pub discard: bool,
    /// Optional test-only fence: a response cannot be written until released.
    pub response_gate: Option<Arc<Semaphore>>,
}

impl FixtureReply {
    pub fn answers(answers: Vec<Record>) -> Self {
        Self {
            code: ResponseCode::NoError,
            answers,
            authorities: Vec::new(),
            truncate_udp: false,
            delay: Duration::ZERO,
            discard: false,
            response_gate: None,
        }
    }

    pub fn code(code: ResponseCode) -> Self {
        Self {
            code,
            ..Self::answers(Vec::new())
        }
    }
}

#[derive(Default)]
pub struct FixtureCounts {
    pub udp: AtomicU64,
    pub tcp: AtomicU64,
    sent: Mutex<BTreeMap<(String, u16), u64>>,
}

impl FixtureCounts {
    /// Successful fixture response writes, not merely received questions.
    pub fn responses_for(&self, canonical_name: &str) -> u64 {
        self.sent
            .lock()
            .expect("fixture sent counts")
            .iter()
            .filter(|((name, _), _)| name == canonical_name)
            .fold(0u64, |total, (_, count)| total.saturating_add(*count))
    }

    /// Acknowledges the requested family, so an AAAA sibling cannot stand in
    /// for the A answer deliberately held across a publication boundary.
    pub fn responses_for_type(&self, canonical_name: &str, record_type: RecordType) -> u64 {
        self.sent
            .lock()
            .expect("fixture sent counts")
            .get(&(canonical_name.to_owned(), u16::from(record_type)))
            .copied()
            .unwrap_or(0)
    }

    fn record_response(&self, canonical_name: String, record_type: RecordType) {
        let mut counts = self.sent.lock().expect("fixture sent counts");
        let key = (canonical_name, u16::from(record_type));
        // The helper remains bounded even for unexpected names and types.
        if counts.contains_key(&key) || counts.len() < 128 {
            let count = counts.entry(key).or_default();
            *count = count.saturating_add(1);
        }
    }
}

pub struct DnsFixture {
    pub address: std::net::SocketAddr,
    pub counts: Arc<FixtureCounts>,
    tasks: Vec<tokio::task::AbortHandle>,
}

type Handler = dyn Fn(&Query, bool) -> FixtureReply + Send + Sync;

impl DnsFixture {
    pub async fn start<F>(handler: F) -> Self
    where
        F: Fn(&Query, bool) -> FixtureReply + Send + Sync + 'static,
    {
        let tcp = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("ephemeral DNS TCP");
        let address = tcp.local_addr().expect("DNS address");
        let udp = Arc::new(
            UdpSocket::bind(address)
                .await
                .expect("same ephemeral DNS UDP"),
        );
        let handler: Arc<Handler> = Arc::new(handler);
        let counts = Arc::new(FixtureCounts::default());
        let udp_handler = Arc::clone(&handler);
        let udp_counts = Arc::clone(&counts);
        let udp_task = tokio::spawn(async move {
            let mut pending = JoinSet::new();
            let quota = Arc::new(Semaphore::new(64));
            let mut bytes = vec![0u8; 65_535];
            loop {
                tokio::select! {
                    Some(_) = pending.join_next(), if !pending.is_empty() => {},
                    received = udp.recv_from(&mut bytes) => {
                        let Ok((size, peer))=received else { break; };
                        let Ok(query)=Message::from_vec(&bytes[..size]) else { continue; };
                        let Some(question)=query.queries.first() else { continue; };
                        udp_counts.udp.fetch_add(1, Ordering::Relaxed);
                        let reply=udp_handler(question, false);
                        let name = question.name().to_ascii();
                        let record_type = question.query_type();
                        let Ok(permit)=Arc::clone(&quota).try_acquire_owned() else { continue; };
                        let socket=Arc::clone(&udp);
                        let sent_counts=Arc::clone(&udp_counts);
                        pending.spawn(async move {
                            let _permit=permit;
                            if reply.discard { return; }
                            if let Some(gate) = &reply.response_gate {
                                let Ok(permit) = gate.acquire().await else { return; };
                                permit.forget();
                            }
                            tokio::time::sleep(reply.delay).await;
                            if let Some(bytes)=response(query, reply, false)
                                && socket.send_to(&bytes, peer).await.is_ok() {
                                sent_counts.record_response(name, record_type);
                            }
                        });
                    }
                }
            }
        });
        let tcp_counts = Arc::clone(&counts);
        let tcp_task = tokio::spawn(async move {
            let mut pending = JoinSet::new();
            let quota = Arc::new(Semaphore::new(32));
            loop {
                tokio::select! {
                    Some(_) = pending.join_next(), if !pending.is_empty() => {},
                    accepted = tcp.accept() => {
                        let Ok((socket,_))=accepted else { break; };
                        let Ok(permit)=Arc::clone(&quota).try_acquire_owned() else { continue; };
                        let handler=Arc::clone(&handler);
                        let counts=Arc::clone(&tcp_counts);
                        pending.spawn(async move { let _permit=permit; tcp_connection(socket,handler,counts).await; });
                    }
                }
            }
        });
        Self {
            address,
            counts,
            tasks: vec![udp_task.abort_handle(), tcp_task.abort_handle()],
        }
    }
}

fn response(query: Message, reply: FixtureReply, tcp: bool) -> Option<Vec<u8>> {
    let mut message = Message::response(query.id, query.op_code);
    message.metadata.recursion_available = true;
    message.metadata.recursion_desired = query.recursion_desired;
    message.metadata.response_code = reply.code;
    message.queries = query.queries;
    message.metadata.truncation = reply.truncate_udp && !tcp;
    if !message.metadata.truncation {
        message.answers = reply.answers;
        message.authorities = reply.authorities;
    }
    message.to_vec().ok()
}

async fn tcp_connection(mut socket: TcpStream, handler: Arc<Handler>, counts: Arc<FixtureCounts>) {
    while let Ok(size) = socket.read_u16().await {
        let mut bytes = vec![0; usize::from(size)];
        if socket.read_exact(&mut bytes).await.is_err() {
            break;
        }
        let Ok(query) = Message::from_vec(&bytes) else {
            break;
        };
        let Some(question) = query.queries.first() else {
            break;
        };
        counts.tcp.fetch_add(1, Ordering::Relaxed);
        let reply = handler(question, true);
        let name = question.name().to_ascii();
        let record_type = question.query_type();
        if reply.discard {
            break;
        }
        if let Some(gate) = &reply.response_gate {
            let Ok(permit) = gate.acquire().await else {
                break;
            };
            permit.forget();
        }
        tokio::time::sleep(reply.delay).await;
        let Some(bytes) = response(query, reply, true) else {
            break;
        };
        let Ok(size) = u16::try_from(bytes.len()) else {
            break;
        };
        if socket.write_u16(size).await.is_err() || socket.write_all(&bytes).await.is_err() {
            break;
        }
        counts.record_response(name, record_type);
    }
}

impl Drop for DnsFixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
