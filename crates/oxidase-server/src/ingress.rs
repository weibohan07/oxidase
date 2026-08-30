use std::collections::{BTreeSet, HashMap};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use std::time::Instant;

use oxidase_config::ListenerLimits;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

use crate::body::DownstreamTimeoutSignal;

/// Socket-lifetime connection admission state for one listener.
///
/// A retained listener keeps this state across transport-plan reloads. Every
/// admission is evaluated against the newest immutable plan while connections
/// admitted by an older plan remain accounted for until their task is dropped.
#[derive(Clone, Debug, Default)]
pub(crate) struct ListenerIngressState {
    shared: Arc<SharedIngressState>,
}

#[derive(Debug, Default)]
struct SharedIngressState {
    inner: Mutex<IngressState>,
}

#[derive(Debug, Default)]
struct IngressState {
    active_connections: u32,
    peers: HashMap<IpAddr, PeerState>,
    idle_order: BTreeSet<(Instant, IpAddr)>,
}

#[derive(Debug)]
struct PeerState {
    active_connections: u32,
    idle_since: Option<Instant>,
}

/// A fixed, bounded reason for rejecting a newly accepted socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionAdmissionRejection {
    ListenerLimit,
    PeerLimit,
    PeerStateCapacity,
}

impl ListenerIngressState {
    pub(crate) fn try_admit(
        &self,
        peer: SocketAddr,
        limits: &ListenerLimits,
    ) -> Result<ConnectionAdmission, ConnectionAdmissionRejection> {
        self.try_admit_at(peer, limits, Instant::now())
    }

    fn try_admit_at(
        &self,
        peer: SocketAddr,
        limits: &ListenerLimits,
        now: Instant,
    ) -> Result<ConnectionAdmission, ConnectionAdmissionRejection> {
        let peer = normalize_peer_ip(peer.ip());
        let mut state = self
            .shared
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if state.active_connections >= limits.max_connections {
            return Err(ConnectionAdmissionRejection::ListenerLimit);
        }

        if !state.peers.contains_key(&peer) {
            let capacity = limits.max_connections as usize;
            if state.peers.len() >= capacity {
                state.evict_expired(now, limits.idle_timeout);
            }
            while state.peers.len() >= capacity {
                // Idle peer identities are a bounded cache only. Prefer the
                // oldest idle entry before rejecting a live, otherwise
                // admissible peer. Active identities are never evicted.
                if let Some((_, oldest_idle)) = state.idle_order.pop_first() {
                    state.peers.remove(&oldest_idle);
                } else {
                    return Err(ConnectionAdmissionRejection::PeerStateCapacity);
                }
            }
            state.peers.insert(
                peer,
                PeerState {
                    active_connections: 0,
                    idle_since: None,
                },
            );
        }

        if let Some(idle_since) = state.peers.get(&peer).and_then(|entry| entry.idle_since) {
            state.idle_order.remove(&(idle_since, peer));
        }
        let peer_state = state
            .peers
            .get_mut(&peer)
            .expect("the peer entry was inserted immediately above");
        if peer_state.active_connections >= limits.max_connections_per_ip {
            return Err(ConnectionAdmissionRejection::PeerLimit);
        }
        peer_state.active_connections += 1;
        peer_state.idle_since = None;
        state.active_connections += 1;
        drop(state);

        Ok(ConnectionAdmission {
            shared: Arc::clone(&self.shared),
            peer,
            released: false,
        })
    }

    #[cfg(test)]
    fn counts(&self) -> (u32, usize) {
        let state = self
            .shared
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (state.active_connections, state.peers.len())
    }
}

impl IngressState {
    fn evict_expired(&mut self, now: Instant, idle_timeout: Duration) {
        loop {
            let Some((idle_since, peer)) = self.idle_order.first().copied() else {
                return;
            };
            if now.saturating_duration_since(idle_since) < idle_timeout {
                return;
            }
            self.idle_order.remove(&(idle_since, peer));
            if self
                .peers
                .get(&peer)
                .is_some_and(|entry| entry.active_connections == 0)
            {
                self.peers.remove(&peer);
            }
        }
    }
}

/// RAII ownership of one accepted socket admission.
///
/// Aborting a TLS handshake, HTTP connection, or upgraded tunnel drops this
/// value with the connection future, so every cancellation path releases both
/// listener-wide and per-peer accounting.
#[must_use = "dropping the admission immediately releases the connection slot"]
#[derive(Debug)]
pub(crate) struct ConnectionAdmission {
    shared: Arc<SharedIngressState>,
    peer: IpAddr,
    released: bool,
}

impl ConnectionAdmission {
    fn release_at(&mut self, now: Instant) {
        if self.released {
            return;
        }
        let mut state = self
            .shared
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active_connections = state.active_connections.saturating_sub(1);
        let mut became_idle = None;
        if let Some(peer) = state.peers.get_mut(&self.peer) {
            peer.active_connections = peer.active_connections.saturating_sub(1);
            if peer.active_connections == 0 {
                peer.idle_since = Some(now);
                became_idle = Some(now);
            }
        }
        if let Some(idle_since) = became_idle {
            state.idle_order.insert((idle_since, self.peer));
        }
        self.released = true;
    }
}

impl Drop for ConnectionAdmission {
    fn drop(&mut self) {
        self.release_at(Instant::now());
    }
}

pub(crate) fn normalize_peer_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        address => address,
    }
}

#[derive(Debug)]
pub(crate) struct ConnectionRequestBudget {
    used: AtomicU32,
    max: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestAdmission {
    Allowed,
    LastAllowed,
    Rejected,
}

impl ConnectionRequestBudget {
    pub(crate) const fn new(max: u32) -> Self {
        Self {
            used: AtomicU32::new(0),
            max,
        }
    }

    pub(crate) fn try_begin(&self) -> RequestAdmission {
        let result = self
            .used
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                (used < self.max).then_some(used + 1)
            });
        match result {
            Ok(previous) if previous + 1 == self.max => RequestAdmission::LastAllowed,
            Ok(_) => RequestAdmission::Allowed,
            Err(_) => RequestAdmission::Rejected,
        }
    }
}

/// Enforces a bidirectional wire-idle deadline without interpreting HTTP.
///
/// The deadline resets only when bytes are actually read or written. This
/// covers an idle keep-alive socket, a peer that stops reading a response, and
/// a peer that stops transmitting a request, without adding per-frame tasks.
pub(crate) struct IdleIo<Io> {
    inner: Pin<Box<Io>>,
    idle_deadline: Pin<Box<Sleep>>,
    idle_timeout: Duration,
    write_progress_deadline: Option<Pin<Box<Sleep>>>,
    write_progress_timeout: Duration,
    downstream_timeout: DownstreamTimeoutSignal,
    timed_out: bool,
}

impl<Io> IdleIo<Io> {
    #[cfg(test)]
    pub(crate) fn new(inner: Io, idle_timeout: Duration, write_progress_timeout: Duration) -> Self {
        Self::with_timeout_signal(
            inner,
            idle_timeout,
            write_progress_timeout,
            DownstreamTimeoutSignal::default(),
        )
    }

    pub(crate) fn with_timeout_signal(
        inner: Io,
        idle_timeout: Duration,
        write_progress_timeout: Duration,
        downstream_timeout: DownstreamTimeoutSignal,
    ) -> Self {
        Self {
            inner: Box::pin(inner),
            idle_deadline: Box::pin(tokio::time::sleep(idle_timeout)),
            idle_timeout,
            write_progress_deadline: None,
            write_progress_timeout,
            downstream_timeout,
            timed_out: false,
        }
    }

    fn record_wire_progress(&mut self) {
        self.idle_deadline
            .as_mut()
            .reset(tokio::time::Instant::now() + self.idle_timeout);
    }

    fn record_write_progress(&mut self) {
        self.record_wire_progress();
        self.write_progress_deadline = None;
    }

    fn poll_idle_timeout(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.timed_out || self.idle_deadline.as_mut().poll(context).is_ready() {
            self.timed_out = true;
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "listener connection idle timeout",
            )))
        } else {
            Poll::Pending
        }
    }

    fn poll_write_progress_timeout(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.timed_out {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "downstream response body idle timeout",
            )));
        }
        let timeout = self.write_progress_timeout;
        let deadline = self
            .write_progress_deadline
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(timeout)));
        if deadline.as_mut().poll(context).is_ready() {
            self.timed_out = true;
            self.downstream_timeout.mark();
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "downstream response body idle timeout",
            )))
        } else {
            Poll::Pending
        }
    }

    fn poll_pending_write(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Poll::Ready(result) = self.poll_idle_timeout(context) {
            self.downstream_timeout.mark();
            return Poll::Ready(result);
        }
        self.poll_write_progress_timeout(context)
    }
}

impl<Io> AsyncRead for IdleIo<Io>
where
    Io: AsyncRead,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.timed_out {
            return self.poll_idle_timeout(context);
        }
        let before = buffer.filled().len();
        match self.inner.as_mut().poll_read(context, buffer) {
            Poll::Ready(Ok(())) => {
                if buffer.filled().len() > before {
                    self.record_wire_progress();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => self.poll_idle_timeout(context),
        }
    }
}

impl<Io> AsyncWrite for IdleIo<Io>
where
    Io: AsyncWrite,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if self.timed_out {
            return match self.poll_idle_timeout(context) {
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => Poll::Ready(Ok(0)),
                Poll::Pending => Poll::Pending,
            };
        }
        match self.inner.as_mut().poll_write(context, buffer) {
            Poll::Ready(Ok(written)) => {
                if written != 0 {
                    self.record_write_progress();
                }
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => match self.poll_pending_write(context) {
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => Poll::Ready(Ok(0)),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        if self.timed_out {
            return self.poll_idle_timeout(context);
        }
        match self.inner.as_mut().poll_flush(context) {
            Poll::Pending => self.poll_pending_write(context),
            Poll::Ready(Ok(())) => {
                self.record_write_progress();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        self.inner.as_mut().poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use std::time::{Duration, Instant};

    use oxidase_config::ListenerLimits;
    use oxidase_core::SourceSpan;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{
        ConnectionAdmissionRejection, ConnectionRequestBudget, IdleIo, ListenerIngressState,
        RequestAdmission, normalize_peer_ip,
    };

    fn limits(max_connections: u32, max_connections_per_ip: u32) -> ListenerLimits {
        ListenerLimits {
            max_connections,
            max_connections_per_ip,
            idle_timeout: Duration::from_secs(30),
            request_body_idle_timeout: Duration::from_secs(10),
            response_body_idle_timeout: Duration::from_secs(10),
            max_header_bytes: 64 * 1024,
            max_headers: 100,
            max_requests_per_connection: 1_000,
            source: SourceSpan::synthetic("listeners[0].limits"),
        }
    }

    fn peer(ip: IpAddr, port: u16) -> SocketAddr {
        SocketAddr::new(ip, port)
    }

    struct PendingWriteIo;

    impl tokio::io::AsyncRead for PendingWriteIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl tokio::io::AsyncWrite for PendingWriteIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _buffer: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            Poll::Pending
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Pending
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn normalizes_ipv4_mapped_ipv6_for_peer_admission() {
        let ipv4 = Ipv4Addr::new(192, 0, 2, 9);
        let mapped = ipv4.to_ipv6_mapped();
        assert_eq!(normalize_peer_ip(IpAddr::V6(mapped)), IpAddr::V4(ipv4));

        let state = ListenerIngressState::default();
        let policy = limits(4, 1);
        let _first = state
            .try_admit(peer(IpAddr::V4(ipv4), 1000), &policy)
            .expect("the first connection is admitted");
        assert!(matches!(
            state.try_admit(peer(IpAddr::V6(mapped), 2000), &policy),
            Err(ConnectionAdmissionRejection::PeerLimit)
        ));
    }

    #[test]
    fn listener_and_peer_limits_are_exact_and_raii_released() {
        let state = ListenerIngressState::default();
        let policy = limits(2, 1);
        let first_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let second_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let first = state
            .try_admit(peer(first_ip, 1000), &policy)
            .expect("first peer is admitted");
        assert!(matches!(
            state.try_admit(peer(first_ip, 1001), &policy),
            Err(ConnectionAdmissionRejection::PeerLimit)
        ));
        let second = state
            .try_admit(peer(second_ip, 1000), &policy)
            .expect("second peer is admitted");
        assert!(matches!(
            state.try_admit(peer(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)), 1000), &policy),
            Err(ConnectionAdmissionRejection::ListenerLimit)
        ));
        assert_eq!(state.counts(), (2, 2));

        drop(first);
        assert_eq!(state.counts().0, 1);
        drop(second);
        assert_eq!(state.counts().0, 0);
    }

    #[test]
    fn a_reloaded_stricter_policy_counts_connections_admitted_by_the_old_plan() {
        let state = ListenerIngressState::default();
        let old = limits(4, 4);
        let new = limits(1, 1);
        let first = state
            .try_admit(peer(IpAddr::V4(Ipv4Addr::LOCALHOST), 1000), &old)
            .expect("old policy admits the connection");
        assert!(matches!(
            state.try_admit(peer(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 1001), &new),
            Err(ConnectionAdmissionRejection::ListenerLimit)
        ));
        drop(first);
        assert!(
            state
                .try_admit(peer(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 1002), &new)
                .is_ok()
        );
    }

    #[test]
    fn idle_peer_cache_is_time_evicted_and_capacity_bounded() {
        let state = ListenerIngressState::default();
        let mut policy = limits(2, 1);
        policy.idle_timeout = Duration::from_secs(5);
        let start = Instant::now();
        let first_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let second_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let third_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));

        let mut first = state
            .try_admit_at(peer(first_ip, 1), &policy, start)
            .expect("first peer is admitted");
        first.release_at(start);
        let mut second = state
            .try_admit_at(peer(second_ip, 2), &policy, start + Duration::from_secs(1))
            .expect("second peer is admitted");
        second.release_at(start + Duration::from_secs(1));
        assert_eq!(state.counts(), (0, 2));

        let _third = state
            .try_admit_at(peer(third_ip, 3), &policy, start + Duration::from_secs(7))
            .expect("expired idle peers are evicted before admission");
        assert_eq!(state.counts(), (1, 1));
    }

    #[test]
    fn concurrent_request_budget_never_exceeds_the_exact_limit() {
        let budget = Arc::new(ConnectionRequestBudget::new(31));
        let mut threads = Vec::new();
        for _ in 0..128 {
            let budget = Arc::clone(&budget);
            threads.push(std::thread::spawn(move || budget.try_begin()));
        }
        let admissions = threads
            .into_iter()
            .map(|thread| thread.join().expect("request worker did not panic"))
            .collect::<Vec<_>>();
        assert_eq!(
            admissions
                .iter()
                .filter(|admission| **admission == RequestAdmission::Allowed)
                .count(),
            30
        );
        assert_eq!(
            admissions
                .iter()
                .filter(|admission| **admission == RequestAdmission::LastAllowed)
                .count(),
            1
        );
        assert_eq!(
            admissions
                .iter()
                .filter(|admission| **admission == RequestAdmission::Rejected)
                .count(),
            97
        );
    }

    #[tokio::test]
    async fn idle_io_resets_on_bytes_and_times_out_without_activity() {
        let (client, mut peer) = tokio::io::duplex(64);
        let mut client = IdleIo::new(client, Duration::from_millis(80), Duration::from_millis(80));
        let (release_peer, hold_peer) = tokio::sync::oneshot::channel();
        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            peer.write_all(b"a").await.expect("peer write succeeds");
            let _ = hold_peer.await;
        });

        let mut byte = [0_u8; 1];
        client
            .read_exact(&mut byte)
            .await
            .expect("activity before the deadline succeeds");
        assert_eq!(byte, *b"a");
        let pending = tokio::time::timeout(Duration::from_millis(40), client.read(&mut byte)).await;
        assert!(pending.is_err(), "the reset deadline has not elapsed");
        let error = tokio::time::timeout(Duration::from_millis(80), client.read(&mut byte))
            .await
            .expect("idle I/O reaches the configured deadline")
            .expect_err("the idle read must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        let _ = release_peer.send(());
        writer.await.expect("writer task did not panic");
    }

    #[tokio::test]
    async fn write_progress_timeout_is_independent_from_connection_idle_timeout() {
        let mut io = IdleIo::new(
            PendingWriteIo,
            Duration::from_secs(5),
            Duration::from_millis(30),
        );
        let error = tokio::time::timeout(Duration::from_secs(1), io.write_all(b"response"))
            .await
            .expect("write-progress timeout completes before the connection idle timeout")
            .expect_err("a client that makes no write progress is disconnected");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("response body"));
    }
}
