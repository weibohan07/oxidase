use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use http::StatusCode;
use oxidase_core::ErrorClass;
use oxidase_runtime::{
    EndpointHealthState, ExecutionObserver, RuntimeSnapshot, ServiceObservationContext,
    ServiceObservationOutcome, ServiceObservationResult,
};

const LATENCY_BOUNDS_MS: [u64; 9] = [1, 5, 10, 25, 50, 100, 250, 500, 1_000];

#[derive(Debug, Default)]
pub struct Metrics {
    requests: AtomicU64,
    active_requests: AtomicU64,
    handled: AtomicU64,
    declined: AtomicU64,
    failed: AtomicU64,
    status_classes: [AtomicU64; 5],
    latency_buckets: [AtomicU64; 10],
    reload_success: AtomicU64,
    reload_failure: AtomicU64,
    observe: Mutex<BTreeMap<String, Arc<ObserveSeries>>>,
    response_body_bytes: AtomicU64,
    response_body_terminations: [AtomicU64; 4],
    response_body_lifetime_buckets: [AtomicU64; 10],
    transport: Mutex<BTreeMap<String, Arc<TransportSeries>>>,
}

impl Metrics {
    pub(crate) fn request_started(self: &Arc<Self>) -> ActiveRequest {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.active_requests.fetch_add(1, Ordering::Relaxed);
        ActiveRequest {
            metrics: self.clone(),
        }
    }

    pub(crate) fn record_request(
        &self,
        outcome: &'static str,
        status: StatusCode,
        latency: Duration,
    ) {
        match outcome {
            "handled" => &self.handled,
            "declined" => &self.declined,
            _ => &self.failed,
        }
        .fetch_add(1, Ordering::Relaxed);

        let class = usize::from(status.as_u16() / 100).saturating_sub(1);
        if let Some(counter) = self.status_classes.get(class) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        let bucket = latency_bucket(latency);
        self.latency_buckets[bucket].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_reload(&self, success: bool) {
        if success {
            &self.reload_success
        } else {
            &self.reload_failure
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    fn observe_series(&self, name: &str) -> Arc<ObserveSeries> {
        let mut observe = self
            .observe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        observe
            .entry(name.to_owned())
            .or_insert_with(|| Arc::new(ObserveSeries::default()))
            .clone()
    }

    pub(crate) fn record_response_body(
        &self,
        bytes: u64,
        termination: BodyTermination,
        lifetime: Duration,
    ) {
        self.response_body_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.response_body_terminations[termination.index()].fetch_add(1, Ordering::Relaxed);
        let bucket = latency_bucket(lifetime);
        self.response_body_lifetime_buckets[bucket].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn listener_transport(&self, listener: &str) -> ListenerTransportMetrics {
        let mut transport = self
            .transport
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ListenerTransportMetrics {
            series: transport
                .entry(listener.to_owned())
                .or_insert_with(|| Arc::new(TransportSeries::default()))
                .clone(),
        }
    }

    #[must_use]
    pub fn render_prometheus(&self) -> String {
        let mut output = String::new();
        push_counter(
            &mut output,
            "oxidase_requests_total",
            self.requests.load(Ordering::Relaxed),
        );
        push_counter(
            &mut output,
            "oxidase_active_requests",
            self.active_requests.load(Ordering::Relaxed),
        );
        for (outcome, value) in [
            ("handled", self.handled.load(Ordering::Relaxed)),
            ("declined", self.declined.load(Ordering::Relaxed)),
            ("failed", self.failed.load(Ordering::Relaxed)),
        ] {
            output.push_str(&format!(
                "oxidase_request_outcomes_total{{outcome=\"{outcome}\"}} {value}\n"
            ));
        }
        for (index, value) in self.status_classes.iter().enumerate() {
            output.push_str(&format!(
                "oxidase_response_status_total{{class=\"{}xx\"}} {}\n",
                index + 1,
                value.load(Ordering::Relaxed)
            ));
        }
        let mut cumulative = 0u64;
        for (index, value) in self.latency_buckets.iter().enumerate() {
            cumulative = cumulative.saturating_add(value.load(Ordering::Relaxed));
            let bound = LATENCY_BOUNDS_MS
                .get(index)
                .map_or_else(|| "+Inf".to_owned(), ToString::to_string);
            output.push_str(&format!(
                "oxidase_request_latency_milliseconds_bucket{{le=\"{bound}\"}} {cumulative}\n"
            ));
        }
        push_counter(
            &mut output,
            "oxidase_reload_success_total",
            self.reload_success.load(Ordering::Relaxed),
        );
        push_counter(
            &mut output,
            "oxidase_reload_failure_total",
            self.reload_failure.load(Ordering::Relaxed),
        );
        let observe = self
            .observe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (name, series) in observe.iter() {
            let name = escape_label(name);
            for (outcome, value) in [
                ("handled", series.handled.load(Ordering::Relaxed)),
                ("declined", series.declined.load(Ordering::Relaxed)),
                ("failed", series.failed.load(Ordering::Relaxed)),
            ] {
                output.push_str(&format!(
                    "oxidase_observe_total{{observe=\"{name}\",outcome=\"{outcome}\"}} {value}\n"
                ));
            }
            for (index, value) in series.status_classes.iter().enumerate() {
                output.push_str(&format!(
                    "oxidase_observe_status_total{{observe=\"{name}\",class=\"{}xx\"}} {}\n",
                    index + 1,
                    value.load(Ordering::Relaxed)
                ));
            }
            for (index, class) in ERROR_CLASSES.iter().enumerate() {
                output.push_str(&format!(
                    "oxidase_observe_errors_total{{observe=\"{name}\",class=\"{class}\"}} {}\n",
                    series.error_classes[index].load(Ordering::Relaxed)
                ));
            }
            let mut cumulative = 0u64;
            for (index, value) in series.latency_buckets.iter().enumerate() {
                cumulative = cumulative.saturating_add(value.load(Ordering::Relaxed));
                let bound = LATENCY_BOUNDS_MS.get(index).map_or_else(
                    || "+Inf".to_owned(),
                    |bound| format!("{:.3}", *bound as f64 / 1_000.0),
                );
                output.push_str(&format!(
                    "oxidase_observe_response_head_duration_seconds_bucket{{observe=\"{name}\",le=\"{bound}\"}} {cumulative}\n"
                ));
            }
        }
        push_counter(
            &mut output,
            "oxidase_response_body_bytes_total",
            self.response_body_bytes.load(Ordering::Relaxed),
        );
        for termination in BodyTermination::ALL {
            output.push_str(&format!(
                "oxidase_response_body_terminations_total{{reason=\"{}\"}} {}\n",
                termination.as_str(),
                self.response_body_terminations[termination.index()].load(Ordering::Relaxed)
            ));
        }
        let mut cumulative = 0u64;
        for (index, value) in self.response_body_lifetime_buckets.iter().enumerate() {
            cumulative = cumulative.saturating_add(value.load(Ordering::Relaxed));
            let bound = LATENCY_BOUNDS_MS.get(index).map_or_else(
                || "+Inf".to_owned(),
                |bound| format!("{:.3}", *bound as f64 / 1_000.0),
            );
            output.push_str(&format!(
                "oxidase_response_body_lifetime_seconds_bucket{{le=\"{bound}\"}} {cumulative}\n"
            ));
        }
        let transport = self
            .transport
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (listener, series) in transport.iter() {
            let listener = escape_label(listener);
            for protocol in ConnectionProtocol::ALL {
                output.push_str(&format!(
                    "oxidase_connections_accepted_total{{listener=\"{listener}\",protocol=\"{}\"}} {}\n",
                    protocol.as_str(),
                    series.connections_accepted[protocol.index()].load(Ordering::Relaxed)
                ));
                output.push_str(&format!(
                    "oxidase_active_connections{{listener=\"{listener}\",protocol=\"{}\"}} {}\n",
                    protocol.as_str(),
                    series.active_connections[protocol.index()].load(Ordering::Relaxed)
                ));
            }
            for outcome in TlsHandshakeOutcome::ALL {
                output.push_str(&format!(
                    "oxidase_tls_handshakes_total{{listener=\"{listener}\",result=\"{}\"}} {}\n",
                    outcome.as_str(),
                    series.tls_handshakes[outcome.index()].load(Ordering::Relaxed)
                ));
                let mut cumulative = 0u64;
                for (index, value) in series.tls_handshake_duration_buckets[outcome.index()]
                    .iter()
                    .enumerate()
                {
                    cumulative = cumulative.saturating_add(value.load(Ordering::Relaxed));
                    let bound = LATENCY_BOUNDS_MS.get(index).map_or_else(
                        || "+Inf".to_owned(),
                        |bound| format!("{:.3}", *bound as f64 / 1_000.0),
                    );
                    output.push_str(&format!(
                        "oxidase_tls_handshake_duration_seconds_bucket{{listener=\"{listener}\",result=\"{}\",le=\"{bound}\"}} {cumulative}\n",
                        outcome.as_str()
                    ));
                }
            }
            for alpn in TlsAlpn::ALL {
                output.push_str(&format!(
                    "oxidase_tls_alpn_total{{listener=\"{listener}\",protocol=\"{}\"}} {}\n",
                    alpn.as_str(),
                    series.tls_alpn[alpn.index()].load(Ordering::Relaxed)
                ));
            }
            output.push_str(&format!(
                "oxidase_http2_active_streams{{listener=\"{listener}\"}} {}\n",
                series.h2_active_streams.load(Ordering::Relaxed)
            ));
            for shutdown in H2Shutdown::ALL {
                output.push_str(&format!(
                    "oxidase_http2_shutdown_total{{listener=\"{listener}\",result=\"{}\"}} {}\n",
                    shutdown.as_str(),
                    series.h2_shutdowns[shutdown.index()].load(Ordering::Relaxed)
                ));
            }
            output.push_str(&format!(
                "oxidase_tunnels_started_total{{listener=\"{listener}\"}} {}\n",
                series.tunnels_started.load(Ordering::Relaxed)
            ));
            output.push_str(&format!(
                "oxidase_active_tunnels{{listener=\"{listener}\"}} {}\n",
                series.active_tunnels.load(Ordering::Relaxed)
            ));
            for direction in TunnelDirection::ALL {
                output.push_str(&format!(
                    "oxidase_tunnel_bytes_total{{listener=\"{listener}\",direction=\"{}\"}} {}\n",
                    direction.as_str(),
                    series.tunnel_bytes[direction.index()].load(Ordering::Relaxed)
                ));
            }
            for termination in TunnelTermination::ALL {
                output.push_str(&format!(
                    "oxidase_tunnel_terminations_total{{listener=\"{listener}\",reason=\"{}\"}} {}\n",
                    termination.as_str(),
                    series.tunnel_terminations[termination.index()].load(Ordering::Relaxed)
                ));
            }
        }
        output
    }

    /// Renders process metrics together with bounded runtime Cluster series
    /// from one pinned snapshot.
    ///
    /// Cluster and endpoint names come exclusively from compiled configuration;
    /// protocol, policy, and health labels are fixed enums. Request URLs,
    /// headers, client addresses, and error strings never become labels.
    #[must_use]
    pub fn render_prometheus_for(&self, snapshot: &RuntimeSnapshot) -> String {
        let mut output = self.render_prometheus();
        let now = Instant::now();
        for cluster in snapshot.resources.clusters.values() {
            let status = cluster.status(now);
            let cluster_name = escape_label(&status.cluster);
            output.push_str(&format!(
                "oxidase_cluster_info{{cluster=\"{cluster_name}\",policy=\"{}\",protocol=\"{}\"}} 1\n",
                status.policy, status.protocol
            ));
            output.push_str(&format!(
                "oxidase_cluster_active_requests{{cluster=\"{cluster_name}\"}} {}\n",
                status.active_requests
            ));
            output.push_str(&format!(
                "oxidase_cluster_active_retries{{cluster=\"{cluster_name}\"}} {}\n",
                status.active_retries
            ));
            output.push_str(&format!(
                "oxidase_cluster_retry_attempts_total{{cluster=\"{cluster_name}\"}} {}\n",
                status.retry_attempts
            ));
            output.push_str(&format!(
                "oxidase_cluster_retry_exhausted_total{{cluster=\"{cluster_name}\"}} {}\n",
                status.retry_exhausted
            ));
            for (reason, value) in [
                ("overloaded", status.overload_rejections),
                ("unavailable", status.unavailable_rejections),
            ] {
                output.push_str(&format!(
                    "oxidase_cluster_admission_rejections_total{{cluster=\"{cluster_name}\",reason=\"{reason}\"}} {value}\n"
                ));
            }

            let mut endpoints = status.endpoints;
            endpoints.sort_by(|left, right| left.name.cmp(&right.name));
            for endpoint in endpoints {
                let endpoint_name = escape_label(&endpoint.name);
                let labels = format!("cluster=\"{cluster_name}\",endpoint=\"{endpoint_name}\"");
                output.push_str(&format!(
                    "oxidase_cluster_endpoint_selections_total{{{labels}}} {}\n",
                    endpoint.runtime.selections
                ));
                output.push_str(&format!(
                    "oxidase_cluster_endpoint_active_requests{{{labels}}} {}\n",
                    endpoint.runtime.active_requests
                ));
                output.push_str(&format!(
                    "oxidase_cluster_endpoint_successes_total{{{labels}}} {}\n",
                    endpoint.runtime.successes
                ));
                output.push_str(&format!(
                    "oxidase_cluster_endpoint_failures_total{{{labels}}} {}\n",
                    endpoint.runtime.failures
                ));
                for (result, value) in [
                    ("success", endpoint.runtime.active_health_successes),
                    ("failure", endpoint.runtime.active_health_failures),
                ] {
                    output.push_str(&format!(
                        "oxidase_cluster_health_checks_total{{{labels},result=\"{result}\"}} {value}\n"
                    ));
                }
                output.push_str(&format!(
                    "oxidase_cluster_passive_ejections_total{{{labels}}} {}\n",
                    endpoint.runtime.passive_ejections
                ));
                output.push_str(&format!(
                    "oxidase_cluster_health_transitions_total{{{labels}}} {}\n",
                    endpoint.runtime.health_transitions
                ));
                for health in CLUSTER_HEALTH_STATES {
                    let value = u8::from(endpoint.runtime.health == health);
                    output.push_str(&format!(
                        "oxidase_cluster_endpoint_health{{{labels},state=\"{}\"}} {value}\n",
                        cluster_health_name(health)
                    ));
                }
            }
        }
        output
    }
}

const CLUSTER_HEALTH_STATES: [EndpointHealthState; 4] = [
    EndpointHealthState::UnknownEligible,
    EndpointHealthState::Healthy,
    EndpointHealthState::Unhealthy,
    EndpointHealthState::PassivelyEjected,
];

const fn cluster_health_name(health: EndpointHealthState) -> &'static str {
    match health {
        EndpointHealthState::UnknownEligible => "unknown_eligible",
        EndpointHealthState::Healthy => "healthy",
        EndpointHealthState::Unhealthy => "unhealthy",
        EndpointHealthState::PassivelyEjected => "passively_ejected",
    }
}

fn latency_bucket(duration: Duration) -> usize {
    let millis = duration.as_millis();
    LATENCY_BOUNDS_MS
        .iter()
        .position(|bound| millis <= u128::from(*bound))
        .unwrap_or(LATENCY_BOUNDS_MS.len())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionProtocol {
    Http1,
    Http2,
}

impl ConnectionProtocol {
    const ALL: [Self; 2] = [Self::Http1, Self::Http2];

    const fn index(self) -> usize {
        match self {
            Self::Http1 => 0,
            Self::Http2 => 1,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Http1 => "http1",
            Self::Http2 => "h2",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TlsHandshakeOutcome {
    Success,
    Failure,
    Timeout,
    Protocol,
    Io,
    Overloaded,
    AlpnRequired,
    AlpnMismatch,
}

impl TlsHandshakeOutcome {
    const ALL: [Self; 8] = [
        Self::Success,
        Self::Failure,
        Self::Timeout,
        Self::Protocol,
        Self::Io,
        Self::Overloaded,
        Self::AlpnRequired,
        Self::AlpnMismatch,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Success => 0,
            Self::Failure => 1,
            Self::Timeout => 2,
            Self::Protocol => 3,
            Self::Io => 4,
            Self::Overloaded => 5,
            Self::AlpnRequired => 6,
            Self::AlpnMismatch => 7,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Timeout => "timeout",
            Self::Protocol => "protocol",
            Self::Io => "io",
            Self::Overloaded => "overloaded",
            Self::AlpnRequired => "alpn_required",
            Self::AlpnMismatch => "alpn_mismatch",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TlsAlpn {
    Http1,
    Http2,
    None,
    Other,
}

impl TlsAlpn {
    const ALL: [Self; 4] = [Self::Http1, Self::Http2, Self::None, Self::Other];

    #[must_use]
    pub(crate) fn from_negotiated(protocol: Option<&[u8]>) -> Self {
        match protocol {
            Some(b"http/1.1") => Self::Http1,
            Some(b"h2") => Self::Http2,
            None => Self::None,
            Some(_) => Self::Other,
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Http1 => 0,
            Self::Http2 => 1,
            Self::None => 2,
            Self::Other => 3,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Http1 => "http1",
            Self::Http2 => "h2",
            Self::None => "none",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum H2Shutdown {
    Graceful,
    Forced,
}

impl H2Shutdown {
    const ALL: [Self; 2] = [Self::Graceful, Self::Forced];

    const fn index(self) -> usize {
        match self {
            Self::Graceful => 0,
            Self::Forced => 1,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Graceful => "graceful",
            Self::Forced => "forced",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunnelDirection {
    DownstreamToUpstream,
    UpstreamToDownstream,
}

impl TunnelDirection {
    const ALL: [Self; 2] = [Self::DownstreamToUpstream, Self::UpstreamToDownstream];

    const fn index(self) -> usize {
        match self {
            Self::DownstreamToUpstream => 0,
            Self::UpstreamToDownstream => 1,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::DownstreamToUpstream => "downstream_to_upstream",
            Self::UpstreamToDownstream => "upstream_to_downstream",
        }
    }
}

/// Fixed, protocol-independent reasons for a tunnel to stop.
///
/// The variants deliberately cannot carry request data or error messages, so
/// they remain safe Prometheus label values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TunnelTermination {
    DownstreamClosed,
    UpstreamClosed,
    Error,
    Cancelled,
}

impl TunnelTermination {
    const ALL: [Self; 4] = [
        Self::DownstreamClosed,
        Self::UpstreamClosed,
        Self::Error,
        Self::Cancelled,
    ];

    const fn index(self) -> usize {
        match self {
            Self::DownstreamClosed => 0,
            Self::UpstreamClosed => 1,
            Self::Error => 2,
            Self::Cancelled => 3,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::DownstreamClosed => "downstream_closed",
            Self::UpstreamClosed => "upstream_closed",
            Self::Error => "error",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Debug, Default)]
struct TransportSeries {
    connections_accepted: [AtomicU64; 2],
    active_connections: [AtomicU64; 2],
    tls_handshakes: [AtomicU64; 8],
    tls_handshake_duration_buckets: [[AtomicU64; 10]; 8],
    tls_alpn: [AtomicU64; 4],
    h2_active_streams: AtomicU64,
    h2_shutdowns: [AtomicU64; 2],
    tunnels_started: AtomicU64,
    active_tunnels: AtomicU64,
    tunnel_bytes: [AtomicU64; 2],
    tunnel_terminations: [AtomicU64; 4],
}

/// Low-cost handle to transport counters for one configured listener name.
///
/// The name is registered once in [`Metrics`] and never accepted from request
/// data. Hot-path updates therefore only touch atomics and cannot create metric
/// series from SNI, paths, headers, or other client-controlled values.
#[derive(Clone)]
pub(crate) struct ListenerTransportMetrics {
    series: Arc<TransportSeries>,
}

impl ListenerTransportMetrics {
    pub(crate) fn connection_accepted(&self, protocol: ConnectionProtocol) -> ActiveConnection {
        self.series.connections_accepted[protocol.index()].fetch_add(1, Ordering::Relaxed);
        self.series.active_connections[protocol.index()].fetch_add(1, Ordering::Relaxed);
        ActiveConnection {
            series: self.series.clone(),
            protocol,
        }
    }

    pub(crate) fn record_tls_handshake(&self, outcome: TlsHandshakeOutcome, duration: Duration) {
        self.series.tls_handshakes[outcome.index()].fetch_add(1, Ordering::Relaxed);
        let bucket = latency_bucket(duration);
        self.series.tls_handshake_duration_buckets[outcome.index()][bucket]
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_tls_alpn(&self, alpn: TlsAlpn) {
        self.series.tls_alpn[alpn.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn h2_stream_started(&self) -> ActiveH2Stream {
        self.series
            .h2_active_streams
            .fetch_add(1, Ordering::Relaxed);
        ActiveH2Stream {
            series: self.series.clone(),
        }
    }

    pub(crate) fn record_h2_shutdown(&self, shutdown: H2Shutdown) {
        self.series.h2_shutdowns[shutdown.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Starts one connection-owned bidirectional tunnel.
    ///
    /// A guard that is dropped without [`ActiveTunnel::finish`] records a
    /// cancellation. This covers task abortion during listener drain without
    /// requiring an async cleanup path.
    pub(crate) fn tunnel_started(&self) -> ActiveTunnel {
        self.series.tunnels_started.fetch_add(1, Ordering::Relaxed);
        self.series.active_tunnels.fetch_add(1, Ordering::Relaxed);
        ActiveTunnel {
            series: self.series.clone(),
            finished: false,
        }
    }
}

#[must_use = "dropping the guard immediately records the connection as inactive"]
pub(crate) struct ActiveConnection {
    series: Arc<TransportSeries>,
    protocol: ConnectionProtocol,
}

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        self.series.active_connections[self.protocol.index()].fetch_sub(1, Ordering::Relaxed);
    }
}

#[must_use = "dropping the guard immediately records the HTTP/2 stream as inactive"]
pub(crate) struct ActiveH2Stream {
    series: Arc<TransportSeries>,
}

impl Drop for ActiveH2Stream {
    fn drop(&mut self) {
        self.series
            .h2_active_streams
            .fetch_sub(1, Ordering::Relaxed);
    }
}

#[must_use = "dropping an unfinished guard records the tunnel as cancelled"]
pub(crate) struct ActiveTunnel {
    series: Arc<TransportSeries>,
    finished: bool,
}

impl ActiveTunnel {
    /// Records the final byte counts and termination reason, then closes the
    /// active lifecycle. Bytes are DATA transferred in each direction; protocol
    /// metadata such as WebSocket framing is intentionally not labelled.
    pub(crate) fn finish(
        mut self,
        downstream_to_upstream_bytes: u64,
        upstream_to_downstream_bytes: u64,
        termination: TunnelTermination,
    ) {
        self.series.tunnel_bytes[TunnelDirection::DownstreamToUpstream.index()]
            .fetch_add(downstream_to_upstream_bytes, Ordering::Relaxed);
        self.series.tunnel_bytes[TunnelDirection::UpstreamToDownstream.index()]
            .fetch_add(upstream_to_downstream_bytes, Ordering::Relaxed);
        self.series.tunnel_terminations[termination.index()].fetch_add(1, Ordering::Relaxed);
        self.finished = true;
    }
}

impl Drop for ActiveTunnel {
    fn drop(&mut self) {
        self.series.active_tunnels.fetch_sub(1, Ordering::Relaxed);
        if !self.finished {
            self.series.tunnel_terminations[TunnelTermination::Cancelled.index()]
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyTermination {
    Completed,
    Error,
    Cancelled,
    Timeout,
}

impl BodyTermination {
    const ALL: [Self; 4] = [Self::Completed, Self::Error, Self::Cancelled, Self::Timeout];

    const fn index(self) -> usize {
        match self {
            Self::Completed => 0,
            Self::Error => 1,
            Self::Cancelled => 2,
            Self::Timeout => 3,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Error => "error",
            Self::Cancelled => "cancelled",
            Self::Timeout => "timeout",
        }
    }
}

const ERROR_CLASSES: [&str; 11] = [
    "configuration",
    "timeout",
    "upstream_connect",
    "upstream_protocol",
    "upstream_unavailable",
    "upstream_overloaded",
    "site_io",
    "template_limit",
    "body_unavailable",
    "invalid_state",
    "internal",
];

#[derive(Debug, Default)]
struct ObserveSeries {
    handled: AtomicU64,
    declined: AtomicU64,
    failed: AtomicU64,
    status_classes: [AtomicU64; 5],
    error_classes: [AtomicU64; 11],
    latency_buckets: [AtomicU64; 10],
}

impl ObserveSeries {
    fn record(&self, outcome: ServiceObservationOutcome, latency: Duration) {
        match outcome {
            ServiceObservationOutcome::Handled(status) => {
                self.handled.fetch_add(1, Ordering::Relaxed);
                let class = usize::from(status.as_u16() / 100).saturating_sub(1);
                if let Some(counter) = self.status_classes.get(class) {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
            }
            ServiceObservationOutcome::Declined => {
                self.declined.fetch_add(1, Ordering::Relaxed);
            }
            ServiceObservationOutcome::Failed(class) => {
                self.failed.fetch_add(1, Ordering::Relaxed);
                self.error_classes[error_class_index(class)].fetch_add(1, Ordering::Relaxed);
            }
        }
        let bucket = latency_bucket(latency);
        self.latency_buckets[bucket].fetch_add(1, Ordering::Relaxed);
    }
}

const fn error_class_index(class: ErrorClass) -> usize {
    match class {
        ErrorClass::Configuration => 0,
        ErrorClass::Timeout => 1,
        ErrorClass::UpstreamConnect => 2,
        ErrorClass::UpstreamProtocol => 3,
        ErrorClass::UpstreamUnavailable => 4,
        ErrorClass::UpstreamOverloaded => 5,
        ErrorClass::SiteIo => 6,
        ErrorClass::TemplateLimit => 7,
        ErrorClass::BodyUnavailable => 8,
        ErrorClass::InvalidState => 9,
        ErrorClass::Internal => 10,
    }
}

pub(crate) struct ProductionObserver<'a> {
    metrics: &'a Metrics,
    config_version: &'a str,
    listener_id: &'a str,
    request_id: u64,
}

impl<'a> ProductionObserver<'a> {
    pub(crate) const fn new(
        metrics: &'a Metrics,
        config_version: &'a str,
        listener_id: &'a str,
        request_id: u64,
    ) -> Self {
        Self {
            metrics,
            config_version,
            listener_id,
            request_id,
        }
    }
}

pub(crate) struct ProductionObservationScope {
    started: std::time::Instant,
    series: Arc<ObserveSeries>,
    span: tracing::Span,
}

impl ExecutionObserver for ProductionObserver<'_> {
    type Scope = ProductionObservationScope;

    fn service_started(&self, context: ServiceObservationContext<'_>) -> Self::Scope {
        let span = tracing::info_span!(
            "oxidase.observe",
            request_id = self.request_id,
            config_version = self.config_version,
            listener_id = self.listener_id,
            observe = context.observe_name,
            service_id = %context.service_id,
            depth = context.depth,
            outcome = tracing::field::Empty,
            status_class = tracing::field::Empty,
            error_class = tracing::field::Empty,
            latency_micros = tracing::field::Empty,
            cancelled = tracing::field::Empty,
        );
        span.in_scope(|| tracing::debug!("Observe service started"));
        ProductionObservationScope {
            started: std::time::Instant::now(),
            series: self.metrics.observe_series(context.observe_name),
            span,
        }
    }

    fn service_finished(&self, scope: Self::Scope, result: ServiceObservationResult) {
        let latency = scope.started.elapsed();
        scope.series.record(result.outcome, latency);
        scope.span.record("outcome", result.outcome.kind());
        match result.outcome {
            ServiceObservationOutcome::Handled(status) => {
                scope.span.record("status_class", status_class(status));
            }
            ServiceObservationOutcome::Failed(class) => {
                scope
                    .span
                    .record("error_class", tracing::field::debug(class));
            }
            ServiceObservationOutcome::Declined => {}
        }
        scope
            .span
            .record("latency_micros", latency.as_micros() as u64);
        scope
            .span
            .in_scope(|| tracing::info!("Observe service finished"));
    }

    fn service_cancelled(&self, scope: Self::Scope) {
        let latency = scope.started.elapsed();
        scope.series.record(
            ServiceObservationOutcome::Failed(ErrorClass::Timeout),
            latency,
        );
        scope.span.record("outcome", "failed");
        scope
            .span
            .record("error_class", tracing::field::debug(ErrorClass::Timeout));
        scope.span.record("cancelled", true);
        scope
            .span
            .record("latency_micros", latency.as_micros() as u64);
        scope
            .span
            .in_scope(|| tracing::info!("Observe service cancelled"));
    }
}

const fn status_class(status: StatusCode) -> &'static str {
    match status.as_u16() / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    }
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

pub(crate) struct ActiveRequest {
    metrics: Arc<Metrics>,
}

impl Drop for ActiveRequest {
    fn drop(&mut self) {
        self.metrics.active_requests.fetch_sub(1, Ordering::Relaxed);
    }
}

fn push_counter(output: &mut String, name: &str, value: u64) {
    output.push_str(name);
    output.push(' ');
    output.push_str(&value.to_string());
    output.push('\n');
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};

    use http::StatusCode;
    use oxidase_config::Compiler;
    use oxidase_core::{ErrorClass, ServiceId};
    use oxidase_runtime::{
        ClusterAdmissionError, ExecutionObserver, RuntimeSnapshot, ServiceObservationContext,
        ServiceObservationOutcome, ServiceObservationResult,
    };
    use tempfile::tempdir;

    use super::{
        ConnectionProtocol, H2Shutdown, Metrics, ProductionObserver, TlsAlpn, TlsHandshakeOutcome,
        TunnelTermination,
    };

    #[test]
    fn metric_labels_are_from_fixed_bounded_sets() {
        let metrics = Arc::new(Metrics::default());
        {
            let _active = metrics.request_started();
            metrics.record_request("handled", StatusCode::OK, Duration::from_millis(4));
        }
        metrics.record_reload(true);
        let output = metrics.render_prometheus();
        assert!(output.contains("outcome=\"handled\""));
        assert!(output.contains("class=\"2xx\""));
        assert!(!output.contains("http://"));
    }

    #[tokio::test]
    async fn snapshot_cluster_metrics_export_all_bounded_runtime_counters() {
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        fs::write(
            &config,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    api:
      protocol: h2
      endpoints:
        - name: api-a
          url: http://127.0.0.1:43123
          weight: 1
      load_balance:
        policy: least_requests
      health:
        active:
          path: /healthz
          interval: 1s
          timeout: 100ms
          healthy_statuses: ["200-299"]
          healthy_threshold: 1
          unhealthy_threshold: 1
        passive:
          consecutive_failures: 1
          eject_for: 30s
services:
  root:
    type: respond
    body:
      text: ok
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      ref: root
"#,
        )
        .expect("fixture config can be written");
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("fixture config compiles"),
        )
        .expect("fixture snapshot prepares");
        let cluster = snapshot
            .resources
            .clusters
            .values()
            .next()
            .expect("fixture cluster exists");
        let request = cluster.acquire().await.expect("request can be admitted");
        let retry = cluster
            .try_acquire_retry()
            .expect("retry budget has capacity");
        cluster.record_retry_attempt();
        cluster.record_retry_exhausted();
        cluster.record_admission_failure(ClusterAdmissionError::Overloaded);
        cluster.record_admission_failure(ClusterAdmissionError::Unavailable);
        let now = Instant::now();
        cluster.record_active_health("api-a", false, now);
        cluster.record_passive_failure("api-a", now);
        cluster.record_active_health("api-a", true, now);
        cluster.record_passive_success("api-a");

        let output = Metrics::default().render_prometheus_for(&snapshot);
        assert!(output.contains(
            "oxidase_cluster_info{cluster=\"api\",policy=\"least_requests\",protocol=\"h2\"} 1"
        ));
        assert!(output.contains("oxidase_cluster_active_requests{cluster=\"api\"} 1"));
        assert!(output.contains("oxidase_cluster_active_retries{cluster=\"api\"} 1"));
        assert!(output.contains("oxidase_cluster_retry_attempts_total{cluster=\"api\"} 1"));
        assert!(output.contains("oxidase_cluster_retry_exhausted_total{cluster=\"api\"} 1"));
        for reason in ["overloaded", "unavailable"] {
            assert!(output.contains(&format!(
                "oxidase_cluster_admission_rejections_total{{cluster=\"api\",reason=\"{reason}\"}} 1"
            )));
        }
        let labels = "cluster=\"api\",endpoint=\"api-a\"";
        for metric in [
            "oxidase_cluster_endpoint_selections_total",
            "oxidase_cluster_endpoint_active_requests",
            "oxidase_cluster_endpoint_successes_total",
            "oxidase_cluster_endpoint_failures_total",
            "oxidase_cluster_passive_ejections_total",
        ] {
            assert!(
                output.contains(&format!("{metric}{{{labels}}} 1")),
                "{output}"
            );
        }
        for result in ["success", "failure"] {
            assert!(output.contains(&format!(
                "oxidase_cluster_health_checks_total{{{labels},result=\"{result}\"}} 1"
            )));
        }
        assert!(output.contains(&format!(
            "oxidase_cluster_endpoint_health{{{labels},state=\"healthy\"}} 1"
        )));
        assert!(!output.contains("127.0.0.1"));
        assert!(!output.contains("/healthz"));

        drop(retry);
        drop(request);
    }

    #[test]
    fn production_observe_metrics_are_bounded_and_record_head_latency() {
        let metrics = Metrics::default();
        let observer = ProductionObserver::new(&metrics, "v2-secret?query=value", "listener", 7);
        let service = ServiceId::new("service:observe");
        let scope = observer.service_started(ServiceObservationContext {
            observe_name: "configured-boundary",
            service_id: &service,
            depth: 0,
        });
        observer.service_finished(
            scope,
            ServiceObservationResult {
                outcome: ServiceObservationOutcome::Handled(StatusCode::OK),
            },
        );
        let output = metrics.render_prometheus();
        assert!(output.contains(
            "oxidase_observe_total{observe=\"configured-boundary\",outcome=\"handled\"} 1"
        ));
        assert!(output.contains(
            "oxidase_observe_status_total{observe=\"configured-boundary\",class=\"2xx\"} 1"
        ));
        assert!(output.contains(
            "oxidase_observe_response_head_duration_seconds_bucket{observe=\"configured-boundary\""
        ));
        assert!(!output.contains("secret?query=value"));
        assert!(!output.contains("service:observe"));
    }

    #[test]
    fn production_observe_exports_cluster_failures_as_fixed_error_classes() {
        let metrics = Metrics::default();
        let observer = ProductionObserver::new(&metrics, "version", "listener", 7);
        let service = ServiceId::new("service:observe");

        for class in [
            ErrorClass::UpstreamUnavailable,
            ErrorClass::UpstreamOverloaded,
        ] {
            let scope = observer.service_started(ServiceObservationContext {
                observe_name: "cluster-boundary",
                service_id: &service,
                depth: 0,
            });
            observer.service_finished(
                scope,
                ServiceObservationResult {
                    outcome: ServiceObservationOutcome::Failed(class),
                },
            );
        }

        let output = metrics.render_prometheus();
        assert!(output.contains(
            "oxidase_observe_errors_total{observe=\"cluster-boundary\",class=\"upstream_unavailable\"} 1"
        ));
        assert!(output.contains(
            "oxidase_observe_errors_total{observe=\"cluster-boundary\",class=\"upstream_overloaded\"} 1"
        ));
        assert!(!output.contains("endpoint="));
        assert!(!output.contains("url="));
    }

    #[test]
    fn transport_guards_release_active_counters() {
        let metrics = Arc::new(Metrics::default());
        let transport = metrics.listener_transport("public");
        let http1 = transport.connection_accepted(ConnectionProtocol::Http1);
        let h2 = transport.connection_accepted(ConnectionProtocol::Http2);
        let stream = transport.h2_stream_started();
        let output = metrics.render_prometheus();
        assert!(output.contains(
            "oxidase_connections_accepted_total{listener=\"public\",protocol=\"http1\"} 1"
        ));
        assert!(
            output.contains(
                "oxidase_connections_accepted_total{listener=\"public\",protocol=\"h2\"} 1"
            )
        );
        assert!(
            output.contains("oxidase_active_connections{listener=\"public\",protocol=\"http1\"} 1")
        );
        assert!(
            output.contains("oxidase_active_connections{listener=\"public\",protocol=\"h2\"} 1")
        );
        assert!(output.contains("oxidase_http2_active_streams{listener=\"public\"} 1"));

        drop(http1);
        drop(h2);
        drop(stream);
        let output = metrics.render_prometheus();
        assert!(
            output.contains("oxidase_active_connections{listener=\"public\",protocol=\"http1\"} 0")
        );
        assert!(
            output.contains("oxidase_active_connections{listener=\"public\",protocol=\"h2\"} 0")
        );
        assert!(output.contains("oxidase_http2_active_streams{listener=\"public\"} 0"));
    }

    #[test]
    fn concurrent_transport_guard_drop_is_exact_and_cancellation_safe() {
        const WORKERS: usize = 32;

        let metrics = Arc::new(Metrics::default());
        let transport = metrics.listener_transport("concurrent");
        let all_active = Arc::new(Barrier::new(WORKERS + 1));
        let release = Arc::new(Barrier::new(WORKERS + 1));
        let workers = (0..WORKERS)
            .map(|_| {
                let transport = transport.clone();
                let all_active = Arc::clone(&all_active);
                let release = Arc::clone(&release);
                std::thread::spawn(move || {
                    let connection = transport.connection_accepted(ConnectionProtocol::Http2);
                    let stream = transport.h2_stream_started();
                    let tunnel = transport.tunnel_started();
                    all_active.wait();
                    release.wait();
                    drop(tunnel);
                    drop(stream);
                    drop(connection);
                })
            })
            .collect::<Vec<_>>();

        all_active.wait();
        let output = metrics.render_prometheus();
        assert!(output.contains(&format!(
            "oxidase_active_connections{{listener=\"concurrent\",protocol=\"h2\"}} {WORKERS}"
        )));
        assert!(output.contains(&format!(
            "oxidase_http2_active_streams{{listener=\"concurrent\"}} {WORKERS}"
        )));
        assert!(output.contains(&format!(
            "oxidase_active_tunnels{{listener=\"concurrent\"}} {WORKERS}"
        )));

        release.wait();
        for worker in workers {
            worker.join().expect("transport worker does not panic");
        }
        let output = metrics.render_prometheus();
        assert!(
            output
                .contains("oxidase_active_connections{listener=\"concurrent\",protocol=\"h2\"} 0")
        );
        assert!(output.contains("oxidase_http2_active_streams{listener=\"concurrent\"} 0"));
        assert!(output.contains("oxidase_active_tunnels{listener=\"concurrent\"} 0"));
        assert!(output.contains(&format!(
            "oxidase_tunnel_terminations_total{{listener=\"concurrent\",reason=\"cancelled\"}} {WORKERS}"
        )));
    }

    #[test]
    fn tls_and_h2_metrics_only_emit_fixed_bounded_labels() {
        let metrics = Metrics::default();
        let transport = metrics.listener_transport("public-https");
        for outcome in TlsHandshakeOutcome::ALL {
            transport.record_tls_handshake(outcome, Duration::from_millis(7));
        }
        for alpn in [
            TlsAlpn::from_negotiated(Some(b"http/1.1")),
            TlsAlpn::from_negotiated(Some(b"h2")),
            TlsAlpn::from_negotiated(None),
            TlsAlpn::from_negotiated(Some(b"secret.example/path?user=42")),
        ] {
            transport.record_tls_alpn(alpn);
        }
        transport.record_h2_shutdown(H2Shutdown::Graceful);
        transport.record_h2_shutdown(H2Shutdown::Forced);

        let output = metrics.render_prometheus();
        for result in [
            "success",
            "failure",
            "timeout",
            "protocol",
            "io",
            "overloaded",
            "alpn_required",
            "alpn_mismatch",
        ] {
            assert!(output.contains(&format!(
                "oxidase_tls_handshakes_total{{listener=\"public-https\",result=\"{result}\"}} 1"
            )));
            assert!(output.contains(&format!(
                "oxidase_tls_handshake_duration_seconds_bucket{{listener=\"public-https\",result=\"{result}\""
            )));
        }
        for protocol in ["http1", "h2", "none", "other"] {
            assert!(output.contains(&format!(
                "oxidase_tls_alpn_total{{listener=\"public-https\",protocol=\"{protocol}\"}} 1"
            )));
        }
        assert!(output.contains(
            "oxidase_http2_shutdown_total{listener=\"public-https\",result=\"graceful\"} 1"
        ));
        assert!(output.contains(
            "oxidase_http2_shutdown_total{listener=\"public-https\",result=\"forced\"} 1"
        ));
        assert!(!output.contains("secret.example"));
        assert!(!output.contains("user=42"));
    }

    #[test]
    fn tunnel_guard_records_directional_bytes_and_fixed_termination() {
        let metrics = Metrics::default();
        let transport = metrics.listener_transport("public");
        let tunnel = transport.tunnel_started();

        let output = metrics.render_prometheus();
        assert!(output.contains("oxidase_tunnels_started_total{listener=\"public\"} 1"));
        assert!(output.contains("oxidase_active_tunnels{listener=\"public\"} 1"));

        tunnel.finish(17, 29, TunnelTermination::DownstreamClosed);

        let output = metrics.render_prometheus();
        assert!(output.contains("oxidase_active_tunnels{listener=\"public\"} 0"));
        assert!(output.contains(
            "oxidase_tunnel_bytes_total{listener=\"public\",direction=\"downstream_to_upstream\"} 17"
        ));
        assert!(output.contains(
            "oxidase_tunnel_bytes_total{listener=\"public\",direction=\"upstream_to_downstream\"} 29"
        ));
        assert!(output.contains(
            "oxidase_tunnel_terminations_total{listener=\"public\",reason=\"downstream_closed\"} 1"
        ));
        assert!(output.contains(
            "oxidase_tunnel_terminations_total{listener=\"public\",reason=\"cancelled\"} 0"
        ));
    }

    #[test]
    fn dropping_unfinished_tunnel_records_cancellation() {
        let metrics = Metrics::default();
        let transport = metrics.listener_transport("public");
        let tunnel = transport.tunnel_started();

        drop(tunnel);

        let output = metrics.render_prometheus();
        assert!(output.contains("oxidase_active_tunnels{listener=\"public\"} 0"));
        assert!(output.contains(
            "oxidase_tunnel_terminations_total{listener=\"public\",reason=\"cancelled\"} 1"
        ));
        assert!(
            output.contains(
                "oxidase_tunnel_terminations_total{listener=\"public\",reason=\"error\"} 0"
            )
        );
        assert!(!output.contains("http://"));
    }

    #[test]
    fn transport_series_are_scoped_and_sorted_by_configured_listener_name() {
        let metrics = Metrics::default();
        let public = metrics.listener_transport("public");
        let internal = metrics.listener_transport("internal");
        public.record_tls_handshake(TlsHandshakeOutcome::Success, Duration::from_millis(2));
        internal.record_tls_handshake(TlsHandshakeOutcome::Timeout, Duration::from_millis(5));

        let output = metrics.render_prometheus();
        let internal_position = output
            .find("oxidase_connections_accepted_total{listener=\"internal\"")
            .expect("internal listener series is rendered");
        let public_position = output
            .find("oxidase_connections_accepted_total{listener=\"public\"")
            .expect("public listener series is rendered");
        assert!(internal_position < public_position);
        assert!(
            output
                .contains("oxidase_tls_handshakes_total{listener=\"public\",result=\"success\"} 1")
        );
        assert!(
            output.contains(
                "oxidase_tls_handshakes_total{listener=\"internal\",result=\"timeout\"} 1"
            )
        );
    }
}
