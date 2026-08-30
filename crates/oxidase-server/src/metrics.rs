use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http::StatusCode;
use oxidase_core::ErrorClass;
use oxidase_runtime::{
    ExecutionObserver, ServiceObservationContext, ServiceObservationOutcome,
    ServiceObservationResult,
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
    connections_accepted: [AtomicU64; 2],
    active_connections: [AtomicU64; 2],
    tls_handshakes: [AtomicU64; 5],
    tls_handshake_duration_buckets: [[AtomicU64; 10]; 5],
    tls_alpn: [AtomicU64; 4],
    h2_active_streams: AtomicU64,
    h2_shutdowns: [AtomicU64; 2],
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

    pub(crate) fn connection_accepted(
        self: &Arc<Self>,
        protocol: ConnectionProtocol,
    ) -> ActiveConnection {
        self.connections_accepted[protocol.index()].fetch_add(1, Ordering::Relaxed);
        self.active_connections[protocol.index()].fetch_add(1, Ordering::Relaxed);
        ActiveConnection {
            metrics: self.clone(),
            protocol,
        }
    }

    pub(crate) fn record_tls_handshake(&self, outcome: TlsHandshakeOutcome, duration: Duration) {
        self.tls_handshakes[outcome.index()].fetch_add(1, Ordering::Relaxed);
        let bucket = latency_bucket(duration);
        self.tls_handshake_duration_buckets[outcome.index()][bucket]
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_tls_alpn(&self, alpn: TlsAlpn) {
        self.tls_alpn[alpn.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn h2_stream_started(self: &Arc<Self>) -> ActiveH2Stream {
        self.h2_active_streams.fetch_add(1, Ordering::Relaxed);
        ActiveH2Stream {
            metrics: self.clone(),
        }
    }

    pub(crate) fn record_h2_shutdown(&self, shutdown: H2Shutdown) {
        self.h2_shutdowns[shutdown.index()].fetch_add(1, Ordering::Relaxed);
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
        for protocol in ConnectionProtocol::ALL {
            output.push_str(&format!(
                "oxidase_connections_accepted_total{{protocol=\"{}\"}} {}\n",
                protocol.as_str(),
                self.connections_accepted[protocol.index()].load(Ordering::Relaxed)
            ));
            output.push_str(&format!(
                "oxidase_active_connections{{protocol=\"{}\"}} {}\n",
                protocol.as_str(),
                self.active_connections[protocol.index()].load(Ordering::Relaxed)
            ));
        }
        for outcome in TlsHandshakeOutcome::ALL {
            output.push_str(&format!(
                "oxidase_tls_handshakes_total{{result=\"{}\"}} {}\n",
                outcome.as_str(),
                self.tls_handshakes[outcome.index()].load(Ordering::Relaxed)
            ));
            let mut cumulative = 0u64;
            for (index, value) in self.tls_handshake_duration_buckets[outcome.index()]
                .iter()
                .enumerate()
            {
                cumulative = cumulative.saturating_add(value.load(Ordering::Relaxed));
                let bound = LATENCY_BOUNDS_MS.get(index).map_or_else(
                    || "+Inf".to_owned(),
                    |bound| format!("{:.3}", *bound as f64 / 1_000.0),
                );
                output.push_str(&format!(
                    "oxidase_tls_handshake_duration_seconds_bucket{{result=\"{}\",le=\"{bound}\"}} {cumulative}\n",
                    outcome.as_str()
                ));
            }
        }
        for alpn in TlsAlpn::ALL {
            output.push_str(&format!(
                "oxidase_tls_alpn_total{{protocol=\"{}\"}} {}\n",
                alpn.as_str(),
                self.tls_alpn[alpn.index()].load(Ordering::Relaxed)
            ));
        }
        push_counter(
            &mut output,
            "oxidase_http2_active_streams",
            self.h2_active_streams.load(Ordering::Relaxed),
        );
        for shutdown in H2Shutdown::ALL {
            output.push_str(&format!(
                "oxidase_http2_shutdown_total{{result=\"{}\"}} {}\n",
                shutdown.as_str(),
                self.h2_shutdowns[shutdown.index()].load(Ordering::Relaxed)
            ));
        }
        output
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
}

impl TlsHandshakeOutcome {
    const ALL: [Self; 5] = [
        Self::Success,
        Self::Failure,
        Self::Timeout,
        Self::Protocol,
        Self::Io,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Success => 0,
            Self::Failure => 1,
            Self::Timeout => 2,
            Self::Protocol => 3,
            Self::Io => 4,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Timeout => "timeout",
            Self::Protocol => "protocol",
            Self::Io => "io",
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

#[must_use = "dropping the guard immediately records the connection as inactive"]
pub(crate) struct ActiveConnection {
    metrics: Arc<Metrics>,
    protocol: ConnectionProtocol,
}

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        self.metrics.active_connections[self.protocol.index()].fetch_sub(1, Ordering::Relaxed);
    }
}

#[must_use = "dropping the guard immediately records the HTTP/2 stream as inactive"]
pub(crate) struct ActiveH2Stream {
    metrics: Arc<Metrics>,
}

impl Drop for ActiveH2Stream {
    fn drop(&mut self) {
        self.metrics
            .h2_active_streams
            .fetch_sub(1, Ordering::Relaxed);
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

const ERROR_CLASSES: [&str; 9] = [
    "configuration",
    "timeout",
    "upstream_connect",
    "upstream_protocol",
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
    error_classes: [AtomicU64; 9],
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
        ErrorClass::SiteIo => 4,
        ErrorClass::TemplateLimit => 5,
        ErrorClass::BodyUnavailable => 6,
        ErrorClass::InvalidState => 7,
        ErrorClass::Internal => 8,
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
    use std::sync::Arc;
    use std::time::Duration;

    use http::StatusCode;
    use oxidase_core::ServiceId;
    use oxidase_runtime::{
        ExecutionObserver, ServiceObservationContext, ServiceObservationOutcome,
        ServiceObservationResult,
    };

    use super::{
        ConnectionProtocol, H2Shutdown, Metrics, ProductionObserver, TlsAlpn, TlsHandshakeOutcome,
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
    fn transport_guards_release_active_counters() {
        let metrics = Arc::new(Metrics::default());
        let http1 = metrics.connection_accepted(ConnectionProtocol::Http1);
        let h2 = metrics.connection_accepted(ConnectionProtocol::Http2);
        let stream = metrics.h2_stream_started();
        let output = metrics.render_prometheus();
        assert!(output.contains("oxidase_connections_accepted_total{protocol=\"http1\"} 1"));
        assert!(output.contains("oxidase_connections_accepted_total{protocol=\"h2\"} 1"));
        assert!(output.contains("oxidase_active_connections{protocol=\"http1\"} 1"));
        assert!(output.contains("oxidase_active_connections{protocol=\"h2\"} 1"));
        assert!(output.contains("oxidase_http2_active_streams 1"));

        drop(http1);
        drop(h2);
        drop(stream);
        let output = metrics.render_prometheus();
        assert!(output.contains("oxidase_active_connections{protocol=\"http1\"} 0"));
        assert!(output.contains("oxidase_active_connections{protocol=\"h2\"} 0"));
        assert!(output.contains("oxidase_http2_active_streams 0"));
    }

    #[test]
    fn tls_and_h2_metrics_only_emit_fixed_bounded_labels() {
        let metrics = Metrics::default();
        for outcome in TlsHandshakeOutcome::ALL {
            metrics.record_tls_handshake(outcome, Duration::from_millis(7));
        }
        for alpn in [
            TlsAlpn::from_negotiated(Some(b"http/1.1")),
            TlsAlpn::from_negotiated(Some(b"h2")),
            TlsAlpn::from_negotiated(None),
            TlsAlpn::from_negotiated(Some(b"secret.example/path?user=42")),
        ] {
            metrics.record_tls_alpn(alpn);
        }
        metrics.record_h2_shutdown(H2Shutdown::Graceful);
        metrics.record_h2_shutdown(H2Shutdown::Forced);

        let output = metrics.render_prometheus();
        for result in ["success", "failure", "timeout", "protocol", "io"] {
            assert!(output.contains(&format!(
                "oxidase_tls_handshakes_total{{result=\"{result}\"}} 1"
            )));
            assert!(output.contains(&format!(
                "oxidase_tls_handshake_duration_seconds_bucket{{result=\"{result}\""
            )));
        }
        for protocol in ["http1", "h2", "none", "other"] {
            assert!(output.contains(&format!(
                "oxidase_tls_alpn_total{{protocol=\"{protocol}\"}} 1"
            )));
        }
        assert!(output.contains("oxidase_http2_shutdown_total{result=\"graceful\"} 1"));
        assert!(output.contains("oxidase_http2_shutdown_total{result=\"forced\"} 1"));
        assert!(!output.contains("secret.example"));
        assert!(!output.contains("user=42"));
    }
}
