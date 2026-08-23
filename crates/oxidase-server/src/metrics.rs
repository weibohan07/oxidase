use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use http::StatusCode;

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
}

impl Metrics {
    pub(crate) fn request_started(&self) -> ActiveRequest<'_> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.active_requests.fetch_add(1, Ordering::Relaxed);
        ActiveRequest { metrics: self }
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
        let millis = latency.as_millis();
        let bucket = LATENCY_BOUNDS_MS
            .iter()
            .position(|bound| millis <= u128::from(*bound))
            .unwrap_or(LATENCY_BOUNDS_MS.len());
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
        output
    }
}

pub(crate) struct ActiveRequest<'a> {
    metrics: &'a Metrics,
}

impl Drop for ActiveRequest<'_> {
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
    use std::time::Duration;

    use http::StatusCode;

    use super::Metrics;

    #[test]
    fn metric_labels_are_from_fixed_bounded_sets() {
        let metrics = Metrics::default();
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
}
