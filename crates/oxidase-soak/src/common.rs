use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rcgen::{CertifiedKey as GeneratedCertificate, generate_simple_self_signed};
use tokio::sync::oneshot;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::crypto::ring::default_provider;
use tokio_rustls::rustls::pki_types::CertificateDer;

use crate::{ProcessObservation, ResourceObservation, SoakError};

pub(crate) struct TestIdentity {
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub certificate_der: CertificateDer<'static>,
}

pub(crate) fn identity() -> Result<TestIdentity, SoakError> {
    // This identity is generated for one local campaign and is never production material.
    let GeneratedCertificate { cert, signing_key } =
        generate_simple_self_signed(vec!["gateway.example.test".to_owned()])
            .map_err(|error| SoakError::message(format!("generate test TLS identity: {error}")))?;
    Ok(TestIdentity {
        certificate_pem: cert.pem(),
        private_key_pem: signing_key.serialize_pem(),
        certificate_der: cert.der().clone(),
    })
}

pub(crate) fn write_identity(directory: &Path, identity: &TestIdentity) -> Result<(), SoakError> {
    fs::write(directory.join("gateway.pem"), &identity.certificate_pem)
        .map_err(|error| SoakError::message(format!("write test certificate: {error}")))?;
    fs::write(directory.join("gateway-key.pem"), &identity.private_key_pem)
        .map_err(|error| SoakError::message(format!("write test private key: {error}")))?;
    Ok(())
}

pub(crate) fn client_config(
    identities: &[&TestIdentity],
    alpn: &[&[u8]],
) -> Result<Arc<ClientConfig>, SoakError> {
    let mut roots = RootCertStore::empty();
    for identity in identities {
        roots
            .add(identity.certificate_der.clone())
            .map_err(|error| SoakError::message(format!("trust test certificate: {error}")))?;
    }
    let provider = Arc::new(default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| SoakError::message(format!("select safe TLS versions: {error}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Ok(Arc::new(config))
}

pub(crate) struct Fixture {
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl Fixture {
    pub(crate) fn new(shutdown: oneshot::Sender<()>, task: tokio::task::JoinHandle<()>) -> Self {
        Self {
            shutdown: Some(shutdown),
            task,
        }
    }

    pub(crate) async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = self.task.await;
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct ProcessSample {
    rss_kib: Option<u64>,
    open_fds: Option<u64>,
}

#[derive(Debug)]
struct Samples {
    baseline: ProcessSample,
    peak: ProcessSample,
}

pub(crate) struct ResourceMonitor {
    samples: Arc<Mutex<Samples>>,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl ResourceMonitor {
    pub(crate) fn start() -> Self {
        let baseline = process_sample();
        let samples = Arc::new(Mutex::new(Samples {
            baseline,
            peak: baseline,
        }));
        let (stop, mut stop_receiver) = oneshot::channel();
        let task_samples = Arc::clone(&samples);
        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(100));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let sample = process_sample();
                        let mut samples = task_samples
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        samples.peak.rss_kib = option_max(samples.peak.rss_kib, sample.rss_kib);
                        samples.peak.open_fds = option_max(samples.peak.open_fds, sample.open_fds);
                    }
                    _ = &mut stop_receiver => break,
                }
            }
        });
        Self {
            samples,
            stop: Some(stop),
            task,
        }
    }

    pub(crate) async fn finish(mut self) -> ProcessObservation {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let _ = self.task.await;
        let final_sample = process_sample();
        let samples = self
            .samples
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ProcessObservation {
            rss_kib: ResourceObservation {
                baseline: samples.baseline.rss_kib,
                peak: option_max(samples.peak.rss_kib, final_sample.rss_kib),
                final_value: final_sample.rss_kib,
            },
            open_fds: ResourceObservation {
                baseline: samples.baseline.open_fds,
                peak: option_max(samples.peak.open_fds, final_sample.open_fds),
                final_value: final_sample.open_fds,
            },
        }
    }
}

fn option_max(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn process_sample() -> ProcessSample {
    ProcessSample {
        rss_kib: linux_rss_kib(),
        open_fds: linux_open_fds(),
    }
}

fn linux_rss_kib() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn linux_open_fds() -> Option<u64> {
    let count = fs::read_dir("/proc/self/fd").ok()?.count();
    u64::try_from(count).ok()
}

pub(crate) struct XorShift64(u64);

impl XorShift64 {
    pub(crate) fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    pub(crate) fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }
}

pub(crate) fn metric_sum(metrics: &str, name: &str) -> u64 {
    metrics
        .lines()
        .filter(|line| line.starts_with(name))
        .filter_map(|line| line.split_whitespace().last())
        .filter_map(|value| value.parse::<u64>().ok())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_sum_collects_bounded_series() {
        let input = "metric{endpoint=\"a\"} 2\nmetric{endpoint=\"b\"} 3\nother 9\n";
        assert_eq!(metric_sum(input, "metric{"), 5);
    }

    #[test]
    fn xorshift_is_reproducible() {
        let mut first = XorShift64::new(42);
        let mut second = XorShift64::new(42);
        assert_eq!(first.next(), second.next());
        assert_eq!(first.next(), second.next());
    }
}
