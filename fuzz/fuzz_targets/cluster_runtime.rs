#![no_main]

use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use oxidase_config::{Compiler, RetryCause};
use oxidase_core::ResourceId;
use oxidase_runtime::PreparedCluster;
use oxidase_server::fuzzing::{retry_allows_cause, retry_allows_status};

const VALID_CLUSTER: &str = r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    api:
      protocol: h2
      endpoints:
        - name: api-a
          url: https://127.0.0.1:8443/base
          weight: 2
        - name: api-b
          url: https://127.0.0.1:9443
          weight: 1
      load_balance:
        policy: weighted_round_robin
      health:
        active:
          path: /healthz
          interval: 5s
          timeout: 1s
          healthy_statuses: ["200-299", 304]
          healthy_threshold: 2
          unhealthy_threshold: 3
        passive:
          consecutive_failures: 2
          eject_for: 30s
      retry:
        max_attempts: 3
        methods: [GET, HEAD]
        retry_on: [connect_failure, response_header_timeout, refused_stream, reset]
        statuses: [502, "503-504"]
        request_body:
          mode: none
          max_bytes: 64KiB
        max_concurrent_retries: 16
      limits:
        max_in_flight: 512
        max_in_flight_per_endpoint: 128
        queue_timeout: 0ms
listeners:
  - name: public
    bind: 127.0.0.1:8080
    service:
      type: respond
"#;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let mutation_end = rest.len().min(512);
    let mutation = serde_json::to_string(&String::from_utf8_lossy(&rest[..mutation_end]))
        .expect("JSON strings are valid YAML quoted scalars");
    let mutated = match selector % 8 {
        0 => VALID_CLUSTER.replace("protocol: h2", &format!("protocol: {mutation}")),
        1 => VALID_CLUSTER.replace("name: api-a", &format!("name: {mutation}")),
        2 => VALID_CLUSTER.replace(
            "url: https://127.0.0.1:8443/base",
            &format!("url: {mutation}"),
        ),
        3 => VALID_CLUSTER.replace(
            "policy: weighted_round_robin",
            &format!("policy: {mutation}"),
        ),
        4 => VALID_CLUSTER.replace(
            "healthy_statuses: [\"200-299\", 304]",
            &format!("healthy_statuses: [{mutation}]"),
        ),
        5 => VALID_CLUSTER.replace(
            "retry_on: [connect_failure, response_header_timeout, refused_stream, reset]",
            &format!("retry_on: [{mutation}]"),
        ),
        6 => VALID_CLUSTER.replace(
            "statuses: [502, \"503-504\"]",
            &format!("statuses: [{mutation}]"),
        ),
        _ => VALID_CLUSTER.replace("weight: 2", &format!("weight: {mutation}")),
    };

    let Ok(directory) = tempfile::tempdir() else {
        return;
    };
    let path = directory.path().join("oxidase.yaml");
    if std::fs::write(&path, mutated).is_ok() {
        let _ = Compiler::compile_path(&path);
    }

    if std::fs::write(&path, VALID_CLUSTER).is_err() {
        return;
    }
    let Ok(gateway) = Compiler::compile_path(path) else {
        return;
    };
    let Some(spec) = gateway
        .resources
        .clusters
        .get(&ResourceId::new("cluster:api"))
        .cloned()
    else {
        return;
    };
    let retry = spec.retry.clone();
    let (cluster, _) = PreparedCluster::prepare(spec, None);
    let start = Instant::now();
    let operations = &rest[mutation_end..];
    let mut elapsed_ms = 0_u64;
    for operation in operations.iter().copied().take(1_024) {
        elapsed_ms = elapsed_ms.saturating_add(u64::from(operation >> 5));
        let now = start + Duration::from_millis(elapsed_ms);
        match operation & 0x07 {
            0 => cluster.record_active_health("api-a", true, now),
            1 => cluster.record_active_health("api-a", false, now),
            2 => cluster.record_passive_success("api-a"),
            3 => cluster.record_passive_failure("api-a", now),
            4 => {
                let _ = cluster.select_endpoint(now);
            }
            5 => {
                let status = 100 + u16::from(operation);
                let _ = retry_allows_status(&retry, status);
            }
            6 => {
                let cause = match (operation >> 3) & 0x03 {
                    0 => RetryCause::ConnectFailure,
                    1 => RetryCause::ResponseHeaderTimeout,
                    2 => RetryCause::RefusedStream,
                    _ => RetryCause::Reset,
                };
                let _ = retry_allows_cause(&retry, cause);
            }
            _ => {
                let _ = cluster.status(now);
            }
        }
    }
});
