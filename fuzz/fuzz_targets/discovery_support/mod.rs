//! Test-only fixture construction. No listener, resolver or background task is
//! started. The one source file is removed after exporting the source-free plan.

use std::sync::OnceLock;

use oxidase_config::{ClusterSpec, Compiler, DnsRecordType};
use oxidase_core::ResourceId;
use oxidase_runtime::{PortableRuntimePlanV1, RuntimeSnapshot};

const SOURCE: &str = r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    api:
      discovery:
        dns:
          name: _http._tcp.lookup.example.test
          record: srv
          origin: http://logical.example.test/base/
          resolver:
            system: true
          refresh:
            min_interval: 10ms
            max_interval: 1s
            jitter_percent: 0
            stale_if_error: 50ms
          limits:
            max_endpoints: 8
            max_targets: 8
      timeouts:
        connect: 50ms
        tls_handshake: 50ms
        request_body_idle: 50ms
        response_header: 50ms
        response_body_idle: 50ms
        pre_response_total: 200ms
      health:
        active:
          path: /healthz
          interval: 1s
          timeout: 10ms
          healthy_threshold: 1
          unhealthy_threshold: 1
        passive:
          consecutive_failures: 2
          eject_for: 10ms
      limits:
        max_in_flight: 8
        max_in_flight_per_endpoint: 2
        queue_timeout: 0ms
services:
  public:
    type: proxy
    cluster: api
listeners:
  - name: fixture
    bind: 127.0.0.1:0
    service:
      ref: public
"#;

struct Fixture {
    spec: ClusterSpec,
    plan: PortableRuntimePlanV1,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let directory = tempfile::tempdir().expect("test-only source directory");
        let source = directory.path().join("fixture.yaml");
        std::fs::write(&source, SOURCE).expect("write test-only compiler fixture");
        let gateway = Compiler::compile_path(&source).expect("offline fixture compiles");
        let spec = gateway.resources.clusters[&ResourceId::new("cluster:api")].clone();
        let snapshot =
            RuntimeSnapshot::prepare(gateway.clone()).expect("inactive fixture prepares");
        let plan = snapshot
            .export_portable(&gateway)
            .expect("fixture exports")
            .plan;
        std::fs::remove_file(source).expect("source-free consumers cannot read this source");
        Fixture { spec, plan }
    })
}

pub fn spec(srv: bool) -> ClusterSpec {
    let mut spec = fixture().spec.clone();
    let discovery = spec.discovery.as_mut().expect("fixture discovery");
    if !srv {
        discovery.record = DnsRecordType::AAndAaaa;
        discovery.name = "lookup.example.test.".to_owned();
        discovery.port = Some(8080);
    }
    spec
}

pub fn plan() -> PortableRuntimePlanV1 {
    fixture().plan.clone()
}

/// Short chunks are zero-filled, so even a one-byte input reaches real state.
pub fn byte(data: &[u8], index: usize) -> u8 {
    data.get(index).copied().unwrap_or(0)
}
