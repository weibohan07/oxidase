use std::collections::BTreeMap;
use std::time::Instant;

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};
use oxidase_core::{
    CompiledTemplate, HeaderTransforms, RequestFrame, RequestMetadata, ResourceId, RespondBody,
    ResponseHead, ServiceId, ServiceKind, ServiceNode, ServiceOutcome, ServiceProgram, SourceSpan,
};
use oxidase_runtime::{BoxLeafFuture, Executor, LeafExecutor};

struct NoLeaves;

impl LeafExecutor<(), Bytes> for NoLeaves {
    fn body_from_bytes(&self, bytes: Bytes) -> Bytes {
        bytes
    }

    fn execute_site<'a>(
        &'a self,
        _resource: &'a ResourceId,
        _request: &'a RequestFrame,
    ) -> BoxLeafFuture<'a, Bytes> {
        Box::pin(async { ServiceOutcome::Handled(ResponseHead::new(StatusCode::OK, Bytes::new())) })
    }

    fn execute_proxy<'a>(
        &'a self,
        _cluster: &'a ResourceId,
        _request: &'a RequestFrame,
        _body: &'a mut Option<()>,
    ) -> BoxLeafFuture<'a, Bytes> {
        Box::pin(async { ServiceOutcome::Handled(ResponseHead::new(StatusCode::OK, Bytes::new())) })
    }
}

#[tokio::main]
async fn main() {
    let id = ServiceId::new("bench:respond");
    let node = ServiceNode {
        id: id.clone(),
        source: SourceSpan::synthetic("bench"),
        kind: ServiceKind::Respond {
            status: StatusCode::OK,
            headers: HeaderTransforms::default(),
            body: RespondBody::Text(
                CompiledTemplate::compile("hello {{ request.path }}")
                    .expect("benchmark template is valid"),
            ),
        },
    };
    let mut nodes = BTreeMap::from([(id.clone(), node)]);
    for index in 0..4_096 {
        let unused_id = ServiceId::new(format!("bench:unused:{index}"));
        nodes.insert(
            unused_id.clone(),
            ServiceNode {
                id: unused_id,
                source: SourceSpan::synthetic("bench.unused"),
                kind: ServiceKind::Respond {
                    status: StatusCode::OK,
                    headers: HeaderTransforms::default(),
                    body: RespondBody::Empty,
                },
            },
        );
    }
    let program = ServiceProgram::from_nodes(id, nodes);
    let request = RequestFrame::new(
        RequestMetadata::try_new(
            Method::GET,
            "http",
            "example.test",
            "/benchmark",
            HeaderMap::new(),
        )
        .expect("benchmark request metadata is valid"),
    );
    let leaves = NoLeaves;
    let executor = Executor::new(&program, &leaves);
    let iterations = 100_000u32;
    let started = Instant::now();
    for _ in 0..iterations {
        let report = executor.execute(request.clone(), None).await;
        if !matches!(report.outcome, ServiceOutcome::Handled(_)) {
            panic!("benchmark program unexpectedly failed");
        }
    }
    let elapsed = started.elapsed();
    println!(
        "executed {iterations} short paths through one shared {}-node graph in {elapsed:?} ({:.0} programs/s)",
        program.graph.len(),
        f64::from(iterations) / elapsed.as_secs_f64()
    );
}
