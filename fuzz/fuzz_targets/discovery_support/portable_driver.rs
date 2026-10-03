use std::path::Path;

use oxidase_bundle::{
    BuildMetadata, BundleArchive, BundleBuilder, BundleLimits, BundleManifest, StableSection,
};
use oxidase_core::ContentDigest;
use oxidase_runtime::{
    PORTABLE_RUNTIME_PLAN_SCHEMA_V1, PortableRuntimePlanV1, bundle_runtime_capabilities,
    prepare_bundle_archive,
};
use oxidase_site::PortableSiteError;
use serde_json::{Value, json};

use crate::discovery_support::{self, byte};

const MAX_INPUT: usize = 32 * 1024;
const DEPLOYMENT_ROOT: &str = "/oxidase-fuzz-unused-deployment";
const PHASES: [&str; 6] = [
    "connect",
    "tls_handshake",
    "request_body_idle",
    "response_header",
    "response_body_idle",
    "pre_response_total",
];

pub fn run(data: &[u8]) {
    let data = &data[..data.len().min(MAX_INPUT)];
    // Raw decoding exercises rejection; derived candidates keep semantic
    // validation and source-free preparation success paths hot on every input.
    if let Ok(plan) = serde_json::from_slice::<PortableRuntimePlanV1>(data) {
        validate(&plan, data);
    }
    let baseline = discovery_support::plan();
    validate(&baseline, b"valid-source-free-baseline");
    let mut value = serde_json::to_value(&baseline).expect("portable fixture serializes");
    mutate(&mut value, data);
    let bytes = serde_json::to_vec(&value).expect("bounded JSON mutation serializes");
    if let Ok(plan) = serde_json::from_slice::<PortableRuntimePlanV1>(&bytes) {
        validate(&plan, &bytes);
    }
    exercise_capabilities(&baseline, byte(data, 0));
}

fn validate(plan: &PortableRuntimePlanV1, bytes: &[u8]) {
    let identity = ContentDigest::of_bytes(bytes);
    let root = Path::new(DEPLOYMENT_ROOT);
    let result = plan.validate_with_assets(identity, root, |_, _, _| {
        Err(PortableSiteError::asset_resolution(
            "this property driver has no assets",
        ))
    });
    if result.is_ok() {
        let encoded = serde_json::to_vec(plan).expect("accepted plan serializes");
        let decoded: PortableRuntimePlanV1 =
            serde_json::from_slice(&encoded).expect("accepted plan round trips");
        assert_eq!(plan, &decoded);
        let compiled = plan
            .gateway
            .compile_at(root)
            .expect("validated Gateway reconstructs");
        for spec in compiled.resources.clusters.values() {
            if let Some(dns) = &spec.discovery {
                let timeouts = spec
                    .timeouts
                    .as_ref()
                    .expect("discovery cannot omit phased contract");
                for timeout in [
                    timeouts.connect,
                    timeouts.tls_handshake,
                    timeouts.request_body_idle,
                    timeouts.response_header,
                    timeouts.response_body_idle,
                    timeouts.pre_response_total,
                ] {
                    assert!(!timeout.is_zero());
                    assert!(timeout <= oxidase_config::MAX_UPSTREAM_PHASE_TIMEOUT);
                }
                assert_eq!(spec.connect_timeout, timeouts.connect);
                assert_eq!(spec.response_timeout, timeouts.response_body_idle);
                assert!(spec.endpoints.is_empty(), "no static/discovery ambiguity");
                assert!(dns.limits.max_endpoints <= oxidase_config::MAX_DNS_ENDPOINTS);
                assert!(dns.limits.max_targets <= oxidase_config::MAX_DNS_TARGETS);
            }
        }
        // Never open arbitrary runtime references, invoke a resolver, or
        // enumerate TLS roots from a randomized plan. Plain HTTP/no-reference
        // plans still reach the actual source-free snapshot preparation path.
        let no_external_material = plan.gateway.secrets.is_empty()
            && plan.gateway.certificates.is_empty()
            && plan.gateway.trust_stores.is_empty()
            && plan.gateway.admin.is_none()
            && plan.sites.is_empty()
            && compiled.resources.clusters.values().all(|spec| {
                spec.tls.is_none()
                    && spec
                        .endpoints
                        .iter()
                        .all(|endpoint| endpoint.url.scheme() == "http")
                    && spec
                        .discovery
                        .as_ref()
                        .is_none_or(|dns| dns.origin.scheme() == "http")
            });
        if no_external_material {
            let (snapshot, _) = plan
                .prepare_with_assets(
                    identity,
                    root,
                    Vec::new(),
                    |_, _, _| Err(PortableSiteError::asset_resolution("no test assets")),
                    None,
                )
                .expect("validated reference-free HTTP plan prepares without YAML or DNS");
            for cluster in snapshot.resources.clusters.values() {
                if cluster.spec().discovery.is_some() {
                    assert!(cluster.endpoints().is_empty());
                    assert!(
                        cluster.begin_discovery_query().is_none(),
                        "prepare must not start DNS"
                    );
                    assert!(!cluster.supervisor_is_activated());
                }
                assert_eq!(cluster.active_requests(), 0);
            }
        }
    }
}

fn mutate(plan: &mut Value, data: &[u8]) {
    let selector = byte(data, 0) % 24;
    let text = String::from_utf8_lossy(
        &data.get(1..).unwrap_or_default()[..data.len().saturating_sub(1).min(256)],
    )
    .into_owned();
    let cluster = &mut plan["gateway"]["clusters"]["cluster:api"];
    match selector {
        0 => {}
        1 => cluster["discovery"]["name"] = json!(text),
        2 => cluster["discovery"]["record"] = json!(text),
        3 => {
            let aa = byte(data, 1) & 1 == 0;
            cluster["discovery"]["record"] = json!(if aa { "a_aaaa" } else { "srv" });
            cluster["discovery"]["name"] = json!(if aa {
                "lookup.example.test."
            } else {
                "_http._tcp.lookup.example.test."
            });
            if aa {
                cluster["discovery"]["port"] = json!(8080);
            } else {
                cluster["discovery"]
                    .as_object_mut()
                    .expect("fixture DNS map")
                    .remove("port");
            }
        }
        4 => {
            cluster["discovery"]["port"] = [json!(null), json!(0), json!(65535), json!("8080")]
                [usize::from(byte(data, 1) % 4)]
            .clone()
        }
        5 => cluster["discovery"]["origin"] = json!(text),
        6 => {
            cluster["discovery"]["resolver"]["mode"] = json!(if byte(data, 1) & 1 == 0 {
                "system"
            } else {
                "nameservers"
            });
            cluster["discovery"]["resolver"]["nameservers"] =
                json!(vec![text; usize::from(byte(data, 2) % 6)]);
        }
        7 => cluster["discovery"]["resolver"]["query_timeout"] = duration(data),
        8 => cluster["discovery"]["refresh"]["min_interval"] = duration(data),
        9 => cluster["discovery"]["refresh"]["max_interval"] = duration(data),
        10 => cluster["discovery"]["refresh"]["stale_if_error"] = duration(data),
        11 => cluster["discovery"]["refresh"]["jitter_percent"] = json!(byte(data, 1)),
        12 => {
            cluster["discovery"]["limits"]["max_endpoints"] =
                json!(u16::from_le_bytes([byte(data, 1), byte(data, 2)]))
        }
        13 => {
            cluster["discovery"]["limits"]["max_targets"] =
                json!(u16::from_le_bytes([byte(data, 1), byte(data, 2)]))
        }
        14 => {
            cluster["discovery"]["address_policy"]["allow_loopback"] = json!(byte(data, 1) & 1 == 0)
        }
        15 => cluster["discovery"]["unknown_field"] = json!(true),
        16 => cluster["timeouts"] = Value::Null,
        17 => {
            let phase = PHASES[usize::from(byte(data, 1)) % PHASES.len()];
            cluster["timeouts"][phase] = duration(data);
            if byte(data, 2) & 1 == 0 {
                if phase == "connect" {
                    cluster["connect_timeout"] = cluster["timeouts"][phase].clone();
                }
                if phase == "response_body_idle" {
                    cluster["response_timeout"] = cluster["timeouts"][phase].clone();
                }
            }
        }
        18 => {
            let phase = PHASES[usize::from(byte(data, 1)) % PHASES.len()];
            cluster["timeouts"]
                .as_object_mut()
                .expect("fixture timing map")
                .remove(phase);
        }
        19 => cluster["connect_timeout"] = duration(data),
        20 => cluster["response_timeout"] = duration(data),
        21 => cluster["protocol"] = json!(text),
        22 => plan["schema_version"] = json!(text),
        _ => cluster["discovery"]["source"]["file"] = json!(text),
    }
}

fn duration(data: &[u8]) -> Value {
    let (seconds, nanoseconds) = match byte(data, 2) % 8 {
        0 => (0, 0),
        1 => (0, 1),
        2 => (86_400, 0),
        3 => (86_400, 1),
        4 => (u64::MAX, 999_999_999),
        5 => (1, 1_000_000_000),
        6 => (
            u64::from_le_bytes(std::array::from_fn(|index| byte(data, index + 3))),
            0,
        ),
        _ => (1, u32::from(byte(data, 3))),
    };
    json!({ "seconds": seconds, "nanoseconds": nanoseconds })
}

fn exercise_capabilities(plan: &PortableRuntimePlanV1, selector: u8) {
    let build = BuildMetadata {
        tool_version: "bounded-discovery-property-driver".to_owned(),
        source_commit: None,
        gateway_api: "oxidase.dev/v1alpha1".to_owned(),
        oxista_api: "v1".to_owned(),
    };
    let mut manifest = BundleManifest::new(build, "0.3.0-alpha.1");
    manifest.required_features = plan.required_features();
    manifest.sections.insert(
        "runtime".to_owned(),
        StableSection::from_serde(PORTABLE_RUNTIME_PLAN_SCHEMA_V1, true, plan)
            .expect("bounded runtime section"),
    );
    let limits = BundleLimits {
        max_bundle_bytes: 256 * 1024,
        max_manifest_bytes: 128 * 1024,
        ..BundleLimits::default()
    };
    let features = manifest
        .required_features
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let omitted = &features[usize::from(selector) % features.len()];
    manifest.required_features.remove(omitted);
    let bytes = BundleBuilder::new(manifest)
        .with_limits(limits.clone())
        .build()
        .expect("valid bounded container with omitted capability");
    let archive = BundleArchive::parse(&bytes, &limits).expect("digest-valid container");
    assert!(
        archive
            .verify_capabilities(&bundle_runtime_capabilities())
            .is_ok(),
        "older capabilities alone cannot detect a stripped declaration"
    );
    let error = prepare_bundle_archive(&archive, Path::new("/unused.oxb"), Path::new(DEPLOYMENT_ROOT), None).expect_err("source-free decoder must reject omitted executable feature before touching runtime references");
    assert_eq!(error.code(), "bundle.required_feature_missing");
    // Successful source-free preparation was exercised separately above. An
    // unsigned in-memory archive is never passed off as an authenticated activation.
    assert!(discovery_support::spec(true).endpoints.is_empty());
}
