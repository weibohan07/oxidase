//! SRV source/portable contracts compile offline; no resolver is invoked here.

use std::fs;

use oxidase_config::{Compiler, DnsRecordType, PortableGatewayConfigV1};
use oxidase_core::ResourceId;
use tempfile::{TempDir, tempdir};

fn gateway(settings: &str) -> String {
    format!(
        "api_version: oxidase.dev/v1alpha1\nkind: gateway\nresources:\n  clusters:\n    api:\n      discovery:\n        dns:\n{settings}services:\n  root:\n    type: respond\nlisteners:\n  - name: public\n    bind: 127.0.0.1:0\n    service:\n      ref: root\n"
    )
}

fn srv_settings() -> &'static str {
    "          name: _HTTPS._TCP.API.EXAMPLE.TEST.\n          record: srv\n          origin: https://logical.example.test:443/base/\n"
}

fn write_source(text: &str) -> (TempDir, std::path::PathBuf) {
    let directory = tempdir().expect("temporary compiler root");
    let path = directory.path().join("oxidase.yaml");
    fs::write(&path, text).expect("source fixture");
    (directory, path)
}

#[test]
fn srv_compiles_offline_with_canonical_question_and_fixed_tls_origin() {
    let (_directory, path) = write_source(&gateway(srv_settings()));
    let compiled = Compiler::compile_path(path).expect("SRV policy compiles without lookup");
    let cluster = &compiled.resources.clusters[&ResourceId::new("cluster:api")];
    let dns = cluster.discovery.as_ref().expect("SRV policy");
    assert_eq!(dns.record, DnsRecordType::Srv);
    assert_eq!(dns.name, "_https._tcp.api.example.test.");
    assert_eq!(dns.port, None);
    assert_eq!(dns.origin.host_str(), Some("logical.example.test"));
    assert_eq!(dns.origin.scheme(), "https");
    assert_eq!(dns.origin.path(), "/base/");
    assert!(cluster.endpoints.is_empty());
    assert!(cluster.timeouts.is_some());
    assert!(compiled.warnings.is_empty());
    let summary = serde_json::to_value(compiled.summary()).expect("inspection summary");
    assert_eq!(summary["clusters"][0]["discovery"]["record"], "srv");
    assert!(summary["clusters"][0]["discovery"].get("port").is_none());
}

#[test]
fn srv_rejects_every_declared_port_at_its_value_span_including_null() {
    for value in ["8443", "0", "null"] {
        let text = gateway(&format!("{}          port: {value}\n", srv_settings()));
        let (_directory, path) = write_source(&text);
        let error = Compiler::compile_path(path).expect_err("SRV port cannot be overridden");
        let diagnostic = &error.diagnostics[0];
        assert_eq!(diagnostic.code, "resource.discovery_srv_port");
        assert_eq!(
            diagnostic.primary.field_path,
            "resources.clusters.api.discovery.dns.port"
        );
        assert_eq!(
            diagnostic.primary.start_byte,
            text.find(&format!("port: {value}")).expect("port field") + 6
        );
        assert!(
            diagnostic
                .help
                .as_ref()
                .is_some_and(|help| { help.contains("remove") && help.contains("origin") })
        );
    }
}

#[test]
fn srv_question_grammar_is_not_a_tls_hostname_or_udp_question() {
    let long_service = format!("_{}._tcp.example.test", "s".repeat(63));
    let invalid_names = [
        "https._tcp.example.test",
        "_._tcp.example.test",
        "_https._udp.example.test",
        "_https._tcp",
        "_https._tcp.example.test..",
        "_https._tcp.127.0.0.1",
        "_https._tcp.例子.test",
        "_https._tcp.*.example.test",
        "_https._tcp._other.example.test",
        "_-https._tcp.example.test",
        "_https-._tcp.example.test",
        long_service.as_str(),
    ];
    for name in invalid_names {
        let text = gateway(&srv_settings().replace("_HTTPS._TCP.API.EXAMPLE.TEST.", name));
        let (_directory, path) = write_source(&text);
        let error = Compiler::compile_path(path).expect_err(name);
        let diagnostic = &error.diagnostics[0];
        assert_eq!(diagnostic.code, "resource.discovery_policy", "{name}");
        assert_eq!(
            diagnostic.primary.field_path, "resources.clusters.api.discovery.dns.name",
            "{name}"
        );
    }
}

#[test]
fn srv_name_and_declared_port_spans_survive_unicode_and_crlf() {
    let text = gateway(&format!("{}          port: null\n", srv_settings()))
        .replacen("kind: gateway", "# 前置文本\nkind: gateway", 1)
        .replace('\n', "\r\n");
    let (_directory, path) = write_source(&text);
    let error = Compiler::compile_path(path).expect_err("declared null port");
    let span = &error.diagnostics[0].primary;
    let byte = text.find("port: null").expect("port field") + 6;
    assert_eq!(span.start_byte, byte);
    assert_eq!(
        span.line,
        text[..byte].bytes().filter(|byte| *byte == b'\n').count() + 1
    );
    assert_eq!(span.column, 17);
    assert_eq!(&text[span.start_byte..span.end_byte], "null");
}

#[test]
fn all_cluster_load_balance_policies_are_valid_inside_srv_target_groups() {
    for policy in ["round_robin", "weighted_round_robin", "least_requests"] {
        let text = gateway(srv_settings()).replace(
            "      discovery:",
            &format!("      load_balance:\n        policy: {policy}\n      discovery:"),
        );
        let (_directory, path) = write_source(&text);
        let compiled = Compiler::compile_path(path).expect(policy);
        assert_eq!(
            compiled.resources.clusters[&ResourceId::new("cluster:api")]
                .load_balance
                .as_str(),
            policy
        );
    }
}

#[test]
fn portable_srv_omits_port_and_does_not_serialize_live_records() {
    let (directory, path) = write_source(&gateway(srv_settings()));
    let compiled = Compiler::compile_path(path).expect("source");
    let portable = PortableGatewayConfigV1::from_compiled(&compiled).expect("portable source");
    let json = serde_json::to_value(&portable).expect("portable JSON");
    let dns = &json["clusters"]["cluster:api"]["discovery"];
    assert_eq!(dns["record"], "srv");
    assert!(dns.get("port").is_none());
    for key in [
        "answers",
        "priority",
        "weight",
        "targets",
        "addresses",
        "generation",
    ] {
        assert!(dns.get(key).is_none(), "no live {key}");
    }
    let rebuilt = serde_json::from_value::<PortableGatewayConfigV1>(json)
        .expect("portable JSON decodes")
        .compile_at(directory.path())
        .expect("source-free offline policy validation");
    let dns = rebuilt.resources.clusters[&ResourceId::new("cluster:api")]
        .discovery
        .as_ref()
        .expect("restored SRV policy");
    assert_eq!(dns.record, DnsRecordType::Srv);
    assert_eq!(dns.port, None);
    assert_eq!(dns.name, "_https._tcp.api.example.test.");
}

#[test]
fn portable_old_address_port_shape_is_preserved_and_null_is_never_missing() {
    let settings = "          name: api.example.test\n          record: a_aaaa\n          port: 8443\n          origin: http://logical.example.test/base/\n";
    let (directory, path) = write_source(&gateway(settings));
    let compiled = Compiler::compile_path(path).expect("address source");
    let portable = PortableGatewayConfigV1::from_compiled(&compiled).expect("portable source");
    let json = serde_json::to_value(&portable).expect("portable JSON");
    assert_eq!(json["clusters"]["cluster:api"]["discovery"]["port"], 8443);
    assert!(
        serde_json::from_value::<PortableGatewayConfigV1>(json.clone())
            .expect("old numeric port decodes")
            .compile_at(directory.path())
            .is_ok()
    );
    for record in ["a_aaaa", "srv"] {
        let mut changed = json.clone();
        changed["clusters"]["cluster:api"]["discovery"]["record"] = record.into();
        changed["clusters"]["cluster:api"]["discovery"]["port"] = serde_json::Value::Null;
        assert!(
            serde_json::from_value::<PortableGatewayConfigV1>(changed).is_err(),
            "{record}: explicit null is invalid"
        );
    }
    let mut missing = json;
    missing["clusters"]["cluster:api"]["discovery"]
        .as_object_mut()
        .expect("DNS object")
        .remove("port");
    assert!(
        serde_json::from_value::<PortableGatewayConfigV1>(missing)
            .expect("missing can be decoded")
            .compile_at(directory.path())
            .is_err(),
        "A/AAAA missing port cannot cross the portable validation boundary"
    );
}

#[test]
fn portable_srv_revalidates_question_port_and_policy_instead_of_trusting_producer() {
    let (directory, path) = write_source(&gateway(srv_settings()));
    let compiled = Compiler::compile_path(path).expect("source");
    let portable = PortableGatewayConfigV1::from_compiled(&compiled).expect("portable source");
    for change in 0..4 {
        let mut malformed = portable.clone();
        let dns = malformed
            .clusters
            .get_mut("cluster:api")
            .expect("cluster")
            .discovery
            .as_mut()
            .expect("DNS");
        match change {
            0 => dns.port = Some(8443),
            1 => dns.name = "_https._udp.example.test.".to_owned(),
            2 => dns.name = "_HTTPS._tcp.example.test.".to_owned(),
            3 => dns.limits.max_targets = 33,
            _ => unreachable!(),
        }
        assert!(
            malformed.compile_at(directory.path()).is_err(),
            "malformed SRV policy {change}"
        );
    }
}
