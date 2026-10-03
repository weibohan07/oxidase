//! Offline discovery-policy compilation and portable trust-boundary regressions.

use std::fs;
use std::net::IpAddr;
use std::time::Duration;

use oxidase_config::{Compiler, DnsAddressPolicy, DnsResolverSource, PortableGatewayConfigV1};
use oxidase_core::ResourceId;
use tempfile::{TempDir, tempdir};

fn gateway(policy: &str) -> String {
    format!(
        "api_version: oxidase.dev/v1alpha1\nkind: gateway\nresources:\n  clusters:\n    api:\n{policy}services:\n  root:\n    type: respond\n    body:\n      text: ready\nlisteners:\n  - name: public\n    bind: 127.0.0.1:0\n    service:\n      ref: root\n"
    )
}

fn policy(extra: &str) -> String {
    format!(
        "      discovery:\n        dns:\n          name: API.EXAMPLE.TEST.\n          record: a_aaaa\n          port: 8443\n          origin: http://logical.example.test/base/\n{extra}"
    )
}

fn source(text: &str) -> (TempDir, std::path::PathBuf) {
    let directory = tempdir().expect("temporary compiler root");
    let file = directory.path().join("oxidase.yaml");
    fs::write(&file, text).expect("fixture source writes");
    (directory, file)
}

#[test]
fn discovery_is_offline_canonical_and_implicitly_uses_phased_timeouts() {
    let (_directory, file) = source(&gateway(&policy("")));
    let compiled = Compiler::compile_path(file).expect("unresolved DNS is not a compile failure");
    let cluster = &compiled.resources.clusters[&ResourceId::new("cluster:api")];
    assert!(cluster.endpoints.is_empty());
    let dns = cluster.discovery.as_ref().expect("static DNS policy");
    assert_eq!(dns.name, "api.example.test.");
    assert_eq!(dns.record.as_str(), "a_aaaa");
    assert_eq!(dns.port, Some(8443));
    assert_eq!(dns.origin.host_str(), Some("logical.example.test"));
    assert_eq!(dns.origin.path(), "/base/");
    assert_eq!(dns.resolver.source, DnsResolverSource::System);
    assert_eq!(dns.resolver.query_timeout, Duration::from_secs(2));
    assert_eq!(dns.refresh.min_interval, Duration::from_secs(1));
    assert_eq!(dns.refresh.max_interval, Duration::from_secs(60));
    assert_eq!(dns.refresh.stale_if_error, Duration::from_secs(30));
    assert_eq!(dns.limits.max_endpoints, 256);
    assert_eq!(dns.limits.max_targets, 32);
    assert_eq!(dns.address_policy, DnsAddressPolicy::default());
    let timeouts = cluster
        .timeouts
        .as_ref()
        .expect("dynamic default is phased");
    assert_eq!(timeouts.connect, Duration::from_secs(5));
    assert_eq!(timeouts.tls_handshake, Duration::from_secs(5));
    assert_eq!(timeouts.request_body_idle, Duration::from_secs(30));
    assert_eq!(timeouts.response_header, Duration::from_secs(10));
    assert_eq!(timeouts.response_body_idle, Duration::from_secs(30));
    assert_eq!(timeouts.pre_response_total, Duration::from_secs(60));
    assert!(compiled.warnings.is_empty());
    let summary = compiled.summary();
    assert_eq!(summary.clusters[0].endpoint_count, 0);
    assert_eq!(
        summary.clusters[0]
            .discovery
            .as_ref()
            .expect("compile-known DNS policy")
            .endpoint_selection,
        "runtime state dependent"
    );
}

#[test]
fn discovery_rejects_static_even_empty_and_each_explicit_legacy_timer() {
    for (field, value, code) in [
        (
            "endpoints",
            "[]",
            "resource.cluster_endpoint_source_conflict",
        ),
        ("connect_timeout", "5s", "resource.discovery_legacy_timeout"),
        (
            "response_timeout",
            "null",
            "resource.discovery_legacy_timeout",
        ),
    ] {
        let (_directory, file) =
            source(&gateway(&format!("      {field}: {value}\n{}", policy(""))));
        let error = Compiler::compile_path(file).expect_err("ambiguous policy must fail");
        let diagnostic = &error.diagnostics[0];
        assert_eq!(diagnostic.code, code);
        assert_eq!(
            diagnostic.primary.field_path,
            format!("resources.clusters.api.{field}")
        );
        assert_eq!(diagnostic.labels.len(), 1);
    }
}

#[test]
fn discovery_rejects_unknown_record_at_record_span_with_supported_help() {
    let text = gateway(&policy("")).replace("record: a_aaaa", "record: txt");
    let (_directory, file) = source(&text);
    let error = Compiler::compile_path(file).expect_err("unknown records cannot be accepted");
    let diagnostic = &error.diagnostics[0];
    assert_eq!(diagnostic.code, "resource.discovery_record_unsupported");
    assert_eq!(
        diagnostic.primary.field_path,
        "resources.clusters.api.discovery.dns.record"
    );
    assert_eq!(
        diagnostic.primary.start_byte,
        text.find("record: txt").expect("record") + 8
    );
    assert!(
        diagnostic
            .help
            .as_ref()
            .is_some_and(|help| help.contains("a_aaaa") && help.contains("srv"))
    );
}

#[test]
fn resolver_selection_is_exclusive_bounded_and_does_not_resolve_nameserver_hosts() {
    let (_directory, file) = source(&gateway(&policy(
        "          resolver:\n            nameservers: [\"[::ffff:127.0.0.1]:5301\", \"127.0.0.1:5300\"]\n            query_timeout: 1s\n",
    )));
    let compiled =
        Compiler::compile_path(file).expect("local explicit resolver policy compiles offline");
    let dns = compiled.resources.clusters[&ResourceId::new("cluster:api")]
        .discovery
        .as_ref()
        .expect("DNS policy");
    assert_eq!(
        dns.resolver.source,
        DnsResolverSource::NameServers(vec![
            "127.0.0.1:5300".parse().expect("socket"),
            "127.0.0.1:5301".parse().expect("socket")
        ])
    );
    for (settings, field) in [
        (
            "            system: true\n            nameservers: [127.0.0.1:5300]\n",
            "resolver.nameservers",
        ),
        ("            system: false\n", "resolver.system"),
        ("            nameservers: null\n", "resolver.nameservers"),
        ("            nameservers: []\n", "resolver.nameservers"),
        (
            "            nameservers: [resolver.example:53]\n",
            "resolver.nameservers[0]",
        ),
        (
            "            nameservers: [\"[fe80::53%1]:53\"]\n",
            "resolver.nameservers[0]",
        ),
        (
            "            nameservers: [0.0.0.0:53]\n",
            "resolver.nameservers[0]",
        ),
        (
            "            nameservers: [127.0.0.1:1,127.0.0.1:2,127.0.0.1:3,127.0.0.1:4,127.0.0.1:5]\n",
            "resolver.nameservers",
        ),
    ] {
        let (_directory, file) = source(&gateway(&policy(&format!(
            "          resolver:\n{settings}"
        ))));
        let error = Compiler::compile_path(file).expect_err("resolver policy must fail closed");
        assert_eq!(
            error.diagnostics[0].primary.field_path,
            format!("resources.clusters.api.discovery.dns.{field}")
        );
    }
}

#[test]
fn bounds_and_fixed_origin_fail_at_the_exact_declared_policy_field() {
    for (extra, field) in [
        (
            "          refresh:\n            min_interval: 0ms\n",
            "refresh.min_interval",
        ),
        (
            "          refresh:\n            max_interval: 1ms\n",
            "refresh.max_interval",
        ),
        (
            "          refresh:\n            jitter_percent: 101\n",
            "refresh.jitter_percent",
        ),
        (
            "          refresh:\n            stale_if_error: 24h1s\n",
            "refresh.stale_if_error",
        ),
        (
            "          limits:\n            max_endpoints: 257\n",
            "limits.max_endpoints",
        ),
        (
            "          limits:\n            max_targets: 33\n",
            "limits.max_targets",
        ),
        (
            "          resolver:\n            query_timeout: 0ms\n",
            "resolver.query_timeout",
        ),
    ] {
        let (_directory, file) = source(&gateway(&policy(extra)));
        let error =
            Compiler::compile_path(file).expect_err("policy exceeds bounded runtime contract");
        assert_eq!(
            error.diagnostics[0].primary.field_path,
            format!("resources.clusters.api.discovery.dns.{field}")
        );
    }
    for origin in [
        "https://user:password@origin.test",
        "https://origin.test/?q=1",
        "https://origin.test/#fragment",
        "ftp://origin.test",
        "https://origin.test:0",
        "https://[fe80::1%25eth0]",
    ] {
        let text = gateway(&policy("")).replace("http://logical.example.test/base/", origin);
        let (_directory, file) = source(&text);
        let error = Compiler::compile_path(file)
            .expect_err("DNS must not control credential/path identity");
        assert_eq!(
            error.diagnostics[0].primary.field_path,
            "resources.clusters.api.discovery.dns.origin"
        );
    }
}

#[test]
fn address_policy_normalizes_mapped_v6_and_has_separate_trust_classes() {
    let default = DnsAddressPolicy::default();
    for address in [
        "10.1.2.3",
        "172.16.2.3",
        "192.168.2.3",
        "fd00::1",
        "203.0.113.1",
        "2001:db8::1",
    ] {
        assert!(
            default.allows(address.parse::<IpAddr>().expect("IP fixture")),
            "{address}"
        );
    }
    for address in [
        "127.0.0.1",
        "::1",
        "::ffff:127.0.0.1",
        "169.254.1.1",
        "fe80::1",
        "0.0.0.0",
        "::",
        "224.0.0.1",
        "ff02::1",
        "255.255.255.255",
    ] {
        assert!(
            !default.allows(address.parse::<IpAddr>().expect("IP fixture")),
            "{address}"
        );
    }
    let restricted = DnsAddressPolicy {
        allow_private: false,
        allow_loopback: true,
        allow_link_local: true,
    };
    assert!(!restricted.allows("::ffff:10.1.2.3".parse().expect("mapped private")));
    assert!(!restricted.allows("fd00::1".parse().expect("ULA")));
    assert!(restricted.allows("::ffff:127.0.0.1".parse().expect("mapped loopback")));
    assert!(restricted.allows("fe80::1".parse().expect("link-local")));
    assert!(!restricted.allows("::".parse().expect("unspecified")));
}

#[test]
fn portable_policy_is_static_only_and_revalidates_modes_timing_and_limits() {
    let (directory, file) = source(&gateway(&policy(
        "          resolver:\n            nameservers: [127.0.0.1:5300]\n          address_policy:\n            allow_loopback: true\n",
    )));
    let compiled = Compiler::compile_path(&file).expect("policy compiles");
    let portable =
        PortableGatewayConfigV1::from_compiled(&compiled).expect("portable policy exports");
    let plan = portable
        .compile_at(directory.path())
        .expect("offline portable policy reconstructs");
    let loaded = plan.resources.clusters[&ResourceId::new("cluster:api")]
        .discovery
        .as_ref()
        .expect("loaded policy");
    assert_eq!(loaded.name, "api.example.test.");
    assert_eq!(loaded.origin.as_str(), "http://logical.example.test/base/");
    assert_eq!(
        loaded.source_span("resolver.nameservers[0]").start_byte,
        compiled.resources.clusters[&ResourceId::new("cluster:api")]
            .discovery
            .as_ref()
            .expect("source policy")
            .source_span("resolver.nameservers[0]")
            .start_byte
    );
    assert_eq!(
        loaded.source.file,
        std::path::Path::new("source/root/oxidase.yaml")
    );
    let json = serde_json::to_value(&portable).expect("portable JSON");
    let policy_json = &json["clusters"]["cluster:api"]["discovery"];
    for prohibited in ["answers", "addresses", "generation", "health", "expires_at"] {
        assert!(policy_json.get(prohibited).is_none());
    }
    let mut with_answers = json.clone();
    with_answers["clusters"]["cluster:api"]["discovery"]["addresses"] =
        serde_json::json!(["127.0.0.1"]);
    assert!(
        serde_json::from_value::<PortableGatewayConfigV1>(with_answers).is_err(),
        "portable plans cannot smuggle live DNS answers"
    );
    for change in 0..6 {
        let mut invalid = portable.clone();
        let cluster = invalid
            .clusters
            .get_mut("cluster:api")
            .expect("portable cluster");
        match change {
            0 => cluster.discovery.as_mut().expect("policy").record = "srv".to_owned(),
            1 => {
                cluster
                    .discovery
                    .as_mut()
                    .expect("policy")
                    .limits
                    .max_endpoints = 257
            }
            2 => cluster.discovery.as_mut().expect("policy").resolver.mode = "system".to_owned(),
            3 => cluster.timeouts = None,
            4 => {
                cluster.discovery.as_mut().expect("policy").name = "UPPER.EXAMPLE.TEST.".to_owned()
            }
            5 => {
                cluster.discovery.as_mut().expect("policy").origin =
                    "http://safe\n.evil/".to_owned()
            }
            _ => unreachable!(),
        }
        assert!(
            invalid.compile_at(directory.path()).is_err(),
            "malformed portable policy {change}"
        );
    }
}

#[test]
fn global_discovery_cluster_quota_is_exact_and_portable_cannot_bypass_it() {
    let clusters = (0..129)
        .map(|index| format!("    c{index:03}:\n{}", policy("")))
        .collect::<String>();
    let text = gateway("").replacen("    api:\n", &clusters, 1);
    let (_directory, file) = source(&text);
    let error = Compiler::compile_path(file).expect_err("global task-owner quota");
    assert_eq!(
        error.diagnostics[0].code,
        "resource.discovery_cluster_limit"
    );
    assert_eq!(
        error.diagnostics[0].primary.field_path,
        "resources.clusters.c128.discovery"
    );
    let (directory, file) = source(&gateway(&policy("")));
    let compiled = Compiler::compile_path(file).expect("single policy");
    let mut portable = PortableGatewayConfigV1::from_compiled(&compiled).expect("portable policy");
    let cluster = portable.clusters["cluster:api"].clone();
    portable.clusters = (0..129)
        .map(|index| (format!("cluster:c{index:03}"), cluster.clone()))
        .collect();
    assert!(portable.compile_at(directory.path()).is_err());
    portable.clusters.remove("cluster:c128");
    assert_eq!(
        portable
            .compile_at(directory.path())
            .expect("portable exact owner bound")
            .resources
            .clusters
            .len(),
        128
    );
    let exactly_at_limit = (0..128)
        .map(|index| format!("    c{index:03}:\n{}", policy("")))
        .collect::<String>();
    let (_limit_directory, limit_file) =
        source(&gateway("").replacen("    api:\n", &exactly_at_limit, 1));
    assert_eq!(
        Compiler::compile_path(limit_file)
            .expect("exactly 128 owners are allowed")
            .resources
            .clusters
            .len(),
        128
    );
}
