use std::path::PathBuf;

use super::{Args, load_http_servers};

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

#[test]
fn load_single_http_server_file() {
    let cfg = fixture_path("single_server.yaml");
    let args = Args {
        config: Some(cfg),
        service_file: None,
        service_inline: None,
        bind: "0.0.0.0:0".into(),
        pick: None,
        validate_only: false,
    };
    let servers = load_http_servers(&args).expect("load failed");
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].bind, "127.0.0.1:7589");
}

#[test]
fn load_servers_wrapper_and_pick() {
    let cfg = fixture_path("servers_wrapper.yaml");
    let args = Args {
        config: Some(cfg),
        service_file: None,
        service_inline: None,
        bind: "0.0.0.0:0".into(),
        pick: Some("second".into()),
        validate_only: false,
    };
    let servers = load_http_servers(&args).expect("load failed");
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].name.as_deref(), Some("second"));
    assert_eq!(servers[0].bind, "0.0.0.0:9090");
}

#[test]
fn load_plain_array() {
    let cfg = fixture_path("servers_array.yaml");
    let args = Args {
        config: Some(cfg),
        service_file: None,
        service_inline: None,
        bind: "0.0.0.0:0".into(),
        pick: None,
        validate_only: false,
    };
    let servers = load_http_servers(&args).expect("load failed");
    assert_eq!(servers.len(), 2);
}

#[test]
fn load_service_file_with_bind() {
    let svc = fixture_path("service_static.yaml");
    let args = Args {
        config: None,
        service_file: Some(svc),
        service_inline: None,
        bind: "0.0.0.0:8088".into(),
        pick: None,
        validate_only: false,
    };
    let servers = load_http_servers(&args).expect("load failed");
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].bind, "0.0.0.0:8088");
}

#[test]
fn load_inline_service() {
    let inline = r#"
handler: static
source_dir: /tmp
"#;
    let args = Args {
        config: None,
        service_file: None,
        service_inline: Some(inline.to_string()),
        bind: "127.0.0.1:12345".into(),
        pick: None,
        validate_only: false,
    };
    let servers = load_http_servers(&args).expect("load failed");
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].bind, "127.0.0.1:12345");
}
