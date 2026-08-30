#![no_main]

use libfuzzer_sys::fuzz_target;
use oxidase_config::Compiler;

const VALID_TRANSPORT: &str = r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    default:
      cert_chain: default.pem
      private_key: default-key.pem
    exact:
      cert_chain: exact.pem
      private_key: exact-key.pem
    wildcard:
      cert_chain: wildcard.pem
      private_key: wildcard-key.pem
listeners:
  - name: secure
    bind: 127.0.0.1:8443
    protocol: https
    tls:
      default_certificate: default
      sni:
        api.example.test: exact
        "*.internal.example.test": wildcard
      handshake_timeout: 5s
    http:
      versions: [h2, http1]
      http1:
        header_read_timeout: 30s
      http2:
        max_concurrent_streams: 256
        max_header_list_size: 64KiB
        keep_alive_interval: 30s
        keep_alive_timeout: 10s
    service:
      type: respond
"#;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, payload)) = data.split_first() else {
        return;
    };
    let payload = &payload[..payload.len().min(1_024)];
    let value = serde_json::to_string(&String::from_utf8_lossy(payload))
        .expect("JSON strings are valid YAML quoted scalars");
    let source = match selector % 8 {
        0 => VALID_TRANSPORT.replace("protocol: https", &format!("protocol: {value}")),
        1 => VALID_TRANSPORT.replace(
            "        api.example.test: exact",
            &format!("        {value}: exact"),
        ),
        2 => VALID_TRANSPORT.replace(
            "        \"*.internal.example.test\": wildcard",
            &format!("        {value}: wildcard"),
        ),
        3 => VALID_TRANSPORT.replace(
            "      default_certificate: default",
            &format!("      default_certificate: {value}"),
        ),
        4 => VALID_TRANSPORT.replace(
            "      versions: [h2, http1]",
            &format!("      versions: [{value}]"),
        ),
        5 => VALID_TRANSPORT.replace(
            "      handshake_timeout: 5s",
            &format!("      handshake_timeout: {value}"),
        ),
        6 => VALID_TRANSPORT.replace(
            "        max_header_list_size: 64KiB",
            &format!("        max_header_list_size: {value}"),
        ),
        _ => VALID_TRANSPORT.replace(
            "        keep_alive_timeout: 10s",
            &format!("        keep_alive_timeout: {value}"),
        ),
    };

    let Ok(directory) = tempfile::tempdir() else {
        return;
    };
    let path = directory.path().join("oxidase.yaml");
    if std::fs::write(&path, source).is_ok() {
        let _ = Compiler::compile_path(&path);
    }

    // Keep a fully valid plan in every iteration so arbitrary SNI bytes reach
    // exact-before-wildcard resolution even when the mutated source is invalid.
    if std::fs::write(&path, VALID_TRANSPORT).is_ok()
        && let Ok(gateway) = Compiler::compile_path(path)
        && let Some(tls) = gateway
            .listeners
            .first()
            .and_then(|listener| listener.tls.as_ref())
    {
        let server_name = String::from_utf8_lossy(payload);
        let _ = tls.select_certificate(Some(&server_name));
        let _ = tls.select_certificate(None);
    }
});
