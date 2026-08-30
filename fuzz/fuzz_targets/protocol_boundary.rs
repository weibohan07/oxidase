#![no_main]

use http::{HeaderMap, HeaderName, HeaderValue, Method, Version, header};
use libfuzzer_sys::fuzz_target;
use oxidase_server::fuzzing::{sanitize_headers, validate_upgrade};

const HEADER_NAMES: [&str; 12] = [
    "connection",
    "upgrade",
    "te",
    "trailer",
    "transfer-encoding",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "content-length",
    "host",
    "x-fuzz",
];

fuzz_target!(|data: &[u8]| {
    let mut headers = HeaderMap::new();
    for chunk in data.chunks(8).take(32) {
        let Some((&selector, value_bytes)) = chunk.split_first() else {
            continue;
        };
        let name =
            HeaderName::from_static(HEADER_NAMES[usize::from(selector) % HEADER_NAMES.len()]);
        let value = ascii_header_value(value_bytes);
        if let Ok(value) = HeaderValue::from_bytes(&value) {
            headers.append(name, value);
        }
    }

    for http2 in [false, true] {
        let mut sanitized = headers.clone();
        if sanitize_headers(&mut sanitized, http2).is_ok() {
            let once = sanitized.clone();
            assert!(sanitize_headers(&mut sanitized, http2).is_ok());
            assert_eq!(sanitized, once, "header sanitization must be idempotent");
            for forbidden in [
                header::CONNECTION,
                header::TRANSFER_ENCODING,
                header::UPGRADE,
            ] {
                assert!(!sanitized.contains_key(forbidden));
            }
            if http2 {
                if let Some(te) = sanitized.get(header::TE) {
                    assert_eq!(te, "trailers");
                }
            } else {
                assert!(!sanitized.contains_key(header::TE));
                assert!(!sanitized.contains_key(header::TRAILER));
            }
        }
    }

    let selector = data.first().copied().unwrap_or_default();
    let method = match selector % 4 {
        0 => Method::GET,
        1 => Method::POST,
        2 => Method::CONNECT,
        _ => Method::OPTIONS,
    };
    let version = match (selector / 4) % 4 {
        0 => Version::HTTP_10,
        1 => Version::HTTP_11,
        2 => Version::HTTP_2,
        _ => Version::HTTP_3,
    };
    let _ = validate_upgrade(method, version, headers);
});

fn ascii_header_value(bytes: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ,-/._\t";
    bytes
        .iter()
        .map(|byte| ALPHABET[usize::from(*byte) % ALPHABET.len()])
        .collect()
}
