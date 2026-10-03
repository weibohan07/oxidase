#![no_main]

use http::{HeaderMap, HeaderName, HeaderValue, Method, header};
use libfuzzer_sys::fuzz_target;
use oxidase_server::fuzzing::classify_admin_request;

fuzz_target!(|data: &[u8]| {
    if data.len() > 32 * 1024 {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut lines = text.lines();
    let method = lines
        .next()
        .and_then(|line| Method::from_bytes(line.as_bytes()).ok())
        .unwrap_or(Method::GET);
    let path = lines.next().unwrap_or("/api/v1/runtime");
    let mut headers = HeaderMap::new();
    for line in lines.take(32) {
        if let Some((name, value)) = line.split_once(':')
            && let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_bytes(value.trim_start().as_bytes()),
            )
        {
            headers.append(name, value);
        }
    }
    let first = classify_admin_request(&method, path, &headers, "\"boot:1\"", 1024);
    assert_eq!(
        first,
        classify_admin_request(&method, path, &headers, "\"boot:1\"", 1024),
        "request classification is deterministic"
    );
    if let Ok(Some((_, true))) = first {
        assert_eq!(headers.get_all(header::IF_MATCH).iter().count(), 1);
        assert_eq!(headers[header::IF_MATCH], "\"boot:1\"");
        assert_eq!(headers.get_all(header::CONTENT_TYPE).iter().count(), 1);
    }
});
