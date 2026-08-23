#![no_main]

use libfuzzer_sys::fuzz_target;
use oxidase_site::validate_request_path;

fuzz_target!(|data: &[u8]| {
    if let Ok(path) = std::str::from_utf8(data) {
        let _ = validate_request_path(path);
    }
});
