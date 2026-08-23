#![no_main]

use libfuzzer_sys::fuzz_target;
use oxidase_core::{CompiledPattern, PatternContext};

fuzz_target!(|data: &[u8]| {
    if let Ok(source) = std::str::from_utf8(data) {
        let _ = CompiledPattern::compile(source, PatternContext::Path);
        let _ = CompiledPattern::compile(source, PatternContext::Host);
        let _ = CompiledPattern::compile(source, PatternContext::Value);
    }
});
