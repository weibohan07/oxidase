#![no_main]

mod discovery_support;
#[path = "discovery_support/runtime_driver.rs"]
mod runtime_driver;

libfuzzer_sys::fuzz_target!(|data: &[u8]| runtime_driver::run(data));
