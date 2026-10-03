#![no_main]

mod discovery_support;
#[path = "discovery_support/portable_driver.rs"]
mod portable_driver;

libfuzzer_sys::fuzz_target!(|data: &[u8]| portable_driver::run(data));
