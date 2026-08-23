#![no_main]

use libfuzzer_sys::fuzz_target;
use oxidase_config::Compiler;

fuzz_target!(|data: &[u8]| {
    let Ok(directory) = tempfile::tempdir() else {
        return;
    };
    let path = directory.path().join("oxidase.yaml");
    if std::fs::write(&path, data).is_ok() {
        let _ = Compiler::compile_path(path);
    }
});
