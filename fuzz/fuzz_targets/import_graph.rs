#![no_main]

use libfuzzer_sys::fuzz_target;
use oxidase_config::Compiler;

fuzz_target!(|data: &[u8]| {
    let Ok(directory) = tempfile::tempdir() else {
        return;
    };
    let root = directory.path().join("root.yaml");
    let imported = directory.path().join("imported.yaml");
    let root_source = b"api_version: oxidase.dev/v1alpha1\nkind: gateway\nimports:\n  - imported.yaml\nlisteners: []\n";
    if std::fs::write(&root, root_source).is_ok() && std::fs::write(imported, data).is_ok() {
        let _ = Compiler::compile_path(root);
    }
});
