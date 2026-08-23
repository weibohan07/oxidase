#![no_main]

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;
use oxidase_core::ResourceId;
use oxidase_site::SiteCompiler;

fuzz_target!(|data: &[u8]| {
    let Ok(directory) = tempfile::tempdir() else {
        return;
    };
    let root = directory.path();
    if std::fs::write(root.join("site.oxsite"), b"oxista: site/v1\n").is_ok()
        && std::fs::write(root.join("page.oxr"), data).is_ok()
    {
        let _ = SiteCompiler::compile(
            ResourceId::new("site:fuzz"),
            root,
            root.join("site.oxsite"),
            BTreeMap::new(),
        );
    }
});
