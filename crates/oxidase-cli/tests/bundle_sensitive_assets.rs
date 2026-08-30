use std::fs;
use std::process::Command;

use tempfile::tempdir;

#[test]
fn bundle_build_never_writes_a_public_site_secret_blob() {
    let directory = tempdir().expect("temporary directory exists");
    let site = directory.path().join("site");
    fs::create_dir(&site).expect("Site directory can be created");
    fs::write(site.join("site.oxsite"), "oxista: site/v1\n").expect("Site manifest can be written");
    let marker = b"bundle-secret-marker-must-never-appear";
    fs::write(site.join("token.txt"), marker).expect("test-only Secret can be written");
    fs::write(
        directory.path().join("oxidase.yaml"),
        r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  secrets:
    token:
      file: site/token.txt
      max_bytes: 1KiB
  sites:
    web:
      root: site
services:
  root:
    type: site
    site: web
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      ref: root
"#,
    )
    .expect("Gateway config can be written");
    let output_path = directory.path().join("gateway.oxb");
    let output = Command::new(env!("CARGO_BIN_EXE_oxidase"))
        .current_dir(directory.path())
        .args(["bundle", "build", "oxidase.yaml", "--output", "gateway.oxb"])
        .output()
        .expect("oxidase bundle build runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("resource.sensitive_site_asset_overlap"));
    assert!(!stderr.contains("site/token.txt"));
    assert!(
        !stderr
            .as_bytes()
            .windows(marker.len())
            .any(|bytes| bytes == marker)
    );
    if let Ok(bytes) = fs::read(output_path) {
        assert!(
            !bytes.windows(marker.len()).any(|bytes| bytes == marker),
            "failed Bundle build wrote raw Secret bytes"
        );
    }
}
