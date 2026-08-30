#![no_main]

use libfuzzer_sys::fuzz_target;
use oxidase_bundle::{
    AssetDescriptor, AssetStorage, BuildMetadata, BundleArchive, BundleBuilder, BundleCapabilities,
    BundleLimits, BundleManifest, InspectionVerbosity,
};

const MAX_FUZZ_BUNDLE_BYTES: u64 = 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    let limits = bounded_limits();
    exercise(data, &limits);

    // Raw mutation alone almost never survives the aggregate content digest.
    // Also derive a small canonical archive from each input, then fuzz its
    // structural boundaries so both success and deep rejection paths remain hot.
    if let Some((&selector, payload)) = data.split_first()
        && let Some(mut candidate) = canonical_candidate(payload, &limits)
    {
        mutate_candidate(selector, payload, &mut candidate);
        exercise(&candidate, &limits);
    }
});

fn exercise(data: &[u8], limits: &BundleLimits) {
    let Ok(archive) = BundleArchive::parse(data, limits) else {
        return;
    };

    // Parsing validates canonical structure and content/blob digests. Continue
    // through every read-only consumer so a valid mutated container reaches
    // deeper model traversal rather than terminating at the parser boundary.
    assert!(archive.verify().is_ok());
    let _ = archive.verify_capabilities(&BundleCapabilities::default());

    let capabilities = BundleCapabilities {
        runtime_version: archive.manifest().minimum_runtime_version.clone(),
        supported_features: archive.manifest().required_features.clone(),
        supported_sections: archive
            .manifest()
            .sections
            .iter()
            .filter(|(_, section)| section.required)
            .map(|(name, section)| (name.clone(), section.schema.clone()))
            .collect(),
    };
    let _ = archive.verify_capabilities(&capabilities);

    let safe = archive.inspect(InspectionVerbosity::Safe);
    let verbose = archive.inspect(InspectionVerbosity::Verbose);
    assert_eq!(safe.content_digest, verbose.content_digest);
    assert!(archive.diff(&archive).identical_content);
}

fn canonical_candidate(payload: &[u8], limits: &BundleLimits) -> Option<Vec<u8>> {
    let manifest = BundleManifest::new(
        BuildMetadata {
            tool_version: "fuzz".to_owned(),
            source_commit: None,
            gateway_api: "oxidase.dev/v1alpha1".to_owned(),
            oxista_api: "v1".to_owned(),
        },
        "0.3.0-alpha.1",
    );
    let mut builder = BundleBuilder::new(manifest).with_limits(limits.clone());
    let blob = payload[..payload.len().min(4 * 1024)].to_vec();
    let digest = builder.add_blob(blob.clone());
    builder.manifest_mut().assets.insert(
        "fuzz.bin".to_owned(),
        AssetDescriptor {
            storage: AssetStorage::Embedded {
                blob: digest,
                length: blob.len() as u64,
            },
        },
    );
    builder.build().ok()
}

fn mutate_candidate(selector: u8, payload: &[u8], candidate: &mut Vec<u8>) {
    let offset = payload.first().copied().unwrap_or_default() as usize;
    match selector % 8 {
        0 => {}
        1 => candidate.truncate(offset % candidate.len()),
        2 => {
            let index = offset % candidate.len();
            candidate[index] ^= payload.get(1).copied().unwrap_or(1).max(1);
        }
        3 => candidate[0] ^= 0xff,
        4 => candidate[12..20].copy_from_slice(&u64::MAX.to_be_bytes()),
        5 => candidate[20..28].copy_from_slice(&u64::MAX.to_be_bytes()),
        6 => candidate[28] ^= 0x80,
        _ => candidate.push(selector),
    }
}

fn bounded_limits() -> BundleLimits {
    BundleLimits {
        max_bundle_bytes: MAX_FUZZ_BUNDLE_BYTES,
        max_manifest_bytes: 64 * 1024,
        max_signature_bytes: 16 * 1024,
        max_blob_count: 128,
        max_blob_bytes: 256 * 1024,
        max_total_blob_bytes: 512 * 1024,
        max_assets: 1_024,
        max_sections: 64,
        max_origins: 1_024,
        max_sensitive_references: 128,
        max_json_depth: 32,
        max_json_nodes: 10_000,
        max_string_bytes: 64 * 1024,
    }
}
