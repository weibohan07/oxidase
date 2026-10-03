//! Deterministic offline property-driver smoke, not a fuzz campaign.

#[path = "../fuzz_targets/discovery_support/mod.rs"]
mod discovery_support;
#[path = "../fuzz_targets/discovery_support/portable_driver.rs"]
mod portable_driver;
#[path = "../fuzz_targets/discovery_support/runtime_driver.rs"]
mod runtime_driver;

#[test]
fn checked_in_discovery_seeds_reach_real_runtime_and_portable_paths() {
    for data in [
        include_bytes!("../seeds/discovery_runtime/expiry-and-retirement").as_slice(),
        include_bytes!("../seeds/discovery_runtime/owner-policy-retry").as_slice(),
        &[],
    ] {
        runtime_driver::run(data);
    }
    for data in [
        include_bytes!("../seeds/portable_discovery/valid-srv").as_slice(),
        include_bytes!("../seeds/portable_discovery/phased-duration").as_slice(),
        &[],
    ] {
        portable_driver::run(data);
    }
}

#[test]
fn every_operation_and_portable_policy_mutation_has_a_deterministic_smoke() {
    for selector in 0..24 {
        let mut data = [0_u8; 12];
        data[0] = selector;
        for (index, byte) in data.iter_mut().enumerate().skip(1) {
            *byte = index as u8;
        }
        portable_driver::run(&data);
        runtime_driver::run(&data);
    }
    let mut state = 600401_u64;
    for _ in 0..32 {
        let data = std::array::from_fn::<_, 768, _>(|_| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            (state >> 32) as u8
        });
        runtime_driver::run(&data);
        portable_driver::run(&data);
    }
}
