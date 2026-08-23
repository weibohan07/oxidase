//! Reusable fixtures for Oxidase integration tests.

#[must_use]
pub fn loopback_address(port: u16) -> String {
    format!("127.0.0.1:{port}")
}
