//! Shared HTTP metadata policy for compiled user-controlled headers.

use http::{HeaderName, header};

/// Returns whether a header is connection-specific and must not cross a
/// protocol boundary or survive root response finalization.
#[must_use]
pub fn is_hop_by_hop_header(name: &HeaderName) -> bool {
    name == header::CONNECTION
        || name == header::TE
        || name == header::TRAILER
        || name == header::TRANSFER_ENCODING
        || name == header::UPGRADE
        || matches!(
            name.as_str(),
            "keep-alive" | "proxy-connection" | "proxy-authenticate" | "proxy-authorization"
        )
}

/// Returns whether source configuration is forbidden from setting, adding, or
/// removing a response framing or hop-by-hop header.
#[must_use]
pub fn is_forbidden_user_header(name: &HeaderName) -> bool {
    name == header::CONTENT_LENGTH || is_hop_by_hop_header(name)
}

#[cfg(test)]
mod tests {
    use http::{HeaderName, header};

    use super::{is_forbidden_user_header, is_hop_by_hop_header};

    #[test]
    fn distinguishes_framing_from_representation_metadata() {
        for name in [
            header::CONNECTION,
            header::TRANSFER_ENCODING,
            header::CONTENT_LENGTH,
            header::UPGRADE,
            header::TE,
            header::TRAILER,
            HeaderName::from_static("keep-alive"),
            HeaderName::from_static("proxy-connection"),
        ] {
            assert!(is_forbidden_user_header(&name), "{name} must be forbidden");
        }
        assert!(is_hop_by_hop_header(&header::CONNECTION));
        assert!(!is_hop_by_hop_header(&header::CONTENT_LENGTH));
        assert!(!is_forbidden_user_header(&header::CONTENT_TYPE));
        assert!(!is_forbidden_user_header(&header::CACHE_CONTROL));
    }
}
