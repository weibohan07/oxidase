use super::*;
use crate::config::router::{OnMatch, RouterRule};
use crate::config::router::r#match::RouterMatch;
use crate::config::service::{Service, ServiceRef};
use crate::config::r#static::StaticService;
use crate::parser::{ParseCache, parse_service_ref};
use std::path::Path;

fn static_service(path: &str) -> Service {
    Service::Static(StaticService {
        source_dir: path.to_string(),
        file_index: "index.html".into(),
        evil_dir_strategy: Default::default(),
        index_strategy: crate::config::r#static::IndexStrategy::Redirect { code: 308 },
        file_404: Default::default(),
        file_500: Default::default(),
    })
}

#[test]
fn build_cache_dedupes_inline_service() {
    let svc = static_service("/tmp/c");
    let base = Path::new("/tmp");
    let mut parse_cache = ParseCache::default();
    let mut build_cache = BuildCache::default();

    let parsed = parse_service_ref(&ServiceRef::Inline(svc.clone()), base, &mut parse_cache).unwrap();
    let _ = build_from_parsed(&parsed, &parsed.root, &mut build_cache).unwrap();
    let compiled_after_first = build_cache.compiled.len();
    let _ = build_from_parsed(&parsed, &parsed.root, &mut build_cache).unwrap();

    assert_eq!(compiled_after_first, 1);
    assert_eq!(build_cache.compiled.len(), 1);
}

#[test]
fn build_cache_reused_for_router_and_next() {
    let next_ref = ServiceRef::Inline(static_service("/tmp/d"));
    let router = Service::Router(crate::config::router::RouterService {
        rules: vec![RouterRule { when: Some(RouterMatch::default()), ops: vec![], on_match: OnMatch::Stop }],
        next: Some(Box::new(next_ref.clone())),
        max_steps: None,
    });
    let base = Path::new("/tmp");
    let mut parse_cache = ParseCache::default();
    let mut build_cache = BuildCache::default();

    let parsed = parse_service_ref(&ServiceRef::Inline(router), base, &mut parse_cache).unwrap();
    let _ = build_from_parsed(&parsed, &parsed.root, &mut build_cache).unwrap();
    let compiled_after_first = build_cache.compiled.len();
    let _ = build_from_parsed(&parsed, &parsed.root, &mut build_cache).unwrap();

    // router + its next static should occupy two compiled entries, and not grow on repeat.
    assert_eq!(compiled_after_first, 2);
    assert_eq!(build_cache.compiled.len(), 2);
}

#[test]
fn build_from_parsed_respects_cache_cross_roots() {
    let svc_a = static_service("/tmp/a");
    let svc_b = static_service("/tmp/a"); // same config, different base -> different key
    let base_a = Path::new("/tmp/base_a");
    let base_b = Path::new("/tmp/base_b");
    let mut parse_cache = ParseCache::default();
    let mut build_cache = BuildCache::default();

    let parsed_a = parse_service_ref(&ServiceRef::Inline(svc_a), base_a, &mut parse_cache).unwrap();
    let parsed_b = parse_service_ref(&ServiceRef::Inline(svc_b), base_b, &mut parse_cache).unwrap();

    let _ = build_from_parsed(&parsed_a, &parsed_a.root, &mut build_cache).unwrap();
    let _ = build_from_parsed(&parsed_b, &parsed_b.root, &mut build_cache).unwrap();

    // Different bases produce different keys; both should be present.
    assert_eq!(build_cache.compiled.len(), 2);
}
