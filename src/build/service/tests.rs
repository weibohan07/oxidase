use super::*;
use crate::config::router::{OnMatch, RouterRule};
use crate::config::router::r#match::RouterMatch;
use crate::config::service::ServiceRef;
use crate::parser::ParseCache;
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

    let _ = build_service_with_cache(&svc, base, &mut parse_cache, &mut build_cache).unwrap();
    let compiled_after_first = build_cache.compiled.len();
    let _ = build_service_with_cache(&svc, base, &mut parse_cache, &mut build_cache).unwrap();

    assert_eq!(compiled_after_first, 1);
    assert_eq!(build_cache.compiled.len(), 1);
}

#[test]
fn build_cache_reused_for_router_and_next() {
    let next_ref = ServiceRef::Inline(static_service("/tmp/d"));
    let router = Service::Router(RouterService {
        rules: vec![RouterRule { when: Some(RouterMatch::default()), ops: vec![], on_match: OnMatch::Stop }],
        next: Some(Box::new(next_ref.clone())),
        max_steps: None,
    });
    let base = Path::new("/tmp");
    let mut parse_cache = ParseCache::default();
    let mut build_cache = BuildCache::default();

    let _ = build_service_with_cache(&router, base, &mut parse_cache, &mut build_cache).unwrap();
    let compiled_after_first = build_cache.compiled.len();
    let _ = build_service_with_cache(&router, base, &mut parse_cache, &mut build_cache).unwrap();

    // router + its next static should occupy two compiled entries, and not grow on repeat.
    assert_eq!(compiled_after_first, 2);
    assert_eq!(build_cache.compiled.len(), 2);
}
