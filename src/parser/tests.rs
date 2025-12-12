use super::*;
use crate::config::router::{OnMatch, RouterRule};
use crate::config::router::r#match::RouterMatch;
use crate::config::router::RouterService;
use crate::config::r#static::StaticService;
use crate::config::service::{Service, ServiceRef};
use std::fs;
use std::path::{Path, PathBuf};

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
fn parse_cache_dedupes_inline_by_hash_and_base() {
    let svc = ServiceRef::Inline(static_service("/tmp/a"));
    let base = Path::new("/tmp");
    let mut cache = ParseCache::default();

    let first = parse_service_ref(&svc, base, &mut cache).unwrap();
    let second = parse_service_ref(&svc, base, &mut cache).unwrap();

    assert_eq!(cache.key_to_parsed.len(), 1);
    assert_eq!(first.root, second.root);
}

#[test]
fn parse_cache_dedupes_import_by_path() {
    let dir = std::env::temp_dir().join("oxidase_parse_cache_import");
    let _ = fs::create_dir_all(&dir);
    let svc_file = dir.join("svc.yaml");
    fs::write(&svc_file, "handler: static\nsource_dir: /tmp/b\nfile_index: index.html\n").unwrap();

    let svc = ServiceRef::Import { import: PathBuf::from("svc.yaml") };
    let mut cache = ParseCache::default();

    let first = parse_service_ref(&svc, &dir, &mut cache).unwrap();
    let second = parse_service_ref(&svc, &dir, &mut cache).unwrap();

    assert_eq!(cache.key_to_parsed.len(), 1);
    assert_eq!(cache.import_to_key.len(), 1);
    assert_eq!(first.root, second.root);
}

#[test]
fn parse_collects_inline_child_dependency() {
    let next_ref = ServiceRef::Inline(static_service("/tmp/child"));
    let router = ServiceRef::Inline(Service::Router(RouterService {
        rules: vec![RouterRule { when: Some(RouterMatch::default()), ops: vec![], on_match: OnMatch::Stop }],
        next: Some(Box::new(next_ref.clone())),
        max_steps: None,
    }));
    let base = Path::new("/tmp");
    let mut cache = ParseCache::default();

    let parsed = parse_service_ref(&router, base, &mut cache).unwrap();
    let root = parsed.services.get(&parsed.root).unwrap();
    match root {
        ParsedService::Router(r) => {
            assert!(r.deps.iter().any(|d| matches!(d, ServiceDep::Inline(_))));
            assert_eq!(r.deps.len(), 1);
            assert!(r.next.is_some());
        }
        _ => panic!("expected router"),
    }
}

#[test]
fn parse_collects_import_dependency_and_transitive() {
    let dir = std::env::temp_dir().join("oxidase_parse_dep_import");
    let _ = fs::create_dir_all(&dir);
    let svc_file = dir.join("svc_dep.yaml");
    // Router with next inline so we get both import path and inline hash in deps.
    fs::write(&svc_file, "handler: router\nrules: []\nnext:\n  handler: static\n  source_dir: /tmp/inner\n  file_index: index.html\n").unwrap();

    let svc = ServiceRef::Import { import: PathBuf::from("svc_dep.yaml") };
    let mut cache = ParseCache::default();

    let parsed = parse_service_ref(&svc, &dir, &mut cache).unwrap();
    let root = parsed.services.get(&parsed.root).unwrap();
    match root {
        ParsedService::Router(r) => {
            let mut has_import = false;
            let mut has_inline = false;
            for dep in r.deps.iter() {
                match dep {
                    ServiceDep::ImportPath(p) => {
                        if p.ends_with("svc_dep.yaml") { has_import = true; }
                    }
                    ServiceDep::Inline(_) => has_inline = true,
                }
            }
            assert!(has_import);
            assert!(has_inline);
        }
        _ => panic!("expected router"),
    }
}
