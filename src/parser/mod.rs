mod router;
pub use router::{ParsedRouter, ParsedRouterOp, ParsedRouterRule};

use crate::config::error::ConfigError;
use crate::config::forward::ForwardService;
use crate::config::service::{Service, ServiceRef};
use crate::config::r#static::StaticService;
use sha2::Digest;
use std::collections::HashSet;
use std::fs::File;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServiceKey {
    pub base_dir: PathBuf,
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ServiceDep {
    ImportPath(PathBuf),
    Inline(ServiceKey),
}

#[derive(Debug, Clone)]
pub enum ParsedService {
    Static(ParsedStatic),
    Forward(ParsedForward),
    Router(ParsedRouter),
}

#[derive(Debug, Clone)]
pub struct ParsedStatic {
    pub base_dir: PathBuf,
    pub config: StaticService,
}

#[derive(Debug, Clone)]
pub struct ParsedForward {
    pub base_dir: PathBuf,
    pub config: ForwardService,
}

#[derive(Default, Clone)]
pub struct ParseCache {
    pub(crate) key_to_parsed: std::collections::HashMap<ServiceKey, ParsedService>,
    pub(crate) import_to_key: std::collections::HashMap<PathBuf, ServiceKey>,
    pub(crate) file_to_keys: std::collections::HashMap<PathBuf, Vec<ServiceKey>>,
}

#[derive(Debug, Clone)]
pub struct ParseResult {
    pub root: ServiceKey,
    pub services: std::collections::HashMap<ServiceKey, ParsedService>,
    #[allow(dead_code)]
    pub file_to_keys: std::collections::HashMap<PathBuf, Vec<ServiceKey>>,
    pub import_to_key: std::collections::HashMap<PathBuf, ServiceKey>,
}

pub fn service_hash(svc: &Service) -> Result<String, ConfigError> {
    let serialized = format!("{:?}", svc);
    let digest = sha2::Sha256::digest(serialized.as_bytes());
    Ok(format!("{:x}", digest))
}

pub fn canonicalize(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

pub fn parse_service_ref(
    svc: &ServiceRef,
    base_dir: &Path,
    cache: &mut ParseCache,
) -> Result<ParseResult, ConfigError> {
    let mut stack = HashSet::new();
    let root = parse_service_ref_inner(svc, base_dir, cache, &mut stack)?;
    Ok(ParseResult {
        root,
        services: cache.key_to_parsed.clone(),
        file_to_keys: cache.file_to_keys.clone(),
        import_to_key: cache.import_to_key.clone(),
    })
}

pub(crate) fn parse_service_ref_inner(
    svc: &ServiceRef,
    base_dir: &Path,
    cache: &mut ParseCache,
    stack: &mut HashSet<PathBuf>,
) -> Result<ServiceKey, ConfigError> {
    match svc {
        ServiceRef::Inline(s) => {
            let base = canonicalize(base_dir);
            let key = ServiceKey { base_dir: base.clone(), hash: service_hash(s)? };
            if cache.key_to_parsed.contains_key(&key) {
                return Ok(key);
            }
            let parsed = match s {
                Service::Static(st) => ParsedService::Static(ParsedStatic { base_dir: base.clone(), config: st.clone() }),
                Service::Forward(fw) => ParsedService::Forward(ParsedForward { base_dir: base.clone(), config: fw.clone() }),
                Service::Router(rt) => ParsedService::Router(router::parse_router(rt, &base, cache, stack)?),
            };
            cache.key_to_parsed.insert(key.clone(), parsed);
            Ok(key)
        }
        ServiceRef::Import { import } => {
            let path = if import.is_absolute() { import.clone() } else { base_dir.join(import) };
            let canon = canonicalize(&path);
            if let Some(k) = cache.import_to_key.get(&canon) {
                return Ok(k.clone());
            }
            if !stack.insert(canon.clone()) {
                return Err(ConfigError::Invalid(format!("service import cycle at {}", canon.display())));
            }
            let file = File::open(&canon)?;
            let nested: ServiceRef = serde_yaml::from_reader(file)?;
            let nested_base = canon.parent().unwrap_or(base_dir);
            let key = parse_service_ref_inner(&nested, nested_base, cache, stack)?;
            stack.remove(&canon);

            cache.import_to_key.insert(canon.clone(), key.clone());
            let slot = cache.file_to_keys.entry(canon.clone()).or_default();
            if !slot.contains(&key) {
                slot.push(key.clone());
            }

            // Record this import path as a dependency for router entries.
            if let Some(entry) = cache.key_to_parsed.get_mut(&key) {
                if let ParsedService::Router(r) = entry {
                    let mut deps = r.deps.clone();
                    deps.push(ServiceDep::ImportPath(canon.clone()));
                    r.deps = dedup_deps(deps);
                }
            }
            Ok(key)
        }
    }
}

pub(crate) fn dedup_deps(deps: Vec<ServiceDep>) -> Vec<ServiceDep> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for d in deps {
        if seen.insert(d.clone()) {
            out.push(d);
        }
    }
    out
}

#[cfg(test)]
mod tests;
