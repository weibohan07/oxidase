use crate::config::error::ConfigError;
use crate::config::service::{Service, ServiceRef};
use crate::config::router::RouterService;
use std::collections::HashSet;
use std::fs::File;
use std::path::{Path, PathBuf};
use sha2::Digest;

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
pub struct ParsedService {
    pub service: Service,
    pub base_dir: PathBuf,
    pub deps: Vec<ServiceDep>,
}

#[derive(Default, Clone)]
pub struct ParseCache {
    imports: std::collections::HashMap<PathBuf, ParsedService>,
    inline: std::collections::HashMap<ServiceKey, ParsedService>,
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
) -> Result<ParsedService, ConfigError> {
    let mut stack = HashSet::new();
    parse_service_ref_inner(svc, base_dir, cache, &mut stack)
}

fn parse_service_ref_inner(
    svc: &ServiceRef,
    base_dir: &Path,
    cache: &mut ParseCache,
    stack: &mut HashSet<PathBuf>,
) -> Result<ParsedService, ConfigError> {
    match svc {
        ServiceRef::Inline(s) => {
            let base = canonicalize(base_dir);
            let key = ServiceKey { base_dir: base.clone(), hash: service_hash(s)? };
            if let Some(hit) = cache.inline.get(&key) {
                return Ok(hit.clone());
            }
            let deps = collect_deps_from_service(s, &base, cache, stack)?;
            let parsed = ParsedService { service: s.clone(), base_dir: base, deps };
            cache.inline.insert(key, parsed.clone());
            Ok(parsed)
        }
        ServiceRef::Import { import } => {
            let path = if import.is_absolute() { import.clone() } else { base_dir.join(import) };
            let canon = canonicalize(&path);
            if let Some(hit) = cache.imports.get(&canon) {
                return Ok(hit.clone());
            }
            if !stack.insert(canon.clone()) {
                return Err(ConfigError::Invalid(format!("service import cycle at {}", canon.display())));
            }
            let file = File::open(&canon)?;
            let nested: ServiceRef = serde_yaml::from_reader(file)?;
            let nested_base = canon.parent().unwrap_or(base_dir);
            let mut parsed = parse_service_ref_inner(&nested, nested_base, cache, stack)?;
            stack.remove(&canon);
            let mut deps = parsed.deps.clone();
            deps.push(ServiceDep::ImportPath(canon.clone()));
            parsed.deps = dedup_deps(deps);
            cache.imports.insert(canon.clone(), parsed.clone());
            Ok(parsed)
        }
    }
}

fn dedup_deps(deps: Vec<ServiceDep>) -> Vec<ServiceDep> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for d in deps {
        if seen.insert(d.clone()) {
            out.push(d);
        }
    }
    out
}

fn collect_deps_from_service(
    svc: &Service,
    base_dir: &Path,
    cache: &mut ParseCache,
    stack: &mut HashSet<PathBuf>,
) -> Result<Vec<ServiceDep>, ConfigError> {
    let mut deps: Vec<ServiceDep> = Vec::new();
    match svc {
        Service::Router(rt) => {
            if let Some(next_ref) = &rt.next {
                let parsed_next = parse_service_ref_inner(next_ref, base_dir, cache, stack)?;
                match &**next_ref {
                    ServiceRef::Import { import } => {
                        let path = if import.is_absolute() { import.clone() } else { base_dir.join(import) };
                        deps.push(ServiceDep::ImportPath(canonicalize(&path)));
                    }
                    ServiceRef::Inline(_) => {
                        let key = ServiceKey {
                            base_dir: canonicalize(&parsed_next.base_dir),
                            hash: service_hash(&parsed_next.service)?,
                        };
                        deps.push(ServiceDep::Inline(key));
                    }
                }
                deps.extend(parsed_next.deps.clone());
            }
        }
        Service::Static(_) | Service::Forward(_) => {}
    }
    Ok(dedup_deps(deps))
}

#[cfg(test)]
mod tests;
