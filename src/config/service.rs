use serde::Deserialize;

use super::error::ConfigError;

use super::{
    r#static::StaticService,
    router::RouterService,
    forward::ForwardService,
};
use std::collections::HashSet;
use std::fs::File;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "handler", rename_all = "lowercase")]
pub enum Service {
    Static(StaticService),
    Router(RouterService),
    Forward(ForwardService),
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum ServiceRef {
    Inline(Service),
    Import { import: PathBuf },
}

pub fn resolve_service_ref(
    svc: &ServiceRef,
    base_dir: &Path,
    stack: &mut HashSet<PathBuf>,
) -> Result<Service, ConfigError> {
    match svc {
        ServiceRef::Inline(s) => Ok(s.clone()),
        ServiceRef::Import { import } => {
            let path = if import.is_absolute() {
                import.clone()
            } else {
                base_dir.join(import)
            };
            let canon = path.canonicalize().unwrap_or(path.clone());
            if !stack.insert(canon.clone()) {
                return Err(ConfigError::Invalid(format!("service import cycle at {}", canon.display())));
            }
            let file = File::open(&canon)?;
            let nested: ServiceRef = serde_yaml::from_reader(file)?;
            let nested_base = canon.parent().unwrap_or(base_dir);
            let resolved = resolve_service_ref(&nested, nested_base, stack)?;
            stack.remove(&canon);
            Ok(resolved)
        }
    }
}

pub fn validate_service(svc: &Service, base_dir: &Path) -> Result<(), ConfigError> {
    match svc {
        Service::Static(st) => {
            if st.source_dir.trim().is_empty() {
                return Err(ConfigError::Invalid("`static.source_dir` cannot be empty".into()));
            }
        }
        Service::Router(rt) => {
            if rt.rules.is_empty() {
                return Err(ConfigError::Invalid("`router.rules` cannot be empty".into()));
            }
            if let Some(n) = &rt.next {
                let mut stack = HashSet::new();
                let resolved = resolve_service_ref(n, base_dir, &mut stack)?;
                validate_service(&resolved, base_dir)?;
            }
        }
        Service::Forward(fw) => {
            if fw.target.host.trim().is_empty() {
                return Err(ConfigError::Invalid("`forward.target.host` cannot be empty".into()));
            }
        }
    }
    Ok(())
}
