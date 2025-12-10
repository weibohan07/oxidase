use std::fs;
use std::path::{Path, PathBuf};

use clap::{Parser, ArgGroup};

use crate::config::error::ConfigError;
use crate::config::http_server::{HttpServer, ServersFile};
use crate::config::service::{ServiceRef};

// Why port 7589? oxidase -> 0x1da5e (121438, too large) -> 0x1da5 -> 7589 (bingo!)

#[derive(Parser, Debug)]
#[command(name = "oxidase", author, version, about)]
#[command(group(ArgGroup::new("source").required(true)
    .args(["config", "service_file", "service_inline"])))]
pub struct Args {
    /// Path to a HttpServer config file (single server & servers list supported)
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Path to a Service config file (bind will be taken from --bind)
    #[arg(long)]
    pub service_file: Option<PathBuf>,

    /// Inline YAML/JSON for a Service
    #[arg(long)]
    pub service_inline: Option<String>,

    /// Bind address when using --service-file / --service-inline
    #[arg(long, default_value = "127.0.0.1:7589")]
    pub bind: String,

    /// Pick a server by name when config contains multiple
    #[arg(long)]
    pub pick: Option<String>,

    /// Only validate configuration, do not start servers
    #[arg(long)]
    pub validate_only: bool,
}

pub fn load_http_servers(args: &Args) -> Result<Vec<HttpServer>, ConfigError> {
    let mut servers = if let Some(cfg) = &args.config {
        load_from_config(cfg)?
    } else if let Some(svc_file) = &args.service_file {
        load_from_service_file(svc_file, &args.bind)?
    } else if let Some(inline) = &args.service_inline {
        load_from_inline(inline, &args.bind)?
    } else {
        return Err(ConfigError::Invalid("no config source provided".to_string()));
    };

    if let Some(name) = &args.pick {
        servers.retain(|s| s.name.as_deref() == Some(name.as_str()));
        if servers.is_empty() {
            return Err(ConfigError::Invalid(format!("no server named `{}` found", name)));
        }
    }

    Ok(servers)
}

fn load_from_config(path: &Path) -> Result<Vec<HttpServer>, ConfigError> {
    // single server
    if let Ok(svc) = HttpServer::load_from_file(path) {
        return Ok(vec![svc]);
    }

    // servers wrapper
    let raw = fs::read_to_string(path)?;
    if let Ok(wrapper) = serde_yaml::from_str::<ServersFile>(&raw) {
        let base = path.parent().unwrap_or(Path::new("."));
        let mut servers = Vec::new();
        for mut s in wrapper.servers {
            s.base_dir = Some(base.to_path_buf());
            s.validate()?;
            servers.push(s);
        }
        return Ok(servers);
    }

    // array of servers
    if let Ok(mut servers) = serde_yaml::from_str::<Vec<HttpServer>>(&raw) {
        let base = path.parent().unwrap_or(Path::new("."));
        for s in &mut servers {
            s.base_dir = Some(base.to_path_buf());
            s.validate()?;
        }
        return Ok(servers);
    }

    Err(ConfigError::Invalid("failed to parse config as HttpServer or servers list".to_string()))
}

fn load_from_service_file(path: &Path, bind: &str) -> Result<Vec<HttpServer>, ConfigError> {
    let svc_ref = ServiceRef::Import { import: path.to_path_buf() };
    let hs = HttpServer {
        name: None,
        bind: bind.to_string(),
        tls: None,
        service: svc_ref,
        base_dir: path.parent().map(|p| p.to_path_buf()),
    };
    hs.validate()?;
    Ok(vec![hs])
}

fn load_from_inline(data: &str, bind: &str) -> Result<Vec<HttpServer>, ConfigError> {
    let svc_ref: ServiceRef = serde_yaml::from_str(data)?;
    let hs = HttpServer {
        name: None,
        bind: bind.to_string(),
        tls: None,
        service: svc_ref,
        base_dir: Some(std::env::current_dir().unwrap_or_default()),
    };
    hs.validate()?;
    Ok(vec![hs])
}

#[cfg(test)]
mod tests;
