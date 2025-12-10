use std::collections::HashMap;

use hyper::{body, http};
use percent_encoding::percent_decode_str;

use crate::config::http_method::HttpMethod;
use crate::template::ValueProvider;

#[derive(Debug, Clone)]
pub struct RouterCtx {
    pub method: Option<HttpMethod>,
    pub scheme: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    pub path: String,
    pub query: HashMap<String, Vec<String>>,
    pub headers: HashMap<String, Vec<String>>,
    pub cookies: HashMap<String, String>,
    pub captures: HashMap<String, String>,
}

impl ValueProvider for RouterCtx {
    fn get(&self, key: &str) -> Option<String> {
        match key {
            "method" => self.method.as_ref().map(|m| format!("{:?}", m).to_ascii_uppercase()),
            "scheme" => self.scheme.clone(),
            "host" => Some(self.host.clone()),
            "port" => self.port.map(|p| p.to_string()),
            "path" => Some(self.path.clone()),
            v if v.starts_with("header.") => {
                let name = v.trim_start_matches("header.").to_ascii_lowercase();
                self.headers.get(&name).and_then(|vals| vals.get(0)).cloned()
            }
            v if v.starts_with("query.") => {
                let k = v.trim_start_matches("query.");
                self.query.get(k).and_then(|vals| vals.get(0)).cloned()
            }
            v if v.starts_with("cookie.") => {
                let k = v.trim_start_matches("cookie.");
                self.cookies.get(k).cloned()
            }
            _ => self.captures.get(key).cloned(),
        }
    }
}

impl RouterCtx {
    pub fn from_request(req: &http::Request<body::Incoming>) -> Self {
        let method = HttpMethod::try_from(req.method().as_str()).ok();
        let scheme = req.uri().scheme_str().map(|s| s.to_ascii_lowercase());
        let (host, port) = parse_host_and_port(req);
        let path = req.uri().path().to_string();
        let query = parse_query(req.uri().query());
        let headers = collect_headers(req);
        let cookies = parse_cookies(headers.get("cookie"));
        RouterCtx {
            method,
            scheme,
            host,
            port,
            path,
            query,
            headers,
            cookies,
            captures: HashMap::new(),
        }
    }
}

pub fn apply_ctx_to_request(ctx: &RouterCtx, req: &mut http::Request<body::Incoming>) {
    if !ctx.host.is_empty() {
        if let Ok(val) = http::HeaderValue::from_str(&ctx.host) {
            req.headers_mut().insert(http::header::HOST, val);
        }
    }

    let mut uri = ctx.path.clone();
    if !ctx.query.is_empty() {
        let mut parts = Vec::new();
        for (k, vals) in &ctx.query {
            for v in vals {
                parts.push(format!("{k}={v}"));
            }
        }
        uri.push('?');
        uri.push_str(&parts.join("&"));
    }
    if let Ok(new_uri) = uri.parse() {
        *req.uri_mut() = new_uri;
    }
}

fn parse_host_and_port(req: &http::Request<body::Incoming>) -> (String, Option<u16>) {
    if let Some(host) = req.uri().host() {
        let port = req.uri().port_u16();
        return (host.to_string(), port);
    }
    if let Some(host_header) = req.headers().get(http::header::HOST) {
        if let Ok(hs) = host_header.to_str() {
            if let Some((h, p)) = hs.split_once(':') {
                if let Ok(port) = p.parse::<u16>() {
                    return (h.to_string(), Some(port));
                }
            }
            return (hs.to_string(), None);
        }
    }
    ("".into(), None)
}

fn parse_query(q: Option<&str>) -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    if let Some(qs) = q {
        for pair in qs.split('&') {
            if pair.is_empty() { continue; }
            let mut iter = pair.splitn(2, '=');
            let key = iter.next().unwrap_or("").to_string();
            let val = iter.next().unwrap_or("").to_string();
            out.entry(key).or_default().push(val);
        }
    }
    out
}

fn collect_headers(req: &http::Request<body::Incoming>) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for (name, value) in req.headers() {
        let key = name.as_str().to_ascii_lowercase();
        if let Ok(vs) = value.to_str() {
            map.entry(key).or_default().push(vs.to_string());
        }
    }
    map
}

fn parse_cookies(cookies: Option<&Vec<String>>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if let Some(list) = cookies {
        for raw in list {
            for part in raw.split(';') {
                let trimmed = part.trim();
                if trimmed.is_empty() { continue; }
                if let Some((k, v)) = trimmed.split_once('=') {
                    let key = k.trim();
                    let val = percent_decode_str(v.trim()).decode_utf8_lossy().to_string();
                    out.insert(key.to_string(), val);
                }
            }
        }
    }
    out
}

impl TryFrom<&str> for HttpMethod {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "GET" => Ok(HttpMethod::Get),
            "POST" => Ok(HttpMethod::Post),
            "PUT" => Ok(HttpMethod::Put),
            "PATCH" => Ok(HttpMethod::Patch),
            "DELETE" => Ok(HttpMethod::Delete),
            "HEAD" => Ok(HttpMethod::Head),
            "OPTIONS" => Ok(HttpMethod::Options),
            _ => Err(()),
        }
    }
}
