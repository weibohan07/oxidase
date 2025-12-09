use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{body, http, Uri};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;

use crate::build::service::LoadedForward;
use crate::config::forward::{PassHost, PassHostMode};
use crate::config::url_scheme::Scheme;
use crate::handler::{BoxResponseFuture, ServiceHandler};

pub type ForwardResult<T> = Result<T, String>;

impl ServiceHandler for LoadedForward {
    fn handle_request<'a>(
        &'a self,
        req: &'a mut http::Request<body::Incoming>,
    ) -> BoxResponseFuture<'a> {
        Box::pin(async move {
            match self.forward_once(req).await {
                Ok(resp) => resp,
                Err(msg) => make_error_resp(http::StatusCode::BAD_GATEWAY, &msg),
            }
        })
    }
}

impl LoadedForward {
    async fn forward_once(
        &self,
        req: &mut http::Request<body::Incoming>,
    ) -> ForwardResult<http::Response<Full<Bytes>>> {
        // TODO: https upstream, timeouts, http version
        if matches!(self.config.target.scheme, Scheme::Https) {
            return Err("TODO: https upstream not yet implemented".to_string());
        }

        let upstream_uri = self.build_upstream_uri(req)?;

        let body_bytes = req
            .body_mut()
            .collect()
            .await
            .map_err(|e| format!("failed to collect request body: {e}"))?
            .to_bytes();

        let mut upstream_req = http::Request::builder()
            .method(req.method())
            .uri(upstream_uri)
            .body(Full::from(body_bytes))
            .map_err(|e| format!("failed to build upstream request: {e}"))?;

        // copy rest of headers
        copy_headers(req, &mut upstream_req, self.host_header(req)?, self.config.x_forwarded);

        let mut connector = HttpConnector::new();
        connector.enforce_http(true); // TODO: later switch to false for HTTPS support
        
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(connector);

        let upstream_resp = client
            .request(upstream_req)
            .await
            .map_err(|e| format!("upstream request failed: {e}"))?;

        let (parts, body) = upstream_resp.into_parts();
        let resp_body = body
            .collect()
            .await
            .map_err(|e| format!("failed to collect upstream body: {e}"))?
            .to_bytes();

        // downstream response builder
        let mut builder = http::Response::builder().status(parts.status);
        for (name, value) in parts.headers.iter() {
            builder = builder.header(name, value);
        }

        builder
            .body(Full::from(resp_body))
            .map_err(|e| format!("failed to build downstream response: {e}"))
    }

    fn build_upstream_uri(
        &self,
        req: &http::Request<body::Incoming>,
    ) -> ForwardResult<Uri> {
        let scheme = match self.config.target.scheme {
            Scheme::Http => "http",
            Scheme::Https => "https",
        };

        let mut path = self.config.target.path_prefix.clone();

        if path.ends_with('/') && req.uri().path().starts_with('/') {
            path.pop();
        }

        path.push_str(req.uri().path());
    
        if !path.starts_with('/') {
            path.insert(0, '/');
        }

        let mut uri = format!("{scheme}://{}:{}{}", self.config.target.host, self.config.target.port, path);
        if let Some(q) = req.uri().query() {
            uri.push('?');
            uri.push_str(q);
        }

        uri.parse::<Uri>()
            .map_err(|e| format!("failed to build upstream URI: {e}"))
    }

    /// Decide the Host header value based on pass_host strategy.
    fn host_header(
        &self,
        req: &http::Request<body::Incoming>,
    ) -> ForwardResult<Option<http::HeaderValue>> {
        match &self.config.pass_host {
            PassHost::Mode(PassHostMode::Incoming) =>
                req.headers().get(http::header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string()),
            PassHost::Mode(PassHostMode::Target) =>
                Some(format_host(&self.config.target.host, self.config.target.port, self.config.target.scheme)),
            PassHost::Custom { custom } => Some(custom.clone()),
        }.map(|h| http::HeaderValue::from_str(&h)
            .map_err(|e| format!("invalid host header value: {e}")))
            .transpose()
    }
}

/// Copy downstream headers into the upstream request, then apply Host and X-Forwarded-* if enabled.
fn copy_headers(
    downstream: &http::Request<body::Incoming>,
    upstream: &mut http::Request<Full<Bytes>>,
    host_header: Option<http::HeaderValue>,
    x_forwarded: bool,
) {
    let headers = upstream.headers_mut();

    for (name, value) in downstream.headers() {
        if name == http::header::HOST {
            continue;
        }
        headers.append(name, value.clone());
    }

    if let Some(host) = host_header {
        headers.insert(http::header::HOST, host);
    }

    if x_forwarded {
        if let Some(host) = downstream.headers().get(http::header::HOST) {
            headers.insert(
                http::header::HeaderName::from_static("x-forwarded-host"),
                host.clone(),
            );
        }

        let proto = downstream.uri().scheme_str().unwrap_or("http");
        if let Ok(xfp) = http::HeaderValue::from_str(proto) {
            headers.insert(
                http::header::HeaderName::from_static("x-forwarded-proto"),
                xfp,
            );
        }

        if let Some(xff) = downstream.headers().get(
            http::header::HeaderName::from_static("x-forwarded-for"),
        ) {
            headers.insert(
                http::header::HeaderName::from_static("x-forwarded-for"),
                xff.clone(),
            );
        }
    }
}

fn make_error_resp(status: http::StatusCode, msg: &str) -> http::Response<Full<Bytes>> {
    let mut resp = http::Response::new(Full::new(Bytes::from(msg.to_string())));
    *resp.status_mut() = status;
    resp
}

/// Drop default ports for http/https when formatting host header.
fn format_host(host: &str, port: u16, scheme: Scheme) -> String {
    let default_port = matches!((scheme, port), (Scheme::Http, 80) | (Scheme::Https, 443));
    if default_port {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}
