pub mod r#static;
pub mod forward;
pub mod router;

use hyper::{body, http};
use http_body_util::Full;
use bytes::Bytes;
use std::future::Future;
use std::pin::Pin;

use crate::build::service::LoadedService;

pub type BoxResponseFuture<'a> = Pin<Box<dyn Future<Output = http::Response<Full<Bytes>>> + Send + 'a>>;

pub trait ServiceHandler {
    fn handle_request<'a>(&'a self, req: &'a mut http::Request<body::Incoming>) -> BoxResponseFuture<'a>;
}

impl ServiceHandler for LoadedService {
    fn handle_request<'a>(&'a self, req: &'a mut http::Request<body::Incoming>) -> BoxResponseFuture<'a> {
        match self {
            LoadedService::Static(handler) => handler.handle_request(req),
            LoadedService::Router(handler) => handler.handle_request(req),
            LoadedService::Forward(handler) => handler.handle_request(req),
        }
    }
}
