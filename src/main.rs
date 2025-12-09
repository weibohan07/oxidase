mod build;
mod config;
mod handler;
mod http_server;

use config::http_server::HttpServer;
use build::service::build_http_server;

#[tokio::main]
async fn main() {
    let config
        = HttpServer::load_from_file("/Users/weibohan/Downloads/oxidase/config.yaml")
            .expect("Failed to load configuration");

    let loaded = build_http_server(config)
        .expect("Failed to build runtime service");

    http_server::start_server(loaded).await;
}
