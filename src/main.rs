mod config;
mod handler;
mod http_server;

use config::http_server::HttpServer;

#[tokio::main]
async fn main() {
    let config
        = HttpServer::load_from_file("/Users/weibohan/Downloads/oxidase/config.yaml")
            .expect("Failed to load configuration");
    http_server::start_server(config).await;
}
