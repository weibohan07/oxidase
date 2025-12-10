mod build;
mod cli;
mod config;
mod handler;
mod http_server;
mod pattern;
mod template;
mod util;

use cli::Args;
use clap::Parser;

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let servers = cli::load_http_servers(&args)
        .expect("Failed to load configuration");

    if args.validate_only {
        println!("configuration valid ({} server(s))", servers.len());
        return;
    }

    // For now start all servers; each start_server runs its own accept loop.
    let mut handles = Vec::new();
    for srv in servers {
        let built = build::build_http_server(srv)
            .expect("Failed to build runtime service");
        handles.push(tokio::spawn(http_server::start_server(built)));
    }

    for h in handles {
        let _ = h.await;
    }
}
