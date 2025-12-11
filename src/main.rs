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
use std::path::Path;
use tokio::task::JoinHandle;

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if args.watch {
        run_watch_loop(&args).await;
    } else {
        run_once(&args).await;
    }
}

async fn run_once(args: &Args) {
    let servers = cli::load_http_servers(args)
        .expect("Failed to load configuration");

    if args.validate_only {
        println!("configuration valid ({} server(s))", servers.len());
        return;
    }

    let handles = spawn_servers(servers);

    for h in handles {
        let _ = h.await;
    }
}

async fn run_watch_loop(args: &Args) {
    use notify::{RecursiveMode, Watcher};

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    
    let mut watcher = notify::recommended_watcher(move |res: Result<notify::Event, _>| {
        if let Ok(event) = res {
             let _ = tx.send(event);
        }
    }).expect("Failed to create file watcher");

    // Identify what to watch
    if let Some(path) = &args.config {
        println!("Watching config file: {:?}", path);
        let _ = watcher.watch(path, RecursiveMode::NonRecursive);
    } else if let Some(path) = &args.service_file {
        println!("Watching service file: {:?}", path);
        let _ = watcher.watch(path, RecursiveMode::NonRecursive);
    } else {
        println!("No file config provided (inline mode). Watching current directory.");
        let _ = watcher.watch(Path::new("."), RecursiveMode::NonRecursive);
    }

    loop {
        let mut handles = Vec::new();
        
        // Attempt to load and start
        println!("Reloading configuration...");
        match cli::load_http_servers(args) {
            Ok(servers) => {
                if args.validate_only {
                    println!("configuration valid ({} server(s))", servers.len());
                } else {
                    handles = spawn_servers(servers);
                    println!("Servers running. Waiting for changes...");
                }
            }
            Err(e) => {
                eprintln!("Configuration Error: {e}");
                eprintln!("Waiting for file changes to retry...");
            }
        }

        // Wait for shutdown or change
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("\nCtrl+C received, shutting down.");
                break;
            }
            Some(_) = rx.recv() => {
                println!("\nFile change detected.");
                // Simple debounce: consume buffered events
                while rx.try_recv().is_ok() {} 
                // Abort current servers
                for h in handles {
                    h.abort();
                }
            }
        }
    }
}

fn spawn_servers(servers: Vec<config::http_server::HttpServer>) -> Vec<JoinHandle<()>> {
    let mut handles = Vec::new();
    let mut parse_cache = build::ParseCache::default();
    let mut build_cache = build::BuildCache::default();
    for srv in servers {
        match build::build_http_server_with_caches(srv, &mut parse_cache, &mut build_cache) {
            Ok(built) => {
                handles.push(tokio::spawn(http_server::start_server(built)));
            }
            Err(e) => {
                eprintln!("Failed to build server: {e}");
            }
        }
    }
    handles
}
