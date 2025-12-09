use http_body_util::Full;
use hyper::{
    server::conn::http1,
    service::service_fn,
    Request,
    Response,
    body,
    Version
};
use tokio::net::TcpListener;
use std::net::SocketAddr;
use crate::build::service::BuiltHttpServer;
use crate::handler::ServiceHandler;
use hyper_util::rt::TokioIo;

use std::sync::Arc;

pub async fn start_server(hs: BuiltHttpServer) {
    let addr
        = hs.bind
            .parse::<SocketAddr>()
            .expect("Invalid bind address");

    let listener
        = TcpListener::bind(addr).await
            .expect("Failed to bind TCP listener");

    let ox_svc_root = Arc::new(hs.service);

    loop {
        let (stream, _peer)
            = listener
                .accept().await
                .expect("Failed to accept connection");

        let ox_svc_conn = ox_svc_root.clone();

        tokio::spawn(async move {
            let io = TokioIo::new(stream);

            let svc_fn
                = service_fn(
                    move |mut req: Request<body::Incoming>| {
                        let ox_svc = ox_svc_conn.clone();
                        async move {
                            if req.version() == Version::HTTP_11 {
                                let resp = ox_svc.handle_request(&mut req).await;
                                Ok::<_, hyper::Error>(resp)
                            } else {
                                Ok(Response::builder()
                                    .status(400)
                                    .body(Full::from("not HTTP/1.1, abort connection"))
                                    .expect("Failed to construct response"))
                            }
                        }
                    }
                );
            
            if let Err(e) = http1::Builder::new().serve_connection(io, svc_fn).await {
                eprintln!("Serve error: {e:?}");
            }
        });
    }
}
