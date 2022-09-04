use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use tokio::{net::TcpListener, task::JoinError};
use tracing::metadata::LevelFilter;
use tracing_subscriber::EnvFilter;

fn enable_tracing() {
    if cfg!(debug_assertions) {
        tracing_subscriber::fmt()
            .pretty()
            .with_env_filter(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::TRACE.into())
                    .with_env_var("LOG_LEVEL")
                    .from_env_lossy(),
            )
            .init();
    } else {
        tracing_subscriber::fmt()
            .pretty()
            .with_file(false)
            .with_line_number(false)
            .with_env_filter(EnvFilter::from_env("LOG_LEVEL"))
            .init();
    }
}

#[tokio::main]
async fn main() -> Result<(), JoinError> {
    enable_tracing();

    // let listener = TcpListener::bind("0.0.0.0:6379").await?;
    let udp_server = Arc::new(
        blackhole::server::udp::Server::builder()
            .listen(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
            .on(6379)
            .build()
            .await
            .unwrap(),
    );

    let api_server = blackhole::api::server::Server::with_context(blackhole::api::Context {
        server: udp_server.clone(),
    });

    let udp_server = tokio::spawn(async move {
        let udp_server = udp_server.clone();
        udp_server.run().await.unwrap();
    });

    let api_server = tokio::spawn(async move {
        api_server.run().await;
    });

    let tcp_server = tokio::spawn(async move {
        // while let Ok((mut stream, _peer)) = listener.accept().await {
        //     stream.readable().await.unwrap();
        //     let _ = blackhole::dns::packet::Packet::from_tcp(&mut stream)
        //         .await
        //         .unwrap();
        // }
    });

    tokio::join!(api_server, udp_server, tcp_server).0
}
