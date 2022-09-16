use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use blackhole::server::udp;
use tracing::{error, metadata::LevelFilter};
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
            .with_env_filter(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .with_env_var("LOG_LEVEL")
                    .from_env_lossy(),
            )
            .init();
    }
}

#[tokio::main]
async fn main() {
    enable_tracing();

    // let listener = TcpListener::bind("0.0.0.0:0379").await?;
    let udp_v4_server = match udp::Server::builder()
        .listen(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        .on(6380)
        .build()
        .await
    {
        Ok(server) => Arc::new(server),
        Err(err) => {
            error!("{err:?}");
            return;
        }
    };

    let udp_v6_server = match udp::Server::builder()
        .listen(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
        .on(6379)
        .build()
        .await
    {
        Ok(server) => Arc::new(server),
        Err(err) => {
            error!("{err:?}");
            return;
        }
    };

    blackhole::filter::FILTERS
        .write()
        .await
        .load("filters.txt")
        .unwrap_or_default();

    let udp_v4_server = tokio::spawn(async move { udp_v4_server.run().await });
    let udp_v6_server = tokio::spawn(async move { udp_v6_server.run().await });

    let api_server = tokio::spawn(async move { blackhole::api::server::Server.run().await });

    tokio::spawn(async move {
        // while let Ok((mut stream, _peer)) = listener.accept().await {
        //     stream.readable().await.unwrap();
        //     let _ = blackhole::dns::packet::Packet::from_tcp(&mut stream)
        //         .await
        //         .unwrap();
        // }
    });

    let _joins = tokio::join!(udp_v4_server, udp_v6_server, api_server);
}
