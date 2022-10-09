mod cli;

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::Arc,
};

use blackhole::server::udp;
use clap::Parser;
use tracing::{error, metadata::LevelFilter};

fn enable_tracing() {
    let level = if let Ok(level) = std::env::var("LOG_LEVEL") {
        match level.to_ascii_lowercase().as_str() {
            "warn" => LevelFilter::WARN,
            "info" => LevelFilter::INFO,
            "trace" => LevelFilter::TRACE,
            _ => LevelFilter::ERROR,
        }
    } else if cfg!(debug_assertions) {
        LevelFilter::TRACE
    } else {
        LevelFilter::ERROR
    };

    if cfg!(debug_assertions) {
        tracing_subscriber::fmt().with_max_level(level).init();
    } else {
        tracing_subscriber::fmt()
            .with_file(false)
            .with_line_number(false)
            .with_max_level(level)
            .init();
    }
}

#[tokio::main]
async fn main() {
    enable_tracing();

    let cli_config = cli::Cli::parse();
    let default_path = cli_config
        .config
        .clone()
        .unwrap_or_else(|| PathBuf::from("/config/blackhole.toml"));

    blackhole::config::Config::load(default_path.as_path())
        .await
        .unwrap();
    blackhole::config::Config::load(cli_config).await.unwrap();

    let config = blackhole::config::CONFIG.read().await;

    println!("{config:#?}");

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
        .load("target/filters.txt")
        .unwrap_or_default();

    let udp_v4_server = tokio::spawn(async move { udp_v4_server.run().await });
    let udp_v6_server = tokio::spawn(async move { udp_v6_server.run().await });

    let api_server = tokio::spawn(async move { blackhole::api::server::Server.run().await });

    let _joins = tokio::join!(udp_v4_server, udp_v6_server, api_server);
}
