mod cli;

use std::{
    net::{IpAddr, Ipv6Addr},
    path::PathBuf,
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
    let cli = cli::Cli::parse();

    enable_tracing();

    let udp_server = match udp::Server::builder()
        .listen(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
        .on(cli.port)
        .build()
        .await
    {
        Ok(server) => tokio::spawn(async move { server.run().await }),
        Err(err) => {
            error!("{err}");
            return;
        }
    };

    blackhole::config::Config::load(
        cli.config
            .clone()
            .unwrap_or_else(|| PathBuf::from("/config/blackhole.toml"))
            .as_path(),
    )
    .await
    .unwrap();
    blackhole::config::Config::load(cli).await.unwrap();

    let api_server = tokio::spawn(async move { blackhole::api::server::Server.run().await });

    blackhole::filter::Filter::update().await;

    let _joins = tokio::join!(udp_server, api_server);
}
