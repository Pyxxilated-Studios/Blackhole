#![allow(incomplete_features)]
#![forbid(unsafe_code)]
#![feature(async_fn_in_trait)]

use std::{
    net::{IpAddr, Ipv6Addr},
    path::PathBuf,
};

use clap::Parser;
use tracing::{error, metadata::LevelFilter};
use tracing_subscriber::{
    prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt, Layer,
};

use blackhole::{server::udp, statistics::Statistics};

mod cli;

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
        LevelFilter::INFO
    };

    tracing_subscriber::Registry::default()
        .with(Statistics::default())
        .with(
            (if cfg!(debug_assertions) {
                tracing_subscriber::fmt::layer()
            } else {
                tracing_subscriber::fmt::layer()
                    .with_file(false)
                    .with_line_number(false)
            })
            .compact()
            .with_ansi(true)
            .with_filter(level),
        )
        .init();
}

#[tokio::main]
async fn main() {
    enable_tracing();

    let mut cli = cli::Cli::parse();

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
            .get_or_insert_with(|| PathBuf::from("/config/blackhole.toml"))
            .clone(),
    )
    .await
    .unwrap_or_default();
    blackhole::config::Config::load(cli).await.unwrap();

    let scheduler = tokio::spawn(async move {
        blackhole::schedule::Scheduler::init(
            blackhole::config::Config::get(|config| config.schedules.clone()).await,
        )
        .await;
    });

    let api_server = tokio::spawn(async move { blackhole::api::Server.run().await });

    tokio::select! {
        _ = udp_server => {}
        _ = api_server => {}
        _ = scheduler => {}
    }
}
