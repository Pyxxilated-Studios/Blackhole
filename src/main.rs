#![allow(incomplete_features)]
#![forbid(unsafe_code)]
#![feature(async_fn_in_trait)]

use std::path::PathBuf;

use clap::Parser;
use futures::StreamExt;
use signal_hook::consts::{SIGINT, SIGQUIT, SIGTERM};
use signal_hook_tokio::Signals;
use tokio::sync::watch::channel;
use tracing::{error, info, metadata::LevelFilter};
use tracing_subscriber::{
    prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt, Layer,
};

use blackhole::statistics::Statistics;

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

    blackhole::config::Config::load(
        cli.config
            .get_or_insert_with(|| PathBuf::from("/config/blackhole.toml")),
    )
    .await
    .unwrap_or_default();
    blackhole::config::Config::load(&cli).await.unwrap();

    let (shutdown, shutdown_signal) = channel(false);

    let blackhole_handle = match blackhole::spawn(shutdown_signal).await {
        Ok(handle) => handle,
        Err(err) => {
            error!("{err}");
            return;
        }
    };

    let mut signals =
        Signals::new([SIGTERM, SIGINT, SIGQUIT]).expect("Could not set signal handler");
    let signals_handle = tokio::spawn(async move {
        while let Some(signal) = signals.next().await {
            match signal {
                SIGTERM | SIGINT | SIGQUIT => {
                    return;
                }
                _ => unreachable!(),
            }
        }
    });

    tokio::select! {
        _ = blackhole_handle => {}
        _ = signals_handle => {}
    };

    info!("Shutting down");
    shutdown
        .send(true)
        .expect("There was an issue shutting down");
    shutdown.closed().await;
}
