#![allow(incomplete_features)]
#![forbid(unsafe_code)]
#![feature(coverage_attribute)]

use std::{path::PathBuf, time::Duration};

use clap::Parser;
use tokio::{
    signal::unix::{signal, SignalKind},
    sync::watch::channel,
};
use tracing::{error, info, metadata::LevelFilter};
use tracing_subscriber::{
    prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt, Layer,
};

mod cli;

#[coverage(off)]
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

#[coverage(off)]
#[tokio::main]
async fn main() {
    enable_tracing();

    let cli = cli::Cli::parse();

    blackhole::config::Config::load(&PathBuf::from(&cli.config))
        .await
        .unwrap_or_default();

    let (shutdown, shutdown_signal) = channel(false);

    let blackhole_handle = match blackhole::spawn(shutdown_signal).await {
        Ok(handle) => handle,
        Err(err) => {
            error!("{err}");
            return;
        }
    };

    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let mut sigint = signal(SignalKind::interrupt()).unwrap();
    let mut sigquit = signal(SignalKind::quit()).unwrap();

    tokio::select! {
        _ = blackhole_handle => {}
        _ = sigint.recv() => {}
        _ = sigquit.recv() => {}
        _ = sigterm.recv() => {}
    };

    info!("Shutting down");
    shutdown
        .send(true)
        .expect("There was an issue shutting down");

    tokio::time::timeout(Duration::from_secs(10), shutdown.closed())
        .await
        .unwrap_or_default();
}
