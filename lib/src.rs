#![allow(incomplete_features)]
#![forbid(unsafe_code)]
#![feature(
    array_try_from_fn,
    async_fn_in_trait,
    ip,
    once_cell,
    option_get_or_insert_default
)]

use std::net::{IpAddr, Ipv6Addr};

use dns::DNSError;
use tokio::{sync::watch::Receiver, task::JoinHandle};

use crate::config::Config;

pub mod api;
pub mod cache;
pub mod config;
pub mod dns;
pub mod filter;
pub mod schedule;
pub mod server;
pub mod statistics;

///
/// Spawn all servers, the API, and initialise the scheduler
///
/// # Errors
/// If there are issues during startup
///
pub async fn spawn(mut shutdown_signal: Receiver<bool>) -> Result<JoinHandle<()>, DNSError> {
    let port = config::Config::get(|config| config.port).await;

    match server::udp::Server::builder()
        .listen(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
        .on(port)
        .build()
        .await
    {
        Ok(server) => tokio::spawn({
            let shutdown_signal = shutdown_signal.clone();
            async move { server.run(shutdown_signal).await }
        }),
        Err(err) => {
            return Err(err);
        }
    };

    match server::tcp::Server::builder()
        .listen(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
        .on(port)
        .build()
        .await
    {
        Ok(server) => tokio::spawn({
            let shutdown_signal = shutdown_signal.clone();
            async move { server.run(shutdown_signal.clone()).await }
        }),
        Err(err) => {
            return Err(err);
        }
    };

    tokio::spawn({
        let shutdown_signal = shutdown_signal.clone();
        async move {
            schedule::Scheduler::init(
                shutdown_signal,
                config::Config::get(|config| config.schedules.clone()).await,
            )
            .await;
        }
    });

    tokio::spawn(async move { api::Server.run().await });

    Ok(tokio::spawn(async move {
        shutdown_signal.changed().await.expect("Failed to shutdown");
        Config::save().await.expect("Failed to save config");
        drop(shutdown_signal);
    }))
}
