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
use tokio::task::JoinHandle;
use tracing::{error, instrument};

pub mod api;
pub mod cache;
pub mod config;
pub mod dns;
pub mod filter;
pub mod schedule;
pub mod server;
pub mod statistics;

#[instrument]
pub async fn spawn() -> Result<JoinHandle<()>, DNSError> {
    let port = config::Config::get(|config| config.port).await;

    let udp_server = match server::udp::Server::builder()
        .listen(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
        .on(port)
        .build()
        .await
    {
        Ok(server) => tokio::spawn(async move { server.run().await }),
        Err(err) => {
            error!("{err}");
            return Err(err);
        }
    };

    let tcp_server = match server::tcp::Server::builder()
        .listen(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
        .on(port)
        .build()
        .await
    {
        Ok(server) => tokio::spawn(async move { server.run().await }),
        Err(err) => {
            error!("{err}");
            return Err(err);
        }
    };

    let scheduler_handle = tokio::spawn(async move {
        schedule::Scheduler::init(config::Config::get(|config| config.schedules.clone()).await)
            .await;
    });

    let api_server = tokio::spawn(async move { api::Server.run().await });

    Ok(tokio::spawn(async move {
        udp_server.await.unwrap().unwrap();
        tcp_server.await.unwrap().unwrap();
        scheduler_handle.await.unwrap();
        api_server.await.unwrap();
    }))
}
