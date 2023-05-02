#![allow(incomplete_features)]
#![forbid(unsafe_code)]
#![feature(ip, no_coverage, lazy_cell, type_alias_impl_trait)]

use std::{
    io,
    net::{IpAddr, Ipv6Addr, ToSocketAddrs},
    time::Duration,
};

use dns::server::Server;
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::watch::Receiver,
    task::JoinHandle,
};
use tracing::{error, info};
use trust_dns_server::ServerFuture;

use crate::config::Config;

pub mod api;
pub mod cache;
pub mod config;
pub mod dns;
pub mod filter;
pub mod metrics;
pub mod schedule;
pub mod statistics;

///
/// Spawn all servers, the API, and initialise the scheduler
///
/// # Errors
/// If there are issues during startup
///
#[no_coverage]
pub async fn spawn(mut shutdown_signal: Receiver<bool>) -> Result<JoinHandle<()>, io::Error> {
    let port = config::Config::get(|config| config.port).await;

    metrics::init();

    let scheduler = tokio::spawn({
        async move {
            schedule::Scheduler::init(config::Config::get(|config| config.schedules.clone()).await)
                .await;
        }
    });

    let dns_server = {
        let address = (IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
        let mut server = ServerFuture::new(Server {});
        server.register_socket(UdpSocket::bind(address).await?);
        server.register_listener(
            TcpListener::bind((IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)).await?,
            Duration::from_secs(30),
        );

        info!(
            "Running DNS server on {:#?}",
            address
                .to_socket_addrs()
                .expect("Unable to parse Server Address")
                .next()
                .expect("Unable to parse Server Address")
        );

        tokio::spawn(async move {
            if let Err(err) = server.block_until_done().await {
                error!("{err}");
            }
        })
    };

    let api = tokio::spawn(api::Server.run());

    Ok(tokio::spawn(async move {
        tokio::select! {
            _ = api => {}
            _ = dns_server => {}
            _ = scheduler => {}
            _ = shutdown_signal.changed() => {}
        }

        Config::save().await.unwrap_or_else(|err| {
            error!("{err}");
        });

        drop(shutdown_signal);
    }))
}
