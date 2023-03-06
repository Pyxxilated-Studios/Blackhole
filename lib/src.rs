#![allow(incomplete_features)]
#![forbid(unsafe_code)]
#![feature(
    array_try_from_fn,
    async_fn_in_trait,
    ip,
    no_coverage,
    once_cell,
    option_get_or_insert_default,
    type_alias_impl_trait
)]
#![feature(async_closure)]

use std::{
    io,
    net::{IpAddr, Ipv6Addr, ToSocketAddrs},
    time::Duration,
};

use tokio::{
    net::{TcpListener, UdpSocket},
    sync::watch::Receiver,
    task::JoinHandle,
};
use tracing::info;
use trust_dns_server::ServerFuture;

use crate::config::Config;

pub mod api;
pub mod cache;
pub mod config;
pub mod dns;
pub mod filter;
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

    let scheduler = tokio::spawn({
        async move {
            schedule::Scheduler::init(config::Config::get(|config| config.schedules.clone()).await)
                .await;
        }
    });

    let dns_server = {
        let mut server = ServerFuture::new(match dns::server::Server::new().await {
            Ok(server) => server,
            Err(err) => {
                // This realistically should not happen
                return Err(err.into());
            }
        });
        server.register_socket(UdpSocket::bind((IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)).await?);
        server.register_listener(
            TcpListener::bind((IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)).await?,
            Duration::from_secs(30),
        );

        tokio::spawn(async move {
            info!(
                "Running DNS server on {:#?}",
                (IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
                    .to_socket_addrs()
                    .expect("Unable to parse Server Address")
                    .next()
                    .expect("Unable to parse Server Address")
            );
            server.block_until_done().await.expect("Issue");
        })
    };

    let api = tokio::spawn(async move { api::Server.run().await });

    Ok(tokio::spawn(async move {
        tokio::select! {
            _ = api => {}
            _ = dns_server => {}
            _ = scheduler => {}
            _ = shutdown_signal.changed() => {}
        }

        Config::save().await.expect("Failed to save config");
        drop(shutdown_signal);
    }))
}
