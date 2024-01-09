#![allow(incomplete_features)]
#![forbid(unsafe_code)]
#![feature(
    cmp_minmax,
    coverage_attribute,
    hash_set_entry,
    ip,
    lazy_cell,
    type_alias_impl_trait
)]

use std::{
    io,
    net::{IpAddr, Ipv6Addr, ToSocketAddrs},
    time::Duration,
};

use config::Config;
use dns::Server;
use hickory_server::ServerFuture;
use schedule::Scheduler;
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::watch::Receiver,
    task::JoinHandle,
};
use tracing::{error, info};

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
#[coverage(off)]
pub async fn spawn(mut shutdown_signal: Receiver<bool>) -> Result<JoinHandle<()>, io::Error> {
    let port = Config::get(|config| config.port).await;

    metrics::init().map_err(|err| io::Error::new(io::ErrorKind::Interrupted, err.to_string()))?;

    let scheduler = tokio::spawn({
        async move {
            Scheduler::init(Config::get(|config| config.schedules.clone()).await).await;
        }
    });

    let dns_server = {
        let address = (IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
        let mut server = ServerFuture::new(Server {});
        match UdpSocket::bind(address).await {
            Ok(socket) => {
                server.register_socket(socket);
            }
            Err(err) => {
                error!("Failed to bind udp socket: {err}");
                return Err(err);
            }
        }

        match TcpListener::bind(address).await {
            Ok(listener) => {
                server.register_listener(listener, Duration::from_secs(30));
            }
            Err(err) => {
                error!("Failed to bind tcp listener: {err}");
                return Err(err);
            }
        }

        info!(
            "Running DNS server on {:?}",
            address
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "Invalid DNS Server Address"
                ))?
        );

        tokio::spawn(async move {
            if let Err(err) = server.block_until_done().await {
                error!("DNS Server failure: {err}");
            }
        })
    };

    let api_shutdown_signal = shutdown_signal.clone();
    let api = tokio::spawn(async move {
        if let Err(err) = api::Server.run(api_shutdown_signal).await {
            error!("API failure: {err}");
        }
    });

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
