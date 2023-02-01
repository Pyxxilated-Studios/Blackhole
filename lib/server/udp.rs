use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use tokio::{
    net::UdpSocket,
    sync::{watch::Receiver, RwLock},
};
use tracing::{info, instrument, trace};

use crate::{
    dns::{
        packet::{Buffer, Packet, ResizableBuffer},
        traits::{FromBuffer, IO},
        Record, Result,
    },
    server::handler::{Client, Handler},
};

pub struct ServerBuilder {
    port: u16,
    addr: IpAddr,
}

impl ServerBuilder {
    #[must_use]
    pub fn listen(mut self, addr: IpAddr) -> ServerBuilder {
        self.addr = addr;
        self
    }

    #[must_use]
    pub fn on(mut self, port: u16) -> ServerBuilder {
        self.port = port;
        self
    }

    ///
    /// Build the server
    ///
    /// # Errors
    /// If we fail to bind to the socket
    ///
    pub async fn build(self) -> Result<Server> {
        let address = (self.addr, self.port).into();
        Ok(Server {
            socket: Arc::new(RwLock::new(UdpSocket::bind(address).await?)),
            address,
        })
    }
}

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone)]
pub struct Server {
    socket: Arc<RwLock<UdpSocket>>,
    address: SocketAddr,
}

impl Server {
    pub fn builder() -> ServerBuilder {
        ServerBuilder {
            port: 53,
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }

    #[instrument(skip(self, shutdown_signal),
        fields(
            addr = %self.address
        )
    )]
    pub async fn run(&self, mut shutdown_signal: Receiver<bool>) -> Result<()> {
        info!("listening on {}", self.socket.read().await.local_addr()?);

        loop {
            tokio::select! {
                _ = shutdown_signal.changed() => {
                    break;
                }

                request = self.receive() => {
                    let Ok((packet, address)) = request else { break; };
                    let socket = self.socket.clone();

                    tokio::spawn(async move {
                        if let Some(Record::OPT { .. }) = packet.resources.first() {
                            Handler::<ResizableBuffer>::serve(
                                Client {
                                    client: socket,
                                    address,
                                },
                                packet,
                            )
                            .await;
                        } else {
                            Handler::<Buffer>::serve(
                                Client {
                                    client: socket,
                                    address,
                                },
                                packet,
                            )
                            .await;
                        }
                    });
                }
            }
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn receive(&self) -> Result<(Packet, SocketAddr)> {
        trace!("Waiting for requests ...");

        let mut buffer = Buffer::default();

        let sock = self.socket.read().await;
        sock.readable().await?;
        let (_bytes, address) = sock.recv_from(buffer.buffer_mut()).await?;

        let packet = Packet::from_buffer(&mut buffer)?;
        trace!(
            "DNS request received from {}:{}: ID: {}",
            address.ip().to_canonical(),
            address.port(),
            packet.header.id
        );

        Ok((packet, address))
    }
}
