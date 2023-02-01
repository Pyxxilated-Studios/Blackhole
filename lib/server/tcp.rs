use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    sync::{watch::Receiver, RwLock},
};
use tracing::{info, instrument, trace};

use crate::{
    dns::{
        packet::{Packet, ResizableBuffer},
        traits::{FromBuffer, IO},
        Result,
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
            listener: Arc::new(RwLock::new(TcpListener::bind(address).await?)),
            address,
        })
    }
}

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone)]
pub struct Server {
    listener: Arc<RwLock<TcpListener>>,
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
        info!("listening on {}", self.listener.read().await.local_addr()?);

        loop {
            tokio::select! {
                _ = shutdown_signal.changed() => {
                    break;
                }


                request = self.receive() => {
                    let Ok((stream, packet, address)) = request else { break; };

                    tokio::spawn(async move {
                        Handler::<ResizableBuffer>::serve(
                            Client {
                                client: stream,
                                address,
                            },
                            packet,
                        )
                        .await;
                    });
                }
            }
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn receive(&self) -> Result<(TcpStream, Packet, SocketAddr)> {
        trace!("Waiting for requests ...");

        let mut buffer = ResizableBuffer::default();

        let listener = self.listener.read().await;
        let (mut stream, address) = listener.accept().await?;

        stream.readable().await?;
        let _length = stream.read_u16().await?;
        let _bytes = stream.read_buf(&mut buffer.buffer_mut()).await?;

        let packet = Packet::from_buffer(&mut buffer)?;

        trace!(
            "DNS request received from {}:{}: ID: {}",
            address.ip().to_canonical(),
            address.port(),
            packet.header.id
        );

        Ok((stream, packet, address))
    }
}
