use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use tokio::{net::UdpSocket, sync::RwLock};
use tracing::{error, info, instrument};

use crate::dns::{
    packet::{Buffer, Packet},
    traits::IO,
    Result, ResultCode,
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
            requests: Arc::new(RwLock::new(HashMap::new())),
            address,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Server {
    socket: Arc<RwLock<UdpSocket>>,
    address: SocketAddr,
    requests: Arc<RwLock<HashMap<String, usize>>>,
}

impl Server {
    pub fn builder() -> ServerBuilder {
        ServerBuilder {
            port: 53,
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }

    pub fn requests(&self) -> &Arc<RwLock<HashMap<String, usize>>> {
        &self.requests
    }

    #[instrument(skip(self),
        fields(
            addr = %self.address
        )
    )]
    pub async fn run(&self) -> Result<()> {
        info!("listening on {}", self.socket.read().await.local_addr()?);

        while let Ok((packet, address)) = self.receive().await {
            let server = self.clone();

            tokio::spawn(async move {
                for question in packet.clone().questions {
                    *server
                        .requests
                        .write()
                        .await
                        .entry(question.name.name())
                        .or_default() += 1;
                }

                server.serve(packet, address).await;
            });
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn receive(&self) -> Result<(Packet, SocketAddr)> {
        let mut buffer = Buffer::default();

        self.socket.read().await.readable().await?;
        let (_, address) = self
            .socket
            .read()
            .await
            .recv_from(buffer.buffer_mut())
            .await?;

        Ok((Packet::try_from(&mut buffer)?, address))
    }

    #[instrument(skip(self, packet, address))]
    async fn respond(&self, mut packet: Packet, address: SocketAddr) -> Result<()> {
        let buffer = Buffer::try_from(packet.clone()).or_else(|err| {
            error!("{err:?}");

            packet.header.rescode = ResultCode::SERVFAIL;
            packet.header.response = true;
            packet.header.answers = 0;
            packet.header.truncated_message = false;
            packet.answers = vec![];
            packet.authorities = vec![];
            packet.resources = vec![];

            Buffer::try_from(packet)
        })?;

        self.socket.read().await.writable().await?;
        self.socket
            .read()
            .await
            .send_to(&buffer.buffer()[..buffer.pos()], address)
            .await?;

        Ok(())
    }

    #[instrument(skip(self, address))]
    async fn respond_error(&self, address: SocketAddr, id: u16) {
        let mut packet = Packet::default();
        packet.header.id = id;
        packet.header.rescode = ResultCode::SERVFAIL;
        packet.header.response = true;
        packet.header.answers = 0;
        packet.header.truncated_message = false;
        packet.answers = vec![];
        packet.authorities = vec![];
        packet.resources = vec![];

        let buffer = match Buffer::try_from(packet) {
            Ok(buffer) => buffer,
            Err(err) => {
                error!("{err:?}");
                return;
            }
        };

        if let Err(err) = self.socket.read().await.writable().await {
            error!("{err:?}");
            return;
        }

        if let Err(err) = self
            .socket
            .read()
            .await
            .send_to(&buffer.buffer()[..buffer.pos()], address)
            .await
        {
            error!("{err:?}");
        }
    }

    #[instrument(skip(self, packet))]
    async fn forward(&self, packet: Packet) -> Result<Packet> {
        const SERVER: (&str, u16) = ("192.168.1.123", 53);
        let forwarder = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 43210)).await?;

        let buffer = Buffer::try_from(packet)?;

        forwarder
            .send_to(&buffer.buffer()[0..buffer.pos()], SERVER)
            .await?;

        let mut res_buffer = Buffer::default();
        forwarder.recv_from(res_buffer.buffer_mut()).await?;

        Packet::try_from(&mut res_buffer)
    }

    #[instrument(skip(self, packet, address),
        fields(
            addr = %self.address
        )
    )]
    async fn serve(&self, packet: Packet, address: SocketAddr) {
        let id = packet.header.id;
        match self.forward(packet).await {
            Ok(response_packet) => {
                let id = response_packet.header.id;

                if let Err(err) = self.respond(response_packet, address).await {
                    error!("{err:?}");
                    self.respond_error(address, id).await;
                }
            }
            Err(err) => {
                error!("{err:?}");
                self.respond_error(address, id).await;
            }
        }
    }
}
