use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use tokio::{net::UdpSocket, sync::RwLock};
use tracing::instrument;

use crate::dns::{
    packet::{Buffer, Packet},
    Result,
};

pub struct ServerBuilder {
    port: u16,
    addr: IpAddr,
}

impl ServerBuilder {
    pub fn listen(mut self, addr: IpAddr) -> ServerBuilder {
        self.addr = addr;
        self
    }

    pub fn on(mut self, port: u16) -> ServerBuilder {
        self.port = port;
        self
    }

    pub async fn build(self) -> Result<Server> {
        Ok(Server {
            socket: Arc::new(RwLock::new(UdpSocket::bind((self.addr, self.port)).await?)),
            requests: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Server {
    socket: Arc<RwLock<UdpSocket>>,
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

    pub async fn run(&self) -> Result<()> {
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

                let response_buffer = server.forward(packet).await.unwrap().try_into().unwrap();
                server.respond(response_buffer, address).await.unwrap();
            });
        }

        Ok(())
    }

    #[instrument(ret, skip(self))]
    async fn receive(&self) -> Result<(Packet, SocketAddr)> {
        let mut buffer = Buffer::default();

        self.socket.read().await.readable().await?;
        let (_, address) = self.socket.read().await.recv_from(&mut buffer.buf).await?;

        Ok((Packet::try_from(&mut buffer)?, address))
    }

    #[instrument(skip(self))]
    async fn respond(&self, buffer: Buffer, address: SocketAddr) -> Result<()> {
        self.socket.read().await.writable().await?;
        self.socket
            .read()
            .await
            .send_to(&buffer.buf[0..buffer.pos], address)
            .await?;

        Ok(())
    }

    #[instrument(ret, skip(self))]
    async fn forward(&self, packet: Packet) -> Result<Packet> {
        const SERVER: (&str, u16) = ("192.168.1.123", 53);
        let forwarder = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 43210)).await?;

        let buffer = Buffer::try_from(packet)?;

        forwarder
            .send_to(&buffer.buf[0..buffer.pos], SERVER)
            .await?;

        let mut res_buffer = Buffer::default();
        forwarder.recv_from(&mut res_buffer.buf).await?;

        Packet::try_from(&mut res_buffer)
    }
}
